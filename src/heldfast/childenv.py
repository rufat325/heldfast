"""What environment a backend actually gets.

The gateway launched every backend with `dict(os.environ)` plus whatever the
config declared. So a token exported once -- for the GitHub server, say --
reached the filesystem server, the postgres server and everything else behind
the same endpoint. Each of those is a separate publisher's code.

That is what every MCP client already does, so it is not a regression. It is
also the one thing the gateway is uniquely placed to fix, and a component that
calls itself an admission boundary while handing every backend every secret on
the machine is not one.

So: a backend gets the infrastructure it needs to run, plus exactly what its
own config entry declares, and nothing else.

The infrastructure includes the user's own package-manager settings -- the
registry, the index, the release-age cutoff, whether install scripts run --
because a server is installed by the process started here, and withholding
them silently left a server behind heldfast less protected than the same
server outside it. What is withheld is said out loud in two groups:
credential-shaped names, and package-manager settings (see `explain`).

THE ALLOWLIST IS THE WHOLE DESIGN
---------------------------------
Withhold too much and every server breaks. The base set below is therefore
evidence-led rather than guessed: 2,406 real server files across the official
servers repo, both SDKs, FastMCP and the community sample were read for every
environment variable they actually consult. 192 distinct names came back, and
they divide cleanly. A handful are how a process finds its runtime and its
configuration -- PATH, HOME, APPDATA, XDG_CONFIG_HOME, USERPROFILE. Everything
else is either a credential (GITHUB_TOKEN, ANTHROPIC_API_KEY, every
*_CLIENT_SECRET) or a setting that belongs to one server.

The rest of the base set is the platform floor that nothing greps for because
nothing has to: on Windows a process without SystemRoot cannot open a socket,
and on POSIX a process without LANG mangles non-ASCII. Those are omissions
that look like unrelated bugs, so they are in the list on purpose.

DECLARING IS ALREADY THE NORM
-----------------------------
A server that needs a secret says so: `"env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}`.
References are resolved from the gateway's own environment, so the declared
shape keeps working and the secret still never sits in the config file. What
changes is only that an *undeclared* variable no longer arrives by accident.
"""

from __future__ import annotations

import os
import re
from typing import Any, NamedTuple

# How a process finds its runtime, its home and its configuration.
_RUNTIME = {
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TMP", "TEMP",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "TERM",
    # Windows. A process without SystemRoot cannot create a socket, and the
    # failure surfaces as something that looks nothing like a missing variable.
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
    "OS", "USERNAME", "USERPROFILE", "USERDOMAIN", "HOMEDRIVE", "HOMEPATH",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "PROGRAMW6432", "PUBLIC", "ALLUSERSPROFILE",
    # XDG, which is where a lot of servers keep their own config.
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR",
}

# Language runtimes: how an interpreter finds the code it is being asked to
# run. Loaders that execute a file (`NODE_OPTIONS=--require`, `PYTHONPATH`
# shadowing) are not inherited; a server that needs one declares it.
_TOOLCHAIN = {
    # PYTHONHOME is deliberately absent. It relocates the standard
    # library wholesale, which is the same class of thing as PYTHONPATH
    # shadowing an import and NODE_OPTIONS=--require: a parent variable
    # that decides what code the child loads. A server that genuinely
    # runs under a relocated interpreter declares it.
    "PYTHONUNBUFFERED", "PYTHONIOENCODING",
    "PYTHONUTF8", "PYTHONDONTWRITEBYTECODE", "VIRTUAL_ENV", "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV", "PIPX_HOME", "PIPX_BIN_DIR", "UV_CACHE_DIR",
    "UV_PYTHON",
    "NODE_PATH", "NODE_ENV", "NVM_DIR", "NVM_BIN",
    "npm_config_prefix", "npm_config_cache", "NPM_CONFIG_PREFIX",
    "BUN_INSTALL", "DENO_DIR", "JAVA_HOME", "GOPATH", "GOROOT", "DOTNET_ROOT",
}

# The user's own install-time defences: which registry or index a package
# manager resolves from, how old a release must be before it is installed,
# whether install scripts run, and which config file says the rest. A server
# launched as `npx -y pkg@1.2.3` or `uvx pkg==1.2.3` is installed by the very
# process heldfast starts, so withholding these silently resolved a newer,
# unscreened dependency tree -- or pointed a company's npm at the public
# registry, past its own curated mirror -- than the same server run without
# heldfast. That left a server behind heldfast less protected than outside it.
#
# Named one by one, and confirmed against the npm 11, pip 26 and uv docs.
# Never a prefix such as NPM_CONFIG_*: that would pass NPM_CONFIG__AUTH.
# Settings in ~/.npmrc or pip.conf already survive, because HOME and APPDATA do.
_PACKAGE_MANAGER = {
    # npm reads any `npm_config_<name>` in either case.
    "NPM_CONFIG_BEFORE", "NPM_CONFIG_MIN_RELEASE_AGE", "NPM_CONFIG_IGNORE_SCRIPTS",
    "NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG",
    "NPM_CONFIG_CAFILE",
    # pip reads PIP_<OPTION>; --uploaded-prior-to is its publish-date cutoff.
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "PIP_CERT",
    "PIP_UPLOADED_PRIOR_TO",
    "UV_EXCLUDE_NEWER", "UV_DEFAULT_INDEX", "UV_INDEX", "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL", "UV_CONFIG_FILE", "UV_INDEX_STRATEGY",
}

# Reaching the network at all, from behind whatever the operator's network is.
_NETWORK = {
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
}

BASE = {name.upper() for name in (_RUNTIME | _TOOLCHAIN | _PACKAGE_MANAGER | _NETWORK)}
_INSTALL_SETTINGS = {name.upper() for name in _PACKAGE_MANAGER}


def carries_login(value: str) -> bool:
    """Whether a registry or index setting has a user name or password in it.

    `https://user:token@host/simple` is the common way to reach a private
    index. The wrapped server runs inside the process that installs it, so an
    index credential handed to `uvx` or `npx` is handed to the server too.
    Several URLs are separated by whitespace (the EXTRA variants, UV_INDEX),
    and UV_INDEX may name one as `name=https://...`.
    """
    from urllib.parse import urlsplit

    for part in str(value or "").split():
        if "=" in part.split("://", 1)[0]:
            part = part.split("=", 1)[1]
        try:
            url = urlsplit(part)
            if url.username or url.password:
                return True
        except ValueError:
            # A value urllib cannot parse is not one this can clear.
            return True
    return False

# This tool's own variables, which are never a child's business.
#
# MCP_PIN_LOG_KEY is the reason this is unconditional. It turns the audit
# chain from a hash into a MAC, and the adversary it is aimed at is precisely
# the server being wrapped -- so handing that server the key gives away the
# one property keying was added for. `auditlog.py` has always said the guard
# does not pass it on; this is where that becomes true.
#
# MCP_PIN_ALLOW_PATH_SCAN is here for the same reason one step down: it is a
# capability this deployment was granted, and a child that happens to be
# another heldfast should not inherit it by standing close enough.
#
# Withheld under `isolate=False` as well. That switch exists so an operator
# can keep their own environment flowing to a server while they move secrets
# into config; it was never a request for ours.
#
# Named one by one rather than matched on an `MCP_PIN_` prefix. The prefix
# version also swallowed variables that are not ours to take -- a server's
# own `MCP_PIN_*` setting, and this suite's `MCP_PIN_HOSTILE`, which is how
# the fixture is told which attack to run. Withholding what we do not own is
# the same class of mistake as leaking what we do, just quieter.
OWN = frozenset({"MCP_PIN_LOG_KEY", "MCP_PIN_ALLOW_PATH_SCAN"})


def _mine(name: str) -> bool:
    return name.upper() in OWN

# `${VAR}`, `$VAR`, and the `%VAR%` a Windows config might carry.
_REF = re.compile(r"^\s*(?:\$\{(\w+)\}|\$(\w+)|%(\w+)%)\s*$")


def _resolve(value: str, source: dict) -> str:
    """A declared value, with a single whole-string reference resolved."""
    match = _REF.match(value or "")
    if not match:
        return value
    name = next(g for g in match.groups() if g)
    # An unresolvable reference stays as written. Substituting an empty string
    # would turn "the operator forgot to export it" into "the server got a
    # blank token", and a blank token fails in ways nobody traces back here.
    return source.get(name, value)


def build(spec: Any | None, parent: dict | None = None,
          share: set | None = None, isolate: bool = True) -> tuple[dict, list]:
    """(environment for this backend, names withheld from it).

    `isolate=False` restores the old behaviour -- the whole parent environment
    -- for anyone who needs it while they move their secrets into config.
    """
    parent = dict(os.environ if parent is None else parent)
    declared = {str(k): str(v) for k, v in (getattr(spec, "env", None) or {}).items()}

    if not isolate:
        env = {k: v for k, v in parent.items() if not _mine(k)}
        env.update({k: _resolve(v, parent) for k, v in declared.items()})
        env.setdefault("PYTHONUNBUFFERED", "1")
        return env, sorted(k for k in parent if _mine(k) and k not in declared)

    shared = {s.upper() for s in (share or set())}
    allowed = BASE | shared
    env = {k: v for k, v in parent.items()
           if k.upper() in allowed and not _mine(k)
           # An index URL with a login in it goes only when named.
           and not (k.upper() in _INSTALL_SETTINGS and k.upper() not in shared
                    and carries_login(v))}
    # Declared last, so a server can override anything in the base set for
    # itself -- that is what declaring it means.
    env.update({k: _resolve(v, parent) for k, v in declared.items()})
    env.setdefault("PYTHONUNBUFFERED", "1")

    withheld = sorted(k for k in parent if k not in env and k not in declared)
    return env, withheld


# Names that read as a credential. Only used to decide what is worth saying
# out loud when something is withheld -- withholding does not depend on it.
_SECRETISH = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|KEY|CREDENTIAL|"
    r"CREDENTIALS|AUTH|ACCESS_KEY|PRIVATE_KEY|SESSION|COOKIE|PAT)(?:$|_)",
    re.IGNORECASE)


# A package manager's own namespace. Only used for reporting, like the above.
_INSTALLISH = re.compile(r"^(?:NPM_CONFIG_|PIP_|PIPX_|UV_|YARN_|PNPM_|BUN_|DENO_)",
                         re.IGNORECASE)


class Notable(NamedTuple):
    """The withheld names an operator would want named, in two groups."""
    credentials: list
    install_settings: list


def notable(withheld: list) -> Notable:
    """The withheld names an operator would want named.

    Listing all ~60 variables of a normal shell would bury the one that
    matters. A server that stops authenticating is almost always looking for
    a credential-shaped name; a server that installs a different dependency
    tree than it does outside heldfast is missing one of the user's own
    package-manager settings. Those two groups are what gets printed. A name
    that is both (NPM_CONFIG__AUTH) is a credential.
    """
    credentials = [n for n in withheld if _SECRETISH.search(n)]
    install = [n for n in withheld if _INSTALLISH.search(n) and n not in credentials]
    return Notable(credentials, install)


def _names(names: list, most: int = 6) -> str:
    return ", ".join(names[:most]) + (f" and {len(names) - most} more" if len(names) > most else "")


def explain(withheld: list) -> list:
    """What `gateway`, `guard` and `probe` say about a child's environment:
    one line per group that is not empty."""
    found = notable(withheld)
    lines = []
    if found.credentials:
        lines.append(f"not given {_names(found.credentials)} -- declare it in the server's "
                     f"env, or pass --share-env NAME")
    if found.install_settings:
        lines.append(f"not given package-manager settings {_names(found.install_settings)} "
                     f"-- pass --share-env NAME. A registry or index URL with a user name or "
                     f"password in it is withheld because the server runs inside the process "
                     f"that installs it; --share-env passes it on with its credential")
    return lines
