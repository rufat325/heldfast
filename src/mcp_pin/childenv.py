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
from typing import Any

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
# run. Withholding these does not protect anything and breaks every server
# installed in a virtualenv or a node prefix.
_TOOLCHAIN = {
    "PYTHONPATH", "PYTHONHOME", "PYTHONUNBUFFERED", "PYTHONIOENCODING",
    "PYTHONUTF8", "PYTHONDONTWRITEBYTECODE", "VIRTUAL_ENV", "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV", "PIPX_HOME", "PIPX_BIN_DIR", "UV_CACHE_DIR",
    "UV_PYTHON", "UV_INDEX",
    "NODE_PATH", "NODE_OPTIONS", "NODE_ENV", "NVM_DIR", "NVM_BIN",
    "npm_config_prefix", "npm_config_cache", "NPM_CONFIG_PREFIX",
    "BUN_INSTALL", "DENO_DIR", "JAVA_HOME", "GOPATH", "GOROOT", "DOTNET_ROOT",
}

# Reaching the network at all, from behind whatever the operator's network is.
_NETWORK = {
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
}

BASE = {name.upper() for name in (_RUNTIME | _TOOLCHAIN | _NETWORK)}

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


def build(spec: Any, parent: dict | None = None,
          share: set | None = None, isolate: bool = True) -> tuple[dict, list]:
    """(environment for this backend, names withheld from it).

    `isolate=False` restores the old behaviour -- the whole parent environment
    -- for anyone who needs it while they move their secrets into config.
    """
    parent = dict(os.environ if parent is None else parent)
    declared = {str(k): str(v) for k, v in (getattr(spec, "env", None) or {}).items()}

    if not isolate:
        env = dict(parent)
        env.update({k: _resolve(v, parent) for k, v in declared.items()})
        env.setdefault("PYTHONUNBUFFERED", "1")
        return env, []

    allowed = BASE | {s.upper() for s in (share or set())}
    env = {k: v for k, v in parent.items() if k.upper() in allowed}
    # Declared last, so a server can override anything in the base set for
    # itself -- that is what declaring it means.
    env.update({k: _resolve(v, parent) for k, v in declared.items()})
    env.setdefault("PYTHONUNBUFFERED", "1")

    withheld = sorted(k for k in parent
                      if k.upper() not in allowed and k not in declared)
    return env, withheld


# Names that read as a credential. Only used to decide what is worth saying
# out loud when something is withheld -- withholding does not depend on it.
_SECRETISH = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|KEY|CREDENTIAL|"
    r"CREDENTIALS|AUTH|ACCESS_KEY|PRIVATE_KEY|SESSION|COOKIE|PAT)(?:$|_)",
    re.IGNORECASE)


def notable(withheld: list) -> list:
    """The withheld names an operator would want named.

    Listing all ~60 variables of a normal shell would bury the one that
    matters. A server that stops authenticating after this lands is almost
    always looking for one of these, so these are the ones printed.
    """
    return [name for name in withheld if _SECRETISH.search(name)]
