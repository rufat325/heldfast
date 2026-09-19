"""The `env` block, which was never read for anything but literal secrets.

A config entry has two ways to decide what a server process does. The command
is one, and MCPA001-004 have watched it from the beginning. The environment is
the other, and nothing looked at it: an attack corpus of thirteen shapes
against the env block scored thirteen misses.

The block can do three things the command can do.

**Run code the server never asked to run.** `NODE_OPTIONS=--require ./x.js`
loads a file into any Node process at startup. `LD_PRELOAD` and
`DYLD_INSERT_LIBRARIES` do it at the loader. `BASH_ENV` does it for any
non-interactive shell. None of these touch the command line, so a config whose
`"command": "npx"` looks entirely ordinary executes something else first.

**Take over what the server resolves.** `PATH` decides which binary `node`
actually is.

**Read the traffic.** `NODE_TLS_REJECT_UNAUTHORIZED=0` turns off certificate
verification; a substituted CA bundle does the same thing while still looking
verified; a proxy sends every request somewhere first.

And a fourth thing the command cannot do at all: **quietly collect a secret
that belongs to another server.** `"DEBUG": "${GITHUB_TOKEN}"` reads as a
debug flag and resolves to the token.

PRECISION
---------
Measured against 196 real config blocks (98 harvested from the community
index, the rest from the official servers repo and the SDKs) carrying 40 `env`
entries between them. Not one uses any variable named here. Exactly one value
is a reference, and its key matches its target, so the aliasing signal has
zero occurrences too. Every real key is either a credential-shaped name or a
plain setting like `PYTHONIOENCODING`.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
`PYTHONSTARTUP` looks like it belongs and does not: CPython reads it only when
the interpreter is interactive, so it does nothing for `python server.py`.
Listing it would be a finding nobody can act on and a claim that is false.

`PYTHONPATH` and `VIRTUAL_ENV` can shadow a module and so reach execution, but
they are also how a local server finds its own code, and real configs set
them. They are left out on that evidence rather than on principle.
"""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlsplit

from ..findings import Finding, Location, Severity
from .base import AuditContext, rule

# Runs attacker-chosen code before the server's own first line. No config in
# the corpus sets any of these.
_LOADER = {
    "LD_PRELOAD": "loads a shared object into the process at startup",
    "LD_AUDIT": "loads an auditing library into the dynamic linker",
    "DYLD_INSERT_LIBRARIES": "loads a dylib into the process at startup (macOS)",
    "DYLD_LIBRARY_PATH": "redirects which dylibs the process loads (macOS)",
    "BASH_ENV": "is executed by every non-interactive bash",
    "PERL5OPT": "injects switches, including -M, into every perl process",
    "RUBYOPT": "injects switches, including -r, into every ruby process",
}

# NODE_OPTIONS is ordinary when it sizes the heap and is code execution when
# it loads a module, so it is judged on its contents rather than its name.
_NODE_EXEC = re.compile(r"--(?:require|import|experimental-loader|loader)\b",
                        re.IGNORECASE)

# Turning off verification. A value is needed: the variable set to 1 is the
# secure default and saying so would be reporting the fix.
_TLS_OFF = {
    "NODE_TLS_REJECT_UNAUTHORIZED": "0",
    "PYTHONHTTPSVERIFY": "0",
    "GIT_SSL_NO_VERIFY": None,      # any value enables it
    "CURL_INSECURE": None,
}

# Deciding what the process trusts, or where its traffic goes first.
_TRUST = {"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
          "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"}
_PROXY = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}

# `${VAR}`, `$VAR`, `%VAR%` as a whole value.
_REF = re.compile(r"^\s*(?:\$\{(\w+)\}|\$(\w+)|%(\w+)%)\s*$")

# A name that reads as a credential. Whole words, so MONKEY is not a KEY.
_SECRETISH = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|KEY|CREDENTIAL|"
    r"CREDENTIALS|AUTH|ACCESS_KEY|PRIVATE_KEY|SESSION|COOKIE|PAT)(?:$|_)",
    re.IGNORECASE)


def _entries(ctx: AuditContext) -> Iterable[tuple]:
    for server in ctx.servers:
        if server.disabled:
            continue
        for key, value in (server.env or {}).items():
            yield server, str(key), str(value)


def _at(server, key: str) -> Location:
    return Location(path=server.source, line=server.line, snippet=f"env.{key}")


@rule("MCPA034", "Environment variable in the config runs code or reads traffic",
      Severity.CRITICAL)
def dangerous_env(ctx: AuditContext) -> Iterable[Finding]:
    """A config entry whose `env` reaches execution or interception.

    The command line is reviewed; the env block beside it is not, and it can
    do the same things.
    """
    for server, key, value in _entries(ctx):
        upper = key.upper()

        if upper in _LOADER:
            yield Finding(
                rule_id="MCPA034",
                title="Environment variable in the config executes code at launch",
                severity=Severity.CRITICAL,
                location=_at(server, key),
                evidence=(
                    f"{server.name} sets {key} in its config, which {_LOADER[upper]}. "
                    f"The command line is unremarkable; this runs first."
                ),
                remediation=(
                    "Remove it. Nothing an MCP server legitimately needs is configured "
                    "this way, and none of 196 real configs sets it. If you did not "
                    "add this line, the config is running code nobody reviewed."
                ),
                server=server.name,
                atlas=["AML.T0011"],
                cwe=["CWE-426", "CWE-94"],
                tags=["environment", "execution"],
            )
            continue

        if upper == "NODE_OPTIONS" and _NODE_EXEC.search(value):
            yield Finding(
                rule_id="MCPA034",
                title="Environment variable in the config executes code at launch",
                severity=Severity.CRITICAL,
                location=_at(server, key),
                evidence=(
                    f"{server.name} sets NODE_OPTIONS to load a module, so Node runs it "
                    f"before the server's own entry point. The command line does not "
                    f"mention it."
                ),
                remediation=(
                    "Remove the loader switch. NODE_OPTIONS is for tuning the runtime "
                    "-- a heap size is fine -- and --require/--import there is a way to "
                    "run code without it appearing in the command."
                ),
                server=server.name,
                atlas=["AML.T0011"],
                cwe=["CWE-94"],
                tags=["environment", "execution"],
            )
            continue

        if upper == "PATH":
            yield Finding(
                rule_id="MCPA034",
                title="Environment variable in the config replaces the command's PATH",
                severity=Severity.HIGH,
                location=_at(server, key),
                evidence=(
                    f"{server.name} sets PATH in its config, which decides which binary "
                    f"every name in its command resolves to -- including the "
                    f"interpreter itself."
                ),
                remediation=(
                    "Name the binary by absolute path in `command` instead, so what "
                    "runs is visible in the line you review."
                ),
                server=server.name,
                atlas=["AML.T0011"],
                cwe=["CWE-426"],
                tags=["environment", "execution"],
            )
            continue

        if upper in _TLS_OFF and (_TLS_OFF[upper] is None
                                  or value.strip() == _TLS_OFF[upper]):
            yield Finding(
                rule_id="MCPA034",
                title="Environment variable in the config disables certificate checking",
                severity=Severity.HIGH,
                location=_at(server, key),
                evidence=(
                    f"{server.name} sets {key}={value.strip()}, which stops the process "
                    f"verifying the certificates it is given. Anything on the path can "
                    f"then read and rewrite its traffic."
                ),
                remediation=(
                    "Remove it and fix the certificate instead. If a corporate root is "
                    "the reason, add that root rather than accepting every certificate."
                ),
                server=server.name,
                atlas=["AML.T0011"],
                cwe=["CWE-295"],
                tags=["environment", "transport"],
            )
            continue

        if upper in _TRUST:
            yield Finding(
                rule_id="MCPA034",
                title="Environment variable in the config replaces the trusted roots",
                severity=Severity.HIGH,
                location=_at(server, key),
                evidence=(
                    f"{server.name} points {key} at a file of its own choosing, so the "
                    f"process trusts whatever signed that. Traffic still looks verified."
                ),
                remediation=(
                    "Install the root in the system trust store, where it is visible to "
                    "everything, rather than substituting one for this process."
                ),
                server=server.name,
                atlas=["AML.T0011"],
                cwe=["CWE-295"],
                confidence=0.85,
                tags=["environment", "transport"],
            )
            continue

        if upper in _PROXY and urlsplit(value).netloc:
            yield Finding(
                rule_id="MCPA034",
                title="Environment variable in the config routes traffic through a proxy",
                severity=Severity.MEDIUM,
                location=_at(server, key),
                evidence=(
                    f"{server.name} sends its requests via {urlsplit(value).netloc} "
                    f"before they reach wherever they were addressed."
                ),
                remediation=(
                    "A proxy set machine-wide is ordinary; one pinned into a server's "
                    "config is worth confirming, because only that server uses it."
                ),
                server=server.name,
                atlas=["AML.T0011"],
                cwe=["CWE-319"],
                confidence=0.7,
                tags=["environment", "transport"],
            )


@rule("MCPA035", "Environment declaration collects a credential under another name",
      Severity.HIGH)
def aliased_credential(ctx: AuditContext) -> Iterable[Finding]:
    """A reference that renames a secret into something that looks dull.

    Referencing a variable is the documented way to keep a secret out of a
    config file, and renaming one is legitimate --
    `GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_TOKEN}` is the same secret under
    the name that server wants.

    Binding it to a key that is *not* credential-shaped is different. It reads
    as a setting, it survives review, and it hands that server a secret which
    belongs to another one. The gateway's environment isolation does not stop
    it, because a declaration is exactly what isolation honours -- so this is
    the rule that makes the isolation's promise true.
    """
    for server, key, value in _entries(ctx):
        match = _REF.match(value)
        if not match:
            continue
        target = next(g for g in match.groups() if g)
        if not _SECRETISH.search(target):
            continue
        if _SECRETISH.search(key):
            continue          # a rename: still a credential, under a credential name
        yield Finding(
            rule_id="MCPA035",
            title="Environment declaration collects a credential under another name",
            severity=Severity.HIGH,
            location=_at(server, key),
            evidence=(
                f"{server.name} declares {key!r}, which reads as an ordinary setting, "
                f"and resolves it from {target!r}. That server receives the secret."
            ),
            remediation=(
                f"If {server.name} needs that credential, name it so -- a reviewer "
                f"should be able to see which servers hold which secrets by reading "
                f"the config. If it does not, delete the line: this is the shape a "
                f"credential-harvesting config entry takes, and it is the one thing "
                f"environment isolation cannot refuse, because a declaration is what "
                f"isolation honours."
            ),
            server=server.name,
            atlas=["AML.T0024", "AML.T0057"],
            cwe=["CWE-522"],
            confidence=0.9,
            tags=["environment", "credentials"],
        )
