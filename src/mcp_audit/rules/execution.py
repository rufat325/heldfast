"""Rules about *how* a local (STDIO) server gets executed.

MCP's STDIO transport launches a local process by design. That is not itself
a vulnerability -- but it means the config file is an execution surface, and
anything that widens that surface (a shell, an unpinned package, a piped
installer) converts "edit a JSON file" into "run arbitrary code".
"""

from __future__ import annotations

import re
from typing import Iterable

from ..findings import Finding, Location, Severity
from .base import AuditContext, rule

SHELL_BINARIES = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh",
    "cmd", "powershell", "pwsh",
}

# Tokens that only mean something to a shell. Their presence in argv implies
# the arguments are being interpreted rather than passed straight to execve.
#
# ${VAR} is deliberately absent. It is the variable indirection that clients
# like VS Code define, and that MCPA005's own remediation tells people to use
# -- flagging it would penalise the exact practice this scanner recommends.
# Args reach execve, not a shell, so it is inert there; and if a shell really
# is involved, the shell-binary branch of MCPA001 catches that directly.
SHELL_METACHARS = re.compile(r"\|\||&&|[;|]|\$\(|>>|<\(|\x60")

PIPE_TO_INTERPRETER = re.compile(
    r"(?:curl|wget|iwr|invoke-webrequest|invoke-restmethod|irm)\b[^|]*\|\s*"
    r"(?:sudo\s+)?(?:sh|bash|zsh|python[0-9.]*|node|iex|invoke-expression|perl|ruby)\b",
    re.IGNORECASE,
)

RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "yarn", "pnpm", "deno", "bun"}

# Runner flags that consume the following token, so it is not the package name.
_FLAGS_WITH_VALUE = {"--package", "-p", "--from", "--with", "--node-range", "--registry"}

# Subcommands that precede the package name for certain runners.
_RUNNER_SUBCOMMANDS = {"dlx", "run", "exec", "x"}


def _basename(cmd: str) -> str:
    base = cmd.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def _server_location(server) -> Location:
    return Location(path=server.source, line=server.line, snippet=server.command_line[:200])


def _active(ctx: AuditContext):
    return [s for s in ctx.servers if not s.disabled]


@rule("MCPA001", "Server command invokes a shell", Severity.HIGH)
def shell_invocation(ctx: AuditContext) -> Iterable[Finding]:
    """Server is launched through a shell interpreter, widening the exec surface."""
    for s in _active(ctx):
        if s.transport != "stdio" or not s.command:
            continue
        uses_shell = _basename(s.command) in SHELL_BINARIES
        has_meta = bool(SHELL_METACHARS.search(" ".join(s.args)))
        if not (uses_shell or has_meta):
            continue
        if uses_shell:
            evidence = f"command={s.command!r} launches a shell: {s.command_line[:200]}"
            remediation = (
                "Invoke the server binary directly with an argv list instead of routing "
                "through a shell. If a shell is genuinely required, ensure no argument is "
                "built from untrusted or environment-derived input."
            )
        else:
            evidence = f"shell metacharacters in args: {s.command_line[:200]}"
            remediation = (
                "Remove shell metacharacters from args. Arguments are passed to the process "
                "directly, so these are either inert or evidence of a hidden shell wrapper."
            )
        yield Finding(
            rule_id="MCPA001",
            title="Server command invokes a shell",
            severity=Severity.HIGH if uses_shell else Severity.MEDIUM,
            location=_server_location(s),
            evidence=evidence,
            remediation=remediation,
            server=s.name,
            atlas=["AML.T0011"],
            cwe=["CWE-78"],
            tags=["execution", "stdio"],
        )


@rule("MCPA002", "Remote code fetched and piped to an interpreter", Severity.CRITICAL)
def curl_pipe_shell(ctx: AuditContext) -> Iterable[Finding]:
    """Server startup downloads code and executes it immediately."""
    for s in _active(ctx):
        line = s.command_line
        if not PIPE_TO_INTERPRETER.search(line):
            continue
        yield Finding(
            rule_id="MCPA002",
            title="Remote code fetched and piped to an interpreter",
            severity=Severity.CRITICAL,
            location=_server_location(s),
            evidence=f"startup command downloads and executes remote code: {line[:200]}",
            remediation=(
                "Never pipe a network fetch into an interpreter at server start. Install the "
                "server from a pinned package or a vendored artifact whose hash you verify."
            ),
            server=s.name,
            atlas=["AML.T0010.001", "AML.T0011"],
            cwe=["CWE-494"],
            tags=["execution", "supply-chain"],
        )


# Runners whose package tokens use PEP 508 specifiers (name==1.2.3) rather
# than npm's name@1.2.3.
_PYTHON_RUNNERS = {"uvx", "pipx"}

_PEP508_SPLIT = re.compile(r"(===|==|>=|<=|~=|!=|>|<)")


def extract_package(s) -> tuple[str, str] | None:
    """Return (runner, package_token) for a runner-style invocation, else None."""
    if not s.command:
        return None
    base = _basename(s.command)
    if base not in RUNNERS:
        return None
    i = 0
    args = s.args
    while i < len(args):
        tok = args[i]
        if tok in _FLAGS_WITH_VALUE:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        if tok in _RUNNER_SUBCOMMANDS:
            i += 1
            continue
        return base, tok
    return None


def split_package(pkg: str, runner: str = "npx") -> tuple[str, str | None]:
    """Split a package token into (name, version_spec_or_None).

    The separator is ecosystem-specific: npm spells it `pkg@1.2.3` while
    uvx/pipx take PEP 508 (`pkg==1.2.3`). Treating a PEP 508 pin as unpinned
    is a false positive on correct configuration, which is worse than a miss.
    """
    if runner in _PYTHON_RUNNERS:
        m = _PEP508_SPLIT.search(pkg)
        if not m:
            # Extras or markers without a version still count as unpinned.
            return pkg.split("[", 1)[0].strip(), None
        name = pkg[: m.start()].split("[", 1)[0].strip()
        return name, pkg[m.start():].strip()
    if pkg.startswith("@"):
        scope, sep, rest = pkg.partition("/")
        if not sep:
            return pkg, None
        name, at, ver = rest.partition("@")
        return f"{scope}/{name}", (ver if at else None)
    name, at, ver = pkg.partition("@")
    return name, (ver if at else None)


# A version specifier that still lets a new publish execute without review.
# `==1.2.3` and `===1.2.3` are pins; every other PEP 508 operator floats.
_FLOATING = re.compile(
    r"^(?:latest|next|canary|beta|alpha|\*|x|\^|~(?!=)|>=|<=|~=|!=|>|<|\d+\.x|\d+\.\d+\.x)")


# Severity LOW, not MEDIUM: `npx -y <pkg>` is the ecosystem's universal
# idiom. Measured against 83 real-world configs it accounted for 77% of all
# findings, which drowns everything else. It is a real supply-chain risk and
# stays reported -- but a rule that fires on essentially every config is
# hygiene advice, not a finding.
@rule("MCPA003", "Package executed without a pinned version", Severity.LOW)
def unpinned_package(ctx: AuditContext) -> Iterable[Finding]:
    """npx/uvx will silently fetch and run the newest publish on every start."""
    for s in _active(ctx):
        found = extract_package(s)
        if not found:
            continue
        runner, pkg = found
        if pkg.startswith((".", "/", "~")) or re.match(r"^[a-zA-Z]:[\\/]", pkg):
            continue  # local path, not a registry fetch
        name, version = split_package(pkg, runner)
        if version and not _FLOATING.match(version):
            continue
        pin_example = f"{name}==1.2.3" if runner in _PYTHON_RUNNERS else f"{name}@1.2.3"
        detail = f"floating version {version!r}" if version else "no version specifier"
        yield Finding(
            rule_id="MCPA003",
            title="Package executed without a pinned version",
            severity=Severity.LOW,
            location=_server_location(s),
            evidence=(
                f"{s.command} resolves {name!r} with {detail}; a new publish is executed "
                "at the next launch without review"
            ),
            remediation=(
                f"Pin an exact version (e.g. {pin_example}) and upgrade deliberately. Floating "
                "resolution is the mechanism that turns a maintainer compromise into your "
                "compromise with no action on your part."
            ),
            server=s.name,
            atlas=["AML.T0010.001"],
            cwe=["CWE-1357"],
            tags=["supply-chain"],
        )


# Well-known first-party MCP server packages, used as the typosquat baseline.
KNOWN_PACKAGES = {
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-time",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-redis",
    "@modelcontextprotocol/server-sentry",
    "@modelcontextprotocol/inspector",
    "mcp-server-fetch",
    "mcp-server-git",
    "mcp-server-sqlite",
    "mcp-server-time",
}

_OFFICIAL_SCOPE = "@modelcontextprotocol/"


def levenshtein(a: str, b: str, cap: int = 2) -> int:
    """Edit distance, early-exiting once it provably exceeds `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


@rule("MCPA004", "Package name resembles a known MCP server (possible typosquat)", Severity.HIGH)
def typosquat(ctx: AuditContext) -> Iterable[Finding]:
    """Near-miss of an official package name -- the impersonation pattern."""
    for s in _active(ctx):
        found = extract_package(s)
        if not found:
            continue
        runner, pkg = found
        name, _ = split_package(pkg, runner)
        if name in KNOWN_PACKAGES:
            continue

        hit: tuple[str, str] | None = None  # (official_name, explanation)

        # Case 1: an unscoped package flattening to an official scoped name.
        flattened = name.replace("@", "").replace("/", "-").replace("_", "-").lower()
        if not name.startswith(_OFFICIAL_SCOPE):
            for known in sorted(KNOWN_PACKAGES):
                known_flat = known.replace("@", "").replace("/", "-").lower()
                if flattened == known_flat:
                    hit = (known, f"{name!r} flattens to the official package {known!r} "
                                  "but is not published under that scope")
                    break

        # Case 2: a small edit distance from an official name.
        if hit is None:
            for known in sorted(KNOWN_PACKAGES):
                dist = levenshtein(name.lower(), known.lower(), cap=2)
                if 0 < dist <= 2:
                    hit = (known, f"{name!r} is {dist} character(s) from the official "
                                  f"package {known!r}")
                    break

        if hit is None:
            continue
        official, explanation = hit
        yield Finding(
            rule_id="MCPA004",
            title="Package name resembles a known MCP server (possible typosquat)",
            severity=Severity.HIGH,
            location=_server_location(s),
            evidence=explanation,
            remediation=(
                f"Verify the publisher before running this. The first-party package is "
                f"{official!r}. If this package is a legitimate fork, pin it and record the "
                "decision so future scans stop flagging it."
            ),
            server=s.name,
            atlas=["AML.T0010.001"],
            cwe=["CWE-1357"],
            tags=["supply-chain", "typosquat"],
        )


# An allowlist is only a restriction if the binaries on it cannot themselves be
# told to run something else. Each of these takes an argument, or reads a
# config key, that executes an arbitrary command -- so a server that checks
# argv[0] against a list containing any of them has a control that does not
# control anything.
ARGUMENT_EXECUTION_PRIMITIVES = {
    "git": "-c alias.x='!cmd', -c core.fsmonitor=cmd and -c diff.external=cmd all run a command",
    "find": "-exec and -execdir run a command per matched file",
    "tar": "--checkpoint-action=exec=cmd and --to-command=cmd run a command",
    "ssh": "-o ProxyCommand=cmd and -o LocalCommand=cmd run a command on this host",
    "rsync": "-e cmd and --rsync-path=cmd run a command",
    "awk": "BEGIN { system(\"cmd\") } runs a command",
    "gawk": "BEGIN { system(\"cmd\") } runs a command",
    "sed": "GNU sed's e flag (s/x/cmd/e) runs a command",
    "vim": "-c ':!cmd' runs a command",
    "env": "env cmd execs anything, so argv[0] is only ever 'env'",
    "xargs": "xargs cmd execs an arbitrary command",
    "nice": "nice cmd execs an arbitrary command",
    "timeout": "timeout N cmd execs an arbitrary command",
    "node": "-e '<code>' evaluates JavaScript, including child_process",
    "python": "-c '<code>' evaluates Python, including os.system",
    "python3": "-c '<code>' evaluates Python, including os.system",
    "perl": "-e '<code>' evaluates Perl, including system()",
    "ruby": "-e '<code>' evaluates Ruby, including system()",
    "php": "-r '<code>' evaluates PHP, including shell_exec()",
    "npm": "run-script executes whatever package.json defines",
    "npx": "-c '<script>' runs a command string",
    "make": "-f - reads a makefile from stdin and runs its recipes",
    "docker": "run --privileged -v /:/host mounts and executes on the host",
}

# Whether an env var names an allowlist is decided on whole tokens, never on
# substrings: DISALLOWED_COMMANDS contains the letters of ALLOW, and reading it
# as an allowlist would invert the meaning of a denylist.
_ALLOW_TOKENS = {"ALLOW", "ALLOWED", "ALLOWLIST", "WHITELIST", "PERMIT",
                 "PERMITTED", "SAFE"}
_DENY_TOKENS = {"DISALLOW", "DISALLOWED", "DENY", "DENIED", "DENYLIST", "BLOCK",
                "BLOCKED", "BLOCKLIST", "BLACKLIST", "FORBID", "FORBIDDEN",
                "EXCLUDE", "EXCLUDED", "NO", "NOT", "NEVER", "UNSAFE"}
# TOOL/TOOLS are deliberately absent. In this ecosystem a "tool" is an agent
# tool, not a binary, and ALLOWED_TOOLS=Bash is MCPA013's subject. Two rules
# describing one fact in different words is how a catalog stops being read.
_SUBJECT_TOKENS = {"COMMAND", "COMMANDS", "CMD", "CMDS", "BIN", "BINARY",
                   "BINARIES", "EXEC", "EXECUTABLE", "EXECUTABLES",
                   "PROGRAM", "PROGRAMS", "SHELL"}

_LIST_SEPARATORS = re.compile(r"[,;:\s]+")


def _is_command_allowlist(key: str) -> bool:
    tokens = {t for t in re.split(r"[^A-Za-z]+", key.upper()) if t}
    if tokens & _DENY_TOKENS:
        return False
    return bool(tokens & _ALLOW_TOKENS) and bool(tokens & _SUBJECT_TOKENS)


def _allowlist_entries(value: str) -> list[str]:
    """Binary names from an allowlist value, however it is punctuated."""
    out = []
    for piece in _LIST_SEPARATORS.split(value or ""):
        piece = piece.strip().strip("\"'")
        if not piece:
            continue
        # An entry may be a path; the allowlist check upstream compares the
        # binary, so that is what matters here too.
        name = piece.replace("\\", "/").rsplit("/", 1)[-1]
        if name.lower().endswith(".exe"):
            name = name[:-4]
        out.append(name.lower())
    return out


@rule("MCPA029", "Command allowlist includes a binary that runs arbitrary commands",
      Severity.HIGH)
def allowlist_bypass(ctx: AuditContext) -> Iterable[Finding]:
    """An allowlist naming git, find or env does not restrict anything."""
    for s in _active(ctx):
        for key, value in (s.env or {}).items():
            if not _is_command_allowlist(str(key)):
                continue
            hits = []
            for name in _allowlist_entries(str(value)):
                if name in SHELL_BINARIES:
                    hits.append((name, "a shell runs whatever string it is given"))
                elif name in ARGUMENT_EXECUTION_PRIMITIVES:
                    hits.append((name, ARGUMENT_EXECUTION_PRIMITIVES[name]))
            if not hits:
                continue

            listed = ", ".join(f"{n} ({why})" for n, why in hits[:3])
            yield Finding(
                rule_id="MCPA029",
                title="Command allowlist includes a binary that runs arbitrary commands",
                severity=Severity.HIGH,
                location=_server_location(s),
                evidence=(
                    f"{key} permits {len(hits)} binary(ies) that execute anything: {listed}"
                ),
                remediation=(
                    "Remove those entries, or stop relying on the allowlist as the "
                    "boundary. A check on the binary name is only a restriction while "
                    "every name on the list can do one thing; these each take an "
                    "argument that runs a command of the caller's choosing, so the "
                    "allowlist permits everything while appearing to permit little."
                ),
                server=s.name,
                atlas=["AML.T0053"],
                cwe=["CWE-183"],
                tags=["execution", "allowlist"],
            )


@rule("MCPA030", "Tool parameter reaches a shell in the server's own source",
      Severity.CRITICAL)
def shell_injection_in_source(ctx: AuditContext) -> Iterable[Finding]:
    """A model-controlled argument interpolated into a command string."""
    for flow in ctx.source_flows:
        via = f" (via {flow.via})" if getattr(flow, "via", "") else ""
        yield Finding(
            rule_id="MCPA030",
            title="Tool parameter reaches a shell in the server's own source",
            severity=Severity.CRITICAL,
            location=Location(path=flow.path, line=flow.line, snippet=flow.snippet),
            evidence=(
                f"{flow.function}(): parameter {flow.parameter!r} reaches "
                f"{flow.sink}{via}"
            ),
            remediation=(
                "Pass an argument list instead of a command string: "
                "subprocess.run([\"wc\", \"-l\", path]) never involves a shell. "
                "Where a shell is genuinely required, wrap every interpolated "
                "value in shlex.quote(); this rule follows that and stays "
                "quiet. A tool parameter is chosen by whatever is steering the "
                "agent, so this is remote code execution wearing a schema."
            ),
            atlas=["AML.T0053"],
            cwe=["CWE-78"],
            confidence=getattr(flow, "confidence", 1.0),
            tags=["execution", "source", "injection"],
        )
