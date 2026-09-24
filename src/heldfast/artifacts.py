"""The code behind the launch command, not just the command.

MCPA016 notices when `"command": "node", "args": ["server.js"]` becomes
something else. It cannot notice when that line stays byte-identical and
`server.js` is rewritten, which is the same rug pull one layer down and
considerably easier to do: editing a file nobody diffs beats editing a config
somebody committed.

So the lockfile records a digest of the scripts a server starts, and a later
scan compares. The launch command is the promise; this is what was actually
behind it.

What gets hashed is deliberately narrow.

A script named in the arguments is hashed -- `server.js`, `main.py`, `run.sh`.
That is the author's own code and the thing that changes when a server is
tampered with or updated.

The command is hashed only when it is a path. `node` and `python` resolved
from PATH are not: system interpreters update on their own schedule for
reasons that have nothing to do with this server, and a rule that fires every
time someone patches Node is a rule people turn off. `/opt/mcp/bin/server` is
a path, is the server, and is hashed.

Nothing is hashed over the network here. A published package's tarball
hash is recorded separately (see integrity.py) when the registry answers;
this module reads files that are already on the machine, which is the
part nobody else is watching.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

# Extensions that mean "somebody wrote this", as opposed to "the OS shipped
# this". An interpreter is not interesting; what it is told to run is.
SCRIPT_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyw", ".rb", ".php",
    ".sh", ".bash", ".zsh", ".ps1", ".pl", ".lua", ".jar", ".exe", ".bin",
}

# Programs that run somebody else's code rather than being it. The command is
# the interpreter whether it was written bare (`node`) or as a path
# (`/usr/bin/node`, or a venv's `python.exe`), and the docstring above has
# always said interpreters are not hashed -- but the check was "is it spelled
# as a path", so an absolute one was hashed anyway. A `uv` that pins its own
# Python by full path, a venv's `python.exe`, an nvm `node`: every one of them
# recorded the interpreter's bytes as if they were the server's, so a security
# patch to Python reported the server as tampered with.
_VERSIONISH = re.compile(r"[0-9][0-9.-]*")

INTERPRETERS = frozenset({
    "python", "python2", "python3", "pythonw", "py", "uv", "uvx", "pipx",
    "node", "nodejs", "npx", "bun", "bunx", "deno", "pnpm", "yarn", "npm",
    "ruby", "perl", "php", "java", "dotnet", "go", "lua",
    "sh", "bash", "zsh", "dash", "fish", "pwsh", "powershell", "cmd",
})


def _is_interpreter(text: str) -> bool:
    """True for `node`, for `/usr/bin/node`, and for a Windows python.exe.

    A trailing version is still the same program -- `node-18`, `python3.12` --
    but only when what follows the separator is a version. Splitting on `-`
    unconditionally would read `python-wrapper-server` as an interpreter and
    quietly stop hashing somebody's server.
    """
    stem = Path(text).stem.lower()
    if stem in INTERPRETERS:
        return True
    for sep in (".", "-"):
        head, found, rest = stem.partition(sep)
        if found and head in INTERPRETERS and _VERSIONISH.fullmatch(rest):
            return True
    return False


# Hashing something enormous on every scan is a cost with no matching benefit;
# a server script that large is not the case this is for.
MAX_BYTES = 16 * 1024 * 1024

_SKIP_ARGS = {"-y", "--yes", "-e", "-c", "--"}


def digest_file(path: Path) -> str | None:
    """sha256 of a file, or None if it cannot or should not be read."""
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _looks_like_path(value: str) -> bool:
    return bool(value) and not value.startswith("-") and (
        "/" in value or "\\" in value or Path(value).suffix.lower() in SCRIPT_SUFFIXES
    )


def _candidates(server: Any) -> list[Path]:
    """Files worth hashing for this server, in the order they appear."""
    out: list[Path] = []

    # Relative arguments are relative to the config that names them, which is
    # how a project-local `server.js` is meant to resolve.
    try:
        source = str(getattr(server, "source", "") or "")
        base = Path(source).resolve().parent if source else Path.cwd()
    except (OSError, ValueError, TypeError):
        base = Path.cwd()

    def add(value: str) -> None:
        text = str(value or "").strip().strip('"').strip("'")
        if not text or text in _SKIP_ARGS:
            return
        if not _looks_like_path(text):
            return
        candidate = Path(os.path.expandvars(text)).expanduser()
        for resolved in ([candidate] if candidate.is_absolute() else
                         [base / candidate, Path.cwd() / candidate]):
            try:
                if resolved.is_file():
                    out.append(resolved.resolve())
                    return
            except OSError:
                continue

    command = str(getattr(server, "command", "") or "")
    # Only a command written as a path, and only when that path is not an
    # interpreter. A bare `node` came off PATH; an absolute one is the same
    # program with its location spelled out, and neither is the server.
    if command and ("/" in command or "\\" in command) and not _is_interpreter(
            command):
        add(command)

    for arg in getattr(server, "args", None) or []:
        add(str(arg))

    return out


def named_scripts(server: Any) -> list[str]:
    """Script-looking tokens in the launch command, whether or not they exist.

    `_candidates` deliberately returns only files that are present, because
    hashing is the point there. Answering "was a script named at all" needs
    the question asked before that filter: a command naming `server.js` when
    no such file is on the machine is a broken launch, not a server with
    nothing to pin, and the two were indistinguishable from the outside.
    """
    out: list[str] = []
    command = str(getattr(server, "command", "") or "")
    if command and ("/" in command or "\\" in command) and not _is_interpreter(
            command):
        out.append(command)
    for arg in getattr(server, "args", None) or []:
        text = str(arg or "").strip().strip('"').strip("'")
        if text and text not in _SKIP_ARGS and _looks_like_path(text):
            out.append(text)
    return out


def _key_for(server: Any, path: Path) -> str:
    """How this file is named in the lockfile.

    Relative to the directory of the config that named the server, with
    forward slashes, whenever the file is inside it -- which is the ordinary
    case, a project-local `server.js` beside the `.mcp.json` that starts it.
    A file outside that tree keeps its absolute path, because there is no
    shorter true name for it; matching does not depend on either spelling.
    """
    try:
        source = str(getattr(server, "source", "") or "")
        if not source:
            return str(path)
        base = Path(source).resolve().parent
        return path.resolve().relative_to(base).as_posix()
    except (OSError, ValueError, TypeError, AttributeError):
        return str(path)


def artifact_digests(server: Any) -> dict[str, str]:
    """{name: sha256} for the scripts this server starts."""
    out: dict[str, str] = {}
    for path in _candidates(server):
        key = _key_for(server, path)
        if key in out:
            continue
        digest = digest_file(path)
        if digest:
            out[key] = digest
    return out


def unmatched(recorded: dict[str, str] | None,
              current: dict[str, str]) -> list[tuple[str, str]]:
    """Approved (name, digest) pairs that nothing this server starts matches.

    Compared by content, not by name. The lockfile is meant to travel -- to a
    colleague's checkout, into CI, into a container -- and it recorded the
    absolute path of every script, so the same bytes one directory over read
    as "no longer readable at that path" and MCPA031 fired HIGH on a tree
    nobody had touched. The claim on the tin is one artifact, three places;
    a file that only validates where it was written is a cache, not a lock.

    What was always being asserted is that the code behind the launch command
    is the code that was reviewed. Its path is how it was found, not what was
    approved, so a digest still present under any name is a match. A digest
    that is present nowhere is the rug pull this rule is for, and still is.

    Reading an old lockfile keyed by absolute path therefore keeps working
    with no migration: those digests match by content like any other.
    """
    if not recorded:
        return []
    have = set(current.values())
    return [(name, digest) for name, digest in sorted(recorded.items())
            if digest not in have]


def mismatch(recorded: dict[str, str] | None, server: Any = None) -> str | None:
    """None if every approved script is still present, by content.

    An empty pin is not a pass -- it is 'there was no local file to hash',
    which `coverage` already says. This only refuses a digest that moved.
    Scan reports that as MCPA031. Guard and gateway must not start the
    child in the same situation, or the pin is a scan-time opinion.
    """
    if not recorded:
        return None
    if server is None:
        # No launch command to re-read, so fall back to the recorded names.
        # Only reachable from a caller that has no server; both real ones
        # pass it.
        current = {name: d for name, d in
                   ((name, digest_file(Path(name))) for name in recorded)
                   if d}
    else:
        current = artifact_digests(server)
    missing = unmatched(recorded, current)
    if not missing:
        return None
    name, _ = missing[0]
    if not current:
        return f"approved script {name} is no longer readable"
    return f"approved script {name} has changed since approval"
