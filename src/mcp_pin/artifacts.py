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

Nothing is hashed over the network. A published package's integrity is the
registry's problem and would need a fetch to check; this reads files that are
already on the machine, which is the part nobody else is watching.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

# Extensions that mean "somebody wrote this", as opposed to "the OS shipped
# this". An interpreter is not interesting; what it is told to run is.
SCRIPT_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyw", ".rb", ".php",
    ".sh", ".bash", ".zsh", ".ps1", ".pl", ".lua", ".jar", ".exe", ".bin",
}

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
        base = Path(server.source).resolve().parent
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
    # Only a command written as a path. A bare `node` came off PATH and is the
    # interpreter, not the server.
    if command and ("/" in command or "\\" in command):
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
    if command and ("/" in command or "\\" in command):
        out.append(command)
    for arg in getattr(server, "args", None) or []:
        text = str(arg or "").strip().strip('"').strip("'")
        if text and text not in _SKIP_ARGS and _looks_like_path(text):
            out.append(text)
    return out


def artifact_digests(server: Any) -> dict[str, str]:
    """{path: sha256} for the scripts this server starts."""
    out: dict[str, str] = {}
    for path in _candidates(server):
        key = str(path)
        if key in out:
            continue
        digest = digest_file(path)
        if digest:
            out[key] = digest
    return out


def mismatch(recorded: dict[str, str] | None) -> str | None:
    """None if every recorded digest still matches, or nothing was recorded.

    An empty pin is not a pass -- it is 'there was no local file to hash',
    which `coverage` already says. This only refuses a digest that moved.
    Scan reports that as MCPA031. Guard and gateway must not start the
    child in the same situation, or the pin is a scan-time opinion.
    """
    if not recorded:
        return None
    for path, approved in recorded.items():
        now = digest_file(Path(path))
        if now is None:
            return f"approved script {path} is no longer readable"
        if now != approved:
            return f"approved script {path} has changed since approval"
    return None
