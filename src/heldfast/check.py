"""Verify a lockfile without scanning, probing, or launching anything.

This is the check another language can run, and the check CI runs when it
only needs to know the file is well-formed. A missing file is MCPA014.
A version this tool does not understand is refused, not truncated.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .lockfile import LOCK_VERSION, Lock, resolve_lock_path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def run(explicit: str | Path | None = None) -> int:
    path = resolve_lock_path(explicit)
    if not path.is_file():
        print(f"heldfast: MCPA014  no lockfile at {path}", file=sys.stderr)
        print("           approve what you reviewed, then commit the file.",
              file=sys.stderr)
        return EXIT_FINDINGS
    try:
        lock = Lock.load(path)
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
        return EXIT_ERROR
    n_tools = 0
    for entry in lock.servers.values():
        if isinstance(entry, dict):
            tools = entry.get("tools") or {}
            if isinstance(tools, dict):
                n_tools += len(tools)
    print(
        f"heldfast: {path} ok  version {lock.version} "
        f"(this tool {LOCK_VERSION})  "
        f"{len(lock.servers)} server(s)  {n_tools} tool(s)"
    )
    return EXIT_OK
