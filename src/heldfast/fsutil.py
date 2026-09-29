"""Writing a file in a directory someone else may have prepared.

heldfast writes into the project it is pointed at: the lockfile, a config
bumped by `updates --apply`, the audit log's head. That project may be a
repository a stranger wrote. Every one of those writes used a fixed
temporary name -- `.mcp-pin.lock.tmp` -- and `write_text` follows a symbolic
link, so a repository shipping `.mcp-pin.lock.tmp -> ~/.bashrc` had
`heldfast approve` write the lockfile into the user's shell startup file.

`atomic_write` creates its temporary file with a random name that must not
already exist (mkstemp: O_CREAT | O_EXCL), so there is no name to plant a
link at, then renames it over the target. A rename replaces a link at the
target rather than writing through it.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: str | os.PathLike, data: bytes) -> None:
    """Write `data` to `path` whole, through a fresh temporary file."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
