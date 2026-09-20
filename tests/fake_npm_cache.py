"""A package cache in the layout npm actually uses, for tests.

The shape is not invented: it was read off a real `_cacache` with 777 tarball
entries, and `pkgcache` was validated against all of them before this helper
existed. Tests that build the directory by hand would drift from the real
format without anything noticing, so they all come through here.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_pin.pkgcache import npm_tarball_url  # noqa: E402

_PREFIX = "make-fetch-happen:request-cache:"


def write_entry(root: Path, name: str, version: str, integrity: str) -> Path:
    """Write one cacache index entry for `name@version` and return its path."""
    url = npm_tarball_url(name, version)
    digest = hashlib.sha256((_PREFIX + url).encode("utf-8")).hexdigest()
    path = root / "_cacache" / "index-v5" / digest[0:2] / digest[2:4] / digest[4:]
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"key": _PREFIX + url, "integrity": integrity, "time": 0,
             "size": 1, "metadata": {"url": url}}
    # cacache writes `<hash of entry>\t<json>` and appends; the last line wins.
    body = json.dumps(entry)
    stamp = hashlib.sha1(body.encode("utf-8")).hexdigest()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\t{body}\n")
    return path


@contextlib.contextmanager
def fake_npm_cache(tmp: str, name: str, version: str, integrity: str):
    """Point npm's cache at `tmp` and put one entry in it."""
    root = Path(tmp)
    write_entry(root, name, version, integrity)
    previous = os.environ.get("npm_config_cache")
    os.environ["npm_config_cache"] = str(root)
    try:
        yield root
    finally:
        if previous is None:
            os.environ.pop("npm_config_cache", None)
        else:
            os.environ["npm_config_cache"] = previous


@contextlib.contextmanager
def empty_npm_cache(tmp: str):
    """A machine whose cache holds nothing for the package in question."""
    previous = os.environ.get("npm_config_cache")
    os.environ["npm_config_cache"] = str(Path(tmp) / "nothing-here")
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("npm_config_cache", None)
        else:
            os.environ["npm_config_cache"] = previous
