"""A package cache in the layout npm actually uses, for tests.

The shape is not invented: it was read off a real `_cacache` with 777 tarball
entries, and `pkgcache` was validated against all of them before this helper
existed. Tests that build the directory by hand would drift from the real
format without anything noticing, so they all come through here.

A real cache has two halves -- an index entry naming an SRI, and a content
blob under `content-v2` whose bytes hash to it -- and the checker reads both.
So by default this derives the SRI from the content, which is what npm does.
`integrity=` overrides it, which is the cache-poisoning case: an index entry
claiming one thing while the bytes beside it are another.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from heldfast.pkgcache import content_path, npm_tarball_url  # noqa: E402

_PREFIX = "make-fetch-happen:request-cache:"


def sri_for(content: bytes, algo: str = "sha512") -> str:
    """The SRI npm would publish for these bytes."""
    digest = hashlib.new(algo, content).digest()
    return f"{algo}-{base64.b64encode(digest).decode()}"


def write_entry(root: Path, name: str, version: str,
                integrity: str | None = None, *,
                content: bytes = b"a tarball, for testing purposes",
                blob: bool = True) -> Path:
    """Write one cacache entry for `name@version` and return its index path.

    `integrity` defaults to the SRI of `content`, so the two halves agree the
    way a real cache's do. Passing both a mismatched `integrity` and `content`
    builds a poisoned cache; `blob=False` builds an index entry with no bytes
    behind it at all.
    """
    sri = integrity if integrity is not None else sri_for(content)
    url = npm_tarball_url(name, version)
    digest = hashlib.sha256((_PREFIX + url).encode("utf-8")).hexdigest()
    path = root / "_cacache" / "index-v5" / digest[0:2] / digest[2:4] / digest[4:]
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"key": _PREFIX + url, "integrity": sri, "time": 0,
             "size": len(content), "metadata": {"url": url}}
    # cacache writes `<hash of entry>\t<json>` and appends; the last line wins.
    body = json.dumps(entry)
    stamp = hashlib.sha1(body.encode("utf-8")).hexdigest()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\t{body}\n")

    if blob:
        where = content_path(root / "_cacache", sri)
        if where is not None:
            where.parent.mkdir(parents=True, exist_ok=True)
            where.write_bytes(content)
    return path


@contextlib.contextmanager
def fake_npm_cache(tmp: str, name: str, version: str,
                   integrity: str | None = None, **kw):
    """Point npm's cache at `tmp` and put one entry in it."""
    root = Path(tmp)
    write_entry(root, name, version, integrity, **kw)
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
def npm_cache_at(tmp: str):
    """Point npm's cache at `tmp` without putting anything in it.

    Used both for a cold cache and for tests that write their own entries.
    """
    previous = os.environ.get("npm_config_cache")
    os.environ["npm_config_cache"] = str(tmp)
    try:
        yield Path(tmp)
    finally:
        if previous is None:
            os.environ.pop("npm_config_cache", None)
        else:
            os.environ["npm_config_cache"] = previous


@contextlib.contextmanager
def empty_npm_cache(tmp: str):
    """A machine whose cache holds nothing for the package in question."""
    with npm_cache_at(str(Path(tmp) / "nothing-here")):
        yield
