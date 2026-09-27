"""Has the world seen this exact tool before?

Chrome asks Safe Browsing about every site before it opens it. This asks the
public log about every tool you approved: has any public server ever shown
this exact definition -- same name, words, schemas, annotations, icons -- and
since when, on how many servers?

- **seen** -- public since a date, on some number of servers. A definition
  thousands of people were also shown is not one crafted for you.
- **never seen** -- this exact definition exists, as far as the public record
  goes, only where you got it. Normal for a server you wrote or run
  privately; worth a look for one you installed from somewhere else.

The fingerprint is the one the lockfile already records (docs/LOCK.md).
By default this downloads the whole record -- every fingerprint the log has
seen, in one file -- and searches it here, so the log learns that someone
looked, and nothing about what.

Buckets (`--lookup buckets`) are the lighter way, and they leak. The record
is also published in 4,096 buckets named by a fingerprint's first three hex
characters; one bucket hides one tool among a few dozen, the way Have I Been
Pwned hides a password. But a lookup asks for every tool a server has at
once, and the set of buckets a server's tools fall in is unique to it for
85% of the servers logged. Whoever serves the buckets can tell which public
servers you use. The protocol, and both ways: docs/LOOKUP.md.

Read from the lock, so nothing is launched and nothing is connected to but
the log.

The whole record is fetched gzipped where the feed publishes it that way, and
kept in the user's cache directory under the feed commit it was read at. What
a commit holds never changes, so a cached copy for the same commit is the same
record, and a second `verify` against an unchanged feed downloads nothing.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import feedlock
from .feedlock import Feed, FeedError

PREFIX = 3


@dataclass
class Record:
    server: str
    seen: dict[str, dict] = field(default_factory=dict)   # tool -> {first_seen, servers}
    unseen: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"server": self.server, "seen": self.seen, "unseen": self.unseen}


def bucket(feed: Feed, prefix: str) -> dict[str, dict]:
    url = f"{feed.base}/lookup/{prefix}.json"
    body = feedlock.get_json(url)
    if body is None:
        return {}
    tools = body.get("tools") if isinstance(body, dict) else None
    if body.get("prefix") != prefix or not isinstance(tools, dict):
        raise FeedError(f"{url}: not the lookup bucket {prefix}")
    return tools


# Cached records kept. The newest two: the one in use, and the one before it
# for a feed that has just moved on.
KEEP = 2


def cache_dir() -> Path:
    """Where this user's machine keeps caches. Tests replace this."""
    home = Path.home()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = home / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or home / ".cache")
    return base / "heldfast"


def _cached(commit: str) -> dict[str, dict] | None:
    path = cache_dir() / f"lookup-{commit}.json.gz"
    try:
        with gzip.open(path, "rb") as fh:
            raw = fh.read(feedlock.MAX_LOOKUP + 1)
        body = json.loads(raw.decode("utf-8")) if len(raw) <= feedlock.MAX_LOOKUP else None
    except FileNotFoundError:
        return None
    except (OSError, EOFError, ValueError):
        body = None
    tools = body.get("tools") if isinstance(body, dict) else None
    if isinstance(tools, dict):
        return tools
    # Parsed before trusted: a copy that does not read as the record is removed
    # and fetched again, never used.
    try:
        path.unlink()
    except OSError:
        pass
    return None


def _keep(commit: str, tools: dict[str, dict]) -> None:
    """Write-then-rename, so a reader never sees half a file; keep the newest two.
    A cache that cannot be written costs the next run a download, nothing else."""
    folder = cache_dir()
    try:
        folder.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="lookup-", suffix=".tmp", dir=folder)
        try:
            with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as fh:
                fh.write(json.dumps({"tools": tools}, sort_keys=True).encode("utf-8"))
            os.replace(tmp, folder / f"lookup-{commit}.json.gz")
        except BaseException:
            os.unlink(tmp)
            raise
        # The one just written, and the newest of the rest.
        others = sorted((p for p in folder.glob("lookup-*.json.gz")
                         if p.name != f"lookup-{commit}.json.gz"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
        for old in others[KEEP - 1:]:
            old.unlink()
    except OSError:
        pass


def everything(feed: Feed) -> dict[str, dict]:
    """The whole record, which says nothing about what is being looked for.

    Gzipped first (lookup/all.json.gz), the plain file where the feed does
    not have that yet; both bounded by the same limit the feed writes to.
    Cached by feed commit when the commit is known -- a --feed base someone
    chose has none, and is read fresh."""
    if feed.commit:
        cached = _cached(feed.commit)
        if cached is not None:
            return cached
    url = f"{feed.base}/lookup/all.json.gz"
    body = feedlock.get_json(url)
    if body is None:
        url = f"{feed.base}/lookup/all.json"
        body = feedlock.get_json(url)
    tools = body.get("tools") if isinstance(body, dict) else None
    if not isinstance(tools, dict):
        raise FeedError(f"{url}: not the lookup record")
    if feed.commit:
        _keep(feed.commit, tools)
    return tools


def seen(fingerprints: list[str], feed: Feed,
         mode: str = "all") -> dict[str, dict | None]:
    """fingerprint -> what the log says about it, or None if it never saw it."""
    wanted = sorted({fp.lower() for fp in fingerprints if isinstance(fp, str) and len(fp) > PREFIX})
    out: dict[str, dict | None] = {}
    if mode == "all" and wanted:
        record = everything(feed)
        return {fp: (dict(record[fp]) if isinstance(record.get(fp), dict) else None)
                for fp in wanted}
    for prefix in sorted({fp[:PREFIX] for fp in wanted}):
        found = bucket(feed, prefix)
        for fp in (f for f in wanted if f.startswith(prefix)):
            row = found.get(fp)
            out[fp] = dict(row) if isinstance(row, dict) else None
    return out


def approved(lock_servers: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(server, tool, fingerprint) for every tool a lock records."""
    rows = []
    for ident, entry in sorted(lock_servers.items()):
        tools = entry.get("tools") if isinstance(entry, dict) else None
        for name, rec in sorted((tools or {}).items()):
            fp = rec.get("fingerprint") if isinstance(rec, dict) else None
            if isinstance(fp, str) and fp:
                rows.append((ident, name, fp))
    return rows


def check(lock_servers: dict[str, Any], feed: Feed, mode: str = "all") -> list[Record]:
    rows = approved(lock_servers)
    found = seen([fp for _, _, fp in rows], feed, mode)
    records: dict[str, Record] = {}
    for server, name, fp in rows:
        rec = records.setdefault(server, Record(server))
        row = found.get(fp.lower())
        if row is None:
            rec.unseen.append(name)
        else:
            rec.seen[name] = row
    return list(records.values())


def render(records: list[Record], mode: str = "all") -> list[str]:
    if not records:
        return []
    how = ("the whole record was downloaded, so nothing about these tools was sent"
           if mode == "all" else
           "by bucket: the set of buckets asked for can identify which public servers "
           "these are")
    lines = ["", f"Approved tools against the public record ({how}):"]
    for r in records:
        head = f"  {r.server:<28}"
        total = len(r.seen) + len(r.unseen)
        if r.seen:
            oldest = min((v.get("first_seen") or "9999") for v in r.seen.values())
            widest = max(int(v.get("servers") or 0) for v in r.seen.values())
            lines.append(f"{head} {len(r.seen)} of {total} seen publicly, the oldest since "
                         f"{oldest}, on up to {widest} server(s)")
        else:
            lines.append(f"{head} none of {total} seen publicly")
        if r.unseen:
            shown = ", ".join(r.unseen[:6]) + (" ..." if len(r.unseen) > 6 else "")
            lines.append(f"      never seen publicly: {shown} -- expected for a server you "
                         f"wrote or run privately; worth a look for one you installed")
    return lines
