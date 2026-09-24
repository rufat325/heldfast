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

It never tells the log which tool you have. The fingerprint is the one the
lockfile already records (docs/LOCK.md); the log publishes every fingerprint
it has recorded in 4,096 buckets named by their first three hex characters,
and this fetches the bucket and searches it here. Asking for a bucket says
your tool is one of the few dozen in it, and nothing more -- the way Have I
Been Pwned checks a password without seeing it. The protocol is small enough
for any client to implement: docs/LOOKUP.md.

Read from the lock, so nothing is launched and nothing is connected to but
the log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


def seen(fingerprints: list[str], feed: Feed) -> dict[str, dict | None]:
    """fingerprint -> what the log says about it, or None if it never saw it."""
    wanted = sorted({fp.lower() for fp in fingerprints if isinstance(fp, str) and len(fp) > PREFIX})
    out: dict[str, dict | None] = {}
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


def check(lock_servers: dict[str, Any], feed: Feed) -> list[Record]:
    rows = approved(lock_servers)
    found = seen([fp for _, _, fp in rows], feed)
    records: dict[str, Record] = {}
    for server, name, fp in rows:
        rec = records.setdefault(server, Record(server))
        row = found.get(fp.lower())
        if row is None:
            rec.unseen.append(name)
        else:
            rec.seen[name] = row
    return list(records.values())


def render(records: list[Record]) -> list[str]:
    if not records:
        return []
    lines = ["", "Approved tools against the public record (only a 3-character bucket "
                 "name is sent per tool):"]
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
