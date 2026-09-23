"""Which pinned servers have newer releases, and what taking one would change.

A pin that never moves goes stale: the server fixes bugs, adds tools, and the
lock still names the version from the day it was written. Bumping is where a
pin earns its keep or gets muted -- every new version is a fresh approval, and
most of them change something (docs/CHURN.md). This answers the question an
upgrade actually raises, before the upgrade: for each server pinned to an
exact npm version, has the feed measured a newer one, and would approving it
be a change `approve --yes` accepts ("quiet") or one a person has to read
("review")?

The grade is `approve`'s own: the newest catalogue is recorded into a lock
of its own and compared with this server's current entry by review.changes,
so an update called quiet here is one approve would write under --yes, and
one called review is one approve would refuse without --yes-tool.

`--apply` takes the quiet ones: it rewrites `pkg@old` to `pkg@new` in the
config file -- only where that exact string occurs once, so comments and
formatting survive -- and re-approves those servers from the feed. It will not
approve anything else along the way: if the lock would change for a server it
was not asked to bump, the config is put back and nothing is written.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import feedlock
from .feedlock import Feed, lookup, pinned
from .lockfile import Lock
from .model import ServerSpec
from .review import Change, changes
from .rules.execution import extract_package


@dataclass
class Update:
    identity: str
    package: str = ""
    current: str = ""
    latest: str = ""
    newer: list[str] = field(default_factory=list)
    releases_changed: int = 0
    moved: list[Change] = field(default_factory=list)
    # current | quiet | review | skipped
    grade: str = "skipped"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.identity, "package": self.package,
            "current": self.current, "latest": self.latest, "newer": self.newer,
            "releases_that_changed_tools": self.releases_changed,
            "grade": self.grade, "note": self.note,
            "changes": [{"kind": c.kind, "name": c.name, "grade": c.grade}
                        for c in self.moved],
        }


def feed_index(feed: Feed) -> dict[str, Any]:
    # Through the module, so the one place tests and mirrors replace is
    # the one every feed read goes through.
    body = feedlock.get_json(f"{feed.base}/index.json")
    packages = body.get("packages") if isinstance(body, dict) else None
    return packages if isinstance(packages, dict) else {}


def bumped(spec: ServerSpec, version: str) -> ServerSpec | None:
    """The same server with its package pinned to `version`, or None."""
    found = extract_package(spec)
    want = pinned(spec)
    if not found or isinstance(want, str) or found[1] not in spec.args:
        return None
    args = list(spec.args)
    args[args.index(found[1])] = f"{want[0]}@{version}"
    return replace(spec, args=args)


def _newer(entry: dict[str, Any], current: str) -> list[str]:
    versions = [v["version"] for v in entry.get("versions") or [] if isinstance(v, dict)]
    if current in versions:
        return versions[versions.index(current) + 1:]
    return versions[-1:]


def check_one(spec: ServerSpec, lock: Lock, feed: Feed, index: dict[str, Any]) -> Update:
    out = Update(spec.identity())
    want = pinned(spec)
    if isinstance(want, str):
        out.note = want
        return out
    out.package, out.current = want
    entry = index.get(out.package)
    if not isinstance(entry, dict) or not entry.get("versions"):
        out.note = f"the feed does not watch {out.package}"
        return out
    out.newer = _newer(entry, out.current)
    out.latest = out.newer[-1] if out.newer else out.current
    if not out.newer:
        out.grade = "current"
        return out
    events = [e for e in entry.get("events") or [] if e.get("to") in out.newer]
    out.releases_changed = len(events)
    target = bumped(spec, out.latest)
    got = lookup(target, feed) if target else "the pinned package is not a separate argument"
    if isinstance(got, str):
        out.note = got
        return out
    candidate = Lock()
    candidate.record([target], got.tools, [])
    before = Lock()
    if spec.identity() in lock.servers:
        before.servers[spec.identity()] = lock.servers[spec.identity()]
    out.moved = [c for c in changes(before, candidate) if c.kind != "integrity"] \
        if not before.is_empty else []
    if before.is_empty:
        out.note = "not in the lockfile yet; approving it is a first review, not an update"
    out.grade = "review" if any(c.grade == "critical" for c in out.moved) else "quiet"
    return out


def check(servers: list[ServerSpec], lock: Lock, feed: Feed) -> list[Update]:
    index = feed_index(feed)
    return [check_one(s, lock, feed, index) for s in servers if not s.disabled]


def rewrite_config(path: Path, old: str, new: str) -> str | None:
    """Replace `"old"` with `"new"` in the config text, only if it occurs once.

    Returns the original text, so the caller can put it back, or None when
    the edit would be ambiguous and was not made.
    """
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    needle, repl = f'"{old}"', f'"{new}"'
    if text.count(needle) != 1:
        return None
    path.write_bytes(text.replace(needle, repl).encode("utf-8"))
    return text


def render(updates: list[Update], source: str) -> str:
    lines = [f"mcp-pin updates -- feed {source}", ""]
    for u in updates:
        head = f"  {u.identity:<28}"
        if u.grade == "skipped":
            lines.append(f"{head} not checked: {u.note}")
            continue
        if u.grade == "current":
            lines.append(f"{head} {u.package}@{u.current}  up to date")
            continue
        lines.append(f"{head} {u.package} {u.current} -> {u.latest}  "
                     f"{u.grade.upper() if u.grade == 'review' else u.grade}")
        detail = (f"{len(u.newer)} newer release(s) measured, "
                  f"{u.releases_changed} of them changed tools")
        counts: dict[str, int] = {}
        for c in u.moved:
            if c.kind == "tool":
                verb = "added" if not c.old else "removed" if not c.new else "changed"
                counts[verb] = counts.get(verb, 0) + 1
        if counts:
            detail += "; the lock would see " + ", ".join(
                f"{n} {verb}" for verb, n in sorted(counts.items()))
        lines.append(f"      {detail}")
        for c in u.moved:
            if c.grade == "critical":
                lines.append(f"      critical: {c.kind} {c.name}")
        if u.note:
            lines.append(f"      {u.note}")
    quiet = [u for u in updates if u.grade == "quiet"]
    review = [u for u in updates if u.grade == "review"]
    lines.append("")
    if quiet:
        lines.append(f"{len(quiet)} quiet update(s): `mcp-pin updates --apply` bumps the "
                     f"config and re-approves them from the feed.")
    if review:
        lines.append(f"{len(review)} to review: bump the version yourself, then "
                     f"`mcp-pin approve --from-feed` shows the diff; a critical change "
                     f"needs --yes-tool NAME.")
    if not quiet and not review:
        lines.append("Nothing to update.")
    return "\n".join(lines) + "\n"
