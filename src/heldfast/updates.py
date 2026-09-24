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

A newer release is screened before it is graded (advisories.py): one
reported as malware, pulled from npm, or younger than --min-age days is
passed over for the next older one, and one that an advisory names or that
adds an install script is review, however still its tools are. Quiet means
no tool change is critical, nothing public names the release, it installs
the way the pinned one did, and it has been out long enough to have been
named if it were malicious. It does not mean anyone read the code. The pinned
release is screened too: if it is reported as malware, that is said first.

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

from . import advisories, feedlock
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
    # The release proposed: the newest one the screen did not pass over.
    target: str = ""
    newer: list[str] = field(default_factory=list)
    releases_changed: int = 0
    moved: list[Change] = field(default_factory=list)
    # current | quiet | review | waiting | blocked | skipped
    grade: str = "skipped"
    note: str = ""
    alarm: str = ""
    passed_over: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.identity, "package": self.package,
            "current": self.current, "latest": self.latest, "target": self.target,
            "newer": self.newer,
            "releases_that_changed_tools": self.releases_changed,
            "grade": self.grade, "note": self.note, "alarm": self.alarm,
            "passed_over": self.passed_over, "concerns": self.concerns,
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


def check_one(spec: ServerSpec, lock: Lock, feed: Feed, index: dict[str, Any],
              min_age: int = advisories.DEFAULT_MIN_AGE) -> Update:
    out = Update(spec.identity())
    want = pinned(spec)
    if isinstance(want, str):
        out.note = want
        return out
    out.package, out.current = want
    entry = index.get(out.package)
    watched = isinstance(entry, dict) and bool(entry.get("versions"))
    out.newer = _newer(entry, out.current) if watched else []
    out.latest = out.newer[-1] if out.newer else out.current
    # The pinned release is screened whether or not anything newer exists:
    # malware you are already running is the most urgent thing to say.
    seen = advisories.screen(out.package, out.current, out.newer, min_age)
    out.alarm = seen.alarm
    if not watched:
        out.note = f"the feed does not watch {out.package}"
        return out
    if not out.newer:
        out.grade = "current"
        return out
    if seen.error:
        # Nothing the ecosystem knows could be read, so nothing is quiet.
        out.grade, out.target = "review", out.latest
        out.concerns = [f"advisories could not be checked ({seen.error}); "
                        f"not proposed as quiet without them"]
        return out
    out.passed_over, out.concerns = seen.passed_over, seen.concerns
    if not seen.target:
        out.grade = "waiting" if seen.waiting else "blocked"
        return out
    out.target = seen.target
    _grade_tools(out, spec, lock, feed, entry)
    return out


def _grade_tools(out: Update, spec: ServerSpec, lock: Lock, feed: Feed,
                 entry: dict[str, Any]) -> None:
    """approve's own review of the target's catalogue against this server's entry."""
    chosen = out.newer[:out.newer.index(out.target) + 1]
    events = [e for e in entry.get("events") or [] if e.get("to") in chosen]
    out.releases_changed = len(events)
    target = bumped(spec, out.target)
    got = lookup(target, feed) if target else "the pinned package is not a separate argument"
    if isinstance(got, str):
        out.grade, out.note = "skipped", got
        return
    candidate = Lock()
    candidate.record([target], got.tools, [])
    before = Lock()
    if spec.identity() in lock.servers:
        before.servers[spec.identity()] = lock.servers[spec.identity()]
    # The tarball hash always moves with the version. What a new tarball can
    # hide is what the screen is for, so it is not graded here as a tool change.
    out.moved = [c for c in changes(before, candidate) if c.kind != "integrity"] \
        if not before.is_empty else []
    if before.is_empty:
        out.note = "not in the lockfile yet; approving it is a first review, not an update"
    critical = any(c.grade == "critical" for c in out.moved)
    out.grade = "review" if critical or out.concerns else "quiet"


def check(servers: list[ServerSpec], lock: Lock, feed: Feed,
          min_age: int = advisories.DEFAULT_MIN_AGE) -> list[Update]:
    index = feed_index(feed)
    return [check_one(s, lock, feed, index, min_age) for s in servers if not s.disabled]


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


def render(updates: list[Update], source: str,
           min_age: int = advisories.DEFAULT_MIN_AGE) -> str:
    lines = [f"heldfast updates -- feed {source}", ""]
    for u in updates:
        lines.extend(_render_one(u))
    lines.append("")
    lines.extend(_summary(updates, min_age))
    return "\n".join(lines) + "\n"


def _render_one(u: Update) -> list[str]:
    head = f"  {u.identity:<28}"
    alarm = [f"      MALWARE: {u.alarm}"] if u.alarm else []
    if u.grade == "skipped":
        return [f"{head} not checked: {u.note}", *alarm]
    if u.grade == "current":
        return [f"{head} {u.package}@{u.current}  up to date", *alarm]
    shown = u.grade.upper() if u.grade in ("review", "blocked") else u.grade
    passed = [f"      passed over {p}" for p in u.passed_over]
    if u.grade in ("waiting", "blocked"):
        return [f"{head} {u.package} {u.current} -> {u.latest}  {shown}", *alarm, *passed]
    lines = [f"{head} {u.package} {u.current} -> {u.target}  {shown}", *alarm]
    if u.target != u.latest:
        lines.append(f"      newest measured is {u.latest}")
    lines.extend(passed)
    chosen = u.newer[:u.newer.index(u.target) + 1] if u.target in u.newer else u.newer
    detail = (f"{len(chosen)} newer release(s) measured, "
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
    lines.extend(f"      critical: {c.kind} {c.name}" for c in u.moved if c.grade == "critical")
    lines.extend(f"      {c}" for c in u.concerns)
    if u.note:
        lines.append(f"      {u.note}")
    return lines


def _summary(updates: list[Update], min_age: int) -> list[str]:
    by = {g: [u for u in updates if u.grade == g]
          for g in ("quiet", "review", "waiting", "blocked")}
    alarms = [u for u in updates if u.alarm]
    lines = []
    if alarms:
        lines.append(f"{len(alarms)} pinned release(s) reported as malware: see MALWARE above.")
    if by["quiet"]:
        lines.append(f"{len(by['quiet'])} quiet update(s): no tool change is critical, no "
                     f"advisory names the release, it adds no install script, and it is "
                     f"at least {min_age} days old. Nobody has read its code. "
                     f"`heldfast updates --apply` bumps the config and re-approves them "
                     f"from the feed.")
    if by["review"]:
        lines.append(f"{len(by['review'])} to review: bump the version yourself, then "
                     f"`heldfast approve --from-feed` shows the diff; a critical change "
                     f"needs --yes-tool NAME.")
    if by["waiting"]:
        lines.append(f"{len(by['waiting'])} waiting: the newer releases are younger than "
                     f"{min_age} days (--min-age).")
    if by["blocked"]:
        lines.append(f"{len(by['blocked'])} blocked: every newer release is reported as "
                     f"malware or was pulled from npm.")
    if not any(by.values()) and not alarms:
        lines.append("Nothing to update.")
    return lines
