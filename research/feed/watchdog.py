"""Notice the drift feed stopping without failing.

feed.yml's alert job reports a run that fails. A run that hangs, a schedule
GitHub quietly stops firing, or a publish that commits nothing day after day
never reaches it. This checks the two things that show those: when the feed
repository last changed, and whether a feed run has been going for hours.

It runs from the feed repository's own workflow (.github/workflows/
watchdog.yml there), not from heldfast's. The feed repository gets a commit
every day while the feed runs, so GitHub never disables its schedule for
inactivity; if the collector in heldfast stops -- including because its own
schedule was disabled after 60 quiet days -- this keeps running and says so.

  watchdog.py check --last-change ISO [--runs FILE] [--now ISO]
                    [--stale-hours 26] [--hung-hours 6]
  watchdog.py idle  --last-change ISO [--now ISO] [--warn-days 50]
  watchdog.py daily --checkpoints DIR [--runs FILE] [--now ISO]
                    [--due 10:00] [--latest 22:30] [--max-starts 3]

`idle` is the early warning for GitHub's 60-day rule: a public repository's
scheduled workflows are disabled after 60 days without activity, and since
the data moved out, rufat325/heldfast -- where the collector's schedule
lives -- is active only when someone commits to it. Given that repository's
last commit, it says how many days are left, so a person makes a real
commit in time. Nothing here commits, re-enables or otherwise works around
the rule on its own.

Prints one line per problem and exits 1 when there is any, 0 when the feed
is moving. `--runs` is the JSON `gh run list --json createdAt,url` prints
for the in-progress feed runs. The workflow opens or updates the issue; this
decides only whether there is one to open, so it can be tested dry.

`daily` guards what a late or dropped schedule loses for good: the day's
checkpoint. GitHub starts scheduled runs late under load -- this
workflow's have started up to three hours late -- and sometimes drops one,
while the four-hourly passes keep publishing, so `check` stays quiet. Given
the feed repository's checkpoints/ directory and the recent feed runs
(`gh run list --json createdAt,event,status,url`), it prints one line --
`ok:`, `wait:`, `start:` or `alert:` and the reason -- and exits 0. `start`
means the workflow should start feed.yml by hand (workflow_dispatch), which
runs outside the schedule and writes the day's checkpoint. It stops after
three starts in a day, and once a run could no longer publish before
midnight UTC, and says so. This works around nothing: a workflow GitHub has
disabled cannot be started this way, and the failed start is reported.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

STALE_HOURS = 26
HUNG_HOURS = 6
IDLE_LIMIT_DAYS = 60
IDLE_WARN_DAYS = 50
DUE = "10:00"        # UTC; the daily run is scheduled for 06:23
LATEST = "22:30"     # UTC; a run started later publishes after midnight
MAX_STARTS = 3
ACTIVE = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})


def _when(text: str) -> datetime:
    moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def problems(last_change: str, runs: list, now: datetime,
             stale_hours: float = STALE_HOURS, hung_hours: float = HUNG_HOURS) -> list[str]:
    out = []
    age = (now - _when(last_change)).total_seconds() / 3600
    if age >= stale_hours:
        out.append(f"the feed has published nothing for {age:.0f} hours (last change {last_change.strip()})")
    for run in runs:
        hours = (now - _when(str(run.get("createdAt")))).total_seconds() / 3600
        if hours >= hung_hours:
            out.append(f"a feed run has been going for {hours:.0f} hours: {run.get('url')}")
    return out


def idle(last_change: str, now: datetime, warn_days: float = IDLE_WARN_DAYS,
         limit_days: float = IDLE_LIMIT_DAYS) -> str | None:
    """A warning when the tool repository nears the 60-day rule, or None."""
    from datetime import timedelta
    last = _when(last_change)
    days = (now - last).total_seconds() / 86400
    if days < warn_days:
        return None
    deadline = (last + timedelta(days=limit_days)).strftime("%Y-%m-%d")
    left = limit_days - days
    when = f"in {left:.0f} day(s), on {deadline}" if left > 0 else f"since {deadline}"
    return (f"rufat325/heldfast has had no commit for {days:.0f} days. GitHub disables a public "
            f"repository's scheduled workflows after {limit_days:.0f} days without activity, "
            f"which stops the feed's collector {when}. Any real commit or merged pull request "
            f"there resets it; if it has already stopped, enable feed.yml again on its Actions tab.")


def _clock(now: datetime, text: str) -> datetime:
    hours, minutes = (int(part) for part in text.split(":"))
    return now.replace(hour=hours, minute=minutes, second=0, microsecond=0)


def daily(checkpoints: str, runs: list, now: datetime, due: str = DUE,
          latest: str = LATEST, max_starts: int = MAX_STARTS) -> tuple[str, str]:
    """ok, wait, start or alert about today's checkpoint, and why."""
    now = now.astimezone(timezone.utc)
    day = now.strftime("%Y-%m-%d")
    if os.path.isfile(os.path.join(checkpoints, f"{day}.json")):
        return "ok", f"the checkpoint for {day} is recorded"
    if now < _clock(now, due):
        return "wait", f"no checkpoint for {day} yet; the daily run has until {due} UTC"
    going = [run for run in runs if str(run.get("status")) in ACTIVE]
    if going:
        return "wait", f"no checkpoint for {day} yet; a feed run is under way: {going[0].get('url')}"
    if now >= _clock(now, latest):
        return "alert", (f"no checkpoint for {day}, and a run started now would publish after "
                         f"midnight UTC, into the next day: {day} will have no anchor")
    started = sorted((run for run in runs if run.get("event") == "workflow_dispatch"
                      and _when(str(run.get("createdAt"))).strftime("%Y-%m-%d") == day),
                     key=lambda run: _when(str(run.get("createdAt"))), reverse=True)
    if len(started) >= max_starts:
        return "alert", (f"no checkpoint for {day} after {len(started)} started run(s); "
                         f"the latest: {started[0].get('url')}")
    return "start", (f"no checkpoint for {day} at {now:%H:%M} UTC and no feed run under way; "
                     f"starting feed.yml ({len(started) + 1} of {max_starts} today)")


def _runs(path: str) -> list:
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh) or []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check")
    c.add_argument("--last-change", required=True, help="ISO time of the feed's newest commit")
    c.add_argument("--runs", default="", help="JSON file of in-progress feed runs")
    c.add_argument("--now", default="", help="ISO time to judge at (default: now)")
    c.add_argument("--stale-hours", type=float, default=STALE_HOURS)
    c.add_argument("--hung-hours", type=float, default=HUNG_HOURS)
    i = sub.add_parser("idle")
    i.add_argument("--last-change", required=True, help="ISO time of rufat325/heldfast's newest commit")
    i.add_argument("--now", default="")
    i.add_argument("--warn-days", type=float, default=IDLE_WARN_DAYS)
    d = sub.add_parser("daily")
    d.add_argument("--checkpoints", required=True, help="the feed repository's checkpoints/ directory")
    d.add_argument("--runs", default="", help="JSON file of recent feed runs")
    d.add_argument("--now", default="", help="ISO time to judge at (default: now)")
    d.add_argument("--due", default=DUE, help="UTC time by which the daily run should have written it")
    d.add_argument("--latest", default=LATEST, help="UTC time after which a run would publish too late")
    d.add_argument("--max-starts", type=int, default=MAX_STARTS)
    args = ap.parse_args()
    now = _when(args.now) if args.now else datetime.now(timezone.utc)
    if args.command == "idle":
        warning = idle(args.last_change, now, args.warn_days)
        print(warning or "rufat325/heldfast is active")
        return 1 if warning else 0
    runs = _runs(args.runs)
    if args.command == "daily":
        action, reason = daily(args.checkpoints, runs, now, args.due, args.latest, args.max_starts)
        print(f"{action}: {reason}")
        return 0
    found = problems(args.last_change, runs, now, args.stale_hours, args.hung_hours)
    for line in found:
        print(f"- {line}")
    if not found:
        print("feed is moving")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
