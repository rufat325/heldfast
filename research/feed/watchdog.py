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
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

STALE_HOURS = 26
HUNG_HOURS = 6
IDLE_LIMIT_DAYS = 60
IDLE_WARN_DAYS = 50


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
    args = ap.parse_args()
    if args.command == "idle":
        now = _when(args.now) if args.now else datetime.now(timezone.utc)
        warning = idle(args.last_change, now, args.warn_days)
        print(warning or "rufat325/heldfast is active")
        return 1 if warning else 0
    runs = []
    if args.runs:
        with open(args.runs, encoding="utf-8") as fh:
            runs = json.load(fh) or []
    now = _when(args.now) if args.now else datetime.now(timezone.utc)
    found = problems(args.last_change, runs, now, args.stale_hours, args.hung_hours)
    for line in found:
        print(f"- {line}")
    if not found:
        print("feed is moving")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
