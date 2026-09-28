"""The feed's watchdog: it speaks when the feed stops, and only then.

research/feed/watchdog.py runs from the feed repository's own schedule, which
GitHub keeps on because that repository changes every day. It decides; the
workflow opens the issue. These run it dry.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "research" / "feed"))

import watch  # noqa: E402
import watchdog  # noqa: E402

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


def ago(hours: float) -> str:
    return (NOW - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def dry(last_change: str, runs: list | None = None) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "runs.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(runs or [], fh)
        proc = subprocess.run([sys.executable, str(ROOT / "research" / "feed" / "watchdog.py"),
                               "check", "--last-change", last_change, "--runs", path,
                               "--now", NOW.isoformat()], capture_output=True, text=True)
    return proc.returncode, proc.stdout


class TestTheWatchdog(unittest.TestCase):
    def test_a_feed_quiet_for_27_hours_is_reported(self) -> None:
        code, said = dry(ago(27))
        self.assertEqual(1, code)
        self.assertIn("published nothing for 27 hours", said)

    def test_a_feed_quiet_for_25_hours_is_not(self) -> None:
        self.assertEqual((0, "feed is moving\n"), dry(ago(25)))

    def test_a_run_going_for_hours_is_reported(self) -> None:
        runs = [{"createdAt": ago(7), "url": "https://github.com/x/y/actions/runs/1"},
                {"createdAt": ago(1), "url": "https://github.com/x/y/actions/runs/2"}]
        code, said = dry(ago(1), runs)
        self.assertEqual(1, code)
        self.assertIn("runs/1", said)
        self.assertNotIn("runs/2", said)

    def test_both_are_said_at_once(self) -> None:
        found = watchdog.problems(ago(30), [{"createdAt": ago(8), "url": "u"}], NOW)
        self.assertEqual(2, len(found))


class TestTheSixtyDayRule(unittest.TestCase):
    """GitHub disables a public repository's schedules after 60 days without
    activity. The watchdog warns ten days ahead, and does nothing else."""

    def days_ago(self, days: float) -> str:
        return ago(days * 24)

    def test_quiet_before_fifty_days(self) -> None:
        self.assertIsNone(watchdog.idle(self.days_ago(49), NOW))

    def test_warns_with_the_days_left_and_the_date(self) -> None:
        said = watchdog.idle(self.days_ago(52), NOW)
        self.assertIn("no commit for 52 days", said)
        self.assertIn("in 8 day(s), on 2026-10-06", said)

    def test_after_the_deadline_it_says_so_and_how_to_recover(self) -> None:
        said = watchdog.idle(self.days_ago(63), NOW)
        self.assertIn("since 2026-09-25", said)
        self.assertIn("enable feed.yml again", said)

    def test_the_command_exits_by_whether_there_is_a_warning(self) -> None:
        run = lambda days: subprocess.run(
            [sys.executable, str(ROOT / "research" / "feed" / "watchdog.py"), "idle",
             "--last-change", self.days_ago(days), "--now", NOW.isoformat()],
            capture_output=True, text=True).returncode
        self.assertEqual((0, 1), (run(10), run(55)))

    def test_it_works_around_nothing(self) -> None:
        """The popular keepalive action was disabled by GitHub; this only warns."""
        workflow = (ROOT / "research" / "feed" / "feed-repo-watchdog.yml").read_text(encoding="utf-8")
        for forbidden in ("/enable", "workflow enable", "git commit", "git push", "--allow-empty"):
            self.assertNotIn(forbidden, workflow)


class TestTheFeedHoldsItsWatchdog(unittest.TestCase):
    """The workflow file sits in the feed repository, so the publishing job's
    check must accept exactly it, and no measuring shard may upload it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data = self._tmp.name
        os.makedirs(os.path.join(self.data, ".github", "workflows"))

    def verify(self) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return watch.verify(SimpleNamespace(data=self.data, complete=False))

    def put(self, name: str) -> None:
        with open(os.path.join(self.data, ".github", "workflows", name), "w",
                  encoding="utf-8") as fh:
            fh.write((ROOT / "research" / "feed" / "feed-repo-watchdog.yml").read_text(
                encoding="utf-8"))

    def test_the_watchdog_file_verifies(self) -> None:
        self.put("watchdog.yml")
        self.assertEqual(0, self.verify())

    def test_any_other_workflow_does_not(self) -> None:
        self.put("publish.yml")
        self.assertEqual(1, self.verify())

    def test_a_shard_cannot_upload_it(self) -> None:
        self.put("watchdog.yml")
        self.assertTrue(watch._foreign(self.data, {}, "npm-0"))


class TestTodaysCheckpoint(unittest.TestCase):
    """GitHub starts scheduled runs late under load and sometimes drops one,
    while the four-hourly passes keep publishing, so `check` stays quiet. A
    day without a checkpoint can never be anchored afterwards, so `daily`
    says when to start the daily run by hand -- and when it is too late."""

    WORKFLOW = ROOT / "research" / "feed" / "feed-repo-watchdog.yml"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def record(self, day: str) -> None:
        with open(os.path.join(self.dir, f"{day}.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")

    def at(self, clock: str) -> datetime:
        hours, minutes = (int(part) for part in clock.split(":"))
        return NOW.replace(hour=hours, minute=minutes)

    def decide(self, clock: str, runs: list | None = None) -> tuple[str, str]:
        return watchdog.daily(self.dir, runs or [], self.at(clock))

    @staticmethod
    def feed_run(event: str, status: str, created: str, n: int = 1) -> dict:
        return {"event": event, "status": status, "createdAt": created,
                "url": f"https://github.com/rufat325/heldfast/actions/runs/{n}"}

    def test_a_recorded_day_needs_nothing(self) -> None:
        self.record("2026-09-28")
        self.assertEqual("ok", self.decide("11:00")[0])

    def test_before_it_is_due_it_waits(self) -> None:
        action, reason = self.decide("09:30")
        self.assertEqual("wait", action)
        self.assertIn("until 10:00 UTC", reason)

    def test_overdue_with_nothing_running_it_starts_the_run(self) -> None:
        self.assertEqual(("start", "no checkpoint for 2026-09-28 at 10:47 UTC and no feed run "
                                   "under way; starting feed.yml (1 of 3 today)"), self.decide("10:47"))

    def test_yesterdays_checkpoint_is_not_todays(self) -> None:
        self.record("2026-09-27")
        self.assertEqual("start", self.decide("11:00")[0])

    def test_a_run_under_way_or_queued_means_wait(self) -> None:
        for status in ("in_progress", "queued"):
            with self.subTest(status=status):
                runs = [self.feed_run("schedule", status, "2026-09-28T10:55:00Z", 7)]
                action, reason = self.decide("11:00", runs)
                self.assertEqual("wait", action)
                self.assertIn("runs/7", reason)

    def test_only_todays_manual_starts_count(self) -> None:
        runs = [self.feed_run("workflow_dispatch", "completed", "2026-09-28T11:47:00Z", 3),
                self.feed_run("workflow_dispatch", "completed", "2026-09-28T10:47:00Z", 2),
                self.feed_run("workflow_dispatch", "completed", "2026-09-27T11:47:00Z", 1),
                self.feed_run("schedule", "completed", "2026-09-28T05:54:00Z", 0)]
        action, reason = self.decide("12:47", runs)
        self.assertEqual("start", action)
        self.assertIn("3 of 3 today", reason)

    def test_it_stops_after_three_starts_and_says_which_was_last(self) -> None:
        runs = [self.feed_run("workflow_dispatch", "completed", f"2026-09-28T1{n}:47:00Z", n)
                for n in (0, 2, 1)]
        action, reason = self.decide("13:47", runs)
        self.assertEqual("alert", action)
        self.assertIn("after 3 started run(s)", reason)
        self.assertIn("runs/2", reason)

    def test_too_late_to_publish_today_is_said_not_attempted(self) -> None:
        action, reason = self.decide("22:45")
        self.assertEqual("alert", action)
        self.assertIn("2026-09-28 will have no anchor", reason)

    def test_the_command_prints_one_decision_and_exits_0(self) -> None:
        proc = subprocess.run([sys.executable, str(ROOT / "research" / "feed" / "watchdog.py"),
                               "daily", "--checkpoints", self.dir,
                               "--now", self.at("11:00").isoformat()],
                              capture_output=True, text=True)
        self.assertEqual(0, proc.returncode)
        self.assertEqual(1, len(proc.stdout.splitlines()))
        self.assertTrue(proc.stdout.startswith("start: "))

    def steps(self) -> list[str]:
        body = self.WORKFLOW.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
        return re.split(r"\n      - ", body)[1:]

    def test_only_the_step_that_starts_the_run_sees_the_token(self) -> None:
        holders = [step for step in self.steps() if "secrets." in step]
        self.assertEqual(1, len(holders))
        self.assertIn("secrets.HELDFAST_DISPATCH_TOKEN", holders[0])
        self.assertIn("gh workflow run feed.yml", holders[0])
        self.assertNotIn("python3", holders[0])

    def test_the_hourly_check_and_the_six_hourly_watch_stay_apart(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  watch:\n    if: github.event.schedule != '47 * * * *'", text)
        self.assertIn("  checkpoint:\n    if: github.event.schedule != '17 */6 * * *'", text)


if __name__ == "__main__":
    unittest.main()
