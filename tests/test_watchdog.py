"""The feed's watchdog: it speaks when the feed stops, and only then.

research/feed/watchdog.py runs from the feed repository's own schedule, which
GitHub keeps on because that repository changes every day. It decides; the
workflow opens the issue. These run it dry.
"""

from __future__ import annotations

import io
import json
import os
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


if __name__ == "__main__":
    unittest.main()
