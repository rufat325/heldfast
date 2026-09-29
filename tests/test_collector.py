"""The portable collector does what feed.yml does, with the same isolation.

research/feed/server/run.py is the collector for a machine you control. The
full dry run needs Docker and a Linux file system (MOVING.md); these hold the
parts that decide what a measured server can reach and what gets published.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "research" / "feed" / "server"))

import run  # noqa: E402

REAL_RUN = subprocess.run


class TestTheIsolate(unittest.TestCase):
    def test_the_container_gets_feed_ymls_flags_and_nothing_else(self) -> None:
        argv = run.container("img", "/data/copy", ["check"], "6g", 2048)
        joined = " ".join(argv)
        for flag in ("--rm", "--cap-drop ALL", "--security-opt no-new-privileges",
                     "--memory 6g", "--cpus 2", "--pids-limit 2048"):
            self.assertIn(flag, joined)
        self.assertNotIn("-e", argv)
        self.assertNotIn("--env", argv)
        self.assertNotIn("--env-file", argv)
        self.assertNotIn("--privileged", argv)
        self.assertEqual(1, sum(a == "-v" for a in argv))

    def test_the_flags_match_the_workflow(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "feed.yml").read_text(encoding="utf-8")
        self.assertIn("--cap-drop ALL --security-opt no-new-privileges", workflow)
        self.assertRegex(workflow, r"--memory 6g --cpus 2 --pids-limit 2048")
        self.assertRegex(workflow, r"--memory 2g --cpus 2 --pids-limit 512")


@unittest.skipUnless(shutil.which("git"), "git is not on PATH")
class TestAShardsUpload(unittest.TestCase):
    """What a shard changed, and only that, becomes its upload."""

    def test_only_what_the_container_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed = os.path.join(tmp, "feed")
            os.makedirs(os.path.join(feed, "state"))
            Path(feed, "state", "a.json").write_text("{}\n", encoding="utf-8")
            Path(feed, "watchlist.json").write_text("{}\n", encoding="utf-8")
            g = ["git", "-C", feed, "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                 "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "init", "-q", feed], check=True)
            subprocess.run(["git", "-C", feed, "config", "core.autocrlf", "false"], check=True)
            subprocess.run(g + ["add", "-A"], check=True)
            subprocess.run(g + ["commit", "-q", "-m", "feed"], check=True)

            def fake_container(result_copy):
                def runner(argv, *a, **kw):
                    if argv and argv[0] == "docker":
                        data = argv[argv.index("-v") + 1].rsplit(":/data", 1)[0]
                        Path(data, "state", "a.json").write_text('{"v": 2}\n', encoding="utf-8")
                        Path(data, "incoming").mkdir()
                        Path(data, "incoming", "npm-0.jsonl").write_text("{}\n", encoding="utf-8")
                        # What a hostile package would plant: a repository whose
                        # config runs a command when the host lists changes, and
                        # a link to a file of the host's.
                        Path(data, ".git").mkdir(exist_ok=True)
                        Path(data, ".git", "config").write_text(
                            "[core]\n\tfsmonitor = \"echo escaped > '%s'; false\"\n"
                            % Path(tmp, "escaped").as_posix(), encoding="utf-8")
                        try:
                            os.symlink(os.path.join(feed, "watchlist.json"),
                                       os.path.join(data, "state", "b.json"))
                        except OSError:
                            pass  # no symlinks without privilege on Windows
                        return subprocess.CompletedProcess(argv, 0)
                    return REAL_RUN(argv, *a, **kw)
                return runner

            deltas = os.path.join(tmp, "deltas")
            with mock.patch.object(run.subprocess, "run", side_effect=fake_container(None)):
                run.shard(feed, os.path.join(tmp, "work"), deltas, "npm", 0, 1, "img",
                          10, 1, False, "2026-09-28")
            got = sorted(p.relative_to(deltas).as_posix() for p in Path(deltas).rglob("*")
                         if p.is_file())
            self.assertEqual(["feed-delta-npm-0/incoming/npm-0.jsonl",
                              "feed-delta-npm-0/state/a.json"], got)
            self.assertFalse(os.path.exists(os.path.join(tmp, "work", "npm-0")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "work", "npm-0.git")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "escaped")),
                             "the host's git ran a command the container planted")

    def test_a_reused_run_id_starts_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stale = os.path.join(tmp, "runs", "daily", "deltas", "feed-delta-npm-0")
            os.makedirs(stale)
            args = SimpleNamespace(state=tmp, run_id="daily", busy=True, remote_shards=0,
                                   npm_shards=0)
            run.measure(args)
            self.assertFalse(os.path.exists(stale))


class TestWhereItRuns(unittest.TestCase):
    def test_windows_is_refused_with_the_reason(self) -> None:
        err = io.StringIO()
        with mock.patch.object(run.sys, "platform", "win32"), \
                mock.patch.object(run.sys, "argv", ["run.py", "dry-run"]), redirect_stderr(err):
            self.assertEqual(2, run.main())
        self.assertIn("Linux", err.getvalue())

    def test_the_timers_are_the_workflows_schedule(self) -> None:
        units = ROOT / "research" / "feed" / "server" / "systemd"
        workflow = (ROOT / ".github" / "workflows" / "feed.yml").read_text(encoding="utf-8")
        for timer, cron, calendar in (("measure", "23 6 * * *", "*-*-* 06:23:00 UTC"),
                                      ("busy", "43 */4 * * *", "*-*-* 00/4:43:00 UTC"),
                                      ("sync", "3 5 * * 1", "Mon *-*-* 05:03:00 UTC")):
            with self.subTest(timer):
                self.assertIn(cron, workflow)
                text = (units / f"heldfast-feed-{timer}.timer").read_text(encoding="utf-8")
                self.assertIn(f"OnCalendar={calendar}", text)

    def test_no_unit_is_enabled_by_being_shipped(self) -> None:
        """Two collectors make conflicting commits; enabling is a decision."""
        units = ROOT / "research" / "feed" / "server" / "systemd"
        for path in units.glob("*.service"):
            self.assertNotIn("[Install]", path.read_text(encoding="utf-8"))

    def test_the_credentials_stay_with_their_users(self) -> None:
        units = ROOT / "research" / "feed" / "server" / "systemd"
        pushers = {p.name for p in units.glob("*.service")
                   if "--push" in p.read_text(encoding="utf-8")}
        for name in pushers:
            self.assertIn("User=heldfast-publish", (units / name).read_text(encoding="utf-8"))
        for name, user in (("heldfast-feed-anchor.service", "heldfast-anchor"),
                           ("heldfast-feed-mirror.service", "heldfast-mirror"),
                           ("heldfast-feed-measure.service", "heldfast-measure")):
            text = (units / name).read_text(encoding="utf-8")
            self.assertIn(f"User={user}", text)
            self.assertNotIn("--push", text)
        self.assertEqual(1, sum("hf.env" in p.read_text(encoding="utf-8")
                                for p in units.glob("*.service")))


if __name__ == "__main__":
    unittest.main()
