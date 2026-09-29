"""Each npm server measured in containers of its own (watch.py check-isolated).

`check` ran a shard's servers side by side in one container that held the
whole feed checkout, with the network on. check-isolated keeps the feed on
the host: per server, one container downloads with install scripts off, a
second runs the server with no network, and the host takes back only a
bounded JSON answer. These tests pin that shape without Docker.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research" / "feed"))
sys.path.insert(0, str(ROOT / "research" / "churn"))

import measure  # noqa: E402
import watch  # noqa: E402

TOOLS = [{"name": "t", "description": "d", "inputSchema": {"type": "object"}}]


def fake_docker(answer: object = None, fetch_exit: int = 0, plant=None):
    """Stands in for `docker run`: records argv, answers like the image."""
    calls = []

    def run(argv, *a, **kw):
        calls.append(argv)
        work = argv[argv.index("-v") + 1].rsplit(":" + watch.SCRATCH, 1)[0]
        if "fetch-one" in argv:
            return subprocess.CompletedProcess(argv, fetch_exit)
        if plant is not None:
            plant(work)
        elif answer is not None:
            Path(work, "result.json").write_text(json.dumps(answer), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0)
    return run, calls


class TestTwoContainersPerServer(unittest.TestCase):
    def measure(self, run, **kw):
        with mock.patch.object(subprocess, "run", side_effect=run):
            seen: dict = {}
            got = watch.in_containers("img", **kw)("pkg", "1.0.0", [], ["KEY"], seen=seen)
        return got, seen

    def test_download_has_network_and_running_has_none(self) -> None:
        run, calls = fake_docker({"tools": TOOLS, "why": None, "protocol": "2025-06-18"})
        (tools, why), seen = self.measure(run, runtime="runsc")
        self.assertEqual((TOOLS, None), (tools, why))
        self.assertEqual({"protocol": "2025-06-18"}, seen)
        fetch, measured = calls
        self.assertIn("fetch-one", fetch)
        self.assertNotIn("--network", fetch)
        self.assertIn("measure-one", measured)
        self.assertEqual("none", measured[measured.index("--network") + 1])
        for argv in calls:
            self.assertEqual("runsc", argv[argv.index("--runtime") + 1])
            self.assertEqual("ALL", argv[argv.index("--cap-drop") + 1])
            self.assertIn("no-new-privileges", argv)
            # The only thing mounted is the server's own scratch folder.
            self.assertEqual(1, argv.count("-v"))
            self.assertTrue(argv[argv.index("-v") + 1].endswith(":" + watch.SCRATCH))
            self.assertEqual(watch.SCRATCH, argv[argv.index("--work") + 1])

    def test_the_scratch_mount_does_not_hide_the_image_code(self) -> None:
        # The first run mounted the scratch folder at /work, the image's
        # WORKDIR, which hid watch.py: every download "failed" with exit 2.
        dockerfile = (ROOT / "research" / "feed" / "Dockerfile").read_text(encoding="utf-8")
        workdirs = [line.split(None, 1)[1].strip() for line in dockerfile.splitlines()
                    if line.startswith("WORKDIR ")]
        self.assertTrue(workdirs)
        for workdir in workdirs:
            self.assertFalse(watch.SCRATCH == workdir
                             or workdir.startswith(watch.SCRATCH.rstrip("/") + "/")
                             or watch.SCRATCH.startswith(workdir.rstrip("/") + "/"),
                             f"{watch.SCRATCH} overlaps the image's WORKDIR {workdir}")

    def test_the_spec_is_all_the_container_is_given(self) -> None:
        seen_files = []

        def plant(work):
            seen_files.extend(sorted(os.listdir(work)))
            spec = json.loads(Path(work, "spec.json").read_text(encoding="utf-8"))
            self.assertEqual({"package": "pkg", "version": "1.0.0", "tail": [],
                              "required": ["KEY"]}, spec)
            Path(work, "result.json").write_text(json.dumps({"tools": TOOLS}), encoding="utf-8")
        run, _ = fake_docker(plant=plant)
        self.measure(run)
        self.assertEqual(["spec.json"], seen_files)

    def test_a_failed_download_runs_nothing(self) -> None:
        run, calls = fake_docker(fetch_exit=1)
        (tools, why), _ = self.measure(run)
        self.assertIsNone(tools)
        self.assertEqual("download failed (exit 1)", why)
        self.assertEqual(1, len(calls))

    def test_no_answer_is_a_reason_not_a_crash(self) -> None:
        run, _ = fake_docker(answer=None)
        (tools, why), _ = self.measure(run)
        self.assertIsNone(tools)
        self.assertIn("no answer", why)

    def test_the_scratch_folder_is_removed(self) -> None:
        folders = []
        run, _ = fake_docker(plant=lambda w: folders.append(w))
        self.measure(run)
        self.assertFalse(os.path.exists(folders[0]))


class TestTheAnswerIsOnlyData(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "result.json")

    def answer(self, body: object) -> dict | None:
        Path(self.path).write_text(json.dumps(body), encoding="utf-8")
        return watch._read_result(self.path)

    def test_a_well_formed_answer(self) -> None:
        self.assertEqual({"tools": TOOLS, "why": None, "protocol": None},
                         self.answer({"tools": TOOLS}))
        self.assertEqual({"tools": None, "why": "exited 1", "protocol": None},
                         self.answer({"tools": None, "why": "exited 1"}))

    def test_wrong_shapes_are_refused(self) -> None:
        for body in ([], {"tools": "x"}, {"why": 3}, {"tools": TOOLS, "protocol": {}}, {}):
            with self.subTest(body=body):
                self.assertIsNone(self.answer(body))

    def test_too_large_is_refused(self) -> None:
        with mock.patch.object(watch, "MAX_RESULT", 10):
            self.assertIsNone(self.answer({"tools": TOOLS}))

    def test_a_link_to_a_host_file_is_not_followed(self) -> None:
        host_file = os.path.join(self.tmp.name, "host-secret.json")
        Path(host_file).write_text(json.dumps({"tools": TOOLS}), encoding="utf-8")
        try:
            os.symlink(host_file, self.path)
        except OSError:
            self.skipTest("no symlinks without privilege on Windows")
        self.assertIsNone(watch._read_result(self.path))


class TestWhichExecutableRuns(unittest.TestCase):
    """installed_bin picks what npx would have picked."""

    def install(self, package: str, bins: object, names: list[str]) -> str:
        prefix = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(prefix, ignore_errors=True))
        base = Path(prefix, "node_modules", *package.split("/"))
        base.mkdir(parents=True)
        (base / "package.json").write_text(json.dumps({"bin": bins}), encoding="utf-8")
        Path(prefix, "node_modules", ".bin").mkdir()
        for name in names:
            Path(prefix, "node_modules", ".bin", name).write_text("", encoding="utf-8")
        return prefix

    def pick(self, prefix, package, name=None):
        got = measure.installed_bin(prefix, package, name)
        return None if got is None else os.path.basename(got).removesuffix(".cmd")

    def test_a_single_bin(self) -> None:
        p = self.install("@s/srv", {"srv-cli": "a.js"}, ["srv-cli"])
        self.assertEqual("srv-cli", self.pick(p, "@s/srv"))

    def test_a_string_bin_is_named_after_the_package(self) -> None:
        p = self.install("@s/srv", "a.js", ["srv"])
        self.assertEqual("srv", self.pick(p, "@s/srv"))

    def test_several_bins_choose_the_package_name(self) -> None:
        p = self.install("srv", {"srv": "a.js", "other": "b.js"}, ["srv", "other"])
        self.assertEqual("srv", self.pick(p, "srv"))
        self.assertEqual("other", self.pick(p, "srv", "other"))

    def test_nothing_to_run(self) -> None:
        p = self.install("srv", {"a": "a.js", "b": "b.js"}, ["a", "b"])
        self.assertIsNone(self.pick(p, "srv"))
        self.assertIsNone(self.pick(p, "srv", "missing"))


class TestOurFailuresAreRetried(unittest.TestCase):
    """A fault of the measuring machinery must not stand for the release."""

    def test_our_failures_retry_and_the_release_s_do_not(self) -> None:
        self.assertTrue(watch._handshake_retry({"why": "download failed (exit 2)",
                                                "handshake": 2}))
        self.assertTrue(watch._handshake_retry(
            {"why": "no answer from the measuring container (exit 1)", "handshake": 2}))
        self.assertFalse(watch._handshake_retry({"why": "exited 1 before initialize: x",
                                                 "handshake": 2}))


class TestTheHostWritesTheFeed(unittest.TestCase):
    """check_one decides and writes; only the reading is handed off."""

    def test_the_catalogue_comes_from_the_given_function(self) -> None:
        data = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(data, ignore_errors=True))
        meta = {"versions": {"1.0.0": {}}, "time": {"1.0.0": "2026-09-01T00:00:00Z"}}
        asked = []

        def catalogue(package, version, tail, required, seen=None):
            asked.append((package, version))
            return TOOLS, None
        with mock.patch.object(measure, "registry_meta", return_value=meta):
            watch.check_one(data, {"package": "srv"}, None, catalogue)
        self.assertEqual([("srv", "1.0.0")], asked)
        self.assertEqual("1.0.0", watch.load_state(data, "srv")["version"])


if __name__ == "__main__":
    unittest.main()
