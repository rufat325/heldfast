"""The probe has to speak to two protocol eras.

The current revision (2026-07-28) replaced the `initialize` handshake with
per-request `_meta` and a mandatory `server/discover`. Most servers in the
wild are still legacy, so the probe sends both and resolves on whichever
answers.

Every case here was a real deadlock or misdetection at some point during
development, which is why each one is pinned.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import probe as probe_mod  # noqa: E402
from heldfast.model import ServerSpec  # noqa: E402
from heldfast.probe import probe_stdio  # noqa: E402

MODERN = ROOT / "tests" / "fixtures" / "modern_server.py"
LEGACY = ROOT / "tests" / "fixtures" / "fake_server.py"


def probe(script: Path, env: dict | None = None, timeout: float = 45.0):
    spec = ServerSpec(name="x", source="<test>", client="test", transport="stdio",
                      command=sys.executable, args=[str(script)], env=env or {})
    return probe_stdio(spec, timeout=timeout)


class TestProtocolVersions(unittest.TestCase):
    def test_current_version_is_advertised(self) -> None:
        self.assertEqual("2026-07-28", probe_mod.PROTOCOL_VERSION)

    def test_legacy_version_kept_for_the_handshake(self) -> None:
        self.assertEqual("2024-11-05", probe_mod.LEGACY_PROTOCOL_VERSION)

    def test_modern_meta_uses_the_namespaced_keys(self) -> None:
        meta = probe_mod._modern_meta()
        self.assertEqual("2026-07-28", meta["io.modelcontextprotocol/protocolVersion"])
        self.assertIn("io.modelcontextprotocol/clientInfo", meta)

    def test_handshake_still_sends_the_legacy_version(self) -> None:
        """A legacy server must not be handed a version it has never heard of."""
        self.assertEqual("2024-11-05", probe_mod._initialize_params()["protocolVersion"])


class TestEraDetection(unittest.TestCase):
    def test_modern_server_is_detected(self) -> None:
        r = probe(MODERN)
        self.assertIsNone(r.error, r.error)
        self.assertEqual("modern", r.protocol_era)
        self.assertEqual(["2026-07-28"], r.supported_versions)

    def test_modern_server_that_ignores_initialize(self) -> None:
        """Deadlocked before: nothing ever answers id 1, so waiting on it hangs."""
        r = probe(MODERN, {"MCP_PIN_FIXTURE_SILENT": "1"})
        self.assertIsNone(r.error, r.error)
        self.assertEqual("modern", r.protocol_era)

    def test_legacy_server_falls_back_to_the_handshake(self) -> None:
        r = probe(LEGACY, {"MCP_PIN_FIXTURE_MODE": "benign"})
        self.assertIsNone(r.error, r.error)
        self.assertEqual("legacy", r.protocol_era)
        self.assertEqual([], r.supported_versions)

    def test_tools_are_read_in_both_eras(self) -> None:
        self.assertTrue(probe(MODERN).tools)
        self.assertTrue(probe(LEGACY, {"MCP_PIN_FIXTURE_MODE": "benign"}).tools)

    def test_instructions_are_read_in_both_eras(self) -> None:
        """In the modern era they arrive on the discover result, not initialize."""
        self.assertIn("notes", probe(MODERN).instructions)
        self.assertIn("invoice", probe(LEGACY, {"MCP_PIN_FIXTURE_MODE": "benign"}).instructions)

    def test_annotations_survive_the_modern_path(self) -> None:
        tool = probe(MODERN).tools[0]
        self.assertTrue(tool.claims_read_only)


class TestReplyOrdering(unittest.TestCase):
    def test_out_of_order_replies_are_not_dropped(self) -> None:
        """Pipelined requests can answer out of order; dropping one deadlocked."""
        r = probe(MODERN)
        self.assertIsNone(r.error, r.error)
        self.assertTrue(r.tools, "tools/list reply was lost while waiting on the era probe")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestHostedEras(unittest.TestCase):
    """Over HTTP, where the two eras cannot be sent together.

    Until this, hosted servers were only ever asked `initialize`: a server
    that speaks nothing but 2026-07-28 read as broken to `--probe`, to
    `verify`, and to the drift feed, which had recorded it that way.
    """

    def setUp(self) -> None:
        sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
        sys.path.insert(0, str(ROOT / "research" / "feed"))
        import http_server
        self.fixture = http_server

    def probe_url(self, url: str):
        spec = ServerSpec(name="notes", source="<test>", client="test", transport="http",
                          url=url)
        return probe_mod.probe_http(spec, timeout=10)

    def test_a_modern_only_server_is_read(self) -> None:
        with self.fixture.serve(era="modern") as url:
            r = self.probe_url(url)
            asked = self.fixture.requests_made()
        self.assertIsNone(r.error)
        self.assertEqual(("modern", ["2026-07-28"]), (r.protocol_era, r.supported_versions))
        self.assertEqual(["list_invoices", "read_invoice"], sorted(t.name for t in r.tools))
        self.assertIn("read-only", r.instructions)
        listed = next(a for a in asked if a["method"] == "tools/list")
        self.assertEqual("2026-07-28", listed["version"])
        self.assertEqual("2026-07-28",
                         listed["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"])
        self.assertNotIn("initialize", [a["method"] for a in asked])

    def test_a_legacy_server_that_errors_on_discover_falls_back(self) -> None:
        with self.fixture.serve() as url:
            r = self.probe_url(url)
        self.assertEqual(("legacy", None), (r.protocol_era, r.error))
        self.assertTrue(r.tools)

    def test_a_legacy_server_that_answers_discover_with_an_http_error_falls_back(self) -> None:
        for status in (400, 404, 405):
            with self.subTest(status):
                with self.fixture.serve(discover_status=status) as url:
                    r = self.probe_url(url)
                self.assertEqual(("legacy", None), (r.protocol_era, r.error))

    def test_the_watcher_reads_both_eras_and_records_which(self) -> None:
        import watch
        for era, expected in (("modern", "2026-07-28"), ("legacy", "2025-06-18")):
            with self.subTest(era):
                seen: dict = {}
                with self.fixture.serve(era=era) as url:
                    tools, why = watch.measure_remote(url, timeout=10, seen=seen)
                self.assertIsNone(why)
                self.assertTrue(tools)
                self.assertEqual(expected, seen["protocol"])


class TestWatcherStdioEras(unittest.TestCase):
    """The drift feed launches npm servers with its own client (measure.py)."""

    def catalogue(self, script: Path) -> tuple:
        import os
        import tempfile
        from unittest import mock
        sys.path.insert(0, str(ROOT / "research" / "churn"))
        import measure
        tmp = tempfile.mkdtemp()
        # Stands in for npx: whatever it is asked to run, it runs the fixture.
        if os.name == "nt":
            shim = Path(tmp) / "npx.cmd"
            shim.write_text(f'@"{sys.executable}" "{script}"\n', encoding="utf-8")
        else:
            shim = Path(tmp) / "npx"
            shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n', encoding="utf-8")
            shim.chmod(0o755)
        seen: dict = {}
        with mock.patch.object(measure.shutil, "which", return_value=str(shim)):
            tools, why = measure.catalogue("pkg", "1.0.0", [], [], boot_timeout=30, seen=seen)
        return tools, why, seen

    def test_a_modern_only_server_is_measured(self) -> None:
        tools, why, seen = self.catalogue(MODERN)
        self.assertIsNone(why)
        self.assertEqual(["read_note"], [t["name"] for t in tools])
        self.assertEqual("2026-07-28", seen["protocol"])

    def test_a_legacy_server_still_is(self) -> None:
        tools, why, seen = self.catalogue(LEGACY)
        self.assertIsNone(why)
        self.assertTrue(tools)
        self.assertNotEqual("2026-07-28", seen["protocol"])
