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
