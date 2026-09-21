"""The lock digest is a published contract: same object, same hex.

Deleting digest.py or changing separators / key order / empty-field rules
must fail these. The JSON files under tests/golden/tools/ are the vectors
a second language implements against.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.digest import tool_digest  # noqa: E402
from mcp_pin.model import ToolSpec  # noqa: E402

GOLDEN = ROOT / "tests" / "golden" / "tools"


def _load() -> list[dict]:
    files = sorted(GOLDEN.glob("*.json"))
    return [json.loads(p.read_text(encoding="utf-8")) for p in files]


class TestGoldenVectors(unittest.TestCase):
    def test_there_are_at_least_ten_vectors(self) -> None:
        self.assertGreaterEqual(len(_load()), 10)

    def test_python_matches_every_pinned_digest(self) -> None:
        for rec in _load():
            with self.subTest(rec["id"]):
                self.assertEqual(rec["digest"], tool_digest(rec["tool"]))

    def test_key_order_pair_is_the_same_digest(self) -> None:
        by_id = {r["id"]: r for r in _load()}
        self.assertEqual(
            by_id["04-schema-key-order-a"]["digest"],
            by_id["05-schema-key-order-b"]["digest"],
        )
        self.assertNotEqual(
            by_id["10-rug-was"]["digest"],
            by_id["11-rug-now"]["digest"],
        )

    def test_toolspec_fingerprint_is_the_digest(self) -> None:
        rec = next(r for r in _load() if r["id"] == "02-description")
        tool = rec["tool"]
        spec = ToolSpec(
            server="s",
            name=tool["name"],
            description=tool.get("description") or "",
            title=tool.get("title") or "",
            input_schema=tool.get("input_schema") or {},
        )
        self.assertEqual(rec["digest"], spec.fingerprint())

    def test_empty_output_schema_is_omitted_not_hashed(self) -> None:
        a = tool_digest({"name": "x"})
        b = tool_digest({"name": "x", "output_schema": {}})
        self.assertEqual(a, b)

    def test_wire_spelling_matches_lock_spelling(self) -> None:
        self.assertEqual(
            tool_digest({"name": "echo", "description": "Echo.",
                         "input_schema": {"type": "object"},
                         "output_schema": {"type": "string"}}),
            tool_digest({"name": "echo", "description": "Echo.",
                         "inputSchema": {"type": "object"},
                         "outputSchema": {"type": "string"}}),
        )


class TestJavascriptAgrees(unittest.TestCase):
    def test_the_zero_dep_checker_matches_the_goldens(self) -> None:
        bin_path = ROOT / "js" / "mcp-pin-check" / "bin.js"
        self.assertTrue(bin_path.is_file())
        proc = subprocess.run(
            ["node", str(bin_path), "--golden", str(GOLDEN)],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        self.assertIn("golden", proc.stdout)


if __name__ == "__main__":
    unittest.main()
