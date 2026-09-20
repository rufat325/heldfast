"""docs/GUARANTEES.md is the spec. If a theorem vanishes from it, this fails.

The file is allowed to grow. It is not allowed to lose an ID that tests
already claim to hold, or to mention a test file that does not exist.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARANTEES = ROOT / "docs" / "GUARANTEES.md"
HANDOFF = ROOT / "docs" / "HANDOFF.md"

REQUIRED_THEOREM_IDS = {
    "T-PATH-NORM", "T-PATH-PREFIX", "T-PATH-PERCENT", "T-PATH-NEST",
    "T-DENY", "T-SQL-STACK", "T-SQL-MASK", "T-HOST-SUFFIX", "T-HOST-SLASH",
    "T-POLICY-UNKNOWN", "T-POLICY-PURE", "T-POLICY-DET",
    "T-FINGERPRINT", "T-LOCK-FUTURE", "T-JSONC", "T-DRIFT",
    "T-ATTACK", "T-GOLDEN", "T-MUTATION", "T-TRACE", "T-FAIL-CLOSED",
    "T-BATCH", "T-PINNED", "T-ISOLATE-LOADER",
    "T-MUX", "T-PROBE-LIFE", "T-UNPINNED", "T-LOCK-TREE",
    "T-LIST-CHANGED", "T-PROBE-GATE", "T-DRIFT-ID",
    "T-TYPES", "T-SIZE",
    "T-WHEEL", "T-REDACT",
    "T-ARTIFACT", "T-LAUNCH", "T-REVIEW", "T-SURFACE",
    "T-YES-CRITICAL", "T-INTEGRITY", "T-CACHE", "T-UNVERIFIED",
    "T-SAFE-OFFLINE",
}

REQUIRED_HEADINGS = (
    "## Theorems",
    "## Best-effort",
    "## Out of scope",
)


class TestGuaranteesDocument(unittest.TestCase):
    def test_the_file_exists_and_has_the_three_buckets(self) -> None:
        text = GUARANTEES.read_text(encoding="utf-8")
        for heading in REQUIRED_HEADINGS:
            self.assertIn(heading, text, f"missing {heading}")

    def test_every_required_theorem_id_is_still_named(self) -> None:
        text = GUARANTEES.read_text(encoding="utf-8")
        found = set(re.findall(r"\bT-[A-Z0-9-]+\b", text))
        missing = REQUIRED_THEOREM_IDS - found
        self.assertFalse(missing, f"theorem ids dropped from GUARANTEES.md: {sorted(missing)}")

    def test_held_by_paths_exist(self) -> None:
        text = GUARANTEES.read_text(encoding="utf-8")
        mentioned = set(re.findall(r"`(tests/[^`]+|\.github/[^`]+)`", text))
        missing = []
        for item in mentioned:
            # Strip trailing method names after a colon if any.
            path = item.split(":")[0]
            if "*" in path:
                continue
            if not (ROOT / path).exists():
                missing.append(item)
        self.assertFalse(missing, f"GUARANTEES.md points at missing files: {missing}")

    def test_handoff_points_at_the_guarantees_file(self) -> None:
        text = HANDOFF.read_text(encoding="utf-8")
        self.assertIn("docs/GUARANTEES.md", text)
        self.assertIn("Feature freeze", text)


if __name__ == "__main__":
    unittest.main()
