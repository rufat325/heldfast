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
    "T-SAFE-OFFLINE", "T-POLICY-CONSISTENT", "T-LOG-WHOLE", "T-LOG-KEYED",
    "T-HOSTED", "T-HOSTED-TLS", "T-LOG-SEALED", "T-LOG-COMPLETE",
    "T-COMPILES-CLEAN",
}

REQUIRED_HEADINGS = (
    "## Theorems",
    "## Best-effort",
    "## Out of scope",
)


class TestTheGateNamesRealTheorems(unittest.TestCase):
    """The gate on adding a rule is itself an invariant, so it can go stale.

    It once named a specific rule id -- "do not add MCPA036 until ..." -- which
    an outside reader found still sitting there after MCPA036 shipped. It is
    phrased generically now, so it cannot rot that way again. What it can
    still do is name a theorem that has been renamed or removed, which would
    make the gate unenforceable while continuing to read like a rule. This is
    the one file where drift is least affordable.
    """

    @staticmethod
    def _gate() -> str:
        """The numbered step that gates adding a rule.

        Located by its position in "Changing a theorem" rather than by its
        wording. Keying on the wording meant a gate that had gone stale in
        the very way this class is about reported "the gate moved" instead,
        which is a report guessing at a cause and guessing wrong.
        """
        text = GUARANTEES.read_text(encoding="utf-8")
        section = text[text.index("## Changing a theorem"):]
        steps = [line for line in section.splitlines()
                 if re.match(r"^\d+\. ", line)]
        gate = [line for line in steps if "Do not add" in line]
        assert len(gate) == 1, f"expected one gate step, found {len(gate)}"
        return gate[0]

    def test_every_theorem_the_gate_names_is_declared_above_it(self) -> None:
        text = GUARANTEES.read_text(encoding="utf-8")
        named = set(re.findall(r"T-[A-Z-]+\*?", self._gate()))
        self.assertTrue(named, "the gate names no theorems")
        declared = set(re.findall(r"^\| (T-[A-Z-]+) \|", text, re.M))
        for theorem in sorted(named):
            with self.subTest(theorem=theorem):
                if theorem.endswith("*"):
                    stem = theorem[:-1]
                    self.assertTrue(
                        any(d.startswith(stem) for d in declared),
                        f"the gate requires {theorem} and no theorem matches it")
                else:
                    self.assertIn(theorem, declared,
                                  f"the gate requires {theorem}, which is not "
                                  f"a theorem in this file")

    def test_the_gate_does_not_name_a_single_rule_id(self) -> None:
        """Naming one id is what went stale. A generic gate cannot."""
        self.assertEqual([], re.findall(r"MCPA\d+", self._gate()),
                         "the gate names a specific rule id, which goes stale "
                         "the moment that rule ships")


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
