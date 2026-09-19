"""The known-bad tree must keep producing the same rule IDs.

A scanner that goes quiet on a fixture it used to catch has not got kinder;
it has gone blind. The pin is the sorted set of rule IDs, not the count, so
swapping one finding for another still fails.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

PIN = Path(__file__).resolve().parent / "golden" / "vulnerable_rule_ids.txt"


def _scan_vulnerable() -> set[str]:
    from mcp_audit.parsers import parse_config
    from mcp_audit.rules import AuditContext, run_rules

    fixtures = ROOT / "tests" / "fixtures"
    vuln = fixtures / "vulnerable" / ".mcp.json"
    if not vuln.is_file():
        sys.path.insert(0, str(fixtures))
        from make_fixtures import main as make
        make()
    servers, errors = parse_config(vuln, "claude-code")
    ctx = AuditContext(servers=servers, config_errors=errors)
    return {f.rule_id for f in run_rules(ctx)}


def _pin() -> set[str]:
    return {line.strip() for line in PIN.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")}


class TestGoldenVulnerableTree(unittest.TestCase):
    def test_the_known_bad_tree_still_fires_the_pinned_rules(self) -> None:
        self.assertTrue(PIN.is_file(), f"missing pin file {PIN}")
        got = _scan_vulnerable()
        expected = _pin()
        self.assertEqual(
            expected, got,
            "known-bad fixture drifted.\n"
            f"  missing: {sorted(expected - got)}\n"
            f"  extra:   {sorted(got - expected)}\n"
            "If the change is intended, update tests/golden/vulnerable_rule_ids.txt "
            "in the same commit and say why in docs/GUARANTEES.md."
        )


if __name__ == "__main__":
    unittest.main()
