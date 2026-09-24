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
    from heldfast.parsers import parse_config
    from heldfast.rules import AuditContext, run_rules

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
        # MCPA006 is POSIX mode bits. The rule returns on win32; the
        # Windows ACL equivalent is listed as best-effort in GUARANTEES.md.
        # Pinning it here would make every Windows job fail for a finding
        # the tool correctly does not claim.
        if sys.platform == "win32":
            expected = expected - {"MCPA006"}
        self.assertEqual(
            expected, got,
            "known-bad fixture drifted.\n"
            f"  missing: {sorted(expected - got)}\n"
            f"  extra:   {sorted(got - expected)}\n"
            "If the change is intended, update tests/golden/vulnerable_rule_ids.txt "
            "in the same commit and say why in docs/GUARANTEES.md."
        )


class TestTheCleanTreeStaysQuiet(unittest.TestCase):
    """The other half of the pin, and the half that only existed in CI.

    `vulnerable_rule_ids.txt` catches a rule that goes blind. Nothing here
    caught a rule that goes *loud* on correct configuration -- that assertion
    lived only in the `action` job of the workflow, which runs the composite
    action against these fixtures and cannot run on a developer machine.

    So a rule that fired on the clean tree passed the whole local suite and
    failed CI, which is exactly what happened: MCPA037 was taught to report a
    registry launch the lockfile records no hash for, and the clean fixture's
    lock is built offline, so all three of its pinned packages lit up. The
    scanner was reporting the correct configuration as the broken one.

    Scanned through `run_rules` rather than the CLI so it stays fast and has
    no console output to parse, but the assertion is the action's: a tree that
    is right produces nothing at all.
    """

    def _scan(self, **options) -> list:
        from heldfast.lockfile import Lock
        from heldfast.parsers import parse_config
        from heldfast.rules import AuditContext, run_rules

        fixtures = ROOT / "tests" / "fixtures"
        config = fixtures / "clean" / ".mcp.json"
        if not config.is_file():
            sys.path.insert(0, str(fixtures))
            from make_fixtures import main as make
            make()
        servers, errors = parse_config(config, "claude-code")
        self.assertEqual([], errors)
        lock = Lock.load(fixtures / "clean" / ".mcp-pin.lock")
        return run_rules(AuditContext(
            servers=servers, config_errors=errors,
            lock={"servers": lock.servers, "skills": lock.skills,
                  "stale_digests": lock.stale_digests},
            options=dict(options)))

    def test_a_correct_configuration_produces_nothing(self) -> None:
        found = self._scan()
        self.assertEqual(
            [], [f"{f.rule_id} {f.severity.label}: {f.evidence[:80]}" for f in found],
            "the clean fixture is what right looks like; a rule that fires on "
            "it is a false positive every user of this tool would see")

    def test_require_integrity_is_allowed_to_speak_up(self) -> None:
        """The one thing that may. The clean lock is recorded offline, so it
        pins no artifact hashes, and a runner that asked not to pass on
        'could not see' is told. That is opt-in, which is why it does not
        break the line above."""
        found = self._scan(require_integrity=True)
        self.assertEqual({"MCPA037"}, {f.rule_id for f in found})


if __name__ == "__main__":
    unittest.main()
