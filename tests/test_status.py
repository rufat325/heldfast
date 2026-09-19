"""Where things stand, on one page.

Every fact here was already on disk. The lockfile knows what was approved, the
scan knows what has moved since, the audit trail knows what the gateway did --
and operating this meant reading three files and holding the join in your
head. This computes nothing new; it answers the question somebody actually has
at the point of use.

Most of what is asserted is the state word, because that is the part a person
reads first and the part that must not lie. A server that has drifted and a
server that was never approved are different problems with different answers,
and "findings: 4" on both would be useless.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit import status as status_mod  # noqa: E402
from mcp_audit.auditlog import AuditLog  # noqa: E402
from mcp_audit.findings import Finding, Location, Severity  # noqa: E402
from mcp_audit.lockfile import Lock  # noqa: E402
from mcp_audit.model import ServerSpec, ToolSpec  # noqa: E402


def spec(name: str) -> ServerSpec:
    return ServerSpec(name=name, source="/p/.mcp.json", client="claude-code",
                      transport="stdio", command="node", args=["s.js"])


def finding(rule_id: str, server: str, severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(rule_id=rule_id, title=f"{rule_id} happened", severity=severity,
                   location=Location(path="/p/.mcp.json", line=1),
                   evidence="e", remediation="r", server=server)


def approved(names: list[str]) -> Lock:
    specs = [spec(n) for n in names]
    lock = Lock(path=Path("/p/.mcp-audit.lock"))
    lock.record(specs, [ToolSpec(server=n, name="read", description="Reads.",
                                 input_schema={}) for n in names], [])
    return lock


class TestTheStateWord(unittest.TestCase):
    def _state(self, lock: Lock, servers: list, findings: list) -> dict:
        data = status_mod.build(lock, servers, findings)
        return {row["identity"]: row["state"] for row in data["servers"]}

    def test_approved_and_unchanged_reads_ok(self) -> None:
        lock = approved(["alpha"])
        self.assertEqual({"claude-code:alpha": "ok"},
                         self._state(lock, [spec("alpha")], []))

    def test_drift_outranks_a_plain_finding(self) -> None:
        """A drifted server and a noisy one are different problems."""
        lock = approved(["alpha"])
        states = self._state(lock, [spec("alpha")],
                             [finding("MCPA015", "alpha"), finding("MCPA010", "alpha")])
        self.assertEqual("DRIFTED", states["claude-code:alpha"])

    def test_every_drift_rule_counts_as_drift(self) -> None:
        for rule_id in ("MCPA015", "MCPA016", "MCPA017", "MCPA019",
                        "MCPA020", "MCPA031"):
            with self.subTest(rule=rule_id):
                lock = approved(["alpha"])
                states = self._state(lock, [spec("alpha")], [finding(rule_id, "alpha")])
                self.assertEqual("DRIFTED", states["claude-code:alpha"])

    def test_a_configured_server_that_was_never_approved(self) -> None:
        """The case the lockfile alone cannot show, and the one most worth
        seeing: it is not in the lock at all, so it has no row to drift."""
        lock = approved(["alpha"])
        states = self._state(lock, [spec("alpha"), spec("gamma")],
                             [finding("MCPA014", "gamma", Severity.MEDIUM)])
        self.assertEqual("UNAPPROVED", states["claude-code:gamma"])

    def test_unapproved_is_read_from_the_lockfile_not_from_the_rule(self) -> None:
        """MCPA014 and the lockfile agree today. If a filter, a severity
        threshold or a later refactor ever silences the rule, this screen must
        still say the server was never approved -- reporting "ok" for an
        unapproved server is the one failure that makes the page harmful."""
        lock = approved(["alpha"])
        states = self._state(lock, [spec("alpha"), spec("gamma")], [])
        self.assertEqual("UNAPPROVED", states["claude-code:gamma"])

    def test_an_approved_server_that_is_no_longer_configured(self) -> None:
        """Approved, then removed from the config. Not dangerous, but not
        nothing either -- the approval is now describing something absent."""
        lock = approved(["alpha", "beta"])
        states = self._state(lock, [spec("alpha")], [])
        self.assertEqual("GONE", states["claude-code:beta"])

    def test_a_server_the_gateway_fronts_is_not_gone(self) -> None:
        """The recommended setup has one config entry, the gateway, and names
        the servers it fronts only in the lockfile. That read as GONE, so the
        correct configuration reported as a pile of missing servers and the
        tool punished its own advice."""
        lock = approved(["alpha", "beta"])
        gateway = ServerSpec(name="everything", source="/p/.mcp.json",
                             client="claude-code", transport="stdio",
                             command="mcp-audit", args=["gateway"])
        states = self._state(lock, [gateway], [])
        self.assertEqual("gateway", states["claude-code:alpha"])
        self.assertEqual("gateway", states["claude-code:beta"])

    def test_the_gateway_entry_is_not_reported_as_unapproved(self) -> None:
        """It has no approval by design: approving the thing that enforces
        approvals is circular."""
        lock = approved(["alpha"])
        gateway = ServerSpec(name="everything", source="/p/.mcp.json",
                             client="claude-code", transport="stdio",
                             command="mcp-audit", args=["gateway"])
        self.assertNotIn("claude-code:everything", self._state(lock, [gateway], []))

    def test_a_gateway_elsewhere_does_not_rescue_this_client(self) -> None:
        """Two clients are two agents."""
        lock = approved(["alpha"])
        elsewhere = ServerSpec(name="everything", source="/p/cursor.json",
                               client="cursor", transport="stdio",
                               command="mcp-audit", args=["gateway"])
        self.assertEqual("GONE", self._state(lock, [elsewhere], [])["claude-code:alpha"])

    def test_findings_short_of_drift_still_show(self) -> None:
        lock = approved(["alpha"])
        states = self._state(lock, [spec("alpha")],
                             [finding("MCPA010", "alpha", Severity.HIGH)])
        self.assertEqual("FINDINGS", states["claude-code:alpha"])


class TestWhatItReports(unittest.TestCase):
    def test_policy_and_pinned_code_are_surfaced(self) -> None:
        lock = approved(["alpha"])
        entry = lock.servers["claude-code:alpha"]
        entry["policy"] = {"read": {"paths": ["/workspace/**"]}}
        entry["artifacts"] = {"/p/s.js": "abc"}

        row = status_mod.build(lock, [spec("alpha")], [])["servers"][0]
        self.assertTrue(row["policy"])
        self.assertTrue(row["artifacts"])

    def test_identities_are_listed_with_their_scope(self) -> None:
        lock = approved(["alpha"])
        lock.identities = {"reader": {"servers": ["alpha"], "deny": ["write"]}}
        data = status_mod.build(lock, [spec("alpha")], [])
        self.assertEqual(["alpha"], data["identities"]["reader"]["servers"])
        self.assertEqual(["write"], data["identities"]["reader"]["deny"])

    def test_only_the_worst_few_findings_per_server(self) -> None:
        """A server with forty findings should not push every other server off
        the page."""
        lock = approved(["alpha"])
        many = [finding("MCPA0%02d" % n, "alpha") for n in range(1, 20)]
        row = status_mod.build(lock, [spec("alpha")], many)["servers"][0]
        self.assertLessEqual(len(row["findings"]), 4)


class TestTheAuditTrail(unittest.TestCase):
    def test_an_intact_trail_is_reported_as_intact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trail.jsonl"
            trail = AuditLog(path, "gateway")
            trail.record("session_start", subject="gateway")
            trail.record("request", subject="alpha__read")

            data = status_mod.build(approved(["alpha"]), [spec("alpha")], [], path)
            self.assertTrue(data["trail"]["intact"])
            self.assertEqual(2, data["trail"]["entries"])

    def test_a_tampered_trail_says_so(self) -> None:
        """The status page is where somebody would notice, so it must not
        report a broken chain as a healthy one."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trail.jsonl"
            trail = AuditLog(path, "gateway")
            trail.record("session_start", subject="gateway")
            trail.record("request", subject="alpha__read")

            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text(lines[0] + "\n", encoding="utf-8")   # a deletion

            data = status_mod.build(approved(["alpha"]), [spec("alpha")], [], path)
            self.assertTrue(data["trail"]["intact"],
                            "one truncated entry is still a valid prefix")

            rewritten = [l.replace("alpha__read", "something_else") for l in lines]
            path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
            data = status_mod.build(approved(["alpha"]), [spec("alpha")], [], path)
            self.assertFalse(data["trail"]["intact"])

    def test_a_missing_trail_is_simply_absent(self) -> None:
        data = status_mod.build(approved(["alpha"]), [spec("alpha")], [],
                                Path("/nowhere/trail.jsonl"))
        self.assertEqual({}, data["trail"])


class TestRendering(unittest.TestCase):
    def test_no_lockfile_says_what_to_do(self) -> None:
        text = status_mod.render(status_mod.build(Lock(), [], []), color=False)
        self.assertIn("No approval lockfile", text)
        self.assertIn("mcp-audit approve", text)

    def test_the_state_word_appears(self) -> None:
        lock = approved(["alpha"])
        data = status_mod.build(lock, [spec("alpha")], [finding("MCPA015", "alpha")])
        self.assertIn("DRIFTED", status_mod.render(data, color=False))

    def test_no_color_means_no_escapes(self) -> None:
        lock = approved(["alpha"])
        data = status_mod.build(lock, [spec("alpha")], [])
        self.assertNotIn("\033", status_mod.render(data, color=False))

    def test_the_payload_is_json_serialisable(self) -> None:
        """-f json has to work, so nothing exotic may leak into the data."""
        lock = approved(["alpha"])
        lock.identities = {"reader": {"servers": ["alpha"]}}
        data = status_mod.build(lock, [spec("alpha")], [finding("MCPA015", "alpha")])
        json.dumps(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
