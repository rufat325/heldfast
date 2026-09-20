"""Reading the trail back.

The record was write-only in practice: `verify-log` said the chain was
intact, `status` showed the last five lines, and neither answered the question
anyone actually has afterwards -- what did this agent do, and what was
refused.

The tests that matter here are the ones about *not* saying more than the file
supports. A summary of a tampered log is worse than no summary, because it
launders an edited file into a clean-looking count; a session with no end is a
fact, not something to quietly merge into the next one; and the reason a
session has no end depends on which of two things happened, so the report must
not invent one.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin import auditlog, sessions  # noqa: E402
from mcp_pin.auditlog import AuditLog  # noqa: E402


class TrailCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "trail.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, events: list) -> AuditLog:
        trail = AuditLog(self.path, "gateway")
        for event, subject, decision, detail in events:
            trail.record(event, subject=subject, decision=decision, detail=detail)
        return trail

    def build(self) -> dict:
        return sessions.build(self.path)


SESSION = [
    ("session_start", "reader", "", "policy=block budget=2"),
    ("backend_started", "claude-code:local", "", ""),
    ("request", "local__read_invoice", "", ""),
    ("request", "local__read_invoice", "", ""),
    ("denied", "local__list_invoices", "block", "identity=reader"),
    ("session_end", "", "", "forwarded=2"),
]


class TestOneSession(TrailCase):
    def test_it_reports_who_what_and_what_was_refused(self) -> None:
        self.write(SESSION)
        data = self.build()
        self.assertEqual(1, len(data["sessions"]))
        session = data["sessions"][0]
        self.assertEqual("reader", session["subject"])
        self.assertEqual(2, session["calls"])
        self.assertEqual({"local__read_invoice": 2}, session["by_tool"])
        self.assertEqual(["local__list_invoices"],
                         [d["subject"] for d in session["denied"]])
        self.assertEqual(["claude-code:local"], session["backends"])
        self.assertFalse(session["unterminated"])

    def test_a_budget_refusal_is_told_apart_from_a_policy_one(self) -> None:
        """They are different problems. One is an agent in a loop, the other
        is an agent reaching for something it may not have."""
        self.write([
            ("session_start", "reader", "", ""),
            ("budget_exhausted", "local__read", "block", "limit=2"),
            ("denied", "local__write", "block", "identity=reader"),
            ("session_end", "", "", ""),
        ])
        kinds = {d["subject"]: d["event"] for d in self.build()["sessions"][0]["denied"]}
        self.assertEqual("budget_exhausted", kinds["local__read"])
        self.assertEqual("denied", kinds["local__write"])

    def test_a_self_declared_client_name_is_shown_as_such(self) -> None:
        """It is in the trail precisely because it authorizes nothing. A
        report that printed it as the caller would undo that."""
        self.write([
            ("session_start", "gateway", "", ""),
            ("client_announced", "totally-the-finance-agent", "",
             "self-declared, not authenticated"),
            ("session_end", "", "", ""),
        ])
        text = sessions.render(self.build(), color=False)
        self.assertIn("claimed to be", text)
        self.assertIn("self-declared", text)

    def test_a_backend_that_would_not_start_is_reported(self) -> None:
        self.write([
            ("session_start", "gateway", "", ""),
            ("backend_failed", "postgres", "", "could not launch"),
            ("session_end", "", "", ""),
        ])
        failure = self.build()["sessions"][0]["failures"][0]
        self.assertEqual("postgres", failure["subject"])
        self.assertIn("could not launch", failure["detail"])


class TestSessionBoundaries(TrailCase):
    def test_two_sessions_stay_two(self) -> None:
        self.write(SESSION + SESSION)
        data = self.build()
        self.assertEqual(2, len(data["sessions"]))
        self.assertEqual(4, data["totals"]["calls"])

    def test_a_session_with_no_end_is_not_merged_into_the_next(self) -> None:
        """A killed guard leaves an open session. Gluing it to the next one
        would attribute one agent's calls to another."""
        self.write([
            ("session_start", "first", "", ""),
            ("request", "a__x", "", ""),
            ("session_start", "second", "", ""),
            ("request", "b__y", "", ""),
            ("session_end", "", "", ""),
        ])
        found = self.build()["sessions"]
        self.assertEqual(["first", "second"], [s["subject"] for s in found])
        self.assertTrue(found[0]["unterminated"])
        self.assertEqual({"a__x": 1}, found[0]["by_tool"])
        self.assertEqual({"b__y": 1}, found[1]["by_tool"])

    def test_a_trail_that_begins_mid_session_says_so(self) -> None:
        """Inventing a start time would be worse than admitting there isn't
        one in the file."""
        self.write([
            ("request", "a__x", "", ""),
            ("session_end", "", "", ""),
        ])
        session = self.build()["sessions"][0]
        self.assertIn("before this file begins", session["subject"])

    def test_the_reason_for_no_end_depends_on_why(self) -> None:
        """A truncated report must not blame a killed process for a cut this
        report performed."""
        self.write([("session_start", "reader", "", ""), ("request", "a__x", "", "")])
        intact = sessions.render(self.build(), color=False)
        self.assertIn("killed or is still running", intact)

        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace("a__x", "something_else")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        broken = sessions.render(self.build(), color=False)
        self.assertIn("record stops at the break", broken)
        self.assertNotIn("killed or is still running", broken)


class TestIntegrityComesFirst(TrailCase):
    def test_an_intact_chain_is_reported_as_such(self) -> None:
        self.write(SESSION)
        data = self.build()
        self.assertTrue(data["integrity"]["intact"])
        self.assertIsNone(data["integrity"]["verified_through_line"])

    def test_nothing_after_the_break_is_counted(self) -> None:
        """The calls in an edited region are numbers somebody chose. Counting
        them would turn a tampered file into a clean-looking report."""
        self.write(SESSION)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[2] = lines[2].replace("read_invoice", "something_else")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        data = self.build()
        self.assertFalse(data["integrity"]["intact"])
        self.assertEqual(2, data["integrity"]["verified_through_line"])
        self.assertEqual(0, data["totals"]["calls"])
        self.assertEqual(0, data["totals"]["denied"])

    def test_the_broken_chain_is_the_first_thing_printed(self) -> None:
        self.write(SESSION)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[2] = lines[2].replace("read_invoice", "something_else")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        text = sessions.render(self.build(), color=False).strip()
        self.assertTrue(text.startswith("CHAIN BROKEN"), text[:80])

    def test_a_crash_mid_write_is_not_reported_as_tampering(self) -> None:
        """Losing the tail is not evidence of tampering -- a killed process
        does it -- so it must not be reported as a broken chain.

        Originally this truncated the log and asserted the chain was intact,
        because nothing could tell a crash from a deletion. The head file can:
        it is written *after* the entry it describes, so a killed process
        leaves it behind the log and never ahead. This test now stages the
        crash properly -- the head lagging one entry -- and the one below
        stages the deletion.
        """
        self.write(SESSION)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        head = json.loads(auditlog.head_path(self.path).read_text(encoding="utf-8"))
        # The guard appended the last entry and died before recording the head.
        head["seq"] = len(lines) - 1
        auditlog.head_path(self.path).write_text(json.dumps(head), encoding="utf-8")
        data = self.build()
        self.assertTrue(data["integrity"]["intact"])

    def test_a_truncated_trail_is_reported_when_the_head_knows_better(self) -> None:
        """A prefix of a valid chain is a valid chain, which is why cutting the
        tail off used to verify clean and take the denial with it."""
        self.write(SESSION)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
        data = self.build()
        self.assertFalse(data["integrity"]["intact"])
        self.assertIn("removed", data["integrity"]["summary"])

    def test_a_trail_with_no_head_file_still_reads_as_a_prefix(self) -> None:
        """Logs written before the head file existed, and logs whose sidecar
        was lost, must still be readable rather than reported as tampered."""
        self.write(SESSION)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
        auditlog.head_path(self.path).unlink()
        data = self.build()
        self.assertTrue(data["integrity"]["intact"])
        self.assertTrue(data["sessions"][0]["unterminated"])


class TestRendering(TrailCase):
    def test_an_empty_trail_says_so(self) -> None:
        self.path.write_text("", encoding="utf-8")
        self.assertIn("No sessions recorded",
                      sessions.render(self.build(), color=False))

    def test_the_limits_of_the_log_are_stated(self) -> None:
        """Somebody reading this will ask what the arguments were. Silence
        reads as an omission; the log refuses on purpose."""
        self.write(SESSION)
        text = sessions.render(self.build(), color=False)
        self.assertIn("Arguments are never recorded", text)

    def test_a_long_tool_list_is_trimmed_unless_asked(self) -> None:
        events = [("session_start", "reader", "", "")]
        events += [("request", "srv__tool%02d" % n, "", "") for n in range(12)]
        events.append(("session_end", "", "", ""))
        self.write(events)
        data = self.build()
        self.assertIn("more (-v for all)", sessions.render(data, color=False))
        self.assertNotIn("more (-v for all)",
                         sessions.render(data, color=False, verbose=True))

    def test_no_color_means_no_escapes(self) -> None:
        self.write(SESSION)
        self.assertNotIn("\033", sessions.render(self.build(), color=False))

    def test_the_payload_is_json_serialisable(self) -> None:
        self.write(SESSION)
        json.dumps(self.build())


class TestThroughTheCommandLine(TrailCase):
    """The exit code is the only thing CI reads."""

    def _run(self, path: Path) -> int:
        import os
        import subprocess
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-m", "mcp_pin", "report", str(path), "--no-color"],
            env=env, capture_output=True, text=True, timeout=120)
        return result.returncode

    def test_an_intact_trail_exits_zero(self) -> None:
        self.write(SESSION)
        self.assertEqual(0, self._run(self.path))

    def test_a_broken_chain_exits_nonzero(self) -> None:
        self.write(SESSION)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[2] = lines[2].replace("read_invoice", "something_else")
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(1, self._run(self.path))

    def test_a_missing_file_is_an_error_not_an_empty_report(self) -> None:
        self.assertEqual(2, self._run(self.path.parent / "nope.jsonl"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
