"""The guard's tamper-evident record of what it did.

Two things are being asserted, and the second matters more than the first.

That the chain works: editing, deleting, reordering or appending to the log
each breaks it, at the right line, with a reason that says which.

That arguments never reach the file. A tool call's arguments are exactly where
a credential or a customer's record would be, and a security tool that copies
both into a log on disk has built the problem it was installed to find. The
test drives a real guarded session with a secret in the arguments and greps
the log for it.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit.auditlog import GENESIS, AuditLog, verify  # noqa: E402

HOSTILE = ROOT / "tests" / "fixtures" / "hostile_server.py"
SECRET = "ghp_" + "A" * 36


def lines_of(path: Path) -> list[str]:
    return [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def rewrite(path: Path, new_lines: list[str]) -> None:
    with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(new_lines) + "\n")


class TestTheChain(unittest.TestCase):
    def _log(self, directory: str) -> Path:
        path = Path(directory) / "trail.jsonl"
        trail = AuditLog(path, "svc")
        trail.record("session_start", subject="svc")
        trail.record("request", subject="read_note", detail="argument_bytes=26")
        trail.record("request", subject="write_note", detail="argument_bytes=11")
        trail.record("session_end", detail="forwarded=3")
        return path

    def test_an_untouched_log_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = verify(self._log(td))
            self.assertTrue(result.ok, result.summary())
            self.assertEqual(4, result.entries)

    def test_the_first_entry_starts_from_genesis(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            first = json.loads(lines_of(self._log(td))[0])
            self.assertEqual(GENESIS, first["prev"])

    def test_editing_an_entry_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._log(td)
            rewrite(path, [l.replace("read_note", "read_nope") for l in lines_of(path)])
            result = verify(path)
            self.assertFalse(result.ok)
            self.assertEqual(2, result.problems[0].line)
            self.assertIn("hash", result.problems[0].reason)

    def test_deleting_an_entry_is_caught(self) -> None:
        """The interesting case: a log you can quietly shorten is no evidence
        at all, because the embarrassing call is the one that goes missing."""
        with tempfile.TemporaryDirectory() as td:
            path = self._log(td)
            rewrite(path, [l for l in lines_of(path) if "read_note" not in l])
            result = verify(path)
            self.assertFalse(result.ok)
            self.assertIn("does not follow", result.problems[0].reason)

    def test_reordering_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._log(td)
            current = lines_of(path)
            current[1], current[2] = current[2], current[1]
            rewrite(path, current)
            self.assertFalse(verify(path).ok)

    def test_a_forged_entry_appended_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._log(td)
            forged = {"seq": 5, "time": "2026-01-01T00:00:00Z", "server": "svc",
                      "event": "request", "subject": "forged", "decision": "",
                      "detail": "", "prev": "0" * 64, "hash": "deadbeef"}
            rewrite(path, lines_of(path) + [json.dumps(forged, sort_keys=True)])
            result = verify(path)
            self.assertFalse(result.ok)
            self.assertEqual(5, result.problems[0].line)

    def test_a_missing_file_is_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(verify(Path(td) / "nothing.jsonl").ok)

    def test_a_restarted_guard_continues_one_chain(self) -> None:
        """Two chains in one file would read as tampering at the join."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trail.jsonl"
            first = AuditLog(path, "svc")
            first.record("session_start")
            first.record("session_end")

            second = AuditLog(path, "svc")
            self.assertEqual(2, second.seq)
            second.record("session_start")
            second.record("session_end")

            result = verify(path)
            self.assertTrue(result.ok, result.summary())
            self.assertEqual(4, result.entries)

    def test_an_unwritable_log_does_not_take_the_proxy_down(self) -> None:
        """The proxy exists to pass traffic. Losing the audit trail is bad;
        losing the server because of it is worse."""
        with tempfile.TemporaryDirectory() as td:
            trail = AuditLog(Path(td) / "sub" / "dir" / "trail.jsonl", "svc")
            trail.record("session_start")
            self.assertIsNotNone(trail.failed)


class TestArgumentsAreNeverWritten(unittest.TestCase):
    def test_a_real_session_does_not_log_the_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trail.jsonl"
            request = json.dumps({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "read_note", "arguments": {"token": SECRET}},
            })
            proc = subprocess.run(
                [sys.executable, "-m", "mcp_audit", "guard", "--quiet", "--name", "h",
                 "--log", str(path), "--", sys.executable, str(HOSTILE)],
                input=request + "\n", text=True, capture_output=True, timeout=120,
                cwd=str(ROOT),
                env={"PATH": "", "SystemRoot": "C:\\Windows",
                     "PYTHONPATH": str(ROOT / "src"), "MCP_AUDIT_HOSTILE": "banner"},
            )
            self.assertTrue(path.exists(), proc.stderr)
            body = path.read_text(encoding="utf-8")

            self.assertNotIn(SECRET, body)
            self.assertNotIn("token", body)
            # The call itself is recorded -- it is the values that are not.
            self.assertIn("read_note", body)
            self.assertIn("argument_bytes", body)
            self.assertTrue(verify(path).ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
