"""Signed segments, and the exact size of what they buy.

The roadmap entry this closes read: "The chain is tamper-evident, not
attributable. Needs a key, which needs somewhere to live." The answer is that
it should not live in this process. `--sign-command` hands a short payload to
something the operator already trusts with keys -- ssh-agent, a smartcard, a
KMS CLI -- and keeps what comes back. There is deliberately no `--signing-key`
flag: a key handed to this process is a key this process can leak.

What a verified segment proves, and it is worth being precise: the prefix it
covers cannot have been rewritten *afterwards*. That is the gap an unkeyed
chain cannot close at all, because an attacker with write access can recompute
every hash in it. What it does not prove is that a live same-user attacker
could not have asked the same agent to sign a story of their choosing while
the guard was running. Nothing on the same host proves that.

The signer under test is a stub, for the same reason `test_wire_shape.py` uses
one: the mechanism must be testable without `ssh-keygen` being installed and
without a real key existing anywhere.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import auditlog  # noqa: E402

STUB = ROOT / "tests" / "fixtures" / "stub_signer.py"
SIGN = f'"{sys.executable}" "{STUB}" sign'
VERIFY = f'"{sys.executable}" "{STUB}" verify {{sig}}'


class SigningCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "trail.jsonl"
        for var in (auditlog.KEY_VAR, "STUB_SIGNER_FAIL", "STUB_SIGNER_WRONG_KEY"):
            os.environ.pop(var, None)

    def tearDown(self) -> None:
        for var in (auditlog.KEY_VAR, "STUB_SIGNER_FAIL", "STUB_SIGNER_WRONG_KEY"):
            os.environ.pop(var, None)
        self._tmp.cleanup()

    def write(self, sign: bool = True) -> auditlog.AuditLog:
        signer = auditlog.Signer(SIGN, name="test-signer") if sign else None
        log = auditlog.AuditLog(self.path, "svc", signer=signer)
        log.record("session_start", detail="policy=block")
        log.record("tool_call", subject="read_invoice", decision="allow")
        log.record("tool_call", subject="wipe_disk", decision="DENY",
                   detail="tool was not present at approval")
        log.record("session_end", detail="1 denied")
        if sign:
            self.assertTrue(log.close_segment(), signer.failed if signer else "")
        return log

    def entries(self) -> list[dict]:
        return [json.loads(line) for line in
                self.path.read_text(encoding="utf-8").splitlines() if line.strip()]


class TestASignedSegmentSealsThePrefix(SigningCase):
    def test_the_segment_is_recorded_as_an_entry_in_the_chain(self) -> None:
        self.write()
        last = self.entries()[-1]
        self.assertEqual(auditlog.SEGMENT_EVENT, last["event"])
        self.assertEqual("test-signer", last["subject"])
        self.assertIn("through=4", last["detail"])
        self.assertTrue(last.get("sig"))

    def test_it_verifies_with_the_verifier(self) -> None:
        self.write()
        result = auditlog.verify(self.path, verify_command=VERIFY)
        self.assertTrue(result.ok, result.summary())
        self.assertEqual(1, result.signatures_checked)
        self.assertIn("1 signed segment(s) verified", result.summary())

    def test_a_rewritten_prefix_no_longer_verifies(self) -> None:
        """The attack an unkeyed chain cannot survive: drop the denial and
        recompute every hash. The hashes all come out right. The signature
        commits to the head the chain used to have, so it does not."""
        self.write()
        kept = [e for e in self.entries() if e.get("subject") != "wipe_disk"]
        prev, seq = auditlog.GENESIS, 1
        for entry in kept:
            entry["seq"], entry["prev"] = seq, prev
            entry.pop("hash", None)
            entry["hash"] = auditlog._digest(entry)
            prev, seq = entry["hash"], seq + 1
        self.path.write_text(
            "\n".join(json.dumps(e, sort_keys=True) for e in kept) + "\n",
            encoding="utf-8")
        auditlog.head_path(self.path).write_text(
            json.dumps({"seq": len(kept), "hash": prev}), encoding="utf-8")

        # Without the verifier the rewrite is invisible, which is exactly why
        # the signature has to be checked rather than merely present.
        self.assertTrue(auditlog.verify(self.path).ok)
        sealed = auditlog.verify(self.path, verify_command=VERIFY)
        self.assertFalse(sealed.ok)
        self.assertIn("did not verify", sealed.problems[0].reason)

    def test_editing_the_signature_breaks_the_chain_itself(self) -> None:
        """The signature is inside the hashed body, so it cannot be swapped
        without also breaking the hash that covers it."""
        self.write()
        raw = self.path.read_text(encoding="utf-8")
        entries = self.entries()
        entries[-1]["sig"] = "Y3Vja29v"
        lines = [json.dumps(e, sort_keys=True) for e in entries]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertNotEqual(raw, self.path.read_text(encoding="utf-8"))
        result = auditlog.verify(self.path)
        self.assertFalse(result.ok)
        self.assertIn("recorded hash", result.problems[0].reason)

    def test_a_segment_from_the_wrong_key_is_rejected(self) -> None:
        self.write()
        os.environ["STUB_SIGNER_WRONG_KEY"] = "1"
        result = auditlog.verify(self.path, verify_command=VERIFY)
        self.assertFalse(result.ok)
        self.assertIn("did not verify", result.problems[0].reason)


class TestSigningIsOptionalAndNeverFatal(SigningCase):
    def test_an_unsigned_log_still_verifies(self) -> None:
        self.write(sign=False)
        result = auditlog.verify(self.path, verify_command=VERIFY)
        self.assertTrue(result.ok)
        self.assertEqual(0, result.signatures_checked)

    def test_present_but_unchecked_segments_are_not_reported_as_verified(self) -> None:
        """Silence has to mean one thing here too. A segment nobody checked is
        not a segment that passed."""
        self.write()
        result = auditlog.verify(self.path)
        self.assertTrue(result.ok)
        self.assertEqual(0, result.signatures_checked)
        self.assertIn("not checked", result.summary())

    def test_a_signer_that_refuses_does_not_lose_the_log(self) -> None:
        """The log is the record; the signature is a claim about it. An agent
        that is locked, absent or says no must not cost the record."""
        os.environ["STUB_SIGNER_FAIL"] = "1"
        signer = auditlog.Signer(SIGN, name="test-signer")
        log = auditlog.AuditLog(self.path, "svc", signer=signer)
        log.record("session_start")
        log.record("tool_call", subject="wipe_disk", decision="DENY")
        self.assertFalse(log.close_segment())
        self.assertIn("the agent said no", str(signer.failed))
        self.assertTrue(auditlog.verify(self.path).ok)
        self.assertEqual(2, auditlog.verify(self.path).entries)

    def test_a_missing_signer_command_is_reported_not_raised(self) -> None:
        signer = auditlog.Signer("definitely-not-a-command-anywhere --sign")
        self.assertIsNone(signer.sign(b"payload"))
        self.assertIsNotNone(signer.failed)

    def test_signing_composes_with_a_keyed_chain(self) -> None:
        os.environ[auditlog.KEY_VAR] = "a-secret"
        self.write()
        result = auditlog.verify(self.path, verify_command=VERIFY)
        self.assertTrue(result.ok, result.summary())
        self.assertTrue(result.keyed)
        self.assertEqual(1, result.signatures_checked)


class TestThroughTheRealCommandLine(SigningCase):
    def _cli(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), NO_COLOR="1")
        # DEVNULL, not inherited: the guard reads stdin until EOF, so an
        # inherited stdin makes this hang until the timeout under a test
        # runner and pass when run alone.
        return subprocess.run([sys.executable, "-m", "heldfast", *args],
                              capture_output=True, text=True, timeout=90,
                              env=env, cwd=str(ROOT),
                              stdin=subprocess.DEVNULL)

    def test_verify_log_checks_segments_when_asked(self) -> None:
        self.write()
        done = self._cli("verify-log", str(self.path), "--verify-command", VERIFY)
        self.assertEqual(0, done.returncode, done.stdout + done.stderr)
        self.assertIn("signed segment(s) verified", done.stdout)

    def test_verify_log_reports_a_bad_segment_and_exits_nonzero(self) -> None:
        self.write()
        os.environ["STUB_SIGNER_WRONG_KEY"] = "1"
        done = self._cli("verify-log", str(self.path), "--verify-command", VERIFY)
        self.assertEqual(1, done.returncode, done.stdout + done.stderr)
        self.assertIn("did not verify", done.stdout)

    def test_guard_seals_the_trail_at_session_end(self) -> None:
        """End to end: the real proxy, the real flag, a real signed segment."""
        from heldfast.lockfile import Lock
        from heldfast.model import ServerSpec

        fake = ROOT / "tests" / "fixtures" / "fake_server.py"
        lock_path = Path(self._tmp.name) / ".mcp-pin.lock"
        spec = ServerSpec(name="invoices", source=str(lock_path), client="test",
                          transport="stdio", command=sys.executable, args=[str(fake)])
        lock = Lock(path=lock_path)
        lock.record([spec], [], [])
        lock.save()

        done = self._cli("guard", "--quiet", "--name", "invoices",
                         "--lock", str(lock_path),
                         "--log", str(self.path),
                         "--sign-command", SIGN,
                         "--", sys.executable, str(fake))
        self.assertIn(done.returncode, (0, 2), done.stderr)
        self.assertTrue(self.path.exists(), "no trail was written")
        result = auditlog.verify(self.path, verify_command=VERIFY)
        self.assertTrue(result.ok, result.summary())
        self.assertGreaterEqual(result.signatures_checked, 1)


if __name__ == "__main__":
    unittest.main()
