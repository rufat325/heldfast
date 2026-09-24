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
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import auditlog  # noqa: E402
from heldfast.auditlog import GENESIS, AuditLog, verify  # noqa: E402

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
                [sys.executable, "-m", "heldfast", "guard", "--quiet", "--name", "h",
                 "--log", str(path), "--", sys.executable, str(HOSTILE)],
                input=request + "\n", text=True, capture_output=True, timeout=120,
                cwd=str(ROOT),
                env={"PATH": "", "SystemRoot": "C:\\Windows",
                     "PYTHONPATH": str(ROOT / "src"), "MCP_PIN_HOSTILE": "banner"},
            )
            self.assertTrue(path.exists(), proc.stderr)
            body = path.read_text(encoding="utf-8")

            self.assertNotIn(SECRET, body)
            self.assertNotIn("token", body)
            # The call itself is recorded -- it is the values that are not.
            self.assertIn("read_note", body)
            self.assertIn("argument_bytes", body)
            self.assertTrue(verify(path).ok)



class TestTheChainIsWhole(unittest.TestCase):
    """Walking the chain proves it is internally consistent. It does not prove
    it is all there, and an outside reader demonstrated both ways round:

        full chain:      4 entries, chain intact
        truncate tail:   2 entries, chain intact   # the denial is gone
        re-chain whole:  3 entries, chain intact   # drop it, recompute

    Any prefix of a valid chain is a valid chain, so nothing inside the file
    can catch the first. The head file the writer keeps is outside it.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "trail.jsonl"
        os.environ.pop(auditlog.KEY_VAR, None)

    def tearDown(self) -> None:
        os.environ.pop(auditlog.KEY_VAR, None)
        self._tmp.cleanup()

    def _write(self, key: bytes | None = None) -> None:
        log = auditlog.AuditLog(self.path, "svc", key=key)
        log.record("session_start", detail="policy=block")
        log.record("tool_call", subject="read_invoice", decision="allow")
        log.record("tool_call", subject="wipe_disk", decision="DENY",
                   detail="tool was not present at approval")
        log.record("session_end", detail="1 denied")

    def _lines(self) -> list[str]:
        return self.path.read_text(encoding="utf-8").splitlines()

    def _rechain(self, drop: str, key: bytes | None = None) -> tuple[str, int]:
        """Remove the entry naming `drop` and recompute every hash after it."""
        kept = [json.loads(x) for x in self._lines()
                if json.loads(x).get("subject") != drop]
        prev, seq = auditlog.GENESIS, 1
        for entry in kept:
            entry["seq"], entry["prev"] = seq, prev
            entry.pop("hash", None)
            entry["hash"] = auditlog._digest(entry, key)
            prev, seq = entry["hash"], seq + 1
        self.path.write_text(
            "\n".join(json.dumps(e, sort_keys=True) for e in kept) + "\n",
            encoding="utf-8")
        return prev, len(kept)

    def test_a_full_chain_verifies(self) -> None:
        self._write()
        result = auditlog.verify(self.path)
        self.assertTrue(result.ok)
        self.assertEqual(4, result.entries)

    def test_a_truncated_tail_no_longer_verifies(self) -> None:
        self._write()
        self.path.write_text("\n".join(self._lines()[:2]) + "\n", encoding="utf-8")
        result = auditlog.verify(self.path)
        self.assertFalse(result.ok)
        self.assertIn("removed", result.problems[0].reason)

    def test_a_rechained_log_no_longer_verifies(self) -> None:
        self._write()
        self._rechain("wipe_disk")
        result = auditlog.verify(self.path)
        self.assertFalse(result.ok)

    def test_rewriting_the_head_too_is_the_documented_limit(self) -> None:
        """An attacker who can write the log can usually write the sidecar
        beside it. This is not claimed to stop that -- which is exactly why
        --expect-head exists, and why a key is the real answer."""
        self._write()
        head, count = self._rechain("wipe_disk")
        auditlog.head_path(self.path).write_text(
            json.dumps({"seq": count, "hash": head, "alg": "sha256"}),
            encoding="utf-8")
        self.assertTrue(auditlog.verify(self.path).ok)

    def test_an_out_of_band_count_catches_it_anyway(self) -> None:
        self._write()
        head, count = self._rechain("wipe_disk")
        auditlog.head_path(self.path).write_text(
            json.dumps({"seq": count, "hash": head}), encoding="utf-8")
        result = auditlog.verify(self.path, expect_count=4)
        self.assertFalse(result.ok)
        self.assertIn("expected 4 entries", result.problems[0].reason)

    def test_an_out_of_band_head_catches_it_anyway(self) -> None:
        self._write()
        real = json.loads(
            auditlog.head_path(self.path).read_text(encoding="utf-8"))["hash"]
        head, count = self._rechain("wipe_disk")
        auditlog.head_path(self.path).write_text(
            json.dumps({"seq": count, "hash": head}), encoding="utf-8")
        result = auditlog.verify(self.path, expect_head=real)
        self.assertFalse(result.ok)

    def test_a_head_behind_the_log_is_a_crash_and_not_tampering(self) -> None:
        """The head is written after the entry it describes, so a killed
        process leaves it behind. Direction is the whole discriminator."""
        self._write()
        head = json.loads(
            auditlog.head_path(self.path).read_text(encoding="utf-8"))
        head["seq"] = 3
        auditlog.head_path(self.path).write_text(json.dumps(head), encoding="utf-8")
        self.assertTrue(auditlog.verify(self.path).ok)

    def test_a_missing_head_file_is_not_an_accusation(self) -> None:
        """Logs written before the sidecar existed must still verify."""
        self._write()
        auditlog.head_path(self.path).unlink()
        self.assertTrue(auditlog.verify(self.path).ok)


class TestKeyedChains(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "trail.jsonl"
        os.environ.pop(auditlog.KEY_VAR, None)

    def tearDown(self) -> None:
        os.environ.pop(auditlog.KEY_VAR, None)
        self._tmp.cleanup()

    def _write(self) -> None:
        log = auditlog.AuditLog(self.path, "svc")
        log.record("session_start")
        log.record("tool_call", subject="wipe_disk", decision="DENY")
        log.record("session_end")

    def test_the_key_comes_from_the_environment(self) -> None:
        os.environ[auditlog.KEY_VAR] = "a-secret"
        self._write()
        result = auditlog.verify(self.path)
        self.assertTrue(result.ok)
        self.assertTrue(result.keyed)
        self.assertIn("keyed", result.summary())

    def test_a_keyed_chain_cannot_be_recomputed_without_the_key(self) -> None:
        """The attack an unkeyed chain cannot survive: drop the denial, redo
        the hashes. With a MAC the loop produces nothing that verifies."""
        os.environ[auditlog.KEY_VAR] = "a-secret"
        self._write()
        kept = [json.loads(x) for x in
                self.path.read_text(encoding="utf-8").splitlines()
                if json.loads(x).get("subject") != "wipe_disk"]
        prev, seq = auditlog.GENESIS, 1
        for entry in kept:
            entry["seq"], entry["prev"] = seq, prev
            entry.pop("hash", None)
            entry["hash"] = auditlog._digest(entry)  # no key: the attacker's best
            prev, seq = entry["hash"], seq + 1
        self.path.write_text(
            "\n".join(json.dumps(e, sort_keys=True) for e in kept) + "\n",
            encoding="utf-8")
        self.assertFalse(auditlog.verify(self.path).ok)

    def test_a_keyed_chain_read_without_the_key_says_so(self) -> None:
        """Silently falling back to sha256 would report a keyed chain as
        broken contents, which sends the reader after the wrong problem."""
        os.environ[auditlog.KEY_VAR] = "a-secret"
        self._write()
        os.environ.pop(auditlog.KEY_VAR)
        result = auditlog.verify(self.path)
        self.assertFalse(result.ok)
        self.assertIn(auditlog.KEY_VAR, result.problems[0].reason)

    def test_an_unkeyed_chain_read_with_a_key_says_so(self) -> None:
        self._write()
        os.environ[auditlog.KEY_VAR] = "a-secret"
        result = auditlog.verify(self.path)
        self.assertFalse(result.ok)
        self.assertIn("not keyed", result.problems[0].reason)

    def test_the_unkeyed_digest_did_not_move(self) -> None:
        """Every log already on disk has to keep verifying.

        `alg` is written into the hashed body only when the chain is keyed. Had
        it gone in unconditionally, every existing entry's hash would change
        and every existing log would read as tampered on upgrade -- the same
        mistake that nearly shipped when `output_schema` joined the tool
        fingerprint.
        """
        body = {"seq": 1, "time": "2026-01-01T00:00:00Z", "server": "svc",
                "event": "session_start", "subject": "svc", "decision": "",
                "detail": "policy=block", "prev": "0" * 64}
        self.assertEqual(
            "52a77f6f23f308a2cb64d7c6d17bed84ba6fc29e5f6825349fef5290cab6b420",
            auditlog._digest(body))
        self.assertNotEqual(auditlog._digest(body),
                            auditlog._digest(dict(body, alg="hmac-sha256"), b"k"))


class TestAMissingSidecarIsNotSilence(unittest.TestCase):
    """Deleting the sidecar is cheaper than forging one.

    An outside reviewer put both side by side:

        truncate + delete sidecar : 2 entries, chain intact (unkeyed) | ok
        truncate + forge sidecar  : 2 entries, chain intact (unkeyed) | ok

    The second is the documented limit -- the sidecar is as writable as the log,
    which is what `--expect-count` is for. The first was not a limit, it was a
    silence: the sentence a complete log prints, printed for a log whose length
    nothing had checked. The module already distinguishes `keyed` from
    `unkeyed` in that same sentence rather than letting both read "intact", so
    this gets the same treatment.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "trail.jsonl"
        os.environ.pop(auditlog.KEY_VAR, None)

    def tearDown(self) -> None:
        os.environ.pop(auditlog.KEY_VAR, None)
        self._tmp.cleanup()

    def _write(self) -> None:
        log = auditlog.AuditLog(self.path, "svc")
        log.record("session_start")
        log.record("tool_call", subject="read_invoice", decision="allow")
        log.record("tool_call", subject="wipe_disk", decision="DENY")
        log.record("session_end")

    def _truncate(self, keep: int = 2) -> None:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:keep]) + "\n", encoding="utf-8")

    def test_with_the_sidecar_the_summary_makes_no_caveat(self) -> None:
        self._write()
        result = auditlog.verify(self.path)
        self.assertTrue(result.ok)
        self.assertEqual("head", result.completeness)
        self.assertNotIn("no head file", result.summary())

    def test_without_the_sidecar_the_summary_says_what_was_not_checked(self) -> None:
        self._write()
        auditlog.head_path(self.path).unlink()
        result = auditlog.verify(self.path)
        self.assertTrue(result.ok, "a missing sidecar is not evidence of tampering")
        self.assertEqual("unchecked", result.completeness)
        self.assertIn("no head file", result.summary())
        self.assertIn("--expect-count", result.summary())

    def test_a_truncated_log_with_no_sidecar_reads_differently_from_a_whole_one(self) -> None:
        """The two strings have to differ, or the report launders the edit."""
        self._write()
        whole = auditlog.verify(self.path).summary()
        self._truncate()
        auditlog.head_path(self.path).unlink()
        cut = auditlog.verify(self.path).summary()
        self.assertNotEqual(whole, cut)
        self.assertIn("would not be visible", cut)

    def test_out_of_band_values_count_as_having_checked(self) -> None:
        self._write()
        auditlog.head_path(self.path).unlink()
        result = auditlog.verify(self.path, expect_count=4)
        self.assertTrue(result.ok)
        self.assertEqual("expected", result.completeness)
        self.assertNotIn("no head file", result.summary())

    def test_out_of_band_values_still_catch_the_truncation(self) -> None:
        self._write()
        self._truncate()
        auditlog.head_path(self.path).unlink()
        result = auditlog.verify(self.path, expect_count=4)
        self.assertFalse(result.ok)
        self.assertIn("expected 4 entries", result.problems[0].reason)


class TestTheTreeCompilesWithoutWarnings(unittest.TestCase):
    """An invalid escape in a docstring is a SyntaxWarning now and a
    SyntaxError from Python 3.15.

    It shipped in `split_command`, where a heredoc turned `C:\\\\Python` into a
    live escape. Cached bytecode hides it from everyone who has already run the
    package once, so the only people who see it are the ones installing for the
    first time -- and eventually the package simply will not import.
    """

    def test_no_module_compiles_with_a_syntax_warning(self) -> None:
        import warnings

        offenders = []
        for path in sorted(list((ROOT / "src").rglob("*.py"))
                           + list((ROOT / "tests").rglob("*.py"))):
            if "__pycache__" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                try:
                    compile(source, str(path), "exec")
                except SyntaxError as exc:
                    offenders.append(f"{path.name}: {exc}")
                    continue
            for warning in caught:
                if issubclass(warning.category, SyntaxWarning):
                    offenders.append(f"{path.name}:{warning.lineno}: {warning.message}")
        self.assertEqual([], offenders,
                         "modules that do not compile cleanly:\n  "
                         + "\n  ".join(offenders))


if __name__ == "__main__":
    unittest.main(verbosity=2)
