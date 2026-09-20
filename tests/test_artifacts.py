"""The code behind the launch command, not just the command.

MCPA016 pins `"command": "node", "args": ["server.js"]`. The line can stay
byte-identical while server.js is rewritten, and that is the same rug pull one
layer down -- an easier one, because editing a file nobody diffs beats editing
a config somebody committed.

The precision question here is what *not* to hash. A bare `node` off PATH
updates whenever the machine updates, for reasons that have nothing to do with
this server, and a rule that fires on every Node patch is a rule people turn
off. So interpreters resolved from PATH are left alone and the author's own
scripts are not.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.artifacts import MAX_BYTES, artifact_digests, digest_file, mismatch  # noqa: E402
from mcp_pin.lockfile import Lock  # noqa: E402
from mcp_pin.model import ServerSpec  # noqa: E402
from mcp_pin.rules import AuditContext, run_rules  # noqa: E402


def server(root: Path, command: str = "node", args=("server.js",)) -> ServerSpec:
    return ServerSpec(name="notes", source=str(root / ".mcp.json"), client="claude-code",
                      transport="stdio", command=command, args=list(args))


class TestWhatGetsHashed(unittest.TestCase):
    def test_a_script_named_in_the_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text("v1", encoding="utf-8")
            digests = artifact_digests(server(root))
            self.assertEqual(1, len(digests))
            self.assertTrue(next(iter(digests)).endswith("server.js"))

    def test_the_digest_follows_the_contents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text("v1", encoding="utf-8")
            before = artifact_digests(server(root))
            (root / "server.js").write_text("v2", encoding="utf-8")
            self.assertNotEqual(before, artifact_digests(server(root)))

    def test_a_relative_script_resolves_against_the_config(self) -> None:
        """Not against the current directory, which is wherever the scan ran."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "project"
            (root / "lib").mkdir(parents=True)
            (root / "lib" / "main.py").write_text("x", encoding="utf-8")
            spec = ServerSpec(name="n", source=str(root / ".mcp.json"),
                              client="c", transport="stdio",
                              command="python", args=["lib/main.py"])
            self.assertEqual(1, len(artifact_digests(spec)))

    def test_a_command_written_as_a_path_is_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / "bin" / "server"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
            spec = server(root, command=str(binary), args=())
            self.assertEqual(1, len(artifact_digests(spec)))

    def test_an_interpreter_off_path_is_not_hashed(self) -> None:
        """`node` updates on the machine's schedule, not the server's. A rule
        that fires on every Node patch is one people turn off."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = server(root, command="node", args=["-e", "console.log(1)"])
            self.assertEqual({}, artifact_digests(spec))

    def test_a_published_package_has_nothing_local_to_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spec = server(Path(td), command="npx", args=["-y", "@scope/pkg@1.0.0"])
            self.assertEqual({}, artifact_digests(spec))

    def test_a_missing_file_is_not_invented(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual({}, artifact_digests(server(Path(td))))

    def test_something_enormous_is_skipped_rather_than_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "huge.js"
            with big.open("wb") as handle:
                handle.seek(MAX_BYTES + 1)
                handle.write(b"\0")
            self.assertIsNone(digest_file(big))

    def test_a_directory_is_not_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(digest_file(Path(td)))


class TestDriftIsReported(unittest.TestCase):
    def _approved(self, root: Path):
        spec = server(root)
        lock = Lock()
        lock.record([spec], [], [])
        return spec, {"servers": lock.servers, "skills": lock.skills}

    def test_editing_the_script_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text("harmless", encoding="utf-8")
            spec, lock = self._approved(root)

            (root / "server.js").write_text("harmless + exfiltrate", encoding="utf-8")
            findings = [f for f in run_rules(AuditContext(servers=[spec], lock=lock))
                        if f.rule_id == "MCPA031"]

            self.assertEqual(1, len(findings))
            self.assertIn("server.js", findings[0].evidence)

    def test_an_untouched_script_is_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text("harmless", encoding="utf-8")
            spec, lock = self._approved(root)
            self.assertEqual([], [f for f in run_rules(AuditContext(servers=[spec], lock=lock))
                                  if f.rule_id == "MCPA031"])

    def test_a_script_that_disappeared_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text("harmless", encoding="utf-8")
            spec, lock = self._approved(root)
            (root / "server.js").unlink()

            findings = [f for f in run_rules(AuditContext(servers=[spec], lock=lock))
                        if f.rule_id == "MCPA031"]
            self.assertEqual(1, len(findings))
            self.assertIn("no longer readable", findings[0].evidence)

    def test_the_command_line_rule_stays_silent(self) -> None:
        """The point of this rule: MCPA016 sees nothing, because nothing it
        watches changed."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text("harmless", encoding="utf-8")
            spec, lock = self._approved(root)
            (root / "server.js").write_text("rewritten", encoding="utf-8")

            found = {f.rule_id for f in run_rules(AuditContext(servers=[spec], lock=lock))}
            self.assertIn("MCPA031", found)
            self.assertNotIn("MCPA016", found)

    def test_a_server_with_no_recorded_artifacts_is_quiet(self) -> None:
        """Locks written before this existed must not start reporting."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text("x", encoding="utf-8")
            spec = server(root)
            lock = {"servers": {spec.identity(): {"name": "notes", "client": "claude-code",
                                                  "command_line": spec.command_line}},
                    "skills": {}}
            self.assertEqual([], [f for f in run_rules(AuditContext(servers=[spec], lock=lock))
                                  if f.rule_id == "MCPA031"])


class TestMismatch(unittest.TestCase):
    """Scan-time MCPA031 is not a runtime boundary. This is."""

    def test_unchanged_bytes_are_silent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "server.js"
            path.write_text("v1", encoding="utf-8")
            recorded = {str(path): digest_file(path)}
            self.assertIsNone(mismatch(recorded))

    def test_rewritten_bytes_are_a_reason(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "server.js"
            path.write_text("v1", encoding="utf-8")
            recorded = {str(path): digest_file(path)}
            path.write_text("v2", encoding="utf-8")
            self.assertIn("changed since approval", mismatch(recorded) or "")

    def test_a_missing_file_is_a_reason(self) -> None:
        recorded = {"/no/such/server.js": "abc"}
        self.assertIn("no longer readable", mismatch(recorded) or "")

    def test_nothing_recorded_is_not_a_pass_it_is_n_a(self) -> None:
        self.assertIsNone(mismatch(None))
        self.assertIsNone(mismatch({}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
