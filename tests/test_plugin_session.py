"""The Claude Code hook catches a hosted tool rewritten under an approved name.

A PreToolUse event carries a tool's name and never its definition, so the
hook alone checks names. With HELDFAST_SESSION_CHECK=1 the SessionStart hook
reads each hosted server the lock records, through `heldfast hosted-drift`
(which runs no server code), and PreToolUse refuses, for that session, the
approved tools whose definition changed. The server is the HTTP stub.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import http_server  # noqa: E402
from heldfast.cli import main  # noqa: E402

SCRIPTS = ROOT / "plugin" / "heldfast" / "scripts"


class TestSessionCheck(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tree = Path(self._tmp.name) / "project"
        self.tree.mkdir()
        self.data = Path(self._tmp.name) / "plugin-data"
        served = http_server.serve("benign")
        self.url = served.__enter__()
        self.addCleanup(served.__exit__, None, None, None)
        (self.tree / ".mcp.json").write_text(json.dumps(
            {"mcpServers": {"invoices": {"type": "http", "url": self.url}}}), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(["approve", str(self.tree), "--probe", "--no-stdio-probe",
                         "--no-user-configs", "--no-skills"])
        self.assertEqual(0, code)

    def env(self, **extra: str) -> dict:
        env = {k: v for k, v in os.environ.items()
               if k not in ("HELDFAST_SESSION_CHECK", "HELDFAST_ALLOW_UNPINNED")}
        env.update(PYTHONPATH=str(ROOT / "src"), MCP_PIN_PYTHON=sys.executable,
                   CLAUDE_PLUGIN_DATA=str(self.data))
        env.update(extra)
        return env

    def start(self, session: str = "s1", **extra: str) -> str:
        proc = subprocess.run(["node", str(SCRIPTS / "session-start.js")],
                              input=json.dumps({"hook_event_name": "SessionStart",
                                                "cwd": str(self.tree), "session_id": session}),
                              capture_output=True, text=True, env=self.env(**extra), timeout=60)
        return proc.stdout

    def call(self, tool: str, session: str = "s1") -> str:
        proc = subprocess.run(["node", str(SCRIPTS / "pre-tool-use.js")],
                              input=json.dumps({"hook_event_name": "PreToolUse",
                                                "cwd": str(self.tree), "session_id": session,
                                                "tool_name": tool, "tool_input": {}}),
                              capture_output=True, text=True, env=self.env(), timeout=60)
        if not proc.stdout.strip():
            return "allow"
        return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecisionReason"]

    def test_a_rewritten_hosted_tool_is_refused_for_the_session(self) -> None:
        http_server.set_mode("poisoned")
        said = self.start(HELDFAST_SESSION_CHECK="1")
        self.assertIn("refused this session", said)
        self.assertIn("read_invoice", said)
        self.assertIn("reads differently", self.call("mcp__invoices__read_invoice"))
        self.assertEqual("allow", self.call("mcp__invoices__list_invoices"))

    def test_an_unchanged_server_passes(self) -> None:
        self.assertIn("no approved tool changed", self.start(HELDFAST_SESSION_CHECK="1"))
        self.assertEqual("allow", self.call("mcp__invoices__read_invoice"))

    def test_a_server_behind_a_login_is_reported_not_refused(self) -> None:
        http_server.set_require_auth(True)
        said = self.start(HELDFAST_SESSION_CHECK="1")
        self.assertIn("Not verified", said)
        self.assertEqual("allow", self.call("mcp__invoices__read_invoice"))

    def test_off_unless_asked_for(self) -> None:
        http_server.set_mode("poisoned")
        said = self.start()
        self.assertNotIn("hosted server", said)
        self.assertEqual("allow", self.call("mcp__invoices__read_invoice"))

    def test_one_session_does_not_govern_another(self) -> None:
        http_server.set_mode("poisoned")
        self.start("s1", HELDFAST_SESSION_CHECK="1")
        self.assertEqual("allow", self.call("mcp__invoices__read_invoice", session="s2"))

    def test_a_state_file_it_cannot_read_refuses(self) -> None:
        self.start(HELDFAST_SESSION_CHECK="1")
        state = next(self.data.glob("session-*.json"))
        state.write_text("{", encoding="utf-8")
        self.assertIn("could not be read", self.call("mcp__invoices__read_invoice"))

    def test_without_heldfast_it_says_so_and_refuses_nothing(self) -> None:
        http_server.set_mode("poisoned")
        said = self.start(HELDFAST_SESSION_CHECK="1", MCP_PIN_PYTHON=str(self.data / "none"))
        self.assertIn("were not read", said)
        self.assertEqual("allow", self.call("mcp__invoices__read_invoice"))

    def test_the_lock_is_never_written(self) -> None:
        lock = self.tree / ".mcp-pin.lock"
        before = lock.read_bytes()
        http_server.set_mode("poisoned")
        self.start(HELDFAST_SESSION_CHECK="1")
        self.assertEqual(before, lock.read_bytes())


if __name__ == "__main__":
    unittest.main()
