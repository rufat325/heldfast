"""Claude Code hooks refuse a missing pin without wrapping argv."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin" / "mcp-pin" / "scripts"


def _node(script: str, payload: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["node", str(PLUGIN / script)],
        input=json.dumps(payload),
        capture_output=True, text=True, cwd=str(cwd),
    )


class TestPreToolUse(unittest.TestCase):
    def test_missing_lock_denies_mcp_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _node("pre-tool-use.js", {
                "cwd": tmp,
                "tool_name": "mcp__files__read_file",
                "tool_input": {"path": "a.txt"},
            }, Path(tmp))
        self.assertEqual(0, proc.returncode, proc.stderr)
        data = json.loads(proc.stdout)
        decision = data["hookSpecificOutput"]["permissionDecision"]
        self.assertEqual("deny", decision)
        self.assertIn("no .mcp-pin.lock", data["hookSpecificOutput"]["permissionDecisionReason"])

    def test_unknown_tool_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = {
                "version": 1,
                "servers": {
                    "claude-code:files": {
                        "name": "files",
                        "tools": {"read_file": {"fingerprint": "abc"}},
                    }
                },
                "skills": {},
            }
            (Path(tmp) / ".mcp-pin.lock").write_text(
                json.dumps(lock), encoding="utf-8")
            proc = _node("pre-tool-use.js", {
                "cwd": tmp,
                "tool_name": "mcp__files__wipe_disk",
                "tool_input": {},
            }, Path(tmp))
        data = json.loads(proc.stdout)
        self.assertEqual("deny", data["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("wipe_disk", data["hookSpecificOutput"]["permissionDecisionReason"])

    def test_pinned_tool_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = {
                "version": 1,
                "servers": {
                    "claude-code:files": {
                        "name": "files",
                        "tools": {"read_file": {"fingerprint": "abc"}},
                    }
                },
                "skills": {},
            }
            (Path(tmp) / ".mcp-pin.lock").write_text(
                json.dumps(lock), encoding="utf-8")
            proc = _node("pre-tool-use.js", {
                "cwd": tmp,
                "tool_name": "mcp__files__read_file",
                "tool_input": {"path": "a.txt"},
            }, Path(tmp))
        self.assertEqual("", proc.stdout.strip(), proc.stdout)
        self.assertEqual(0, proc.returncode, proc.stderr)

    def test_non_mcp_tools_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _node("pre-tool-use.js", {
                "cwd": tmp,
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
            }, Path(tmp))
        self.assertEqual("", proc.stdout.strip())
        self.assertEqual(0, proc.returncode)

    def test_session_start_names_the_missing_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _node("session-start.js", {"cwd": tmp}, Path(tmp))
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn("no .mcp-pin.lock", proc.stdout)


class TestPluginDigestMatchesGoldens(unittest.TestCase):
    def test_plugin_lib_agrees_with_the_checker(self) -> None:
        lib = str(PLUGIN / "lib.js")
        checker = str(ROOT / "js" / "mcp-pin-check" / "index.js")
        golden = str(ROOT / "tests" / "golden" / "tools")
        script = """
const a = require(%s);
const b = require(%s);
const fs = require("fs");
const dir = %s;
for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".json"))) {
  const rec = JSON.parse(fs.readFileSync(require("path").join(dir, f), "utf8"));
  const da = a.toolDigest(rec.tool);
  const db = b.toolDigest(rec.tool);
  if (da !== db || da !== rec.digest) {
    console.error(f, da, db, rec.digest);
    process.exit(1);
  }
}
""" % (json.dumps(lib), json.dumps(checker), json.dumps(golden))
        proc = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)


if __name__ == "__main__":
    unittest.main()
