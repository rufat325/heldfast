"""Wrap is guard. check is the lockfile verifier. ci will not probe."""

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

from heldfast.cli import _COMMANDS, _with_default_command, build_parser  # noqa: E402
from heldfast.lockfile import DEFAULT_LOCK_NAME  # noqa: E402


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), NO_COLOR="1")
    return subprocess.run(
        [sys.executable, "-m", "heldfast", *args],
        capture_output=True, text=True, env=env,
        cwd=str(cwd or ROOT),
    )


class TestWrapIsGuard(unittest.TestCase):
    def test_wrap_is_an_alias_of_guard(self) -> None:
        parser = build_parser()
        self.assertIn("wrap", parser.mcp_commands)
        self.assertIs(_COMMANDS["wrap"], _COMMANDS["guard"])

    def test_bare_double_dash_is_wrap(self) -> None:
        parser = build_parser()
        argv = _with_default_command(parser, ["--", "npx", "-y", "pkg@1.0.0"])
        self.assertEqual("wrap", argv[0])
        args = parser.parse_args(argv)
        self.assertEqual("wrap", args.command)

    def test_doctor_is_scan(self) -> None:
        parser = build_parser()
        self.assertIn("doctor", parser.mcp_commands)
        self.assertIs(_COMMANDS["doctor"], _COMMANDS["scan"])

    def test_wrap_without_a_command_explains_itself(self) -> None:
        proc = _run("wrap")
        self.assertEqual(2, proc.returncode)
        self.assertIn("wrap needs a server command", proc.stderr)


class TestCheck(unittest.TestCase):
    def test_missing_lock_is_mcpa014(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run("check", cwd=Path(tmp))
        self.assertEqual(1, proc.returncode)
        self.assertIn("MCPA014", proc.stderr)

    def test_a_well_formed_lock_is_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / DEFAULT_LOCK_NAME
            path.write_text(json.dumps({
                "version": 1,
                "generated": "2026-09-21T00:00:00Z",
                "servers": {
                    "claude-code:files": {
                        "name": "files",
                        "tools": {"read_file": {"fingerprint": "abc"}},
                    }
                },
                "skills": {},
            }, indent=2) + "\n", encoding="utf-8")
            proc = _run("check", cwd=Path(tmp))
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn("1 server(s)", proc.stdout)
        self.assertIn("1 tool(s)", proc.stdout)

    def test_a_future_version_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / DEFAULT_LOCK_NAME
            path.write_text(json.dumps({
                "version": 99, "servers": {}, "skills": {},
            }) + "\n", encoding="utf-8")
            proc = _run("check", cwd=Path(tmp))
        self.assertEqual(2, proc.returncode)
        self.assertIn("newer", proc.stderr)


class TestCiRefusesProbe(unittest.TestCase):
    def test_ci_help_exists(self) -> None:
        proc = _run("ci", "-h")
        self.assertEqual(0, proc.returncode)
        self.assertIn("MCPA014", proc.stdout)

    def test_ci_overrides_probe(self) -> None:
        from unittest.mock import patch
        from heldfast import cli
        args = cli.build_parser().parse_args(["ci", "--probe", "--fail-on", "never", "."])
        self.assertTrue(args.probe)
        self.assertEqual("never", args.fail_on)
        with patch.object(cli, "cmd_scan", return_value=0) as scan:
            self.assertEqual(0, cli.cmd_ci(args))
        self.assertFalse(args.probe)
        self.assertEqual("high", args.fail_on)
        scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
