"""Robustness against servers that misbehave.

Real MCP servers print banners to stdout before speaking the protocol, emit
notifications mid-reply, start slowly, return enormous payloads and sometimes
refuse to exit. The spec forbids some of that and it happens anyway.

`tests/fixtures/hostile_server.py` does each of these deliberately. It is
hostile to the protocol, not to the machine: no files, no network, no
subprocesses.

Written after testing against live servers showed the probe had only ever
spoken to fixtures that behaved.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit import lifetime  # noqa: E402
from mcp_audit.model import ServerSpec  # noqa: E402
from mcp_audit.probe import probe_stdio  # noqa: E402

HOSTILE = ROOT / "tests" / "fixtures" / "hostile_server.py"


def probe(mode: str, *, through_guard: bool = False, timeout: float = 20.0):
    env = {"MCP_AUDIT_HOSTILE": mode, "PYTHONPATH": str(ROOT / "src")}
    if through_guard:
        args = ["-m", "mcp_audit", "guard", "--quiet", "--name", "h", "--",
                sys.executable, str(HOSTILE)]
    else:
        args = [str(HOSTILE)]
    spec = ServerSpec(name="h", source="<test>", client="test", transport="stdio",
                      command=sys.executable, args=args, env=env)
    return probe_stdio(spec, timeout=timeout)


class TestProbeRobustness(unittest.TestCase):
    """Each of these is a real behaviour seen in the wild."""

    def test_banner_before_the_protocol(self) -> None:
        """Servers MUST NOT write non-protocol text to stdout. They do."""
        r = probe("banner")
        self.assertIsNone(r.error, r.error)
        self.assertEqual(1, len(r.tools))

    def test_notifications_interleaved_with_replies(self) -> None:
        r = probe("notifications")
        self.assertIsNone(r.error, r.error)
        self.assertEqual(1, len(r.tools))

    def test_duplicate_reply_ids(self) -> None:
        r = probe("duplicate_id")
        self.assertIsNone(r.error, r.error)

    def test_reply_to_an_id_nobody_sent(self) -> None:
        r = probe("unsolicited")
        self.assertIsNone(r.error, r.error)
        self.assertEqual(1, len(r.tools))

    def test_blank_lines_in_the_stream(self) -> None:
        self.assertIsNone(probe("empty_lines").error)

    def test_large_tool_list(self) -> None:
        self.assertEqual(400, len(probe("huge").tools))

    def test_invalid_utf8_in_a_description(self) -> None:
        """A lone surrogate must not take the probe down."""
        r = probe("badutf8")
        self.assertIsNone(r.error, r.error)
        self.assertEqual(1, len(r.tools))

    def test_two_megabyte_single_line(self) -> None:
        r = probe("longline")
        self.assertIsNone(r.error, r.error)
        self.assertGreater(len(r.tools[0].description), 1_000_000)

    def test_server_exits_mid_conversation(self) -> None:
        r = probe("crash")
        self.assertIsNotNone(r.error)
        self.assertIn("closed the connection", r.error)

    def test_slow_server_times_out_cleanly(self) -> None:
        start = time.time()
        r = probe("slow", timeout=3)
        self.assertIsNotNone(r.error)
        self.assertIn("timed out", r.error)
        self.assertLess(time.time() - start, 25, "timeout was not honoured")

    def test_server_that_refuses_to_exit(self) -> None:
        """Ignoring stdin close must not hang the probe."""
        start = time.time()
        r = probe("hang", timeout=10)
        self.assertIsNone(r.error, r.error)
        self.assertLess(time.time() - start, 25)


class TestGuardRobustness(unittest.TestCase):
    """The same servers, reached through the proxy."""

    def test_guard_survives_a_banner(self) -> None:
        r = probe("banner", through_guard=True)
        self.assertIsNone(r.error, r.error)
        self.assertEqual(1, len(r.tools))

    def test_guard_forwards_a_large_payload(self) -> None:
        self.assertEqual(400, len(probe("huge", through_guard=True).tools))

    def test_guard_survives_invalid_utf8(self) -> None:
        self.assertIsNone(probe("badutf8", through_guard=True).error)

    def test_guard_reports_a_crashed_server(self) -> None:
        self.assertIsNotNone(probe("crash", through_guard=True).error)

    def test_guard_forwards_interleaved_notifications(self) -> None:
        self.assertIsNone(probe("notifications", through_guard=True).error)


class TestChildLifetime(unittest.TestCase):
    """The guard's finally block covers a normal exit. It does not run when
    the guard is killed, and a server that ignores stdin close would then be
    orphaned indefinitely -- which is exactly what happened when this was
    first tried."""

    def test_bind_child_never_raises(self) -> None:
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        try:
            note = lifetime.bind_child(proc)
            self.assertIsInstance(note, str)
            self.assertTrue(note)
        finally:
            proc.kill()
            proc.wait(timeout=10)

    def test_posix_preexec_is_none_off_linux(self) -> None:
        hook = lifetime.posix_preexec()
        if sys.platform.startswith("linux"):
            self.assertTrue(callable(hook))
        else:
            self.assertIsNone(hook)

    @unittest.skipUnless(sys.platform == "win32", "job objects are Windows-only")
    def test_killed_guard_takes_the_server_with_it(self) -> None:
        def running() -> int:
            out = subprocess.run(
                ["wmic", "process", "where", "name='python.exe'", "get", "CommandLine"],
                capture_output=True, text=True, timeout=120)
            return sum(1 for line in out.stdout.splitlines()
                       if "hostile_server" in line and "guard" not in line)

        env = dict(os.environ, MCP_AUDIT_HOSTILE="hang", PYTHONPATH=str(ROOT / "src"))
        guard = subprocess.Popen(
            [sys.executable, "-m", "mcp_audit", "guard", "--quiet", "--name", "h", "--",
             sys.executable, str(HOSTILE)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=str(ROOT), env=env)
        try:
            time.sleep(3)
            guard.kill()          # abrupt: the finally block never runs
            guard.wait(timeout=15)
            time.sleep(3)
            self.assertEqual(0, running(), "the server outlived the guard")
        finally:
            if guard.poll() is None:
                guard.kill()
                guard.wait(timeout=10)
            for stream in (guard.stdin, guard.stdout):
                if stream is not None:
                    stream.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
