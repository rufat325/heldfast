"""Robustness against servers that misbehave.

Real MCP servers print banners to stdout before speaking the protocol, emit
notifications mid-reply, start slowly, return enormous payloads and sometimes
refuse to exit. The spec forbids some of that and it happens anyway.

`tests/fixtures/hostile_server.py` does each of these deliberately. It is
hostile to the protocol, not to the machine: no network, no subprocesses, and
the only file it writes is a pid file a test asks it for.

Written after testing against live servers showed the probe had only ever
spoken to fixtures that behaved.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin import lifetime  # noqa: E402
from mcp_pin.model import ServerSpec  # noqa: E402
from mcp_pin.probe import probe_stdio  # noqa: E402

HOSTILE = ROOT / "tests" / "fixtures" / "hostile_server.py"


def probe(mode: str, *, through_guard: bool = False, timeout: float = 20.0):
    env = {"MCP_PIN_HOSTILE": mode, "PYTHONPATH": str(ROOT / "src")}
    if through_guard:
        args = ["-m", "mcp_pin", "guard", "--quiet", "--name", "h", "--",
                sys.executable, str(HOSTILE)]
    else:
        args = [str(HOSTILE)]
    spec = ServerSpec(name="h", source="<test>", client="test", transport="stdio",
                      command=sys.executable, args=args, env=env)
    return probe_stdio(spec, timeout=timeout)


def wait_for_pidfile(path: Path, timeout: float = 20.0) -> int:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        if text.isdigit():
            return int(text)
        time.sleep(0.1)
    raise AssertionError("the fixture never wrote its pid to %s" % path)


def pid_alive(pid: int) -> bool:
    """Whether that process still exists, without shelling out to anything.

    A process that exits with code 259 reads as alive here, which is the
    standard caveat and cannot happen to the fixture.
    """
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


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
        """This asked wmic to enumerate processes and matched command lines.
        Current Windows runner images do not ship wmic, so the call raised
        FileNotFoundError and every Windows job failed -- the tool was being
        tested on a machine that still had a deprecated utility. The fixture
        now reports its own pid, which is exact and needs no external tool."""
        with tempfile.TemporaryDirectory() as td:
            pidfile = Path(td) / "server.pid"
            env = dict(os.environ, MCP_PIN_HOSTILE="hang",
                       MCP_PIN_HOSTILE_PIDFILE=str(pidfile),
                       PYTHONPATH=str(ROOT / "src"))
            guard = subprocess.Popen(
                [sys.executable, "-m", "mcp_pin", "guard", "--quiet", "--name", "h", "--",
                 sys.executable, str(HOSTILE)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=str(ROOT), env=env)
            try:
                pid = wait_for_pidfile(pidfile)
                self.assertTrue(pid_alive(pid), "the server never started")

                guard.kill()          # abrupt: the finally block never runs
                guard.wait(timeout=15)

                deadline = time.time() + 20
                while pid_alive(pid) and time.time() < deadline:
                    time.sleep(0.25)
                self.assertFalse(pid_alive(pid), "the server outlived the guard")
            finally:
                if guard.poll() is None:
                    guard.kill()
                    guard.wait(timeout=10)
                for stream in (guard.stdin, guard.stdout):
                    if stream is not None:
                        stream.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
