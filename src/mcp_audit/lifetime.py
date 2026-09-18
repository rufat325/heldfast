"""Tie a child process's lifetime to this one's.

`guard` launches the real MCP server as a subprocess and proxies between it
and the client. Its `finally` block terminates the child on a normal exit,
which covers the ordinary cases -- but not the one that matters: if the guard
is killed outright, the `finally` never runs and the server is orphaned. A
server that ignores stdin close, which the spec says it should honour but
which nothing enforces, then runs until the machine reboots.

Found by killing the guard mid-proxy against a fixture that deliberately
refuses to exit, and finding the fixture still running afterwards.

The mechanism is per-platform and entirely best effort. Failing to set it up
is logged and ignored: a proxy that refuses to start because it could not
arrange its own cleanup would be worse than one that occasionally leaks.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Callable

# Windows Job Object handles are kept here so they are not garbage collected;
# the job dies with this process, and its children with it.
_JOB_HANDLES: list[Any] = []


def _windows_kill_on_close(proc: subprocess.Popen) -> str:
    """Put the child in a Job Object that kills it when this process dies."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001

    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObject failed")

    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
        job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")

    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, proc.pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    try:
        if not kernel32.AssignProcessToJobObject(job, handle):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    finally:
        kernel32.CloseHandle(handle)

    _JOB_HANDLES.append(job)
    return "job object (kill on close)"


def posix_preexec() -> Callable[[], None] | None:
    """Ask Linux to signal the child when this process dies.

    `prctl(PR_SET_PDEATHSIG, SIGKILL)` is Linux-only. macOS has no equivalent,
    so there the ordinary termination path is all there is.
    """
    if not sys.platform.startswith("linux"):
        return None

    def _set_pdeathsig() -> None:  # pragma: no cover - runs in the child
        import ctypes
        import signal
        try:
            ctypes.CDLL("libc.so.6").prctl(1, signal.SIGKILL, 0, 0, 0)  # PR_SET_PDEATHSIG
        except Exception:
            pass

    return _set_pdeathsig


def bind_child(proc: subprocess.Popen) -> str:
    """Best-effort: make `proc` die when this process does. Returns a note."""
    if sys.platform == "win32":
        try:
            return _windows_kill_on_close(proc)
        except Exception as exc:
            return f"unavailable ({type(exc).__name__}: {exc})"
    if sys.platform.startswith("linux"):
        return "prctl PDEATHSIG (set at spawn)"
    return "unavailable on this platform; relying on normal termination"
