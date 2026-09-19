"""One endpoint in front of every approved MCP server.

`guard` wraps a single server. That is the right shape for one connection and
the wrong shape for a machine, because an agent does not have one server -- it
has eight, from three different publishers, and the interesting properties are
the ones that only exist across the whole set.

The gateway is one MCP server that the client points at instead. Behind it sit
every approved server from the lockfile, started as children, and every call
passes through the same enforcement `guard` already applies:

    client ──stdio──> mcp-audit gateway ──stdio──> github server
                            │                 └──> filesystem server
                            │                 └──> postgres server
                            ▼
                      lockfile + policy + one audit trail

WHAT THIS BUYS THAT PER-SERVER WRAPPING DOES NOT
------------------------------------------------
Tool names are namespaced `server__tool`. That is not cosmetic: two servers
offering `read_file` is MCPA027, and a scanner can only report it. Here the
collision cannot occur, because the names the model sees are distinct by
construction. Reporting a problem is worth less than making it impossible.

One audit trail covers the fleet, so "what did the agent do" is a question
with a single answer rather than eight files to correlate.

One policy file governs every server, and an unapproved server contributes
nothing at all rather than being a separate thing somebody forgot to wrap.

FAILURE POSTURE
---------------
Same as the guard, deliberately. A security event fails closed: an unapproved
server is not started, a drifted tool is withheld, a call outside policy is
refused. An operational failure fails open and loudly: a backend that will not
start is reported and the others carry on, because one broken server should
not take the agent's whole tool surface with it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auditlog import AuditLog
from .findings import Severity
from .guard import Guard
from .lifetime import bind_child, posix_preexec
from .lockfile import Lock
from .model import ServerSpec

PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "mcp-audit-gateway", "version": "0.1.0"}

# `server__tool`. Two underscores because single ones are common inside tool
# names and would make the split ambiguous.
SEPARATOR = "__"


@dataclass
class GatewayStats:
    backends_started: int = 0
    backends_failed: list[str] = field(default_factory=list)
    backends_refused: list[str] = field(default_factory=list)
    tools_exposed: int = 0
    tools_withheld: list[str] = field(default_factory=list)
    calls_forwarded: int = 0
    calls_refused: list[str] = field(default_factory=list)


class Backend:
    """One upstream server, with its own request id space.

    The gateway serves a single client over stdio, so requests arrive one at a
    time and a lock around the exchange is enough. Anything cleverer would be
    concurrency for its own sake.
    """

    def __init__(self, spec: ServerSpec, timeout: float = 30.0) -> None:
        self.spec = spec
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self.error: str | None = None
        self.tools: list[dict[str, Any]] = []
        self.instructions: str = ""
        self._id = 0
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return self.spec.name

    def start(self) -> bool:
        import os
        import shutil

        if not self.spec.command:
            self.error = "no command configured"
            return False

        exe = shutil.which(self.spec.command) or self.spec.command
        env = dict(os.environ)
        env.update(self.spec.env)
        env.setdefault("PYTHONUNBUFFERED", "1")

        try:
            self.proc = subprocess.Popen(
                [exe, *self.spec.args],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=env, text=True, encoding="utf-8", errors="replace", bufsize=1,
                preexec_fn=posix_preexec(),
            )
        except (OSError, ValueError) as exc:
            self.error = f"could not launch: {exc}"
            return False

        bind_child(self.proc)

        reply = self.request("initialize", {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-audit-gateway", "version": "0.1.0"},
        })
        if reply is None or "error" in reply:
            self.error = "did not answer initialize"
            return False
        self.instructions = str((reply.get("result") or {}).get("instructions") or "")
        self.notify("notifications/initialized", {})

        listed = self.request("tools/list", {})
        if listed and isinstance(listed.get("result"), dict):
            tools = listed["result"].get("tools")
            if isinstance(tools, list):
                self.tools = [t for t in tools if isinstance(t, dict)]
        return True

    def _send(self, message: dict[str, Any]) -> bool:
        if self.proc is None or self.proc.stdin is None:
            return False
        try:
            self.proc.stdin.write(json.dumps(message) + "\n")
            self.proc.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        """Send and wait for the matching reply, discarding notifications."""
        with self._lock:
            self._id += 1
            request_id = self._id
            if not self._send({"jsonrpc": "2.0", "id": request_id,
                               "method": method, "params": params}):
                return None
            if self.proc is None or self.proc.stdout is None:
                return None

            deadline = threading.Event()
            timer = threading.Timer(self.timeout, deadline.set)
            timer.daemon = True
            timer.start()
            try:
                while not deadline.is_set():
                    line = self.proc.stdout.readline()
                    if not line:
                        return None
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        continue      # banner text, which servers really emit
                    if isinstance(message, dict) and message.get("id") == request_id:
                        return message
                return None
            finally:
                timer.cancel()

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                self.proc.kill()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for stream in (self.proc.stdin, self.proc.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


class Gateway:
    """Fronts several backends, enforcing the lockfile across all of them."""

    def __init__(self, servers: list[ServerSpec], lock: Lock, *,
                 policy: str = "block", block_severity: Severity = Severity.CRITICAL,
                 allow_unapproved: bool = False, dry_run: bool = False,
                 quiet: bool = False, timeout: float = 30.0,
                 trail: AuditLog | None = None) -> None:
        self.lock = lock
        self.quiet = quiet
        self.trail = trail
        self.stats = GatewayStats()
        self.backends: dict[str, Backend] = {}
        self.guards: dict[str, Guard] = {}

        for spec in servers:
            if spec.disabled:
                continue
            guard = Guard(spec.identity(), lock, policy=policy, quiet=True,
                          block_severity=block_severity,
                          allow_unapproved=allow_unapproved, dry_run=dry_run)
            # An unapproved server is not started at all. Withholding its tools
            # after paying to run it would be theatre -- the process is the
            # thing that reads your files.
            if guard._locked_tools is None and not allow_unapproved:
                self.stats.backends_refused.append(spec.identity())
                self.log(f"not started: {spec.identity()} is not in the lockfile. "
                         f"Run `mcp-audit approve --probe`, or pass "
                         f"--allow-unapproved.")
                continue
            self.backends[spec.name] = Backend(spec, timeout=timeout)
            self.guards[spec.name] = guard

    def log(self, message: str) -> None:
        if not self.quiet:
            print(f"mcp-audit gateway: {message}", file=sys.stderr)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        for name, backend in list(self.backends.items()):
            if backend.start():
                self.stats.backends_started += 1
                self.log(f"started {backend.spec.identity()} "
                         f"({len(backend.tools)} tool(s) offered)")
                if self.trail:
                    self.trail.record("backend_started", subject=backend.spec.identity())
            else:
                # Operational failure: report it and carry on. One broken
                # server should not remove the agent's whole tool surface.
                self.stats.backends_failed.append(f"{name}: {backend.error}")
                self.log(f"could not start {name}: {backend.error}")
                if self.trail:
                    self.trail.record("backend_failed", subject=name,
                                      detail=str(backend.error)[:120])
                backend.close()
                self.backends.pop(name, None)

    def close(self) -> None:
        for backend in self.backends.values():
            backend.close()

    # -- the aggregated surface -------------------------------------------

    def aggregate_tools(self) -> list[dict[str, Any]]:
        """Every approved tool, namespaced so two servers cannot collide.

        MCPA027 exists because two servers offering `read_file` leave the
        model guessing. A scanner can only report that. Here the names are
        distinct by construction, so the ambiguity has nowhere to occur.
        """
        out: list[dict[str, Any]] = []
        for name, backend in self.backends.items():
            guard = self.guards[name]
            screened = guard.filter_tools([dict(t) for t in backend.tools])
            for tool in screened:
                raw = str(tool.get("name") or "")
                if not raw:
                    continue
                if "BLOCKED BY mcp-audit" in str(tool.get("description") or ""):
                    self.stats.tools_withheld.append(f"{name}{SEPARATOR}{raw}")
                tool["name"] = f"{name}{SEPARATOR}{raw}"
                out.append(tool)
        self.stats.tools_exposed = len(out)
        return out

    def split_name(self, namespaced: str) -> tuple[str, str] | None:
        """`server__tool` back into its parts, longest server name first."""
        for name in sorted(self.backends, key=len, reverse=True):
            prefix = name + SEPARATOR
            if namespaced.startswith(prefix):
                return name, namespaced[len(prefix):]
        return None

    # -- request handling --------------------------------------------------

    def _error(self, request_id: Any, text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id,
                "result": {"content": [{"type": "text", "text": text}],
                           "isError": True}}

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = str(message.get("method") or "")
        request_id = message.get("id")

        if method == "initialize":
            return {"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            }}
        if method == "server/discover":
            return {"jsonrpc": "2.0", "id": request_id, "result": {
                "serverInfo": SERVER_INFO,
                "capabilities": {"tools": {}},
                "supportedVersions": [PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
            }}
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": {"tools": self.aggregate_tools()}}

        if method == "tools/call":
            return self.handle_call(message)

        if request_id is None:
            return None
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32601, "message": f"method not found: {method}"}}

    def handle_call(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id = message.get("id")
        params = message.get("params")
        if not isinstance(params, dict):
            return self._error(request_id, "[mcp-audit] malformed tools/call")

        namespaced = str(params.get("name") or "")
        split = self.split_name(namespaced)
        if split is None:
            self.stats.calls_refused.append(namespaced)
            return self._error(request_id, (
                f"[BLOCKED BY mcp-audit] no approved server offers "
                f"{namespaced!r}. Tool names here are prefixed with the server "
                f"they belong to."))

        name, tool = split
        backend, guard = self.backends[name], self.guards[name]

        # The guard's own checks, on the un-namespaced call it expects.
        inner = dict(message)
        inner["params"] = dict(params, name=tool)
        refusal = guard.check_call(inner)
        if refusal is not None:
            self.stats.calls_refused.append(namespaced)
            if self.trail:
                self.trail.record("denied", subject=namespaced, decision="block")
            refusal["id"] = request_id
            return refusal

        if self.trail:
            arguments = params.get("arguments")
            detail = ""
            if arguments is not None:
                try:
                    detail = f"argument_bytes={len(json.dumps(arguments))}"
                except (TypeError, ValueError):
                    detail = "argument_bytes=?"
            self.trail.record("request", subject=namespaced, detail=detail)

        reply = backend.request("tools/call", inner["params"])
        if reply is None:
            return self._error(request_id, (
                f"[mcp-audit] {name} did not answer. The gateway is still up; "
                f"other servers are unaffected."))

        self.stats.calls_forwarded += 1
        result = reply.get("result")
        if isinstance(result, dict):
            reply["result"] = guard.screen_result_text(result)
        reply["id"] = request_id
        return reply

    def summary(self) -> str:
        s = self.stats
        bits = [f"{s.backends_started} backend(s)", f"{s.tools_exposed} tool(s)"]
        if s.backends_refused:
            bits.append(f"{len(s.backends_refused)} unapproved and not started")
        if s.backends_failed:
            bits.append(f"{len(s.backends_failed)} failed to start")
        if s.tools_withheld:
            bits.append(f"{len(s.tools_withheld)} tool(s) withheld")
        if s.calls_forwarded:
            bits.append(f"{s.calls_forwarded} call(s) forwarded")
        if s.calls_refused:
            bits.append(f"{len(s.calls_refused)} call(s) refused")
        return ", ".join(bits)


def run(servers: list[ServerSpec], lock_path: Path, *, policy: str = "block",
        allow_unapproved: bool = False, dry_run: bool = False, quiet: bool = False,
        timeout: float = 30.0, log_path: Path | None = None) -> int:
    """Serve the gateway on stdio until the client goes away."""
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-audit gateway: {exc}", file=sys.stderr)
        return 2

    trail = None
    if log_path is not None:
        trail = AuditLog(log_path, "gateway")
        if trail.failed:
            print(f"mcp-audit gateway: audit log unavailable: {trail.failed}",
                  file=sys.stderr)
            trail = None
        else:
            trail.record("session_start", subject="gateway", detail=f"policy={policy}")

    gateway = Gateway(servers, lock, policy=policy, allow_unapproved=allow_unapproved,
                      dry_run=dry_run, quiet=quiet, timeout=timeout, trail=trail)
    if not gateway.backends:
        print("mcp-audit gateway: nothing approved to serve. Run "
              "`mcp-audit approve --probe` first, or pass --allow-unapproved.",
              file=sys.stderr)
        return 2

    gateway.start()
    if not gateway.backends:
        print("mcp-audit gateway: no backend started successfully.", file=sys.stderr)
        gateway.close()
        return 2

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            try:
                reply = gateway.handle(message)
            except Exception as exc:          # never take the agent down
                gateway.log(f"INTERNAL ERROR: {exc}")
                reply = gateway._error(message.get("id"),
                                       f"[mcp-audit] internal error: {exc}")
            if reply is not None:
                sys.stdout.write(json.dumps(reply) + "\n")
                sys.stdout.flush()
    except (OSError, ValueError) as exc:
        gateway.log(f"transport error: {exc}")
    finally:
        if trail:
            trail.record("session_end", detail=gateway.summary())
        gateway.log(gateway.summary())
        gateway.close()
    return 0
