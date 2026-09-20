"""One endpoint in front of every approved MCP server.

`guard` wraps a single server. That is the right shape for one connection and
the wrong shape for a machine, because an agent does not have one server -- it
has eight, from three different publishers, and the interesting properties are
the ones that only exist across the whole set.

The gateway is one MCP server that the client points at instead. Behind it sit
every approved server from the lockfile, started as children, and every call
passes through the same enforcement `guard` already applies:

    client ──stdio──> mcp-pin gateway ──stdio──> github server
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
from .childenv import build as build_env
from .childenv import notable
from .findings import Severity
from .guard import Guard
from .identity import Identity, UnknownIdentity
from .lifetime import bind_child, posix_preexec
from .lockfile import Lock
from .model import ServerSpec

PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "mcp-pin-gateway", "version": "0.1.0"}

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
    calls_over_budget: list[str] = field(default_factory=list)
    client_announced: str = ""


class Backend:
    """One upstream server, with its own request id space.

    The gateway serves a single client over stdio, so requests arrive one at a
    time and a lock around the exchange is enough. Anything cleverer would be
    concurrency for its own sake.
    """

    def __init__(self, spec: ServerSpec, timeout: float = 30.0, *,
                 isolate_env: bool = True, share_env: set | None = None) -> None:
        self.spec = spec
        self.timeout = timeout
        self.isolate_env = isolate_env
        self.share_env = share_env or set()
        self.withheld: list = []
        self.proc: subprocess.Popen | None = None
        self.error: str | None = None
        self.tools: list[dict[str, Any]] = []
        self.instructions: str = ""
        # Called with (server_name, message) for anything that is not the
        # reply being waited on. Returns a message to send back, or None.
        self.on_unsolicited: Any = None
        self.recorded_artifacts: dict[str, str] = {}
        self.approved_launch: str = ""
        self.recorded_integrity: dict[str, str] = {}
        self.artifact_urls: dict[str, str] = {}
        self.require_integrity: bool = False
        self._id = 0
        self._lock = threading.Lock()
        self.needs_refresh = False

    @property
    def name(self) -> str:
        return self.spec.name

    def start(self) -> bool:
        import os
        import shutil

        from .artifacts import mismatch
        from .lockfile import launch_mismatch
        from .pkgcache import refusal

        # Offline, and on the launch path on purpose: the registry answer is
        # a scan-time opinion, while the package cache holds the bytes this
        # spawn is about to run.
        reason = (mismatch(self.recorded_artifacts)
                  or launch_mismatch(self.approved_launch, self.spec.argv)
                  or refusal(self.recorded_integrity, self.artifact_urls,
                             require=self.require_integrity))
        if reason:
            self.error = reason
            return False

        if not self.spec.command:
            self.error = "no command configured"
            return False

        exe = shutil.which(self.spec.command) or self.spec.command
        # A backend gets what it declared plus the infrastructure it needs to
        # run, and not every other server's credentials. See childenv.
        env, self.withheld = build_env(self.spec, share=self.share_env,
                                       isolate=self.isolate_env)

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
            "clientInfo": {"name": "mcp-pin-gateway", "version": "0.1.0"},
        })
        if reply is None or "error" in reply:
            self.error = "did not answer initialize"
            return False
        self.instructions = str((reply.get("result") or {}).get("instructions") or "")
        self.notify("notifications/initialized", {})

        listed = self.request("tools/list", {})
        self._adopt_tools(listed)
        return True

    def _adopt_tools(self, listed: dict[str, Any] | None) -> None:
        if listed and isinstance(listed.get("result"), dict):
            tools = listed["result"].get("tools")
            if isinstance(tools, list):
                self.tools = [t for t in tools if isinstance(t, dict)]

    def refresh_tools(self) -> None:
        """Re-read tools/list after the server said the catalogue changed.

        Must not run from inside request()'s wait loop: that holds _lock.
        The flag is set there; the next tools/list or call pulls.
        """
        if not self.needs_refresh:
            return
        self.needs_refresh = False
        self._adopt_tools(self.request("tools/list", {}))

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
        """Send and wait for the matching reply.

        Anything arriving that is not the reply goes to `on_unsolicited` --
        server-initiated requests and notifications both. This used to discard
        them, which fails closed and also meant a server asking to run a
        completion, or announcing that its tool list just changed, left no
        trace at all.
        """
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
                    if not isinstance(message, dict):
                        continue
                    if message.get("id") == request_id:
                        return message
                    if self.on_unsolicited is not None:
                        answer = self.on_unsolicited(self.name, message)
                        if answer is not None:
                            self._send(answer)
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
                 trail: AuditLog | None = None,
                 identity: Identity | None = None,
                 max_calls: int = 0,
                 deny_sampling: bool = False,
                 deny_elicitation: bool = False,
                 isolate_env: bool = True,
                 share_env: set | None = None,
                 require_integrity: bool = False) -> None:
        self.lock = lock
        self.quiet = quiet
        self.trail = trail
        self.identity = identity
        self.max_calls = max_calls
        self.dry_run = dry_run
        self.stats = GatewayStats()
        self.backends: dict[str, Backend] = {}
        self.guards: dict[str, Guard] = {}
        self._calls: dict[str, int] = {}

        for spec in servers:
            if spec.disabled:
                continue
            if identity is not None and not identity.may_use_server(spec.name):
                # Not "started and then hidden". An identity that may not use a
                # server should not cause that server's process to exist.
                self.stats.backends_refused.append(
                    f"{spec.identity()} (not granted to {identity.name})")
                continue
            guard = Guard(spec.identity(), lock, policy=policy, quiet=True,
                          block_severity=block_severity,
                          allow_unapproved=allow_unapproved, dry_run=dry_run,
                          deny_sampling=deny_sampling,
                          deny_elicitation=deny_elicitation)
            # An unapproved server is not started at all. Withholding its tools
            # after paying to run it would be theatre -- the process is the
            # thing that reads your files.
            if guard._locked_tools is None and not allow_unapproved:
                self.stats.backends_refused.append(spec.identity())
                self.log(f"not started: {spec.identity()} is not in the lockfile. "
                         f"Run `mcp-pin approve --probe`, or pass "
                         f"--allow-unapproved.")
                continue
            backend = Backend(spec, timeout=timeout,
                              isolate_env=isolate_env,
                              share_env=share_env)
            entry = guard._resolve_entry() or {}
            recorded = entry.get("artifacts")
            backend.recorded_artifacts = recorded if isinstance(recorded, dict) else {}
            backend.approved_launch = str(entry.get("command_line") or "")
            integrity = entry.get("integrity")
            backend.recorded_integrity = integrity if isinstance(integrity, dict) else {}
            urls = entry.get("artifact_urls")
            backend.artifact_urls = urls if isinstance(urls, dict) else {}
            backend.require_integrity = require_integrity
            backend.on_unsolicited = self.screen_server_message
            if spec.name in self.backends:
                other = self.backends[spec.name].spec.identity()
                self.stats.backends_refused.append(spec.identity())
                self.log(
                    f"not started: {spec.identity()} shares the name {spec.name!r} "
                    f"with {other}. Two clients configuring the same name are not "
                    f"the same server; guessing which is which is how one client's "
                    f"approvals get enforced against the other's."
                )
                continue
            self.backends[spec.name] = backend
            self.guards[spec.name] = guard

    def log(self, message: str) -> None:
        if not self.quiet:
            print(f"mcp-pin gateway: {message}", file=sys.stderr)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self.identity is not None:
            scope = ("every approved server" if self.identity.servers is None
                     else ", ".join(self.identity.servers) or "no servers")
            self.log(f"acting as {self.identity.name!r}: {scope}")
        for name, backend in list(self.backends.items()):
            if backend.start():
                self.stats.backends_started += 1
                self.log(f"started {backend.spec.identity()} "
                         f"({len(backend.tools)} tool(s) offered)")
                # Naming the credential-shaped variables it did not get. A
                # server that stops authenticating after this lands is looking
                # for one of these, and one stderr line is the difference
                # between a one-line fix and an afternoon.
                hidden = notable(backend.withheld)
                if hidden:
                    self.log(f"  {name}: not given {', '.join(hidden[:6])}"
                             f"{' and %d more' % (len(hidden) - 6) if len(hidden) > 6 else ''}"
                             f" -- declare it in the server's env, or pass "
                             f"--share-env NAME")
                if self.trail:
                    self.trail.record("backend_started", subject=backend.spec.identity(),
                                      detail=f"withheld={len(backend.withheld)}")
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
            pull = getattr(backend, "refresh_tools", None)
            if callable(pull):
                pull()
            guard = self.guards[name]
            screened = guard.filter_tools([dict(t) for t in backend.tools])
            for tool in screened:
                raw = str(tool.get("name") or "")
                if not raw:
                    continue
                namespaced = f"{name}{SEPARATOR}{raw}"
                if self.identity is not None and \
                        self.identity.denies_tool(namespaced, raw):
                    self.stats.tools_withheld.append(namespaced)
                    continue
                if "BLOCKED BY mcp-pin" in str(tool.get("description") or ""):
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
            # Recorded, never trusted. The client chooses this string, so it
            # identifies nothing; authority comes from --as and the lockfile.
            info = (message.get("params") or {}).get("clientInfo")
            if isinstance(info, dict):
                announced = str(info.get("name") or "")[:80]
                self.stats.client_announced = announced
                if self.trail and announced:
                    self.trail.record("client_announced", subject=announced,
                                      detail="self-declared, not authenticated")
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
            return self._error(request_id, "[mcp-pin] malformed tools/call")

        namespaced = str(params.get("name") or "")
        split = self.split_name(namespaced)
        if split is None:
            self.stats.calls_refused.append(namespaced)
            return self._error(request_id, (
                f"[BLOCKED BY mcp-pin] no approved server offers "
                f"{namespaced!r}. Tool names here are prefixed with the server "
                f"they belong to."))

        name, tool = split
        backend, guard = self.backends[name], self.guards[name]
        pull = getattr(backend, "refresh_tools", None)
        if callable(pull):
            pull()
            guard.filter_tools([dict(t) for t in backend.tools])

        if self.identity is not None:
            if self.identity.denies_tool(namespaced, tool):
                self.stats.calls_refused.append(namespaced)
                if self.trail:
                    self.trail.record("denied", subject=namespaced,
                                      decision="block",
                                      detail=f"identity={self.identity.name}")
                return self._error(request_id, (
                    f"[BLOCKED BY mcp-pin] {namespaced} is not available to "
                    f"{self.identity.name!r}. The lockfile grants this agent a "
                    f"narrower surface than the server offers."))

            extra = self.identity.policy_for(namespaced, tool)
            if extra:
                decision = extra.check(tool, params.get("arguments"))
                if not decision.allowed:
                    self.stats.calls_refused.append(namespaced)
                    if self.trail:
                        self.trail.record("denied", subject=namespaced,
                                          decision="block",
                                          detail=f"identity={self.identity.name}")
                    return self._error(request_id, (
                        f"[BLOCKED BY mcp-pin] {namespaced} was not called. "
                        f"{decision.reason}. This limit belongs to "
                        f"{self.identity.name!r} and is narrower than the "
                        f"server's own."))

        if self.max_calls:
            used = self._calls.get(namespaced, 0)
            if used >= self.max_calls:
                self.stats.calls_over_budget.append(namespaced)
                if self.trail:
                    self.trail.record("budget_exhausted", subject=namespaced,
                                      decision="block")
                if not self.dry_run:
                    return self._error(request_id, (
                        f"[BLOCKED BY mcp-pin] {namespaced} has been called "
                        f"{used} times this session and the budget is "
                        f"{self.max_calls}. A tool that suddenly runs in a loop "
                        f"is usually an agent that has lost the plot, and the "
                        f"budget is there to bound the damage rather than to "
                        f"judge the call."))
            self._calls[namespaced] = used + 1

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
                f"[mcp-pin] {name} did not answer. The gateway is still up; "
                f"other servers are unaffected."))

        self.stats.calls_forwarded += 1
        result = reply.get("result")
        if isinstance(result, dict):
            # Both screens, and both are load-bearing. `screen_result_text`
            # reads what the server said; `screen_input_required` reads what
            # it is asking the *client* to do -- which, since MRTR, arrives
            # inside the result rather than as a separate request. Calling
            # only the first left a server on the current protocol able to ask
            # the user for a credential through the client's own dialog with
            # nothing in the way, which the guard has screened since it
            # learned about MRTR and this did not.
            reply["result"] = guard.screen_input_required(
                guard.screen_result_text(result))
        reply["id"] = request_id
        return reply

    def screen_server_message(self, name: str, message: dict[str, Any]) -> dict | None:
        """Screen something a backend sent that was not a reply.

        Returns a message to send *back to that server*, or None to send
        nothing. Two kinds arrive here.

        A server-initiated request -- `sampling/createMessage` asks the client
        to run a completion on the user's model and the user's bill;
        `elicitation/create` asks it to collect input from the user, which is
        the shape of a credential phish wearing the client's own dialog.
        Neither is illegitimate, so the default is to allow and record. What
        matters is that they stop being invisible, and the gateway's read loop
        was dropping them on the floor -- which fails closed and also leaves
        no trace that a server ever asked.

        A notification -- `notifications/tools/list_changed` and its siblings.
        A notification has no id, so it is never answered; the point is that
        the one moment a rug pull announces itself is written down instead of
        passing in silence.
        """
        guard = self.guards.get(name)
        if guard is None:
            return None

        method = str(message.get("method") or "")
        if method in guard.LIST_CHANGED:
            guard.note_notification(message)
            if self.trail:
                self.trail.record("list_changed", subject=name, detail=method)
            self.log(f"{name}: {method} -- the server says its catalogue changed")
            if method == "notifications/tools/list_changed":
                backend = self.backends.get(name)
                if backend is not None:
                    backend.needs_refresh = True
            return None

        if "id" not in message:
            return None      # some other notification; nothing to decide

        if not guard.screen_server_request(message):
            if self.trail:
                self.trail.record("denied", subject=f"{name}:{method}",
                                  decision="block")
            self.log(f"{name}: DENIED {method}")
            denial = guard.deny_response(message)
            # The server is waiting on *its* id. An error carrying any other
            # one leaves it waiting forever, which is a hang and not a refusal.
            denial["id"] = message.get("id")
            return denial

        if self.trail:
            self.trail.record("server_request", subject=f"{name}:{method}")
        return None

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
        if s.calls_over_budget:
            bits.append(f"{len(s.calls_over_budget)} over budget")
        return ", ".join(bits)


def _one_reply(gateway: "Gateway", message: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return gateway.handle(message)
    except Exception as exc:          # never take the agent down
        gateway.log(f"INTERNAL ERROR: {exc}")
        return gateway._error(message.get("id"),
                              f"[mcp-pin] internal error: {exc}")


def _replies_for(gateway: "Gateway", payload: Any) -> Any:
    if isinstance(payload, dict):
        return _one_reply(gateway, payload)
    if not isinstance(payload, list):
        return None
    out = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        reply = _one_reply(gateway, item)
        if reply is not None:
            out.append(reply)
    return out or None


def run(servers: list[ServerSpec], lock_path: Path, *, policy: str = "block",
        allow_unapproved: bool = False, dry_run: bool = False, quiet: bool = False,
        timeout: float = 30.0, log_path: Path | None = None,
        act_as: str | None = None, max_calls: int = 0,
        deny_sampling: bool = False, deny_elicitation: bool = False,
        isolate_env: bool = True, share_env: set | None = None,
        require_integrity: bool = False) -> int:
    """Serve the gateway on stdio until the client goes away."""
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-pin gateway: {exc}", file=sys.stderr)
        return 2

    identity = None
    if act_as:
        try:
            identity = Identity.from_lock(lock, act_as)
        except UnknownIdentity as exc:
            print(f"mcp-pin gateway: {exc}", file=sys.stderr)
            return 2

    trail = None
    if log_path is not None:
        trail = AuditLog(log_path, "gateway")
        if trail.failed:
            print(f"mcp-pin gateway: audit log unavailable: {trail.failed}",
                  file=sys.stderr)
            trail = None
        else:
            trail.record("session_start", subject=act_as or "gateway",
                         detail=f"policy={policy} budget={max_calls or 'none'}")

    gateway = Gateway(servers, lock, policy=policy, allow_unapproved=allow_unapproved,
                      dry_run=dry_run, quiet=quiet, timeout=timeout, trail=trail,
                      identity=identity, max_calls=max_calls,
                      deny_sampling=deny_sampling,
                      deny_elicitation=deny_elicitation,
                      isolate_env=isolate_env, share_env=share_env,
                      require_integrity=require_integrity)
    if not gateway.backends:
        print("mcp-pin gateway: nothing approved to serve. Run "
              "`mcp-pin approve --probe` first, or pass --allow-unapproved.",
              file=sys.stderr)
        return 2

    gateway.start()
    if not gateway.backends:
        print("mcp-pin gateway: no backend started successfully.", file=sys.stderr)
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
            replies = _replies_for(gateway, message)
            if replies is None:
                continue
            sys.stdout.write(json.dumps(replies) + "\n")
            sys.stdout.flush()
    except (OSError, ValueError) as exc:
        gateway.log(f"transport error: {exc}")
    finally:
        if trail:
            trail.record("session_end", detail=gateway.summary())
        gateway.log(gateway.summary())
        gateway.close()
    return 0
