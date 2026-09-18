"""Connect to configured servers and read back their advertised tools.

SAFETY
------
Probing a STDIO server means *launching it*. If the server is malicious, the
launch is the compromise -- before a single tool is called. That is an
uncomfortable property for a security scanner, so probing is opt-in
(`--probe`), never implied, and this module makes no attempt to pretend it is
safe. Static rules (MCPA001-009, MCPA013) run without it.

The honest tradeoff: tool descriptions are the highest-value thing to
inspect, and there is no way to read them from a STDIO server without running
it. Where that is unacceptable, run the scan against a remote endpoint, or
probe inside a sandbox, and rely on static rules everywhere else.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .model import PromptSpec, ResourceSpec, ServerSpec, ToolSpec

# The current protocol revision. Kept alongside the legacy one because the
# probe has to speak to both eras: everything published before 2026-07-28
# negotiates through an `initialize` handshake, and most servers in the wild
# still do.
PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "mcp-audit", "version": "0.1.0"}


@dataclass
class ProbeResult:
    server: str
    tools: list[ToolSpec]
    error: str | None = None
    # The server's `instructions` string from the initialize response. The
    # spec says it MAY be added to the system prompt, which makes it the
    # highest-privilege text a server controls.
    instructions: str = ""
    prompts: list[PromptSpec] = field(default_factory=list)
    resources: list[ResourceSpec] = field(default_factory=list)
    # "modern" (2026-07-28 per-request _meta) or "legacy" (initialize
    # handshake), decided by whether server/discover answered.
    protocol_era: str = "unknown"
    supported_versions: list[str] = field(default_factory=list)


def _modern_meta() -> dict[str, Any]:
    """`_meta` for a 2026-07-28 request, where version lives per request."""
    return {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _initialize_params() -> dict[str, Any]:
    return {
        "protocolVersion": LEGACY_PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": CLIENT_INFO,
    }


def _parse_prompts(server: str, payload: dict[str, Any]) -> list[PromptSpec]:
    out: list[PromptSpec] = []
    for p in (payload.get("result") or {}).get("prompts") or []:
        if isinstance(p, dict):
            args = p.get("arguments") or []
            out.append(PromptSpec(
                server=server, name=str(p.get("name") or ""),
                title=str(p.get("title") or ""),
                description=str(p.get("description") or ""),
                arguments=[a for a in args if isinstance(a, dict)],
            ))
    return out


def _parse_resources(server: str, payload: dict[str, Any]) -> list[ResourceSpec]:
    out: list[ResourceSpec] = []
    for r in (payload.get("result") or {}).get("resources") or []:
        if isinstance(r, dict):
            out.append(ResourceSpec(
                server=server,
                uri=str(r.get("uri") or r.get("uriTemplate") or ""),
                name=str(r.get("name") or ""),
                title=str(r.get("title") or ""),
                description=str(r.get("description") or ""),
                mime_type=str(r.get("mimeType") or ""),
                is_template="uriTemplate" in r,
            ))
    return out


def _parse_tools(server: str, payload: dict[str, Any]) -> list[ToolSpec]:
    tools = (payload.get("result") or {}).get("tools") or []
    out: list[ToolSpec] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        out.append(
            ToolSpec(
                server=server,
                name=str(t.get("name") or ""),
                title=str(t.get("title") or ""),
                description=str(t.get("description") or ""),
                input_schema=t.get("inputSchema") or t.get("input_schema") or {},
                annotations=t.get("annotations") or {},
            )
        )
    return out


# ---------------------------------------------------------------------------
# STDIO
# ---------------------------------------------------------------------------

def probe_stdio(s: ServerSpec, timeout: float = 20.0) -> ProbeResult:
    if not s.command:
        return ProbeResult(s.name, [], "no command configured")
    exe = shutil.which(s.command) or s.command
    env = dict(os.environ)
    env.update(s.env)
    # Servers commonly buffer stdout when they think they are not on a tty.
    env.setdefault("PYTHONUNBUFFERED", "1")

    try:
        proc = subprocess.Popen(
            [exe, *s.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except (OSError, ValueError) as exc:
        return ProbeResult(s.name, [], f"could not launch: {exc}")

    stderr_tail: list[str] = []

    def drain_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            stderr_tail.append(line.rstrip())
            del stderr_tail[:-10]

    drainer = threading.Thread(target=drain_stderr, daemon=True)
    drainer.start()

    result: dict[str, Any] = {}
    init_result: dict[str, Any] = {}
    discover_result: dict[str, Any] = {}
    prompts_result: dict[str, Any] = {}
    resources_result: dict[str, Any] = {}
    templates_result: dict[str, Any] = {}
    error: str | None = None

    def converse() -> None:
        nonlocal result, error, init_result, prompts_result, resources_result
        nonlocal discover_result, templates_result
        assert proc.stdin is not None and proc.stdout is not None
        try:
            def send(msg: dict[str, Any]) -> None:
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()

            # Replies can arrive out of order once requests are pipelined, so
            # anything not being waited on is kept rather than dropped. The
            # earlier version discarded non-matching messages, which meant
            # waiting on the discover reply would silently eat the initialize
            # reply and then block until the whole probe timed out.
            pending: dict[Any, dict[str, Any]] = {}

            def read_reply(expect_id: Any) -> dict[str, Any] | None:
                if expect_id in pending:
                    return pending.pop(expect_id)
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        return None
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # servers sometimes emit banner text on stdout
                    if not isinstance(msg, dict) or "id" not in msg:
                        continue  # a notification, not a reply we asked for
                    if msg.get("id") == expect_id:
                        return msg
                    pending[msg["id"]] = msg

            # Era probe. The current protocol (2026-07-28) replaced the
            # initialize handshake with per-request `_meta` and a mandatory
            # `server/discover`. The spec's stdio backward-compatibility rules
            # say a dual-era client SHOULD send server/discover first, and
            # MUST NOT key the legacy fallback to one error code, since legacy
            # servers answer an unknown pre-initialize request with whatever
            # they like -- or with nothing at all.
            #
            # Both probes are pipelined rather than waiting on a timeout to
            # decide. A modern server answers discover; a legacy one errors or
            # ignores it and answers initialize. One round trip covers both,
            # and the "no response" case needs no special handling because the
            # initialize reply still arrives.
            def read_any(expected: set) -> dict[str, Any] | None:
                """First reply matching any of `expected`; the rest are buffered."""
                for known in expected:
                    if known in pending:
                        return pending.pop(known)
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        return None
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(msg, dict) or "id" not in msg:
                        continue
                    if msg.get("id") in expected:
                        return msg
                    pending[msg["id"]] = msg

            send({"jsonrpc": "2.0", "id": 0, "method": "server/discover",
                  "params": {"_meta": _modern_meta()}})
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": _initialize_params()})

            # Resolve on whichever answer arrives first. Waiting on one
            # specific id deadlocks against a server that answers only the
            # other -- a modern server never replies to `initialize`, and a
            # legacy one may ignore `server/discover` outright.
            first = read_any({0, 1})
            if first is None:
                error = "server closed the connection during the era probe"
                return

            if first.get("id") == 0 and isinstance(first.get("result"), dict):
                discover_result = first
                init_result = first          # instructions live here in this era
            else:
                # Either initialize answered first, or discover errored. Both
                # mean the legacy handshake is the path; the spec is explicit
                # that the fallback must not be keyed to one error code.
                init = first if first.get("id") == 1 else read_reply(1)
                if init is None:
                    error = "server closed the connection during initialize"
                    return
                if "error" in init:
                    error = f"initialize failed: {init['error']}"
                    return
                init_result = init
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            listed = read_reply(2)
            if listed is None:
                error = "server closed the connection during tools/list"
                return
            if "error" in listed:
                error = f"tools/list failed: {listed['error']}"
                return
            result = listed

            # Ask for prompts and resources only where the server said it has
            # them. Calling an unsupported method returns an error the server
            # is entitled to send, and treating that as a probe failure would
            # make well-behaved servers look broken.
            source = discover_result or init or {}
            caps = (source.get("result") or {}).get("capabilities") or {}
            if isinstance(caps, dict):
                if isinstance(caps.get("prompts"), dict):
                    send({"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}})
                    reply = read_reply(3)
                    if reply and "error" not in reply:
                        prompts_result = reply
                if isinstance(caps.get("resources"), dict):
                    send({"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}})
                    reply = read_reply(4)
                    if reply and "error" not in reply:
                        resources_result = reply
                    # Templates are a separate list with the same shape. A
                    # server can put all of its text there and none in
                    # resources/list, so asking for only one reads half.
                    send({"jsonrpc": "2.0", "id": 5,
                          "method": "resources/templates/list", "params": {}})
                    reply = read_reply(5)
                    if reply and "error" not in reply:
                        templates_result = reply
        except (OSError, ValueError) as exc:
            error = f"transport error: {exc}"

    worker = threading.Thread(target=converse, daemon=True)
    worker.start()
    worker.join(timeout)

    timed_out = worker.is_alive()
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    # Close the pipes explicitly. A scan probes every configured server in
    # turn, so leaked descriptors accumulate across a run rather than being
    # reclaimed between them.
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass

    if timed_out:
        detail = f"; stderr: {stderr_tail[-1]}" if stderr_tail else ""
        return ProbeResult(s.name, [], f"timed out after {timeout:.0f}s{detail}")
    if error:
        detail = f"; stderr: {stderr_tail[-1]}" if stderr_tail else ""
        return ProbeResult(s.name, [], f"{error}{detail}")
    return ProbeResult(
        s.name,
        _parse_tools(s.name, result),
        instructions=str((init_result.get("result") or {}).get("instructions") or ""),
        prompts=_parse_prompts(s.name, prompts_result),
        resources=(_parse_resources(s.name, resources_result)
                   + _parse_resources(s.name, templates_result)),
        protocol_era="modern" if discover_result else "legacy",
        supported_versions=[
            str(v) for v in
            ((discover_result.get("result") or {}).get("supportedVersions") or [])
        ],
    )


# ---------------------------------------------------------------------------
# HTTP / SSE
# ---------------------------------------------------------------------------

def _post_jsonrpc(url: str, headers: dict[str, str], payload: dict[str, Any],
                  timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-supplied URL by design
        raw = resp.read().decode("utf-8", errors="replace")
    raw = raw.strip()
    if raw.startswith("event:") or raw.startswith("data:"):
        # Server-sent events framing: take the last data: payload.
        chunks = [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")]
        raw = chunks[-1] if chunks else "{}"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def probe_http(s: ServerSpec, timeout: float = 20.0) -> ProbeResult:
    if not s.url:
        return ProbeResult(s.name, [], "no url configured")
    try:
        init = _post_jsonrpc(
            s.url, s.headers,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": _initialize_params()},
            timeout,
        )
        if "error" in init:
            return ProbeResult(s.name, [], f"initialize failed: {init['error']}")
        listed = _post_jsonrpc(
            s.url, s.headers,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            timeout,
        )
        if "error" in listed:
            return ProbeResult(s.name, [], f"tools/list failed: {listed['error']}")

        caps = (init.get("result") or {}).get("capabilities") or {}
        prompts_payload: dict[str, Any] = {}
        resources_payload: dict[str, Any] = {}
        if isinstance(caps, dict):
            if isinstance(caps.get("prompts"), dict):
                reply = _post_jsonrpc(s.url, s.headers,
                                      {"jsonrpc": "2.0", "id": 3, "method": "prompts/list",
                                       "params": {}}, timeout)
                if "error" not in reply:
                    prompts_payload = reply
            if isinstance(caps.get("resources"), dict):
                reply = _post_jsonrpc(s.url, s.headers,
                                      {"jsonrpc": "2.0", "id": 4, "method": "resources/list",
                                       "params": {}}, timeout)
                if "error" not in reply:
                    resources_payload = reply

        return ProbeResult(
            s.name,
            _parse_tools(s.name, listed),
            instructions=str((init.get("result") or {}).get("instructions") or ""),
            prompts=_parse_prompts(s.name, prompts_payload),
            resources=_parse_resources(s.name, resources_payload),
        )
    except urllib.error.HTTPError as exc:
        return ProbeResult(s.name, [], f"HTTP {exc.code} {exc.reason}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return ProbeResult(s.name, [], f"connection failed: {exc}")


def probe(servers: list[ServerSpec], *, timeout: float = 20.0,
          allow_stdio: bool = True, verbose: bool = False) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for s in servers:
        if s.disabled:
            continue
        if verbose:
            print(f"  probing {s.identity()} ...", file=sys.stderr)
        if s.is_remote:
            results.append(probe_http(s, timeout))
        elif allow_stdio:
            results.append(probe_stdio(s, timeout))
        else:
            results.append(ProbeResult(s.name, [], "stdio probing disabled"))
    return results
