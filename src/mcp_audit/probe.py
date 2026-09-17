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
from dataclasses import dataclass
from typing import Any

from .model import ServerSpec, ToolSpec

PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "mcp-audit", "version": "0.1.0"}


@dataclass
class ProbeResult:
    server: str
    tools: list[ToolSpec]
    error: str | None = None


def _initialize_params() -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": CLIENT_INFO,
    }


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
                description=str(t.get("description") or ""),
                input_schema=t.get("inputSchema") or t.get("input_schema") or {},
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
    error: str | None = None

    def converse() -> None:
        nonlocal result, error
        assert proc.stdin is not None and proc.stdout is not None
        try:
            def send(msg: dict[str, Any]) -> None:
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()

            def read_reply(expect_id: int) -> dict[str, Any] | None:
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
                    if isinstance(msg, dict) and msg.get("id") == expect_id:
                        return msg

            send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": _initialize_params()})
            init = read_reply(1)
            if init is None:
                error = "server closed the connection during initialize"
                return
            if "error" in init:
                error = f"initialize failed: {init['error']}"
                return
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
    return ProbeResult(s.name, _parse_tools(s.name, result))


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
        return ProbeResult(s.name, _parse_tools(s.name, listed))
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
