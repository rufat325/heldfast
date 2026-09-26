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

from .childenv import build as build_child_env
from .fetch import USER_AGENT
from .fetch import urlopen as fetch_url
from .lifetime import bind_child, posix_preexec
from .model import PromptSpec, ResourceSpec, ServerSpec, ToolSpec

# The current protocol revision. Kept alongside the legacy one because the
# probe has to speak to both eras: everything published before 2026-07-28
# negotiates through an `initialize` handshake, and most servers in the wild
# still do.
PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "heldfast", "version": "0.1.0"}


def _obs_id(s: ServerSpec) -> str:
    """Key observations under client:name. The bare name is not unique."""
    return s.identity()


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
                icons=_icons(p.get("icons")),
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
                icons=_icons(r.get("icons")),
            ))
    return out


def _icons(raw: Any) -> list[dict[str, Any]]:
    """Icons as declared, or an empty list.

    Kept as raw dicts like `annotations` is: the interesting part is the `src`
    the client will fetch, and normalising past it would lose exactly what
    MCPA033 reads.
    """
    if not isinstance(raw, list):
        return []
    return [i for i in raw if isinstance(i, dict)]


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
                output_schema=t.get("outputSchema") or t.get("output_schema") or {},
                annotations=t.get("annotations") or {},
                icons=_icons(t.get("icons")),
            )
        )
    return out


# ---------------------------------------------------------------------------
# STDIO
# ---------------------------------------------------------------------------

def probe_stdio(s: ServerSpec, timeout: float = 20.0,
                share_env: set | None = None) -> ProbeResult:
    if not s.command:
        return ProbeResult(_obs_id(s), [], "no command configured")
    exe = shutil.which(s.command) or s.command
    # A server being probed gets what it declared and the infrastructure it
    # needs to run -- not every token on the machine.
    #
    # This matters more here than at the gateway. The gateway starts servers
    # that were approved; probing is the operation that launches code *before*
    # anyone has reviewed it, which is the whole reason it is opt-in. Handing
    # a config pasted from a README every secret in the environment, in order
    # to find out whether it is hostile, is the wrong order to do things in.
    env, _ = build_child_env(s, share=share_env)
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
            preexec_fn=posix_preexec(),
        )
    except (OSError, ValueError) as exc:
        return ProbeResult(_obs_id(s), [], f"could not launch: {exc}")

    bind_child(proc)

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
        return ProbeResult(_obs_id(s), [], f"timed out after {timeout:.0f}s{detail}")
    if error:
        detail = f"; stderr: {stderr_tail[-1]}" if stderr_tail else ""
        return ProbeResult(_obs_id(s), [], f"{error}{detail}")
    return ProbeResult(
        _obs_id(s),
        _parse_tools(_obs_id(s), result),
        instructions=str((init_result.get("result") or {}).get("instructions") or ""),
        prompts=_parse_prompts(_obs_id(s), prompts_result),
        resources=(_parse_resources(_obs_id(s), resources_result)
                   + _parse_resources(_obs_id(s), templates_result)),
        protocol_era="modern" if discover_result else "legacy",
        supported_versions=[
            str(v) for v in
            ((discover_result.get("result") or {}).get("supportedVersions") or [])
        ],
    )


# ---------------------------------------------------------------------------
# HTTP / SSE
# ---------------------------------------------------------------------------

SESSION_HEADER = "Mcp-Session-Id"


def post_rpc(url: str, headers: dict[str, str], payload: dict[str, Any],
             timeout: float) -> tuple[dict[str, Any], dict[str, str]]:
    """One JSON-RPC exchange over Streamable HTTP: (reply, response headers).

    Public because the gateway speaks to remote backends through it. Keeping
    one implementation matters more than the few lines it saves: the SSE
    framing below is the sort of thing that gets fixed in one copy and not the
    other, and this repo has already paid for a client and a server drifting
    apart on protocol detail.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if not any(k.lower() == "user-agent" for k in headers):
        req.add_header("User-Agent", USER_AGENT)
    for k, v in headers.items():
        req.add_header(k, v)
    # Not urllib's default opener: that one follows a redirect with the
    # Authorization header still attached, and onto cleartext. See fetch.py.
    with fetch_url(req, timeout) as resp:  # noqa: S310 - user-supplied URL by design
        raw = resp.read().decode("utf-8", errors="replace")
        got = {k: v for k, v in resp.headers.items()}
    raw = raw.strip()
    if raw.startswith("event:") or raw.startswith("data:"):
        # Server-sent events framing: take the last data: payload.
        chunks = [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")]
        raw = chunks[-1] if chunks else "{}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}, got
    return (parsed if isinstance(parsed, dict) else {}), got


def _post_jsonrpc(url: str, headers: dict[str, str], payload: dict[str, Any],
                  timeout: float) -> dict[str, Any]:
    return post_rpc(url, headers, payload, timeout)[0]


# What a 2026-07-28 request carries over HTTP beside the `_meta` in its body.
VERSION_HEADER = "MCP-Protocol-Version"


class HandshakeFailed(Exception):
    """The server answered, and refused to open a conversation."""


def http_handshake(url: str, headers: dict[str, str],
                   timeout: float) -> tuple[dict[str, Any], dict[str, str], str]:
    """Open a Streamable HTTP conversation in whichever era the server speaks.

    Returns (the handshake reply, the headers every later request needs,
    "modern" or "legacy"). Over HTTP each request is its own exchange, so the
    two eras cannot be pipelined the way stdio does. `server/discover` goes
    first, as the spec says a dual-era client should; anything short of a
    result -- an error object, an HTTP error status, a body that is not
    JSON-RPC -- falls back to `initialize`. The fallback is not keyed to one
    error code: a legacy server answers a method it does not know however it
    likes, often with 400 for want of a session. A connection that fails
    outright is not retried as legacy: a dead host is dead in both eras, and
    trying twice would only double the wait.
    """
    try:
        found, _ = post_rpc(url, headers, {"jsonrpc": "2.0", "id": 0, "method": "server/discover",
                                           "params": {"_meta": _modern_meta()}}, timeout)
    except urllib.error.HTTPError as exc:
        exc.close()
        found = {}
    if isinstance(found.get("result"), dict):
        onward = dict(headers)
        onward[VERSION_HEADER] = PROTOCOL_VERSION
        return found, onward, "modern"
    init, got = post_rpc(url, headers, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                        "params": _initialize_params()}, timeout)
    if "error" in init:
        raise HandshakeFailed(f"initialize failed: {init['error']}")
    # Streamable HTTP hands out a session on initialize and requires it on
    # everything after. Without this the probe worked against servers that
    # do not bother and failed on every server that does -- which reads as
    # "the endpoint is broken" and is the scanner's fault. Found when the
    # gateway gained the same transport and a stub enforced the rule.
    onward = dict(headers)
    onward.update({k: v for k, v in got.items() if k.lower() == SESSION_HEADER.lower() and v})
    return init, onward, "legacy"


def request_params(era: str) -> dict[str, Any]:
    """Params for a request after the handshake: 2026-07-28 carries its version
    on every request, the handshake era carried it once."""
    return {"_meta": _modern_meta()} if era == "modern" else {}


def _describe_connection_error(exc: Exception) -> str:
    """Describe a failed connection without blaming the wrong party.

    A TLS verification failure reads like the server's fault and often is not.
    Measured against 15 real public MCP endpoints, seven reported "certificate
    has expired" while every certificate in their chains was in date -- the
    local OpenSSL CA bundle was stale. Reporting that as a server problem
    would have been a false positive on nearly half of them, so the message
    names the other possibility explicitly.
    """
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "SSLCertVerificationError" in text:
        detail = text.split("certificate verify failed:", 1)[-1].strip(" )]'\"")
        return (
            f"TLS verification failed ({detail or 'no detail'}). This may be the server's "
            "certificate or a stale CA bundle on this machine -- check with `openssl "
            "s_client -connect HOST:443` before treating it as a server fault."
        )
    return f"connection failed: {exc}"


def probe_http(s: ServerSpec, timeout: float = 20.0) -> ProbeResult:
    if not s.url:
        return ProbeResult(_obs_id(s), [], "no url configured")
    try:
        init, onward, era = http_handshake(s.url, s.headers, timeout)
        listed = _post_jsonrpc(
            s.url, onward,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": request_params(era)},
            timeout,
        )
        if "error" in listed:
            return ProbeResult(_obs_id(s), [], f"tools/list failed: {listed['error']}")

        opened = init.get("result") or {}
        caps = opened.get("capabilities") or {}
        prompts_payload: dict[str, Any] = {}
        resources_payload: dict[str, Any] = {}
        if isinstance(caps, dict):
            if isinstance(caps.get("prompts"), dict):
                reply = _post_jsonrpc(s.url, onward,
                                      {"jsonrpc": "2.0", "id": 3, "method": "prompts/list",
                                       "params": request_params(era)}, timeout)
                if "error" not in reply:
                    prompts_payload = reply
            if isinstance(caps.get("resources"), dict):
                reply = _post_jsonrpc(s.url, onward,
                                      {"jsonrpc": "2.0", "id": 4, "method": "resources/list",
                                       "params": request_params(era)}, timeout)
                if "error" not in reply:
                    resources_payload = reply

        versions = opened.get("supportedVersions")
        return ProbeResult(
            _obs_id(s),
            _parse_tools(_obs_id(s), listed),
            instructions=str(opened.get("instructions") or ""),
            prompts=_parse_prompts(_obs_id(s), prompts_payload),
            resources=_parse_resources(_obs_id(s), resources_payload),
            protocol_era=era,
            supported_versions=[str(v) for v in versions] if isinstance(versions, list) else [],
        )
    except HandshakeFailed as exc:
        return ProbeResult(_obs_id(s), [], str(exc))
    except urllib.error.HTTPError as exc:
        return ProbeResult(_obs_id(s), [], f"HTTP {exc.code} {exc.reason}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return ProbeResult(_obs_id(s), [], _describe_connection_error(exc))


def probe(servers: list[ServerSpec], *, timeout: float = 20.0,
          allow_stdio: bool = True, verbose: bool = False,
          share_env: set | None = None) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for s in servers:
        if s.disabled:
            continue
        if verbose:
            print(f"  probing {s.identity()} ...", file=sys.stderr)
        if s.is_remote:
            results.append(probe_http(s, timeout))
        elif allow_stdio:
            results.append(probe_stdio(s, timeout, share_env=share_env))
        else:
            results.append(ProbeResult(_obs_id(s), [], "stdio probing disabled"))
    return results
