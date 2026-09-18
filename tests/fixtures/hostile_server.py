"""A deliberately badly behaved MCP server.

Real servers misbehave. They print banners to stdout before speaking the
protocol, emit notifications in the middle of a reply, start slowly, never
exit when stdin closes, and occasionally send malformed UTF-8. The spec
forbids some of this and it happens anyway, so a client that only ever talks
to a polite fixture has not been tested.

Each mode is one realistic failure. Selected with MCP_AUDIT_HOSTILE=<mode>:

    banner        writes human text to stdout before any JSON-RPC
    notifications interleaves notifications between request and reply
    duplicate_id  answers the same id twice
    unsolicited   sends a reply to an id nobody asked about
    slow          delays before answering (tests the probe timeout)
    huge          returns a very large tool list
    badutf8       emits a lone surrogate in a description
    longline      returns one enormous single line
    crash         exits abruptly mid-conversation
    hang          ignores stdin close and never exits
    empty_lines   pads the stream with blank lines
    out_of_order  answers later ids before earlier ones

Nothing here reaches outside the process: no network, no subprocesses, and
the only file it writes is a pid file, only to the path a test hands it in
MCP_AUDIT_HOSTILE_PIDFILE. It is hostile to the protocol, not to the machine.
"""

from __future__ import annotations

import json
import os
import sys
import time

MODE = os.environ.get("MCP_AUDIT_HOSTILE", "")

TOOLS = [{
    "name": "read_note",
    "description": "Read a note by its identifier.",
    "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
}]


def emit(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def send(msg: dict) -> None:
    emit(json.dumps(msg))


def tools_payload() -> list:
    if MODE == "huge":
        return [{"name": f"tool_{i}",
                 "description": "Reads a record. " * 40,
                 "inputSchema": {"type": "object"}} for i in range(400)]
    if MODE == "badutf8":
        # A lone surrogate: legal in a Python str, not encodable as UTF-8.
        return [{"name": "read_note",
                 "description": "Reads a note \ud800 with a lone surrogate.",
                 "inputSchema": {"type": "object"}}]
    if MODE == "longline":
        return [{"name": "read_note", "description": "x" * 2_000_000,
                 "inputSchema": {"type": "object"}}]
    return TOOLS


def initialize_result() -> dict:
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "hostile", "version": "1.0.0"},
        "instructions": "A deliberately awkward server.",
    }


def main() -> int:
    # The orphan test needs to know exactly which process to look for. Writing
    # the pid is precise and costs nothing; the alternative was enumerating
    # processes and matching command lines, which meant shelling out to wmic --
    # absent from current Windows runner images, and the reason CI was red.
    pidfile = os.environ.get("MCP_AUDIT_HOSTILE_PIDFILE")
    if pidfile:
        with open(pidfile, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))

    if MODE == "banner":
        # Servers really do this, despite the spec saying they MUST NOT.
        emit("hostile-server v1.0.0 starting up")
        emit("listening on stdio...")
        emit("")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method, req_id = req.get("method"), req.get("id")

        if MODE == "empty_lines":
            emit("")
            emit("   ")

        if MODE == "notifications" and req_id is not None:
            send({"jsonrpc": "2.0", "method": "notifications/message",
                  "params": {"level": "info", "data": "chatter before the reply"}})
            send({"jsonrpc": "2.0", "method": "notifications/progress",
                  "params": {"progressToken": 1, "progress": 50}})

        if MODE == "unsolicited":
            send({"jsonrpc": "2.0", "id": 9999, "result": {"nobody": "asked"}})

        if MODE == "slow":
            time.sleep(8)

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": req_id, "result": initialize_result()})
            if MODE == "duplicate_id":
                send({"jsonrpc": "2.0", "id": req_id, "result": initialize_result()})
        elif method == "tools/list":
            if MODE == "crash":
                sys.stdout.flush()
                os._exit(1)
            payload = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_payload()}}
            if MODE == "badutf8":
                # Write bytes directly so the surrogate survives to the client.
                raw = json.dumps(payload, ensure_ascii=False)
                sys.stdout.buffer.write(raw.encode("utf-8", errors="surrogatepass") + b"\n")
                sys.stdout.buffer.flush()
            else:
                send(payload)
        elif req_id is not None:
            send({"jsonrpc": "2.0", "id": req_id,
                  "error": {"code": -32601, "message": f"method not found: {method}"}})

    if MODE == "hang":
        # stdin closed and we refuse to leave.
        time.sleep(3600)
    return 0


if __name__ == "__main__":
    sys.exit(main())
