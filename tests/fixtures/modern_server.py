"""A 2026-07-28 era MCP server fixture.

Implements `server/discover` and deliberately does NOT implement the legacy
`initialize` handshake -- it answers that with an error, the way a
modern-only server would. Exists so the dual-era probe is tested against a
server that actually speaks the current protocol rather than only against a
legacy one.

MCP_PIN_FIXTURE_SILENT=1 makes it ignore unknown methods entirely instead
of erroring, which is the harder legacy-detection case: the probe must not
block waiting for a reply that never comes.
"""

from __future__ import annotations

import json
import os
import sys

TOOLS = [
    {
        "name": "read_note",
        "description": "Read a note by its identifier.",
        "inputSchema": {"type": "object",
                        "properties": {"id": {"type": "string"}}},
        "annotations": {"readOnlyHint": True},
    },
]

INSTRUCTIONS = "This server exposes read-only access to notes."


def send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main() -> int:
    silent = os.environ.get("MCP_PIN_FIXTURE_SILENT") == "1"
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method, req_id = req.get("method"), req.get("id")

        if method == "server/discover":
            send({"jsonrpc": "2.0", "id": req_id, "result": {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "instructions": INSTRUCTIONS,
                "_meta": {"io.modelcontextprotocol/serverInfo":
                          {"name": "modern-notes", "version": "2.0.0"}},
            }})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        elif req_id is not None and not silent:
            # A modern-only server does not know `initialize`.
            send({"jsonrpc": "2.0", "id": req_id,
                  "error": {"code": -32601, "message": f"method not found: {method}"}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
