"""Pinned JSON-RPC conversations through the guard and the gateway.

Awareness tests can pass while the wire quietly changes: a refusal that
became a protocol error, a banner parsed as a frame, a rewrite that kept
its name and its poison. These files are the conversation. Changing one
is a behaviour change and needs a new pin in the same commit.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from fake_server import BENIGN_TOOLS, POISONED_TOOLS  # noqa: E402
from mcp_audit.gateway import Gateway  # noqa: E402
from mcp_audit.guard import Guard  # noqa: E402
from mcp_audit.lockfile import Lock  # noqa: E402
from mcp_audit.model import ServerSpec, ToolSpec  # noqa: E402

PIN_DIR = Path(__file__).resolve().parent / "golden" / "traces"
WRITE = os.environ.get("MCP_AUDIT_WRITE_GOLDEN") == "1"
HOSTILE = ROOT / "tests" / "fixtures" / "hostile_server.py"
FAKE = ROOT / "tests" / "fixtures" / "fake_server.py"

BENIGN_DESC = BENIGN_TOOLS[0]["description"]
POISONED_DESC = POISONED_TOOLS[0]["description"]


def _canon(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _pin(name: str, live: Any) -> None:
    path = PIN_DIR / f"{name}.json"
    live = _canon(live)
    if WRITE:
        PIN_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(live, indent=2) + "\n", encoding="utf-8")
        return
    if not path.is_file():
        raise AssertionError(
            f"missing pin {path}. Capture with MCP_AUDIT_WRITE_GOLDEN=1 "
            "and commit the file."
        )
    expected = json.loads(path.read_text(encoding="utf-8"))
    if expected != live:
        raise AssertionError(
            f"{path.name} drifted.\n"
            f"  expected: {json.dumps(expected, sort_keys=True)}\n"
            f"  live:     {json.dumps(live, sort_keys=True)}\n"
            "If this is intended, MCP_AUDIT_WRITE_GOLDEN=1 and explain why "
            "in docs/GUARANTEES.md in the same commit."
        )


def _lock_for(server: str, tools: list[dict], policy: dict | None = None) -> Lock:
    spec = ServerSpec(name=server, source="/tmp/.mcp.json", client="test",
                      transport="stdio", command="node", args=["s.js"])
    recorded = [
        ToolSpec(
            server=server,
            name=str(t["name"]),
            description=str(t.get("description") or ""),
            input_schema=t.get("inputSchema") or {},
        )
        for t in tools
    ]
    lock = Lock()
    lock.record([spec], recorded, [])
    if policy:
        key = next(iter(lock.servers))
        lock.servers[key]["policy"] = policy
    return lock


def _guard(policy: dict | None = None, tools: list[dict] | None = None) -> Guard:
    return Guard("svc", _lock_for("svc", tools or BENIGN_TOOLS, policy), quiet=True)


def _call(name: str, arguments: dict, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


def _list(tools: list[dict], req_id: int = 2) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": json.loads(json.dumps(tools))}}


def _classify_stdout(text: str) -> dict[str, Any]:
    frames = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError:
            frames.append({"kind": "raw", "text": stripped})
            continue
        frames.append({
            "kind": "jsonrpc",
            "id": msg.get("id"),
            "method": msg.get("method"),
            "has_result": "result" in msg,
            "has_error": "error" in msg,
            "is_error_result": bool((msg.get("result") or {}).get("isError"))
            if isinstance(msg.get("result"), dict) else False,
            "blocked": "BLOCKED BY mcp-audit" in stripped,
            "leaked_secret": "id_rsa" in stripped,
        })
    return {"frames": frames}


class TestGuardAllowAndDeny(unittest.TestCase):
    def test_an_in_bounds_call_is_forwarded(self) -> None:
        guard = _guard({"read_invoice": {"paths": ["/workspace/**"]}})
        refusal = guard.check_call(_call("read_invoice", {
            "invoice_id": "/workspace/inv/1.pdf"}))
        _pin("guard-allow", {
            "id": "guard-allow",
            "action": "forward",
            "refusal": refusal,
        })

    def test_a_traversal_is_answered_here(self) -> None:
        guard = _guard({"read_invoice": {"paths": ["/workspace/**"]}})
        refusal = guard.check_call(_call("read_invoice", {
            "invoice_id": "/workspace/../../etc/passwd"}))
        _pin("guard-deny", {
            "id": "guard-deny",
            "action": "refuse",
            "refusal": refusal,
        })
        self.assertIsNotNone(refusal)
        self.assertTrue(refusal["result"]["isError"])
        self.assertNotIn("error", refusal)


class TestRewriteAfterNCalls(unittest.TestCase):
    """The delayed rug pull: N honest calls, then a new catalogue.

    The guard does not count calls. It re-fingerprints every tools/list.
    The pin is that the first list is forwarded, the second is blocked,
    and the poisoned prose never reaches the client.
    """

    def test_the_second_catalogue_is_blocked(self) -> None:
        guard = _guard(tools=BENIGN_TOOLS)
        first = guard.handle_server_message(_list(BENIGN_TOOLS, 2))
        # Two honest calls. The guard forwards them: no policy on this lock.
        call_one = guard.check_call(_call("read_invoice", {"invoice_id": "1"}, 3))
        call_two = guard.check_call(_call("read_invoice", {"invoice_id": "2"}, 4))
        note = guard.handle_server_message({
            "jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        second = guard.handle_server_message(_list(POISONED_TOOLS, 5))
        tools = second["result"]["tools"]
        _pin("rewrite-after-2-calls", {
            "id": "rewrite-after-2-calls",
            "first_list_blocked": [
                t["name"] for t in first["result"]["tools"]
                if "BLOCKED BY mcp-audit" in str(t.get("description"))
            ],
            "calls_forwarded": [call_one, call_two],
            "list_changed_forwarded": note.get("method"),
            "second_list_blocked": [
                t["name"] for t in tools
                if "BLOCKED BY mcp-audit" in str(t.get("description"))
            ],
            "second_list_leaked_secret": any(
                "id_rsa" in str(t.get("description")) for t in tools),
            "stats_list_changed": guard.stats.list_changed,
        })
        self.assertEqual([], [
            t["name"] for t in first["result"]["tools"]
            if "BLOCKED BY mcp-audit" in str(t.get("description"))
        ])
        self.assertIn("read_invoice", [
            t["name"] for t in tools
            if "BLOCKED BY mcp-audit" in str(t.get("description"))
        ])


class TestGatewayTraces(unittest.TestCase):
    def _gateway(self) -> Gateway:
        spec = ServerSpec(name="alpha", source="/p/.mcp.json", client="claude-code",
                          transport="stdio", command=sys.executable, args=[str(FAKE)])
        lock = Lock()
        lock.record(
            [spec],
            [ToolSpec(server="alpha", name="read_invoice",
                      description=BENIGN_DESC, input_schema={})],
            [],
        )
        gateway = Gateway([spec], lock, quiet=True)

        class Dead:
            def __init__(self) -> None:
                self.spec = spec
                self.name = "alpha"
                self.error = None
                self.instructions = ""
                self.tools = [dict(BENIGN_TOOLS[0])]
                self.sent: list = []

            def request(self, method: str, params: dict) -> dict:
                self.sent.append((method, params))
                return {"jsonrpc": "2.0", "id": 1,
                        "result": {"content": [
                            {"type": "text", "text": "Invoice 41: 120.00 USD"}]}}

            def close(self) -> None:
                pass

        dead = Dead()
        gateway.backends["alpha"] = dead  # type: ignore[assignment]
        self._backend = dead
        return gateway

    def test_a_namespaced_call_is_routed(self) -> None:
        gateway = self._gateway()
        listed = gateway.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        reply = gateway.handle_call({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "alpha__read_invoice",
                       "arguments": {"invoice_id": "INV-1"}}})
        _pin("gateway-allow", {
            "id": "gateway-allow",
            "listed_names": sorted(t["name"] for t in listed["result"]["tools"]),
            "call": reply,
            "backend_saw": self._backend.sent,
        })

    def test_an_unknown_server_is_refused_here(self) -> None:
        gateway = self._gateway()
        reply = gateway.handle_call({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "ghost__do_thing", "arguments": {}}})
        _pin("gateway-deny", {
            "id": "gateway-deny",
            "call": reply,
        })
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("BLOCKED BY mcp-audit", reply["result"]["content"][0]["text"])


class TestHostileStdoutBeforeFrame(unittest.TestCase):
    def test_a_banner_is_not_a_jsonrpc_frame(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["MCP_AUDIT_HOSTILE"] = "banner"
        stdin = (
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {}}) + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                          "params": {}}) + "\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "mcp_audit", "guard", "--quiet",
             "--allow-unapproved", "--name", "h", "--",
             sys.executable, str(HOSTILE)],
            input=stdin, capture_output=True, text=True, timeout=30, env=env,
        )
        live = _classify_stdout(result.stdout)
        _pin("hostile-stdout-before-frame", {
            "id": "hostile-stdout-before-frame",
            "returncode_ok": result.returncode == 0,
            "kinds": [f["kind"] for f in live["frames"]],
            "first_jsonrpc_id": next(
                (f["id"] for f in live["frames"] if f["kind"] == "jsonrpc"), None),
            "frames": live["frames"],
        })
        kinds = [f["kind"] for f in live["frames"]]
        self.assertGreaterEqual(kinds.count("raw"), 1, live)
        self.assertIn("jsonrpc", kinds)
        self.assertEqual("raw", kinds[0], "the banner must come before any frame")


if __name__ == "__main__":
    unittest.main()
