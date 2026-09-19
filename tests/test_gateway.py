"""One endpoint in front of every approved server.

`guard` wraps one server, which is the right shape for one connection and the
wrong shape for a machine: an agent has eight servers from three publishers,
and the properties worth enforcing are the ones that only exist across the
whole set.

The one worth pointing at is namespacing. MCPA027 exists because two servers
offering `read_file` leave the model guessing which it is calling, and a
scanner can only report that. Through the gateway the names are
`alpha__read_file` and `beta__read_file`, so the ambiguity has nowhere to
occur. Making a problem impossible beats reporting it.

Everything else is the guard's enforcement, applied across all of them: an
unapproved server is never started, a drifted tool is withheld, a call outside
policy is refused, and one audit trail covers the fleet.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.gateway import SEPARATOR, Gateway  # noqa: E402
from mcp_pin.lockfile import Lock  # noqa: E402
from mcp_pin.model import ServerSpec, ToolSpec  # noqa: E402

FAKE = ROOT / "tests" / "fixtures" / "fake_server.py"
INIT = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
LIST = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'


def spec(name: str, source: str = "/p/.mcp.json") -> ServerSpec:
    return ServerSpec(name=name, source=source, client="claude-code",
                      transport="stdio", command=sys.executable, args=[str(FAKE)])


class TestNamespacing(unittest.TestCase):
    """In process, so the naming logic is tested without paying for servers."""

    def _gateway(self, names: list[str]) -> Gateway:
        specs = [spec(n) for n in names]
        lock = Lock()
        lock.record(specs, [ToolSpec(server=n, name="read_invoice",
                                     description="Reads.", input_schema={})
                            for n in names], [])
        return Gateway(specs, lock, quiet=True)

    def test_a_name_collision_cannot_occur(self) -> None:
        gateway = self._gateway(["alpha", "beta"])
        for name, backend in gateway.backends.items():
            backend.tools = [{"name": "read_invoice", "description": "Reads.",
                              "inputSchema": {}}]
        exposed = [t["name"] for t in gateway.aggregate_tools()]
        self.assertEqual(sorted(["alpha__read_invoice", "beta__read_invoice"]),
                         sorted(exposed))
        self.assertEqual(len(exposed), len(set(exposed)))

    def test_the_split_is_unambiguous_with_overlapping_names(self) -> None:
        """`alpha` and `alpha_extra` both prefix the same string, so the
        longest server name has to win or calls route to the wrong backend."""
        gateway = self._gateway(["alpha", "alpha_extra"])
        self.assertEqual(("alpha_extra", "read"),
                         gateway.split_name("alpha_extra__read"))
        self.assertEqual(("alpha", "read"), gateway.split_name("alpha__read"))

    def test_an_unknown_prefix_does_not_resolve(self) -> None:
        gateway = self._gateway(["alpha"])
        self.assertIsNone(gateway.split_name("ghost__read"))
        self.assertIsNone(gateway.split_name("read_invoice"))

    def test_the_separator_is_not_a_single_underscore(self) -> None:
        """Tool names contain single underscores constantly; the split would
        be ambiguous on every one of them."""
        self.assertEqual("__", SEPARATOR)


class TestApprovalIsEnforcedBeforeStarting(unittest.TestCase):
    def test_an_unapproved_server_is_refused_not_merely_filtered(self) -> None:
        """Withholding a server's tools after paying to run it is theatre --
        the process is the thing that reads your files."""
        approved, unapproved = spec("alpha"), spec("gamma")
        lock = Lock()
        lock.record([approved], [], [])

        gateway = Gateway([approved, unapproved], lock, quiet=True)
        self.assertIn("alpha", gateway.backends)
        self.assertNotIn("gamma", gateway.backends)
        self.assertIn("claude-code:gamma", gateway.stats.backends_refused)

    def test_allow_unapproved_admits_it(self) -> None:
        approved, unapproved = spec("alpha"), spec("gamma")
        lock = Lock()
        lock.record([approved], [], [])
        gateway = Gateway([approved, unapproved], lock, quiet=True,
                          allow_unapproved=True)
        self.assertIn("gamma", gateway.backends)


class TestTwoClientsAreNotOneServer(unittest.TestCase):
    """Lock entries are keyed client:name. The gateway keyed backends by
    the bare name, so the second `github` silently replaced the first."""

    def test_the_second_github_is_not_started(self) -> None:
        cursor = ServerSpec(name="github", source="/c/.mcp.json", client="cursor",
                            transport="stdio", command="node", args=["s.js"])
        claude = ServerSpec(name="github", source="/d/.mcp.json",
                            client="claude-code", transport="stdio",
                            command="node", args=["s.js"])
        lock = Lock()
        lock.record([cursor, claude], [
            ToolSpec(server="github", name="x", description="d", input_schema={}),
        ], [])
        gateway = Gateway([cursor, claude], lock, quiet=True, allow_unapproved=True)
        self.assertEqual(["cursor:github"],
                         [b.spec.identity() for b in gateway.backends.values()])
        self.assertIn("claude-code:github", gateway.stats.backends_refused)


class TestTheWholeThingOverStdio(unittest.TestCase):
    """The gateway as a client meets it: a real process, real backends."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        # The fixture reads its mode from the environment, and the gateway
        # now passes through only what a server declares. Declaring it is the
        # same migration a real user makes for a token, so the tests do it.
        mode = {"MCP_PIN_FIXTURE_MODE": "${MCP_PIN_FIXTURE_MODE}"}
        config = {"mcpServers": {
            "alpha": {"command": sys.executable, "args": [str(FAKE)], "env": mode},
            "beta": {"command": sys.executable, "args": [str(FAKE)], "env": mode},
        }}
        (self.project / ".mcp.json").write_text(json.dumps(config, indent=2),
                                                encoding="utf-8")
        self._run(["approve", ".", "--no-user-configs", "--probe"])

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, args: list[str], stdin: str = "",
             poisoned: bool = False) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["MCP_PIN_FIXTURE_MODE"] = "poisoned" if poisoned else "benign"
        return subprocess.run([sys.executable, "-m", "mcp_pin", *args],
                              cwd=str(self.project), env=env, input=stdin,
                              capture_output=True, text=True, timeout=180)

    def _replies(self, lines: list[str], **kw) -> list[dict]:
        result = self._run(["gateway", ".", "--no-user-configs"],
                           stdin="\n".join(lines) + "\n", **kw)
        out = []
        for line in result.stdout.splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        self._stderr = result.stderr
        return out

    def test_both_backends_are_served_through_one_endpoint(self) -> None:
        listed = next(r for r in self._replies([INIT, LIST]) if r.get("id") == 2)
        names = sorted(t["name"] for t in listed["result"]["tools"])
        self.assertIn("alpha__read_invoice", names)
        self.assertIn("beta__read_invoice", names)
        self.assertEqual(len(names), len(set(names)))

    def test_a_call_is_routed_to_the_named_backend(self) -> None:
        """The backend's own answer coming back is the proof the call reached
        it rather than being answered here.

        This used to assert the fixture's -32601, because fake_server had no
        tools/call at all. It grew one to exercise the server->client
        screening, so the proof is now the content it returns -- which is the
        same claim on more direct evidence.
        """
        call = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "alpha__read_invoice",
                                      "arguments": {"invoice_id": "INV-1"}}})
        reply = next(r for r in self._replies([INIT, LIST, call]) if r.get("id") == 3)
        self.assertNotIn("error", reply)
        self.assertIn("Invoice 41", reply["result"]["content"][0]["text"])

    def test_a_tool_no_backend_offers_is_refused_here(self) -> None:
        call = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                           "params": {"name": "ghost__do_thing", "arguments": {}}})
        reply = next(r for r in self._replies([INIT, call]) if r.get("id") == 4)
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("BLOCKED BY mcp-pin", reply["result"]["content"][0]["text"])

    def test_drift_is_withheld_across_the_fleet(self) -> None:
        listed = next(r for r in self._replies([INIT, LIST], poisoned=True)
                      if r.get("id") == 2)
        blocked = [t["name"] for t in listed["result"]["tools"]
                   if "BLOCKED" in str(t.get("description"))]
        self.assertIn("alpha__read_invoice", blocked)
        self.assertIn("beta__read_invoice", blocked)

    def test_a_server_added_after_approval_is_not_started(self) -> None:
        config = json.loads((self.project / ".mcp.json").read_text(encoding="utf-8"))
        config["mcpServers"]["gamma"] = {
            "command": sys.executable, "args": [str(FAKE)],
            "env": {"MCP_PIN_FIXTURE_MODE": "${MCP_PIN_FIXTURE_MODE}"}}
        (self.project / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")

        listed = next(r for r in self._replies([INIT, LIST]) if r.get("id") == 2)
        names = [t["name"] for t in listed["result"]["tools"]]
        self.assertEqual([], [n for n in names if n.startswith("gamma")])
        self.assertIn("not started", self._stderr)

    def test_it_answers_both_protocol_eras(self) -> None:
        discover = '{"jsonrpc":"2.0","id":9,"method":"server/discover","params":{}}'
        replies = self._replies([discover])
        reply = next(r for r in replies if r.get("id") == 9)
        self.assertIn("supportedVersions", reply["result"])

    def test_the_session_can_be_recorded(self) -> None:
        from mcp_pin.auditlog import verify
        trail = self.project / "trail.jsonl"
        result = self._run(["gateway", ".", "--no-user-configs", "--log", str(trail)],
                           stdin=INIT + "\n" + LIST + "\n")
        self.assertTrue(trail.exists(), result.stderr)
        self.assertTrue(verify(trail).ok)
        body = trail.read_text(encoding="utf-8")
        self.assertIn("backend_started", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
