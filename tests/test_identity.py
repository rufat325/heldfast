"""Which agent may reach which servers.

The gateway knew *what* was called and not *who* called it, which is one
boundary rather than access control: the finance agent and the scratch agent
were the same principal because there was only one.

An identity is declared in the lockfile and selected with `--as`. What it
grants is operator-declared, which is the only kind that means anything here:
whoever writes the client configuration chooses the identity, and the lockfile
says what that identity may do.

The `clientInfo` a client sends in `initialize` is *not* that. The client
picks the string, so anything able to talk to the gateway can claim to be
anything; it is recorded in the audit trail and never reaches a decision.
There is a test for that specifically, because treating a self-declared name
as authorization is how an access-control layer becomes decoration.
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

from mcp_audit.gateway import Gateway  # noqa: E402
from mcp_audit.identity import Identity, UnknownIdentity, all_identities  # noqa: E402
from mcp_audit.lockfile import Lock  # noqa: E402
from mcp_audit.model import ServerSpec, ToolSpec  # noqa: E402

FAKE = ROOT / "tests" / "fixtures" / "fake_server.py"
INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"clientInfo": {"name": "totally-the-finance-agent"}}})
LIST = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'


def spec(name: str) -> ServerSpec:
    return ServerSpec(name=name, source="/p/.mcp.json", client="claude-code",
                      transport="stdio", command=sys.executable, args=[str(FAKE)])


class TestResolution(unittest.TestCase):
    def _lock(self) -> Lock:
        lock = Lock()
        lock.identities = {
            "reader": {"servers": ["github"], "deny": ["delete_repository"],
                       "policy": {"postgres__query": {"sql": ["SELECT"]}}},
            "admin": {},
        }
        return lock

    def test_an_identity_limits_which_servers_it_may_use(self) -> None:
        reader = Identity.from_lock(self._lock(), "reader")
        self.assertTrue(reader.may_use_server("github"))
        self.assertFalse(reader.may_use_server("postgres"))

    def test_an_identity_with_no_server_list_may_use_all_of_them(self) -> None:
        admin = Identity.from_lock(self._lock(), "admin")
        self.assertIsNone(admin.servers)
        self.assertTrue(admin.may_use_server("anything"))

    def test_an_empty_server_list_means_none_not_all(self) -> None:
        """Absent and empty are different, and reading empty as 'all' would
        turn the most restrictive declaration into the least."""
        lock = Lock()
        lock.identities = {"nothing": {"servers": []}}
        nobody = Identity.from_lock(lock, "nothing")
        self.assertEqual([], nobody.servers)
        self.assertFalse(nobody.may_use_server("github"))

    def test_deny_accepts_both_spellings(self) -> None:
        """Namespaced names one tool on one server; bare denies it wherever it
        appears, which is what a fleet-wide rule means."""
        reader = Identity.from_lock(self._lock(), "reader")
        self.assertTrue(reader.denies_tool("github__delete_repository",
                                           "delete_repository"))
        self.assertFalse(reader.denies_tool("github__read_file", "read_file"))

    def test_an_unknown_identity_raises_rather_than_falling_back(self) -> None:
        """The whole point of asking for a restricted principal is that a typo
        must not silently produce an unrestricted one."""
        with self.assertRaises(UnknownIdentity):
            Identity.from_lock(self._lock(), "typo")

    def test_the_error_names_what_is_available(self) -> None:
        try:
            Identity.from_lock(self._lock(), "typo")
        except UnknownIdentity as exc:
            self.assertIn("reader", str(exc))
            self.assertIn("admin", str(exc))

    def test_identity_policy_narrows_a_tool(self) -> None:
        reader = Identity.from_lock(self._lock(), "reader")
        policy = reader.policy_for("postgres__query", "query")
        self.assertTrue(policy)
        self.assertTrue(policy.check("query", {"sql": "SELECT 1"}))
        self.assertFalse(policy.check("query", {"sql": "DROP TABLE t"}))

    def test_listing_them_all(self) -> None:
        self.assertEqual({"reader", "admin"}, set(all_identities(self._lock())))

    def test_a_lockfile_with_no_identities_is_not_an_error(self) -> None:
        self.assertEqual({}, all_identities(Lock()))


class TestTheGatewayHonoursIt(unittest.TestCase):
    def _gateway(self, identity_entry: dict, **kw) -> Gateway:
        specs = [spec("alpha"), spec("beta")]
        lock = Lock()
        lock.record(specs, [ToolSpec(server=n, name="read_invoice",
                                     description="Reads.", input_schema={})
                            for n in ("alpha", "beta")], [])
        lock.identities = {"reader": identity_entry}
        return Gateway(specs, lock, quiet=True,
                       identity=Identity.from_lock(lock, "reader"), **kw)

    def test_a_server_outside_the_grant_is_never_started(self) -> None:
        """Not started and then hidden. An identity that may not use a server
        should not cause that server's process to exist."""
        gateway = self._gateway({"servers": ["alpha"]})
        self.assertIn("alpha", gateway.backends)
        self.assertNotIn("beta", gateway.backends)
        self.assertTrue(any("not granted" in r
                            for r in gateway.stats.backends_refused))

    def test_a_denied_tool_is_absent_from_the_listing(self) -> None:
        gateway = self._gateway({"servers": ["alpha"], "deny": ["read_invoice"]})
        gateway.backends["alpha"].tools = [
            {"name": "read_invoice", "description": "Reads.", "inputSchema": {}}]
        self.assertEqual([], [t["name"] for t in gateway.aggregate_tools()])

    def test_a_denied_tool_is_also_refused_at_call_time(self) -> None:
        """Hiding it from the listing is not enough: nothing stops a client
        asking for a name it was never shown."""
        gateway = self._gateway({"servers": ["alpha"], "deny": ["read_invoice"]})
        reply = gateway.handle_call({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "alpha__read_invoice", "arguments": {}}})
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("not available to 'reader'",
                      reply["result"]["content"][0]["text"])


class TestCallBudget(unittest.TestCase):
    """A tool that suddenly runs in a loop is usually an agent that has lost
    the plot. The budget bounds the damage; it does not judge the call."""

    def _gateway(self, **kw) -> Gateway:
        specs = [spec("alpha")]
        lock = Lock()
        lock.record(specs, [ToolSpec(server="alpha", name="read_invoice",
                                     description="Reads.", input_schema={})], [])
        gateway = Gateway(specs, lock, quiet=True, **kw)
        gateway.backends["alpha"].tools = [
            {"name": "read_invoice", "description": "Reads.", "inputSchema": {}}]
        return gateway

    def _call(self, gateway: Gateway, n: int) -> dict:
        return gateway.handle_call({
            "jsonrpc": "2.0", "id": n, "method": "tools/call",
            "params": {"name": "alpha__read_invoice", "arguments": {}}})

    def test_the_budget_stops_the_call(self) -> None:
        gateway = self._gateway(max_calls=2)
        for n in (1, 2):
            reply = self._call(gateway, n)
            self.assertNotIn("budget", json.dumps(reply))
        reply = self._call(gateway, 3)
        self.assertIn("budget", reply["result"]["content"][0]["text"])
        self.assertEqual(["alpha__read_invoice"], gateway.stats.calls_over_budget)

    def test_no_budget_by_default(self) -> None:
        gateway = self._gateway()
        for n in range(1, 6):
            self._call(gateway, n)
        self.assertEqual([], gateway.stats.calls_over_budget)

    def test_dry_run_reports_the_overrun_without_blocking(self) -> None:
        gateway = self._gateway(max_calls=1, dry_run=True)
        self._call(gateway, 1)
        reply = self._call(gateway, 2)
        self.assertTrue(gateway.stats.calls_over_budget)
        self.assertNotIn("BLOCKED", json.dumps(reply))

    def test_the_budget_is_per_tool(self) -> None:
        gateway = self._gateway(max_calls=1)
        gateway.backends["alpha"].tools.append(
            {"name": "list_invoices", "description": "Lists.", "inputSchema": {}})
        self._call(gateway, 1)
        other = gateway.handle_call({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "alpha__list_invoices", "arguments": {}}})
        self.assertNotIn("budget", json.dumps(other))


class TestClientInfoIsNotAuthorization(unittest.TestCase):
    """A client chooses its own clientInfo, so it identifies nothing."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        (self.project / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "alpha": {"command": sys.executable, "args": [str(FAKE)],
                      "env": {"MCP_AUDIT_FIXTURE_MODE":
                              "${MCP_AUDIT_FIXTURE_MODE}"}},
            "beta": {"command": sys.executable, "args": [str(FAKE)],
                     "env": {"MCP_AUDIT_FIXTURE_MODE":
                             "${MCP_AUDIT_FIXTURE_MODE}"}},
        }}), encoding="utf-8")
        self._cli(["approve", ".", "--no-user-configs", "--probe"])

        lock_path = self.project / ".mcp-audit.lock"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["identities"] = {"reader": {"servers": ["alpha"]}}
        lock_path.write_text(json.dumps(lock, indent=2), encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cli(self, args: list[str], stdin: str = "") -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["MCP_AUDIT_FIXTURE_MODE"] = "benign"
        return subprocess.run([sys.executable, "-m", "mcp_audit", *args],
                              cwd=str(self.project), env=env, input=stdin,
                              capture_output=True, text=True, timeout=180)

    def _tools(self, extra: list[str]) -> list[str]:
        result = self._cli(["gateway", ".", "--no-user-configs", *extra],
                           stdin=INIT + "\n" + LIST + "\n")
        for line in result.stdout.splitlines():
            try:
                reply = json.loads(line)
            except ValueError:
                continue
            if reply.get("id") == 2:
                return sorted(t["name"] for t in reply["result"]["tools"])
        return []

    def test_claiming_to_be_someone_grants_nothing(self) -> None:
        """The client announces "totally-the-finance-agent" in both runs. Only
        --as changes what it can reach."""
        self.assertEqual(4, len(self._tools([])))
        self.assertEqual(2, len(self._tools(["--as", "reader"])))

    def test_the_claim_is_recorded_though(self) -> None:
        from mcp_audit.auditlog import verify
        trail = self.project / "trail.jsonl"
        self._cli(["gateway", ".", "--no-user-configs", "--log", str(trail)],
                  stdin=INIT + "\n" + LIST + "\n")
        body = trail.read_text(encoding="utf-8")
        self.assertIn("totally-the-finance-agent", body)
        self.assertIn("self-declared, not authenticated", body)
        self.assertTrue(verify(trail).ok)

    def test_an_unknown_identity_refuses_to_start(self) -> None:
        result = self._cli(["gateway", ".", "--no-user-configs", "--as", "typo"],
                           stdin=INIT + "\n")
        self.assertEqual(2, result.returncode)
        self.assertIn("Refusing to fall back", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
