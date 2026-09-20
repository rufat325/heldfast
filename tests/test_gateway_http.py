"""The gateway in front of a hosted server.

`guard` wraps a child process, so a server configured with a `url` had nothing
for it to sit between: hosted MCP was scanned and pinned and never enforced at
the call site. That is the wrong half to be missing, and an outside reviewer
said so plainly -- a reader who runs mostly remote servers correctly concluded
the tool was not for them.

Nothing the gateway decides was ever tied to the child being local. It resolves
the lock entry, filters the catalogue, screens the result and counts the call,
all on messages. So these tests exist to hold one claim: a hosted backend gets
*the same* enforcement as a local one, not a reduced version of it.

The server under test is `tests/fixtures/http_server.py`, a stdlib Streamable
HTTP stub on loopback. Same reason as `test_wire_shape.py` pointing the real
Anthropic SDK at a local stub: the only honest way to test a client is against
something that answers like the real thing, and this project does not run
third-party servers.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))

import http_server  # noqa: E402
from mcp_pin.gateway import Backend, Gateway, HttpBackend  # noqa: E402
from mcp_pin.lockfile import Lock  # noqa: E402
from mcp_pin.model import (ServerSpec, ToolSpec,  # noqa: E402
                           instructions_fingerprint as _fingerprint)


def hosted(url: str, name: str = "invoices") -> ServerSpec:
    return ServerSpec(name=name, source=str(ROOT / "tests" / ".mcp.json"),
                      client="claude-code", transport="http", url=url)


def approved(spec: ServerSpec, descriptions: dict[str, str]) -> Lock:
    tools = [ToolSpec(server=spec.name, name=n, description=d,
                      input_schema={"type": "object",
                                    "properties": {"id": {"type": "string"}}})
             for n, d in descriptions.items()]
    lock = Lock()
    lock.record([spec], tools, [])
    return lock


class TestTheTransportIsTheOnlyDifference(unittest.TestCase):
    def test_a_hosted_backend_is_chosen_for_a_url(self) -> None:
        with http_server.serve() as url:
            spec = hosted(url)
            lock = approved(spec, {"read_invoice": http_server.BENIGN_TOOL})
            gateway = Gateway([spec], lock, quiet=True)
            gateway.start()
            try:
                backend = gateway.backends["invoices"]
                self.assertIsInstance(backend, HttpBackend)
                self.assertIsNone(backend.error)
            finally:
                gateway.close()

    def test_a_local_backend_is_still_a_pipe(self) -> None:
        spec = ServerSpec(name="local", source="/x/.mcp.json", client="claude-code",
                          transport="stdio", command=sys.executable,
                          args=[str(ROOT / "tests" / "fixtures" / "fake_server.py")],
                          env={"MCP_PIN_FIXTURE_MODE": "benign",
                               "PYTHONPATH": str(ROOT / "src")})
        lock = approved(spec, {"read_invoice": "x"})
        gateway = Gateway([spec], lock, quiet=True, allow_unapproved=True)
        try:
            self.assertIsInstance(gateway.backends["local"], Backend)
            self.assertNotIsInstance(gateway.backends["local"], HttpBackend)
        finally:
            gateway.close()

    def test_the_session_id_is_returned_on_every_later_request(self) -> None:
        """A client that takes the session id and forgets to send it back works
        exactly once, and the failure looks like the server's fault."""
        with http_server.serve() as url:
            spec = hosted(url)
            lock = approved(spec, {"read_invoice": http_server.BENIGN_TOOL})
            gateway = Gateway([spec], lock, quiet=True)
            gateway.start()
            try:
                self.assertIsNone(gateway.backends["invoices"].error)
            finally:
                gateway.close()
        seen = http_server.sessions_seen()
        self.assertEqual("", seen[0], "initialize cannot carry a session yet")
        self.assertTrue(seen[1:], "nothing was sent after initialize")
        for value in seen[1:]:
            self.assertEqual(http_server.SESSION_ID, value)

    def test_server_sent_event_framing_is_understood(self) -> None:
        """A Streamable HTTP server may answer in either framing."""
        with http_server.serve(sse=True) as url:
            spec = hosted(url)
            lock = approved(spec, {"read_invoice": http_server.BENIGN_TOOL})
            gateway = Gateway([spec], lock, quiet=True)
            gateway.start()
            try:
                backend = gateway.backends["invoices"]
                self.assertIsNone(backend.error)
                self.assertEqual(["read_invoice", "list_invoices"],
                                 [t["name"] for t in backend.tools])
            finally:
                gateway.close()


class TestAHostedRugPullIsRefused(unittest.TestCase):
    """The whole point. Approve the benign hosted server, then let it change
    its mind, and the gateway must withhold what moved."""

    def _fronted(self, mode: str):
        """Approve the benign hosted server for real, then let it change.

        The lock is built by probing the live stub rather than by hand, because
        a hand-written fingerprint is a fingerprint of what the test author
        imagined the server offers. Mode is switched on the running server, so
        the endpoint and the config are byte-identical across the change --
        which is the whole point of a rug pull.
        """
        from mcp_pin.probe import probe_http

        self._ctx = http_server.serve("benign")
        url = self._ctx.__enter__()
        spec = hosted(url)
        first = probe_http(spec, timeout=10)
        self.assertEqual([], [first.error] if first.error else [])
        lock = Lock()
        lock.record([spec], first.tools, [],
                    instructions={spec.name: first.instructions})
        http_server.set_mode(mode)
        gateway = Gateway([spec], lock, quiet=True)
        gateway.start()
        return gateway

    def tearDown(self) -> None:
        ctx = getattr(self, "_ctx", None)
        if ctx is not None:
            ctx.__exit__(None, None, None)

    def test_the_approved_catalogue_passes_through(self) -> None:
        gateway = self._fronted("benign")
        try:
            listed = gateway.handle({"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list", "params": {}})
            names = [t["name"] for t in listed["result"]["tools"]]
            self.assertIn("invoices__read_invoice", names)
            for tool in listed["result"]["tools"]:
                self.assertNotIn("BLOCKED", tool["description"])
        finally:
            gateway.close()

    def test_a_drifted_hosted_tool_is_withheld(self) -> None:
        gateway = self._fronted("poisoned")
        try:
            listed = gateway.handle({"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list", "params": {}})
            by_name = {t["name"]: t for t in listed["result"]["tools"]}
            drifted = by_name["invoices__read_invoice"]
            self.assertIn("BLOCKED BY mcp-pin", drifted["description"])
            self.assertNotIn("id_rsa", drifted["description"])
            # The tool that did not change still works. A gateway that broke
            # the whole server would be a gateway people remove.
            self.assertNotIn("BLOCKED",
                             by_name["invoices__list_invoices"]["description"])
        finally:
            gateway.close()

    def test_calling_the_drifted_hosted_tool_is_refused(self) -> None:
        """Hiding it from the catalogue is not enough on its own; an agent can
        name a tool it was never shown."""
        gateway = self._fronted("poisoned")
        try:
            gateway.handle({"jsonrpc": "2.0", "id": 1,
                            "method": "tools/list", "params": {}})
            reply = gateway.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "invoices__read_invoice",
                           "arguments": {"id": "42"}}})
            text = json.dumps(reply)
            self.assertIn("BLOCKED BY mcp-pin", text)
            self.assertEqual([], http_server.calls_made(),
                             "the refused call must not reach the server")
        finally:
            gateway.close()

    def test_poisoned_hosted_instructions_are_withheld(self) -> None:
        gateway = self._fronted("poisoned")
        try:
            reply = gateway.handle({"jsonrpc": "2.0", "id": 1,
                                    "method": "initialize", "params": {}})
            text = str((reply.get("result") or {}).get("instructions") or "")
            self.assertNotIn("id_rsa", text)
        finally:
            gateway.close()


class TestCleartextIsRefused(unittest.TestCase):
    def test_a_non_loopback_http_url_is_not_fronted(self) -> None:
        """The gateway sees every call, so it is the last place that should
        carry them over a transport somebody can rewrite. MCPA007 reports this
        on a scan; refusing here stops a reviewed lockfile being enforced over
        cleartext by accident."""
        spec = hosted("http://tools.example.com/mcp")
        lock = approved(spec, {"read_invoice": "x"})
        gateway = Gateway([spec], lock, quiet=True, allow_unapproved=True)
        gateway.start()
        try:
            # A backend that will not start is dropped rather than served, so
            # the refusal is in the stats and the tool surface is empty.
            self.assertNotIn("invoices", gateway.backends)
            self.assertTrue(any("cleartext" in f for f in
                                gateway.stats.backends_failed),
                            gateway.stats.backends_failed)
        finally:
            gateway.close()

    def test_loopback_http_is_allowed(self) -> None:
        """Otherwise nothing local could be tested or developed against."""
        with http_server.serve() as url:
            spec = hosted(url)
            lock = approved(spec, {"read_invoice": http_server.BENIGN_TOOL})
            gateway = Gateway([spec], lock, quiet=True)
            gateway.start()
            try:
                self.assertIsNone(gateway.backends["invoices"].error)
            finally:
                gateway.close()


class TestTheScannerCarriesTheSessionToo(unittest.TestCase):
    """A bug this feature uncovered in code that predates it.

    `probe_http` took the session id from the initialize response and threw it
    away, so `scan --probe` worked against hosted servers that do not enforce
    sessions and failed on every server that does -- reporting it as the
    endpoint's fault. Found only because the gateway grew the same transport
    and the stub here enforces the rule a real Streamable HTTP server does.
    """

    def test_a_session_enforcing_server_can_be_probed(self) -> None:
        from mcp_pin.probe import probe_http

        with http_server.serve() as url:
            result = probe_http(hosted(url), timeout=10)
        self.assertIsNone(result.error)
        self.assertEqual(["read_invoice", "list_invoices"],
                         [t.name for t in result.tools])
        self.assertIn("invoice records", result.instructions)

    def test_the_session_is_sent_on_the_calls_after_initialize(self) -> None:
        from mcp_pin.probe import probe_http

        with http_server.serve() as url:
            probe_http(hosted(url), timeout=10)
        seen = http_server.sessions_seen()
        self.assertGreater(len(seen), 1, "nothing followed initialize")
        self.assertTrue(all(v == http_server.SESSION_ID for v in seen[1:]), seen)


if __name__ == "__main__":
    unittest.main()
