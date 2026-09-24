"""Where a redirect is allowed to take a request, and what it may carry.

`urllib.request.urlopen` uses the default opener, which follows redirects with
the original headers attached -- `HTTPRedirectHandler` strips `content-length`
and `content-type` and nothing else. Two guarantees leaked through that:

* T-HOSTED-TLS says `gateway` refuses to front a non-loopback server over
  cleartext `http://`. It checked the URL it was configured with, once. A
  backend on `https://` answering `302 Location: http://...` moved every later
  call onto cleartext and the check never ran again.

* The `Authorization` header configured for one backend was handed to whatever
  host a `Location:` named. Those are the same header names
  `rules/transport.py` already calls credentials.

Everything here runs against two loopback servers. Nothing reaches the network.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import fetch  # noqa: E402
from heldfast.probe import post_rpc  # noqa: E402

RECEIVED: dict = {}


def _drain(handler: BaseHTTPRequestHandler) -> None:
    length = int(handler.headers.get("Content-Length") or 0)
    if length:
        handler.rfile.read(length)


class _Destination(BaseHTTPRequestHandler):
    """Records what actually arrived, and answers like an MCP endpoint."""

    protocol_version = "HTTP/1.1"

    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        RECEIVED["body"] = self.rfile.read(length).decode("utf-8") if length else ""
        RECEIVED["headers"] = dict(self.headers)
        RECEIVED["path"] = self.path
        RECEIVED["method"] = self.command
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, *args: object) -> None:
        return None


def _serve(handler: type) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _redirector(location: str, code: int = 302) -> type:
    class _Redirect(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            _drain(self)
            self.send_response(code)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            return None

    return _Redirect


class _ServerCase(unittest.TestCase):
    """Starts loopback servers and takes them down again.

    `shutdown()` stops the serve loop; `server_close()` releases the listening
    socket. Without the second one the suite prints a ResourceWarning per test.
    Cleanups run last-registered-first, so they go on in that order.
    """

    def spawn(self, handler: type) -> HTTPServer:
        server = _serve(handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server


class TestRedirectsDoNotCarryCredentials(_ServerCase):
    CREDENTIAL = "Bearer SECRET-TOKEN-123"

    def setUp(self) -> None:
        RECEIVED.clear()
        self.destination = self.spawn(_Destination)

    def _destination_url(self, path: str = "/stolen") -> str:
        return f"http://127.0.0.1:{self.destination.server_port}{path}"

    def _post_through(self, location: str) -> None:
        hop = self.spawn(_redirector(location))
        post_rpc(f"http://127.0.0.1:{hop.server_port}/mcp",
                 {"Authorization": self.CREDENTIAL},
                 {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {}}, 5.0)

    def test_a_cross_origin_hop_loses_the_credential(self) -> None:
        """A different port is a different origin. The redirect is followed --
        the spec has clients follow them -- and the token does not go."""
        self._post_through(self._destination_url())
        self.assertEqual("/stolen", RECEIVED["path"])
        self.assertIsNone(RECEIVED["headers"].get("Authorization"))

    def test_a_same_origin_hop_keeps_it(self) -> None:
        """Refusing every redirect would break working servers. A hop that
        stays on the same scheme, host and port is not a disclosure."""
        same = f"http://127.0.0.1:{self.destination.server_port}"

        class _SelfRedirect(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                _drain(self)
                RECEIVED["headers"] = dict(self.headers)
                RECEIVED["path"] = self.path
                body = json.dumps({"jsonrpc": "2.0", "id": 1,
                                   "result": {}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                return None

        server = self.spawn(_SelfRedirect)
        origin = f"http://127.0.0.1:{server.server_port}"
        request = urllib.request.Request(origin + "/mcp", data=b"{}",
                                         method="POST")
        request.add_header("Authorization", self.CREDENTIAL)
        fetch.urlopen(request, 5.0).read()
        self.assertEqual(self.CREDENTIAL, RECEIVED["headers"].get("Authorization"))

    def test_every_credential_header_is_dropped_not_just_authorization(self) -> None:
        for header in ("Authorization", "X-Api-Key", "X-Auth-Token", "Cookie"):
            with self.subTest(header=header):
                RECEIVED.clear()
                hop = self.spawn(_redirector(self._destination_url()))
                request = urllib.request.Request(
                    f"http://127.0.0.1:{hop.server_port}/mcp", data=b"{}",
                    method="POST")
                request.add_header(header, "secret-value")
                fetch.urlopen(request, 5.0).read()
                self.assertIsNone(RECEIVED["headers"].get(header))

    def test_an_ordinary_header_survives_the_hop(self) -> None:
        """Only credentials are dropped. A redirect that lost `Accept` would
        change what the endpoint answers with."""
        hop = self.spawn(_redirector(self._destination_url()))
        request = urllib.request.Request(
            f"http://127.0.0.1:{hop.server_port}/mcp", data=b"{}", method="POST")
        request.add_header("Accept", "application/json")
        fetch.urlopen(request, 5.0).read()
        self.assertEqual("application/json", RECEIVED["headers"].get("Accept"))


class TestRedirectsCannotDowngradeTheTransport(_ServerCase):
    """T-HOSTED-TLS, applied to every hop instead of only the first."""

    def test_a_hop_onto_cleartext_for_a_public_host_is_refused(self) -> None:
        hop = self.spawn(_redirector("http://attacker.example/x"))
        with self.assertRaises(urllib.error.HTTPError) as caught:
            post_rpc(f"http://127.0.0.1:{hop.server_port}/mcp", {},
                     {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {}}, 5.0)
        self.assertIn("cleartext", str(caught.exception.reason))

    def test_a_hop_onto_another_scheme_is_refused(self) -> None:
        for location in ("ftp://attacker.example/x", "file:///etc/passwd"):
            with self.subTest(location=location):
                hop = self.spawn(_redirector(location))
                with self.assertRaises(urllib.error.URLError):
                    post_rpc(f"http://127.0.0.1:{hop.server_port}/mcp", {},
                             {"jsonrpc": "2.0", "id": 1,
                              "method": "initialize", "params": {}}, 5.0)

    def test_loopback_over_cleartext_is_still_allowed(self) -> None:
        """The same exemption the configured-URL check makes. A local server
        on plain http is the ordinary case, not an attack."""
        self.assertIsNone(fetch.transport_refusal("http://127.0.0.1:8080/mcp"))
        self.assertIsNone(fetch.transport_refusal("http://localhost:8080/mcp"))
        self.assertIsNone(fetch.transport_refusal("https://api.example/mcp"))

    def test_a_public_host_over_cleartext_is_not(self) -> None:
        self.assertIsNotNone(fetch.transport_refusal("http://api.example/mcp"))


class TestOriginComparison(unittest.TestCase):
    def test_scheme_host_and_port_all_count(self) -> None:
        same = "https://api.example/a"
        for other in ("https://api.example/b", "https://API.EXAMPLE/b"):
            with self.subTest(other=other):
                self.assertEqual(fetch.origin_of(same), fetch.origin_of(other))
        for other in ("http://api.example/a", "https://evil.example/a",
                      "https://api.example:8443/a"):
            with self.subTest(other=other):
                self.assertNotEqual(fetch.origin_of(same),
                                    fetch.origin_of(other))


class TestItSaysWhoItIs(unittest.TestCase):
    """urllib's default User-Agent gets this tool blocked.

    `Python-urllib/3.x` is what bot filters in front of hosted MCP servers
    look for: gitmcp.io answers 403 to it and 200 to curl, to a browser, and
    to no User-Agent at all -- so `probe` and `gateway` could not reach a
    server anything else reaches. `integrity.get_json` had always sent a real
    name; `post_rpc`, the one that talks to other people's servers, had not.

    Naming the tool is also the courteous half: an operator reading their
    access log can tell what connected to them.
    """

    def setUp(self) -> None:
        RECEIVED.clear()
        self.server = _serve(_Destination)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def _post(self, headers):
        from heldfast.probe import post_rpc
        post_rpc(f"http://127.0.0.1:{self.server.server_port}/mcp", headers,
                 {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, 5.0)
        return RECEIVED.get("headers", {})

    def test_the_default_agent_is_not_what_goes_out(self) -> None:
        agent = self._post({}).get("User-Agent", "")
        self.assertNotIn("Python-urllib", agent)
        self.assertIn("heldfast", agent)

    def test_it_is_the_same_name_the_registry_lookup_uses(self) -> None:
        from heldfast import integrity
        self.assertEqual(fetch.USER_AGENT, integrity._UA)

    def test_a_configured_agent_still_wins(self) -> None:
        """An operator who set one meant it."""
        agent = self._post({"User-Agent": "acme-corp-proxy/2"}).get("User-Agent", "")
        self.assertEqual("acme-corp-proxy/2", agent)


class TestMethodPreservingRedirects(_ServerCase):
    """307 and 308 keep the method and the body; the stdlib refuses them.

    `HTTPRedirectHandler.redirect_request` allows 301/302/303 on POST and
    raises on everything else, so for a POST-only transport it refused 307 and
    308 outright -- and those are exactly the codes a server uses when it
    wants the request repeated as sent. A hosted MCP server behind an
    apex-to-www or moved-path redirect was unreachable, while the spec has
    clients follow redirects. Reproduced against a real 307 from httpbin.org.
    """

    BODY = b'{"jsonrpc":"2.0","id":1,"method":"initialize"}'

    def _through(self, code, destination=None):
        RECEIVED.clear()
        landing = self.spawn(_Destination)
        target = destination or f"http://127.0.0.1:{landing.server_port}/landed"
        hop = self.spawn(_redirector(target, code))
        request = urllib.request.Request(
            f"http://127.0.0.1:{hop.server_port}/mcp", data=self.BODY, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", "Bearer SECRET")
        fetch.urlopen(request, 5.0).read()
        return RECEIVED

    def test_the_method_and_body_survive(self) -> None:
        for code in (307, 308):
            with self.subTest(code=code):
                got = self._through(code)
                self.assertEqual("POST", got.get("method"))
                self.assertEqual(self.BODY.decode(), got.get("body"))

    def test_the_credential_is_still_dropped_across_the_hop(self) -> None:
        """Preserving the method must not quietly preserve the token too."""
        got = self._through(307)
        self.assertIsNone(got.get("headers", {}).get("Authorization"))

    def test_a_downgrade_is_refused_on_these_codes_too(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._through(308, destination="http://attacker.example/x")
        self.assertIn("cleartext", str(caught.exception.reason))

    def test_302_keeps_the_stdlib_meaning(self) -> None:
        """Left alone on purpose: those codes have meant "retry as GET" for
        twenty years, and a server that wants its body preserved says 307."""
        got = self._through(302)
        self.assertEqual("GET", got.get("method"))

    def test_308_is_dispatched_by_this_class_and_not_by_the_stdlib(self) -> None:
        """The version-independence, asserted rather than assumed.

        urllib only learned 308 in Python 3.11. On 3.9 and 3.10 the redirect
        handler aliases 301/303/307 onto `http_error_302` and nothing else, so
        a 308 fell straight past `redirect_request` to the default handler and
        came back as a bare `HTTP Error 308`: the hop was neither followed nor
        checked for a downgrade. The behavioural tests above cannot see this
        on a modern interpreter, because there the stdlib supplies the alias
        and everything passes -- it was three red 3.9 jobs that showed it.

        So this asserts the dispatch is ours: `http_error_308` defined on
        `GuardedRedirectHandler` itself, not inherited from whichever stdlib
        happens to be running.
        """
        self.assertIn("http_error_308", vars(fetch.GuardedRedirectHandler))
        self.assertIs(fetch.GuardedRedirectHandler.http_error_308,
                      urllib.request.HTTPRedirectHandler.http_error_302)


if __name__ == "__main__":
    unittest.main()
