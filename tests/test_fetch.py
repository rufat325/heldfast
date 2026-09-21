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

from mcp_pin import fetch  # noqa: E402
from mcp_pin.probe import post_rpc  # noqa: E402

RECEIVED: dict = {}


def _drain(handler: BaseHTTPRequestHandler) -> None:
    length = int(handler.headers.get("Content-Length") or 0)
    if length:
        handler.rfile.read(length)


class _Destination(BaseHTTPRequestHandler):
    """Records what actually arrived, and answers like an MCP endpoint."""

    protocol_version = "HTTP/1.1"

    def _answer(self) -> None:
        _drain(self)
        RECEIVED["headers"] = dict(self.headers)
        RECEIVED["path"] = self.path
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


def _redirector(location: str) -> type:
    class _Redirect(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            _drain(self)
            self.send_response(302)
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


if __name__ == "__main__":
    unittest.main()
