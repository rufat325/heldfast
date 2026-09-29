"""A server's reply is bounded in size and in time.

A socket timeout bounds each read, not the reply. post_rpc used to read a
reply whole, so a server sending without end filled memory, and one sending
a byte every few seconds held the call open for as long as it liked -- a
user's probe or gateway, or a worker in the feed reading thousands of
servers. These run real servers on loopback that do both.
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from heldfast import fetch, probe  # noqa: E402


class Hostile(BaseHTTPRequestHandler):
    mode = "flood"

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            if self.mode == "flood":
                block = b" " * 65536
                for _ in range(4096):  # 256 MiB, far past any limit used here
                    self.wfile.write(block)
            elif self.mode == "drip":
                for _ in range(600):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.05)
            else:
                self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}')
        except OSError:
            pass  # the client gave up, which is the point


class TestBoundedReplies(unittest.TestCase):
    def serve(self, mode: str) -> str:
        handler = type("H", (Hostile,), {"mode": mode})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/mcp"

    def test_a_reply_past_the_size_limit_is_refused(self) -> None:
        url = self.serve("flood")
        with mock.patch.object(fetch, "MAX_RESPONSE", 1024 * 1024):
            with mock.patch("heldfast.fetch.read_bounded.__defaults__", (1024 * 1024, None)):
                with self.assertRaises(ValueError):
                    probe.post_rpc(url, {}, {"jsonrpc": "2.0", "id": 1}, 5.0)

    def test_a_trickled_reply_is_cut_off_at_the_deadline(self) -> None:
        url = self.serve("drip")
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            probe.post_rpc(url, {}, {"jsonrpc": "2.0", "id": 1}, 5.0,
                           deadline=time.monotonic() + 1.0)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_the_handshake_passes_the_deadline_on(self) -> None:
        url = self.serve("drip")
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            probe.http_handshake(url, {}, 5.0, time.monotonic() + 1.0)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_an_ordinary_reply_is_read(self) -> None:
        url = self.serve("ok")
        reply, _ = probe.post_rpc(url, {}, {"jsonrpc": "2.0", "id": 1}, 5.0)
        self.assertEqual({"ok": True}, reply["result"])

    def test_the_default_deadline_leaves_room_for_long_calls(self) -> None:
        now = time.monotonic()
        self.assertGreaterEqual(fetch.deadline_for(1.0) - now, fetch.MIN_DEADLINE - 1)
        self.assertGreaterEqual(fetch.deadline_for(100.0) - now, 599)


if __name__ == "__main__":
    unittest.main()
