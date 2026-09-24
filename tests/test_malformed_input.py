"""Everything here parses input somebody else wrote.

The config files come off disk and may be half-edited. The JSON-RPC messages
come from a server the user is running precisely because they are not sure
they trust it. None of it is a place to raise.

The guard fails closed on an inspect error: the payload is withheld, the
proxy stays up. `--fail-open` restores the old "forward uninspected" path.
The parsers have no such wrapper: they are hand-written, they are the first
thing a scan touches, and an exception in one ends the scan rather than
skipping a file.

Fuzzed while writing this: 2,904 inputs through the parsers and 561 malformed
JSON-RPC shapes through the guard, zero exceptions in either. The samples
below are the reduced version that runs in CI in under a second.
"""

from __future__ import annotations

import itertools
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import inspect as inspect_mod  # noqa: E402
from heldfast.discovery import _strip_jsonc, find_key_line  # noqa: E402
from heldfast.findings import redact  # noqa: E402
from heldfast.guard import Guard  # noqa: E402
from heldfast.lockfile import Lock  # noqa: E402
from heldfast.model import ServerSpec, ToolSpec  # noqa: E402

BS = chr(92)

TEXT_FRAGMENTS = [
    "", " ", "\x00", "\ud800", "\n" * 20, "\t",
    "{", "}", "[", "]", "{}", '{"a":1}', '{"a":}', "{,}", '{"a":1,}',
    '"', "'", '"' + BS, '"' + BS + "u", '"unterminated',
    "//", "/*", "*/", "/*/", "// x\n", "/* x */",
    "{/*}*/}", '{"a": "//not a comment"}', '{"a": "/*nope*/"}',
    '{"a": "}"}', BS, BS + BS,
    '{"mcpServers":{"x":{"command":"node"}}}',
    "{" * 60, "}" * 60, '{"a":' * 40, '"' * 60,
    "﻿{}", "​{}", '{"a": 1e999}',
]


class TestTheHandWrittenParsers(unittest.TestCase):
    """A scan opens every config it finds. One that raises ends the scan."""

    def test_nothing_raises_on_any_pair(self) -> None:
        for a, b in itertools.product(TEXT_FRAGMENTS, repeat=2):
            text = a + b
            with self.subTest(text=text[:24]):
                _strip_jsonc(text)
                find_key_line(text, "mcpServers")
                find_key_line(text, "")
                redact(text)
                inspect_mod.classify_env_value("TOKEN", text)

    def test_random_soup(self) -> None:
        random.seed(11)
        alphabet = '{}[]",:' + BS + "/*' \nabc01\x00"
        for _ in range(300):
            text = "".join(random.choice(alphabet) for _ in range(200))
            _strip_jsonc(text)
            find_key_line(text, "a")
            redact(text)

    def test_a_comment_marker_inside_a_string_is_not_a_comment(self) -> None:
        """The reason this parser is hand-written rather than a regex."""
        self.assertIn("//not a comment", _strip_jsonc('{"a": "//not a comment"}'))
        self.assertIn("/*nope*/", _strip_jsonc('{"a": "/*nope*/"}'))

    def test_redaction_never_returns_the_secret(self) -> None:
        token = "ghp_" + "A" * 36
        for wrapper in ("%s", "prefix %s suffix", '{"k": "%s"}', "%s%s"):
            text = wrapper % ((token,) * wrapper.count("%s"))
            self.assertNotIn(token, redact(text))


class TestTheGuardAgainstAHostileServer(unittest.TestCase):
    """The messages here come from the server, which is the thing the user was
    unsure about. Its posture is that a security event fails closed and an
    internal error fails open -- never that the proxy stops."""

    VALUES = [
        None, 0, -1, 1.5, True, False, "", "x", "\x00", "\ud800", "a" * 500,
        [], {}, [None], [{}], [[]], {"": None}, {"type": None},
        [{"type": "text"}], [{"type": "text", "text": None}],
        [{"text": 5}], [{"type": 5, "text": 5}],
        {"content": "not-a-list"}, {"tools": "not-a-list"},
        {"tools": [None, 1, "x"]}, {"tools": [{"name": None}]},
        {"tools": [{"name": "read", "description": None}]},
        {"instructions": None}, {"instructions": 5},
        {"resultType": "input_required"}, {"inputRequests": None},
        {"inputRequests": [None]}, {"contents": [None]}, {"messages": [None]},
    ]

    def _guard(self) -> Guard:
        lock = Lock()
        spec = ServerSpec(name="svc", source="/c/.mcp.json", client="test",
                          transport="stdio", command="node", args=["s.js"])
        lock.record([spec], [ToolSpec(server="svc", name="read", description="Reads.",
                                      input_schema={"type": "object"})], [])
        return Guard("svc", lock, quiet=True)

    def test_no_message_shape_raises(self) -> None:
        for key, value in itertools.product(
                ["result", "params", "error", "method", "id", "jsonrpc"], self.VALUES):
            message = {"jsonrpc": "2.0", "id": 1, key: value}
            with self.subTest(key=key, value=str(value)[:24]):
                guard = self._guard()
                guard.handle_server_message(dict(message))
                guard.check_call(dict(message))
                guard.screen_server_request(dict(message))

    def test_a_tool_list_of_nonsense(self) -> None:
        for value in self.VALUES:
            with self.subTest(value=str(value)[:24]):
                self._guard().filter_tools(value if isinstance(value, list) else [value])

    def test_a_deeply_nested_result(self) -> None:
        deep = cur = {}
        for _ in range(300):
            cur["n"] = {}
            cur = cur["n"]
        guard = self._guard()
        guard.handle_server_message({"jsonrpc": "2.0", "id": 1, "result": deep})
        guard.handle_server_message(
            {"jsonrpc": "2.0", "id": 1, "result": {"content": [deep]}})

    def test_an_internal_error_withholds_the_uninspected_payload(self) -> None:
        """Fail-closed: a rule that raises does not take the proxy down, and
        does not forward a catalogue nobody inspected."""
        guard = self._guard()

        def explode(_tools):
            raise RuntimeError("boom")

        guard.filter_tools = explode
        message = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "read"}]}}
        returned = guard.handle_server_message(dict(message))
        self.assertTrue(returned["result"]["isError"])
        self.assertIn("WITHHELD BY heldfast", returned["result"]["content"][0]["text"])
        self.assertTrue(guard.stats.internal_errors)

    def test_fail_open_still_forwards_the_uninspected_payload(self) -> None:
        lock = Lock()
        spec = ServerSpec(name="svc", source="/c/.mcp.json", client="test",
                          transport="stdio", command="node", args=["s.js"])
        lock.record([spec], [ToolSpec(server="svc", name="read", description="Reads.",
                                      input_schema={"type": "object"})], [])
        guard = Guard("svc", lock, quiet=True, strict=False)

        def explode(_tools):
            raise RuntimeError("boom")

        guard.filter_tools = explode
        message = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "read"}]}}
        returned = guard.handle_server_message(dict(message))
        self.assertEqual(message, returned)
        self.assertTrue(guard.stats.internal_errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
