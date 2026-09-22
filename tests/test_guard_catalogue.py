"""What the guard knows about the server's tools, and how it comes to know it.

Both findings here came from driving a real `@modelcontextprotocol/server-filesystem`
through `wrap` rather than from reading the code. Neither is visible to a
suite that launches `sys.executable` and calls `filter_tools` by hand.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin import guard as guard_mod  # noqa: E402
from mcp_pin.guard import Guard  # noqa: E402
from mcp_pin.lockfile import Lock  # noqa: E402
from mcp_pin.model import ToolSpec  # noqa: E402

TOOL = {"name": "read_text_file", "description": "Read a file.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}


def _lock(fingerprint: str | None = None) -> Lock:
    spec = ToolSpec(server="files", name=TOOL["name"],
                    description=TOOL["description"],
                    input_schema=TOOL["inputSchema"])
    return Lock(servers={"c:files": {
        "name": "files", "client": "c",
        "tools": {TOOL["name"]: {"fingerprint": fingerprint or spec.fingerprint()}}}})


def _call(name: str = "read_text_file") -> dict:
    return {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": name, "arguments": {"path": "a.txt"}}}


class TestTheRunnerIsResolvedBeforeSpawning(unittest.TestCase):
    """`npx` on Windows is `npx.cmd`, and CreateProcess cannot run a batch file.

    `mcp-pin wrap -- npx -y @scope/server@1.2.3` is the command the README
    leads with and the `.mcp.json` snippet beside it, and it died with
    "cannot launch 'npx'". `gateway` and `probe` both resolve through
    `shutil.which` first; the guard was the one launch path that did not. The
    matrix never caught it because every test here launches `sys.executable`,
    an absolute path that needs no resolving.
    """

    def test_the_program_is_looked_up_on_the_path(self) -> None:
        with mock.patch.object(guard_mod.shutil, "which",
                               return_value="/usr/local/bin/npx.cmd") as which, \
             mock.patch.object(guard_mod.subprocess, "Popen") as popen:
            guard_mod._launch(["npx", "-y", "@scope/server@1.2.3"])
        which.assert_called_once_with("npx")
        argv = popen.call_args[0][0]
        self.assertEqual("/usr/local/bin/npx.cmd", argv[0])
        self.assertEqual(["-y", "@scope/server@1.2.3"], argv[1:])

    def test_an_unresolvable_name_is_still_attempted(self) -> None:
        """So the OS error stays the one the operator needs to read, rather
        than being swallowed into a different message here."""
        with mock.patch.object(guard_mod.shutil, "which", return_value=None), \
             mock.patch.object(guard_mod.subprocess, "Popen") as popen:
            guard_mod._launch(["definitely-not-a-program"])
        self.assertEqual(["definitely-not-a-program"], popen.call_args[0][0])

    def test_the_pin_still_compares_the_tokens_the_operator_wrote(self) -> None:
        """Resolution happens at spawn and not a line earlier. `launch_mismatch`
        has to see `npx`, or every pinned command would mismatch itself."""
        from mcp_pin.lockfile import launch_mismatch
        approved = "npx -y @scope/server@1.2.3"
        self.assertIsNone(launch_mismatch(
            approved, ["npx", "-y", "@scope/server@1.2.3"]))


class TestTheGuardFetchesItsOwnCatalogue(unittest.TestCase):
    """The drift check used to depend on the client asking for the tool list.

    `filter_tools` is what compares a live tool against its approved
    fingerprint, and it only ran when a `tools/list` reply went past. Driving
    a real filesystem server with a deliberately drifted lock and no
    `tools/list` returned the file contents: the rug pull was caught only if
    the client happened to ask for the catalogue.

    Refusing the unlisted call on its own was not enough either -- a client
    that pipelines a call behind its own list would race it and have a
    legitimate call refused. So the guard asks for the catalogue itself, the
    way `gateway` always has.
    """

    INITIALIZE_REPLY = {"jsonrpc": "2.0", "id": 1, "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {"listChanged": True}},
        "serverInfo": {"name": "files", "version": "1"}}}

    def _proxying_guard(self, lock: Lock) -> tuple[Guard, list]:
        g = Guard("files", lock, quiet=True)
        sent: list = []
        g.respond_to_server = sent.append
        return g, sent

    def test_it_asks_once_the_server_has_initialised(self) -> None:
        g, sent = self._proxying_guard(_lock())
        forwarded = g.handle_server_message(dict(self.INITIALIZE_REPLY))
        self.assertIsNotNone(forwarded, "the initialize reply is the client's")
        self.assertEqual(1, len(sent))
        self.assertEqual("tools/list", sent[0]["method"])

    def test_it_asks_only_once(self) -> None:
        g, sent = self._proxying_guard(_lock())
        for _ in range(3):
            g.handle_server_message(dict(self.INITIALIZE_REPLY))
        self.assertEqual(1, len(sent))

    def test_its_own_answer_is_consumed_not_forwarded(self) -> None:
        """The client never asked for it, so it must not arrive."""
        g, sent = self._proxying_guard(_lock())
        g.handle_server_message(dict(self.INITIALIZE_REPLY))
        answer = {"jsonrpc": "2.0", "id": sent[0]["id"],
                  "result": {"tools": [dict(TOOL)]}}
        self.assertIsNone(g.handle_server_message(answer))
        self.assertIn(TOOL["name"], g._listed)

    def test_the_id_cannot_collide_with_a_clients(self) -> None:
        """A string id, and `_id_key` keys on type as well as value, so a
        client using 1, 2, 3 can never be answered with ours by mistake."""
        g, sent = self._proxying_guard(_lock())
        g.handle_server_message(dict(self.INITIALIZE_REPLY))
        self.assertIsInstance(sent[0]["id"], str)
        clients = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        self.assertIsNotNone(g.handle_server_message(clients))

    def test_a_drifted_tool_is_refused_without_the_client_listing(self) -> None:
        g, sent = self._proxying_guard(_lock(fingerprint="0" * 64))
        g.handle_server_message(dict(self.INITIALIZE_REPLY))
        g.handle_server_message({"jsonrpc": "2.0", "id": sent[0]["id"],
                                 "result": {"tools": [dict(TOOL)]}})
        refusal = g.check_call(_call())
        self.assertIsNotNone(refusal, "a drifted tool was callable")
        self.assertIn("changed since approval",
                      refusal["result"]["content"][0]["text"])

    def test_an_approved_tool_still_works_without_the_client_listing(self) -> None:
        g, sent = self._proxying_guard(_lock())
        g.handle_server_message(dict(self.INITIALIZE_REPLY))
        g.handle_server_message({"jsonrpc": "2.0", "id": sent[0]["id"],
                                 "result": {"tools": [dict(TOOL)]}})
        self.assertIsNone(g.check_call(_call()))

    def test_withholding_the_catalogue_is_not_a_way_round_the_pin(self) -> None:
        """A server that answers initialize and never answers tools/list has
        told us nothing about its tools, so it gets no calls either."""
        g, sent = self._proxying_guard(_lock())
        g.handle_server_message(dict(self.INITIALIZE_REPLY))
        self.assertEqual(1, len(sent))          # asked
        refusal = g.check_call(_call())         # never answered
        self.assertIsNotNone(refusal)
        self.assertIn("did not advertise",
                      refusal["result"]["content"][0]["text"])

    def test_a_guard_that_never_asked_leaves_it_to_the_policy(self) -> None:
        """Not reachable while proxying -- `adopt_catalogue` runs on the
        initialize reply -- but a `Guard` used as a library has no upstream
        channel, and the identity layer has nothing to say there. `gateway`
        drives `filter_tools` itself and never lands here."""
        g = Guard("files", _lock(), quiet=True)
        self.assertFalse(g._asked_for_catalogue)
        self.assertIsNone(g.check_call(_call()))

    def test_an_unapproved_name_is_refused_either_way(self) -> None:
        for asked in (False, True):
            with self.subTest(asked=asked):
                g, sent = self._proxying_guard(_lock())
                if asked:
                    g.handle_server_message(dict(self.INITIALIZE_REPLY))
                self.assertIsNotNone(g.check_call(_call("wipe_disk")))


if __name__ == "__main__":
    unittest.main()
