"""Enforcement that is configured and can be walked around.

The lockfile is a committed artifact. It says which servers were approved,
what their arguments may be, which identity may reach them. None of that is in
the path unless the client actually talks to the gateway, and nothing checked
that it does -- so a repository could carry a reviewed, signed-off boundary
while the agent talked straight to the servers.

The failure is not an intrusion. It is following the README: you add the
gateway entry and leave the entries it was meant to replace, so every tool
appears twice and one copy is unenforced.

Most of this file is the cases where it must stay silent. A rule that fires on
a machine which has simply not adopted the gateway is reporting "you are not
using this tool", which is not a finding, and the permanent ignore line that
earns takes the real signal with it.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast.lockfile import Lock  # noqa: E402
from heldfast.model import ServerSpec  # noqa: E402
from heldfast.rules import run_rules  # noqa: E402
from heldfast.rules.base import AuditContext  # noqa: E402
from heldfast.enforcement import subcommand as _heldfast_subcommand  # noqa: E402


def server(name: str, command: str = "npx", args: list | None = None,
           client: str = "claude-code") -> ServerSpec:
    return ServerSpec(name=name, source="/proj/.mcp.json", client=client,
                      transport="stdio", command=command,
                      args=args if args is not None else ["-y", "@scope/srv"])


def fired(servers: list, approved: list | None = None) -> list:
    lock = Lock()
    if approved:
        lock.record(approved, [], [])
    ctx = AuditContext(servers=servers,
                       lock={"servers": lock.servers, "skills": lock.skills})
    return [f for f in run_rules(ctx) if f.rule_id == "MCPA032"]


GATEWAY = server("everything", "heldfast", ["gateway"])


class TestItFires(unittest.TestCase):
    def test_a_gateway_beside_the_server_it_fronts(self) -> None:
        direct = server("github")
        found = fired([GATEWAY, direct], approved=[direct])
        self.assertEqual(1, len(found))
        self.assertEqual("claude-code:github", found[0].server)

    def test_each_bypassable_server_is_named_separately(self) -> None:
        """Four servers and one summary line would leave you guessing which."""
        a, b = server("github"), server("postgres")
        found = fired([GATEWAY, a, b], approved=[a, b])
        self.assertEqual({"claude-code:github", "claude-code:postgres"},
                         {f.server for f in found})

    def test_the_remedy_says_what_the_gateway_already_exposes(self) -> None:
        direct = server("github")
        found = fired([GATEWAY, direct], approved=[direct])
        self.assertIn("github__", found[0].remediation)


class TestItStaysQuiet(unittest.TestCase):
    def test_no_gateway_configured_is_not_a_finding(self) -> None:
        """The overwhelmingly common case: this tool is not in the path at
        all. Reporting it would fire on every machine in the ecosystem."""
        direct = server("github")
        self.assertEqual([], fired([direct], approved=[direct]))

    def test_a_gateway_with_nothing_beside_it_is_the_correct_setup(self) -> None:
        self.assertEqual([], fired([GATEWAY], approved=[server("github")]))

    def test_an_unapproved_server_beside_a_gateway_is_not_this_rule(self) -> None:
        """The gateway would not have served it either, so removing the direct
        entry would take the server away rather than enforce it. MCPA014 is
        the finding there."""
        approved, stray = server("github"), server("stray")
        self.assertEqual([], [f for f in fired([GATEWAY, approved, stray],
                                               approved=[approved])
                              if f.server == "claude-code:stray"])

    def test_nothing_approved_means_nothing_to_bypass(self) -> None:
        self.assertEqual([], fired([GATEWAY, server("github")]))

    def test_a_gateway_in_another_client_does_not_cover_this_one(self) -> None:
        """Two clients are two agents. A gateway in Cursor says nothing about
        what Claude Code can reach, and claiming otherwise would report a
        bypass of a boundary that was never in front of it."""
        direct = server("github", client="claude-code")
        elsewhere = ServerSpec(name="everything", source="/p/cursor.json",
                               client="cursor", transport="stdio",
                               command="heldfast", args=["gateway"])
        self.assertEqual([], fired([elsewhere, direct], approved=[direct]))

    def test_a_disabled_direct_entry_is_not_reachable(self) -> None:
        direct = server("github")
        direct.disabled = True
        self.assertEqual([], fired([GATEWAY, direct], approved=[direct]))

    def test_a_guarded_entry_is_not_a_bypass(self) -> None:
        """`heldfast guard -- npx ...` is the enforcement, not a way round
        it. Reporting the fix is the failure mode this project is most
        careful about."""
        guarded = server("github", "heldfast",
                         ["guard", "--", "npx", "-y", "@scope/srv"])
        self.assertEqual([], fired([GATEWAY, guarded], approved=[guarded]))


class TestRecognisingItsOwnInvocation(unittest.TestCase):
    """The detection has to see through the shapes people actually write, or
    the rule fires on a correctly configured gateway it failed to recognise --
    which is the same bug pointed the other way."""

    def test_the_console_script(self) -> None:
        self.assertEqual("gateway", _heldfast_subcommand(
            server("g", "heldfast", ["gateway"])))

    def test_an_absolute_path_to_it(self) -> None:
        self.assertEqual("gateway", _heldfast_subcommand(
            server("g", "/usr/local/bin/heldfast", ["gateway", "--log", "t.jsonl"])))

    def test_the_windows_executable(self) -> None:
        self.assertEqual("gateway", _heldfast_subcommand(
            server("g", r"C:\Python\Scripts\heldfast.exe", ["gateway"])))

    def test_the_cmd_wrapper_windows_users_are_told_to_write(self) -> None:
        self.assertEqual("gateway", _heldfast_subcommand(
            server("g", "cmd", ["/c", "heldfast", "gateway"])))

    def test_python_dash_m(self) -> None:
        self.assertEqual("gateway", _heldfast_subcommand(
            server("g", "python", ["-m", "heldfast", "gateway"])))

    def test_flags_before_the_subcommand_are_skipped(self) -> None:
        self.assertEqual("gateway", _heldfast_subcommand(
            server("g", "uvx", ["--from", "heldfast", "heldfast", "gateway"])))

    def test_guard_is_told_apart_from_gateway(self) -> None:
        self.assertEqual("guard", _heldfast_subcommand(
            server("g", "heldfast", ["guard", "--", "npx"])))

    def test_something_else_entirely(self) -> None:
        self.assertEqual("", _heldfast_subcommand(server("g", "npx", ["-y", "pkg"])))

    def test_a_package_that_merely_mentions_the_name(self) -> None:
        """`npx -y heldfast-helper` is somebody else's package. Matching on a
        substring would hand any publisher the ability to look like the
        gateway, and a rule that can be disabled by naming a package is not a
        rule."""
        self.assertEqual("", _heldfast_subcommand(
            server("g", "npx", ["-y", "heldfast-helper"])))


if __name__ == "__main__":
    unittest.main(verbosity=2)
