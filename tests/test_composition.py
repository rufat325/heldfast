"""Findings that only exist in the combination of servers.

Every other scanner in this space reads one server at a time, so it cannot see
these at all. What makes them worth having is also what makes them dangerous:
a rule about combinations fires on configurations where nothing is wrong,
unless the trigger is narrow.

So most of what is pinned here is silence. A filesystem server scoped to a
project directory, two servers in different clients, a denylist that merely
contains the letters of "allow" -- each of those has to produce nothing.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.model import ServerSpec, ToolSpec  # noqa: E402
from mcp_pin.rules import AuditContext, run_rules  # noqa: E402


def server(name: str, client: str = "claude-desktop", **kw) -> ServerSpec:
    return ServerSpec(name=name, source=f"/cfg/{client}.json", client=client,
                      transport="stdio", command=kw.pop("command", "npx"), **kw)


def tool(server_name: str, name: str, schema: dict | None = None) -> ToolSpec:
    return ToolSpec(server=server_name, name=name, description="Does a thing.",
                    input_schema=schema or {})


def ids(ctx: AuditContext, rule_id: str) -> list:
    return [f for f in run_rules(ctx) if f.rule_id == rule_id]


FETCH_SCHEMA = {"type": "object", "properties": {"url": {"type": "string"}}}


class TestToolShadowing(unittest.TestCase):
    def test_two_servers_in_one_client_sharing_a_name(self) -> None:
        ctx = AuditContext(
            servers=[server("notes"), server("helper")],
            tools=[tool("notes", "read_file"), tool("helper", "read_file")],
        )
        found = ids(ctx, "MCPA027")
        self.assertEqual(1, len(found))
        self.assertIn("read_file", found[0].evidence)
        self.assertIn("helper", found[0].evidence)

    def test_distinct_names_are_quiet(self) -> None:
        ctx = AuditContext(
            servers=[server("notes"), server("helper")],
            tools=[tool("notes", "read_file"), tool("helper", "write_file")],
        )
        self.assertEqual([], ids(ctx, "MCPA027"))

    def test_servers_in_different_clients_do_not_shadow(self) -> None:
        """Two clients are two agents. Neither can call the other's tool, so
        there is no ambiguity to report -- and reporting it would fire on
        anyone who runs the same server in Cursor and Claude Desktop."""
        ctx = AuditContext(
            servers=[server("notes", client="cursor"),
                     server("helper", client="claude-desktop")],
            tools=[tool("notes", "read_file"), tool("helper", "read_file")],
        )
        self.assertEqual([], ids(ctx, "MCPA027"))

    def test_one_server_reached_from_two_clients_is_not_shadowing(self) -> None:
        """The same server configured in two clients is one definition."""
        ctx = AuditContext(
            servers=[server("notes", client="cursor"),
                     server("notes", client="claude-desktop")],
            tools=[tool("notes", "read_file")],
        )
        self.assertEqual([], ids(ctx, "MCPA027"))

    def test_a_disabled_server_shadows_nothing(self) -> None:
        ctx = AuditContext(
            servers=[server("notes"), server("helper", disabled=True)],
            tools=[tool("notes", "read_file"), tool("helper", "read_file")],
        )
        self.assertEqual([], ids(ctx, "MCPA027"))

    def test_needs_probe_data(self) -> None:
        """Tool names are not in the config, so a scan without --probe is
        silent rather than guessing."""
        ctx = AuditContext(servers=[server("notes"), server("helper")])
        self.assertEqual([], ids(ctx, "MCPA027"))


class TestExfiltrationReach(unittest.TestCase):
    def test_home_directory_plus_an_arbitrary_destination(self) -> None:
        ctx = AuditContext(
            servers=[server("files", args=["-y", "@modelcontextprotocol/server-filesystem",
                                           "/home/dev"]),
                     server("web", args=["-y", "@modelcontextprotocol/server-fetch"])],
            tools=[tool("web", "fetch", FETCH_SCHEMA)],
        )
        found = ids(ctx, "MCPA028")
        self.assertEqual(1, len(found))
        self.assertIn("files", found[0].evidence)
        self.assertIn("web", found[0].evidence)

    def test_a_scoped_filesystem_server_is_quiet(self) -> None:
        """The whole point. A filesystem server pointed at a project directory
        is a correct configuration and must produce nothing, or the rule fires
        on every developer who has both servers installed."""
        ctx = AuditContext(
            servers=[server("files", args=["-y", "@modelcontextprotocol/server-filesystem",
                                           "/home/dev/projects/app"]),
                     server("web", args=["-y", "@modelcontextprotocol/server-fetch"])],
            tools=[tool("web", "fetch", FETCH_SCHEMA)],
        )
        self.assertEqual([], ids(ctx, "MCPA028"))

    def test_credential_directories_count_however_deep(self) -> None:
        ctx = AuditContext(
            servers=[server("files", args=["-y", "@modelcontextprotocol/server-filesystem",
                                           "/home/dev/.ssh"]),
                     server("web", args=["-y", "server-fetch"])],
            tools=[tool("web", "post", FETCH_SCHEMA)],
        )
        self.assertEqual(1, len(ids(ctx, "MCPA028")))

    def test_home_alone_is_not_a_finding(self) -> None:
        """Reading is not exfiltration without a way out."""
        ctx = AuditContext(
            servers=[server("files", args=["-y", "@modelcontextprotocol/server-filesystem",
                                           "~"])],
            tools=[tool("files", "read_file", {"properties": {"path": {}}})],
        )
        self.assertEqual([], ids(ctx, "MCPA028"))

    def test_egress_alone_is_not_a_finding(self) -> None:
        ctx = AuditContext(
            servers=[server("web", args=["-y", "@modelcontextprotocol/server-fetch"])],
            tools=[tool("web", "fetch", FETCH_SCHEMA)],
        )
        self.assertEqual([], ids(ctx, "MCPA028"))

    def test_capability_is_not_inferred_from_description_prose(self) -> None:
        """A tool that talks about fetching URLs but whose schema takes only
        text is not a destination. Inferring capability from prose is what
        makes other tools fire on everything."""
        chatty = ToolSpec(server="web", name="summarize",
                          description="Fetches the url, runs an http request, reads files.",
                          input_schema={"properties": {"text": {"type": "string"}}})
        ctx = AuditContext(
            servers=[server("files", args=["-y", "@modelcontextprotocol/server-filesystem",
                                           "~"]),
                     server("web", args=["-y", "something"])],
            tools=[chatty],
        )
        self.assertEqual([], ids(ctx, "MCPA028"))

    def test_the_pair_must_share_a_client(self) -> None:
        ctx = AuditContext(
            servers=[server("files", client="cursor",
                            args=["-y", "@modelcontextprotocol/server-filesystem", "~"]),
                     server("web", client="zed", args=["-y", "server-fetch"])],
            tools=[tool("web", "fetch", FETCH_SCHEMA)],
        )
        self.assertEqual([], ids(ctx, "MCPA028"))

    def test_one_server_holding_both_halves_is_not_this_rule(self) -> None:
        ctx = AuditContext(
            servers=[server("everything",
                            args=["-y", "@modelcontextprotocol/server-filesystem", "~"])],
            tools=[tool("everything", "fetch", FETCH_SCHEMA)],
        )
        self.assertEqual([], ids(ctx, "MCPA028"))

    def test_one_finding_per_pair_not_per_tool(self) -> None:
        ctx = AuditContext(
            servers=[server("files", args=["-y", "@modelcontextprotocol/server-filesystem",
                                           "~"]),
                     server("web", args=["-y", "server-fetch"])],
            tools=[tool("web", "fetch", FETCH_SCHEMA),
                   tool("web", "post", FETCH_SCHEMA),
                   tool("web", "put", FETCH_SCHEMA)],
        )
        self.assertEqual(1, len(ids(ctx, "MCPA028")))


class TestAllowlistBypass(unittest.TestCase):
    def test_git_on_an_allowlist(self) -> None:
        ctx = AuditContext(servers=[server("s", env={"ALLOWED_COMMANDS": "ls,cat,git"})])
        found = ids(ctx, "MCPA029")
        self.assertEqual(1, len(found))
        self.assertIn("git", found[0].evidence)

    def test_a_harmless_allowlist_is_quiet(self) -> None:
        ctx = AuditContext(servers=[server("s", env={"ALLOWED_COMMANDS": "ls,cat,wc,head"})])
        self.assertEqual([], ids(ctx, "MCPA029"))

    def test_a_denylist_is_not_an_allowlist(self) -> None:
        """DISALLOWED contains the letters of ALLOW. Substring matching would
        read a denylist as an allowlist and invert its meaning."""
        for key in ("DISALLOWED_COMMANDS", "BLOCKED_BINARIES", "DENY_CMDS",
                    "FORBIDDEN_COMMANDS"):
            ctx = AuditContext(servers=[server("s", env={key: "git,find,env"})])
            self.assertEqual([], ids(ctx, "MCPA029"), key)

    def test_the_variable_must_be_about_commands(self) -> None:
        """ALLOWED_ORIGINS is an allowlist of something else entirely."""
        ctx = AuditContext(servers=[server("s", env={"ALLOWED_ORIGINS": "git,find"})])
        self.assertEqual([], ids(ctx, "MCPA029"))

    def test_paths_and_exe_suffixes_are_compared_by_binary(self) -> None:
        ctx = AuditContext(servers=[server(
            "s", env={"CMD_WHITELIST": "/usr/bin/ls C:\\Windows\\System32\\find.exe"})])
        self.assertEqual(1, len(ids(ctx, "MCPA029")))

    def test_several_separators(self) -> None:
        for value in ("ls,git", "ls;git", "ls:git", "ls git"):
            ctx = AuditContext(servers=[server("s", env={"ALLOWLIST_COMMANDS": value})])
            self.assertEqual(1, len(ids(ctx, "MCPA029")), value)

    def test_an_agent_tool_allowlist_belongs_to_another_rule(self) -> None:
        """In this ecosystem a "tool" is an agent tool, not a binary.
        ALLOWED_TOOLS=Bash is MCPA013's subject, and reporting it here as well
        would describe one fact twice in different words."""
        ctx = AuditContext(servers=[server("s", env={"ALLOWED_TOOLS": "Bash, Read"})])
        self.assertEqual([], ids(ctx, "MCPA029"))

    def test_names_taken_from_real_configs(self) -> None:
        """Collected by grepping the variable names other MCP projects
        actually use, rather than the ones that occurred to me."""
        for key in ("ALLOW_COMMANDS", "ALLOWED_COMMANDS", "MCP_ALLOWED_COMMANDS",
                    "CMD_WHITELIST", "EXEC_ALLOWLIST"):
            ctx = AuditContext(servers=[server("s", env={key: "ls,git"})])
            self.assertEqual(1, len(ids(ctx, "MCPA029")), key)
        for key in ("DISALLOW_COMMANDS", "allowed_sources", "list_allowed_directories",
                    "ALLOWED_ORIGINS", "NEVER_ALLOW_COMMANDS"):
            ctx = AuditContext(servers=[server("s", env={key: "ls,git"})])
            self.assertEqual([], ids(ctx, "MCPA029"), key)

    def test_a_shell_on_the_list_counts(self) -> None:
        ctx = AuditContext(servers=[server("s", env={"PERMITTED_BINARIES": "bash"})])
        self.assertTrue(ids(ctx, "MCPA029"))


class TestTheCleanCorpusStaysClean(unittest.TestCase):
    """These three rules are the most likely of any to become noise, so the
    ordinary shapes get their own guard beyond the fixture corpus."""

    def test_a_typical_developer_setup_reports_nothing(self) -> None:
        ctx = AuditContext(
            servers=[
                server("filesystem", args=["-y", "@modelcontextprotocol/server-filesystem",
                                           "/home/dev/code/app"]),
                server("github", args=["-y", "@modelcontextprotocol/server-github"],
                       env={"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}),
                server("postgres", args=["-y", "@modelcontextprotocol/server-postgres"]),
            ],
            tools=[tool("filesystem", "read_file", {"properties": {"path": {}}}),
                   tool("github", "create_issue", {"properties": {"title": {}}}),
                   tool("postgres", "query", {"properties": {"sql": {}}})],
        )
        for rule_id in ("MCPA027", "MCPA028", "MCPA029"):
            self.assertEqual([], ids(ctx, rule_id), rule_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
