"""What an approved tool may be asked to do.

The lockfile answers whether a tool is the one that was approved. That is
integrity, and it is a different question from authority: a `delete_file`
whose definition has not changed by a byte is still the tool that deletes
~/.ssh/id_rsa when something talks the agent into asking for it.

Most of these tests are the evasions. A path allowlist that compares the
string it was handed is decoration, because `/workspace/../../etc/passwd`
starts with `/workspace`; a domain allowlist that uses a substring lets
`api.github.com.evil.io` through; a SQL allowlist that reads the first word
misses `SELECT 1; DROP TABLE users`. Each of those has a test, because each
of them is how this kind of check is usually got wrong.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit.guard import Guard  # noqa: E402
from mcp_audit.lockfile import Lock  # noqa: E402
from mcp_audit.model import ServerSpec, ToolSpec  # noqa: E402
from mcp_audit.policy import Policy, normalize_path  # noqa: E402

POLICY = {
    "read_file": {"paths": ["/workspace/**", "/tmp"]},
    "wipe": {"deny": True},
    "query": {"sql": ["SELECT"]},
    "fetch": {"domains": ["api.github.com"]},
}


def check(tool: str, arguments: object):
    return Policy(POLICY).check(tool, arguments)


class TestPaths(unittest.TestCase):
    def test_inside_the_boundary(self) -> None:
        self.assertTrue(check("read_file", {"path": "/workspace/app/main.py"}))

    def test_a_bare_directory_authorises_what_is_under_it(self) -> None:
        self.assertTrue(check("read_file", {"path": "/tmp/session.json"}))

    def test_traversal_is_resolved_before_matching(self) -> None:
        """The one that matters. This string starts with /workspace."""
        decision = check("read_file", {"path": "/workspace/../../etc/passwd"})
        self.assertFalse(decision)
        self.assertIn("/etc/passwd", decision.reason)

    def test_a_prefix_is_not_a_parent(self) -> None:
        """/workspace-evil is not inside /workspace, though it starts the same."""
        self.assertFalse(check("read_file", {"path": "/workspace-evil/x"}))

    def test_home_is_not_inside_an_absolute_allowlist(self) -> None:
        self.assertFalse(check("read_file", {"path": "~/.ssh/id_rsa"}))

    def test_backslashes_are_the_same_path(self) -> None:
        self.assertTrue(check("read_file", {"path": r"\workspace\app\main.py"}))

    def test_a_second_path_in_an_unexpected_field(self) -> None:
        """Every string is checked, not the one the author had in mind."""
        self.assertFalse(check("read_file",
                               {"path": "/workspace/ok", "backup": "/etc/shadow"}))

    def test_a_path_nested_deep_in_the_arguments(self) -> None:
        self.assertFalse(check("read_file",
                               {"opts": {"targets": [{"file": "/etc/shadow"}]}}))

    def test_single_star_does_not_cross_a_directory(self) -> None:
        policy = Policy({"read_file": {"paths": ["/workspace/*"]}})
        self.assertTrue(policy.check("read_file", {"p": "/workspace/a"}))
        self.assertFalse(policy.check("read_file", {"p": "/workspace/a/b"}))

    def test_normalization_is_stable(self) -> None:
        self.assertEqual("/etc/passwd", normalize_path("/workspace/../../etc/passwd"))
        self.assertEqual("/a/b", normalize_path("/a//b/"))
        self.assertEqual("/~/.ssh", normalize_path("~/.ssh"))


class TestDomains(unittest.TestCase):
    def test_the_approved_host(self) -> None:
        self.assertTrue(check("fetch", {"url": "https://api.github.com/repos"}))

    def test_a_subdomain_of_an_approved_host(self) -> None:
        self.assertTrue(check("fetch", {"url": "https://x.api.github.com/y"}))

    def test_a_suffix_is_not_a_subdomain(self) -> None:
        """api.github.com.evil.io ends with the approved name and is not it."""
        self.assertFalse(check("fetch", {"url": "https://api.github.com.evil.io/x"}))

    def test_cloud_metadata(self) -> None:
        self.assertFalse(check("fetch", {"url": "http://169.254.169.254/latest/meta-data"}))

    def test_case_and_a_trailing_dot_are_the_same_host(self) -> None:
        self.assertTrue(check("fetch", {"url": "https://API.GITHUB.COM./repos"}))

    def test_a_non_url_string_is_not_a_destination(self) -> None:
        self.assertTrue(check("fetch", {"note": "see api.github.com for details"}))


class TestSql(unittest.TestCase):
    def test_a_permitted_operation(self) -> None:
        self.assertTrue(check("query", {"sql": "SELECT * FROM invoices"}))

    def test_a_forbidden_operation(self) -> None:
        decision = check("query", {"sql": "DELETE FROM customers"})
        self.assertFalse(decision)
        self.assertIn("DELETE", decision.reason)

    def test_stacked_statements(self) -> None:
        """Reading only the first keyword is how this check is usually wrong."""
        self.assertFalse(check("query", {"sql": "SELECT 1; DROP TABLE users"}))

    def test_a_semicolon_inside_a_string_literal_is_not_a_statement(self) -> None:
        self.assertTrue(check("query", {"sql": "SELECT name FROM t WHERE x = ';'"}))

    def test_a_leading_comment_does_not_hide_the_verb(self) -> None:
        self.assertFalse(check("query", {"sql": "/* harmless */ DROP TABLE t"}))


class TestScope(unittest.TestCase):
    def test_a_tool_with_no_rule_is_untouched(self) -> None:
        """Policy is an allowlist of constraints, not of tools. Tools govern
        themselves through the lockfile; this only adds argument limits where
        somebody wrote one."""
        self.assertTrue(check("some_other_tool", {"path": "/etc/passwd"}))

    def test_deny_needs_no_arguments(self) -> None:
        self.assertFalse(check("wipe", {}))

    def test_an_empty_policy_allows_everything(self) -> None:
        self.assertTrue(Policy({}).check("anything", {"path": "/etc/shadow"}))


class TestTheGuardEnforcesIt(unittest.TestCase):
    def _guard(self, **kw) -> Guard:
        lock = Lock()
        lock.servers = {"test:h": {"name": "h", "client": "test",
                                   "tools": {"read_file": {"fingerprint": "x"}},
                                   "policy": POLICY}}
        return Guard("h", lock, quiet=True, **kw)

    def _call(self, tool: str, arguments: dict) -> dict:
        return {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments}}

    def test_an_allowed_call_is_forwarded(self) -> None:
        self.assertIsNone(
            self._guard().check_call(self._call("read_file", {"p": "/workspace/a"})))

    def test_a_denied_call_is_answered_not_forwarded(self) -> None:
        guard = self._guard()
        refusal = guard.check_call(self._call("read_file", {"p": "/etc/shadow"}))
        self.assertIsNotNone(refusal)
        self.assertEqual(7, refusal["id"])
        self.assertTrue(refusal["result"]["isError"])
        self.assertIn("/etc/shadow", refusal["result"]["content"][0]["text"])
        self.assertEqual(["read_file: paths"], guard.stats.calls_denied)

    def test_the_refusal_is_a_result_not_a_protocol_error(self) -> None:
        """The model is shown why in the channel it reads answers in, so it
        can ask for something permitted. A JSON-RPC error tells it the
        connection broke and it retries the same call."""
        refusal = self._guard().check_call(self._call("wipe", {}))
        self.assertIn("result", refusal)
        self.assertNotIn("error", refusal)

    def test_only_tools_call_is_inspected(self) -> None:
        guard = self._guard()
        self.assertIsNone(guard.check_call({"jsonrpc": "2.0", "id": 1,
                                            "method": "tools/list", "params": {}}))

    def test_dry_run_reports_and_forwards(self) -> None:
        guard = self._guard(dry_run=True)
        self.assertIsNone(guard.check_call(self._call("read_file", {"p": "/etc/shadow"})))
        self.assertEqual(["read_file: paths"], guard.stats.calls_would_deny)
        self.assertEqual([], guard.stats.calls_denied)
        self.assertIn("WOULD be refused", guard.summary())

    def test_a_server_with_no_policy_does_no_argument_work(self) -> None:
        lock = Lock()
        lock.servers = {"test:h": {"name": "h", "client": "test", "tools": {}}}
        guard = Guard("h", lock, quiet=True)
        self.assertFalse(guard.call_policy)
        self.assertIsNone(guard.check_call(self._call("anything", {"p": "/etc/shadow"})))


class TestPolicySurvivesApproval(unittest.TestCase):
    def test_re_approving_does_not_discard_it(self) -> None:
        """Policy is written by a person; everything else in an entry is
        observed from the server and rebuilt. Losing it on `approve --probe`
        would silently drop the boundary at the moment someone re-reviews."""
        spec = ServerSpec(name="files", source="/c/.mcp.json", client="cursor",
                          transport="stdio", command="npx")
        lock = Lock()
        lock.record([spec], [ToolSpec(server="files", name="read", description="a")], [])
        lock.servers["cursor:files"]["policy"] = {"read": {"paths": ["/workspace/**"]}}

        lock.record([spec], [ToolSpec(server="files", name="read", description="b")], [])

        self.assertEqual({"read": {"paths": ["/workspace/**"]}},
                         lock.servers["cursor:files"]["policy"])

    def test_it_round_trips_through_json(self) -> None:
        lock = Lock()
        lock.servers = {"test:h": {"name": "h", "policy": POLICY}}
        restored = json.loads(json.dumps(lock.servers))
        self.assertTrue(Policy.from_lock_entry(restored["test:h"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestSuggestion(unittest.TestCase):
    """A policy nobody writes protects nothing, so one is proposed from the
    schemas a probe already saw. Everything proposed is a placeholder that
    refuses every call until edited: a generated policy that quietly permitted
    the machine's home directory would read like a boundary and be a rubber
    stamp."""

    def _tools(self):
        from mcp_audit.model import ToolSpec
        return [
            ToolSpec(server="s", name="read_file",
                     input_schema={"properties": {"path": {}}}),
            ToolSpec(server="s", name="fetch_page",
                     input_schema={"properties": {"url": {}}}),
            ToolSpec(server="s", name="run_query",
                     input_schema={"properties": {"sql": {}}}),
            ToolSpec(server="s", name="delete_repository",
                     input_schema={"properties": {"name": {}}}),
            ToolSpec(server="s", name="list_items",
                     input_schema={"properties": {"limit": {}}}),
        ]

    def _suggest(self):
        from mcp_audit.policy import suggest
        from mcp_audit.rules.annotations import MUTATING_VERBS
        return suggest(self._tools(), MUTATING_VERBS)

    def test_a_path_parameter_gets_a_path_limit(self) -> None:
        self.assertIn("paths", self._suggest()["read_file"])

    def test_a_url_parameter_gets_a_destination_limit(self) -> None:
        self.assertIn("domains", self._suggest()["fetch_page"])

    def test_a_query_parameter_gets_an_operation_limit(self) -> None:
        self.assertEqual(["SELECT"], self._suggest()["run_query"]["sql"])

    def test_a_destructive_name_is_proposed_as_denied(self) -> None:
        self.assertEqual({"deny": True}, self._suggest()["delete_repository"])

    def test_a_tool_with_nothing_risky_gets_no_rule(self) -> None:
        """Proposing something for every tool trains people to delete most of
        the file, and the ones they keep are the ones they stop reading."""
        self.assertNotIn("list_items", self._suggest())

    def test_the_placeholder_refuses_rather_than_permits(self) -> None:
        """If a generated value were permissive it would be worse than none."""
        policy = Policy(self._suggest())
        self.assertFalse(policy.check("read_file", {"path": "/home/me/notes.txt"}))
        self.assertFalse(policy.check("fetch_page", {"url": "https://example.com/x"}))
