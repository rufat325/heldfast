"""Tests for the client registry, `inspect`, and the rule catalog."""

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

from mcp_audit import clients, inspect as inspect_mod, rule_docs  # noqa: E402
from mcp_audit.model import ServerSpec, SkillSpec, ToolSpec  # noqa: E402
from mcp_audit.parsers import normalize_tool_grants, parse_config  # noqa: E402
from mcp_audit.rules import all_rules  # noqa: E402


class TestClientRegistry(unittest.TestCase):
    def test_every_client_has_somewhere_to_look(self) -> None:
        for c in clients.CLIENTS:
            self.assertTrue(c.user_paths or c.project_paths, f"{c.id} has no paths")

    def test_ids_and_names_are_unique(self) -> None:
        ids = [c.id for c in clients.CLIENTS]
        self.assertEqual(len(ids), len(set(ids)))
        names = [c.name for c in clients.CLIENTS]
        self.assertEqual(len(names), len(set(names)))

    def test_paths_resolve_without_raising(self) -> None:
        for c in clients.CLIENTS:
            for p in c.resolved_user_paths():
                self.assertIsInstance(p, Path)
                self.assertNotIn("{", str(p), f"{c.id} left an unexpanded placeholder")

    def test_unsupported_formats_are_declared_not_silently_skipped(self) -> None:
        for c in clients.CLIENTS:
            if c.unsupported_format:
                self.assertTrue(c.notes, f"{c.id} must explain why it is unparsed")
                self.assertFalse(clients.is_parseable(c.id))

    def test_unparseable_config_reports_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "config.yaml"
            p.write_text("mcpServers:\n  a: {}\n", encoding="utf-8")
            servers, errors = parse_config(p, "goose")
            self.assertEqual([], servers)
            self.assertEqual(1, len(errors))
            self.assertIn("YAML", errors[0])

    def test_known_clients_are_registered(self) -> None:
        for expected in ("claude-desktop", "claude-code", "cursor", "vscode",
                         "windsurf", "zed", "cline"):
            self.assertIn(expected, clients.BY_ID)

    def test_vscode_uses_its_own_server_key(self) -> None:
        self.assertIn("servers", clients.server_keys_for("vscode"))
        self.assertIn("context_servers", clients.server_keys_for("zed"))


class TestGrantNormalization(unittest.TestCase):
    """A bare string once made a skill report that it was granted the tool 'B'."""

    def test_comma_separated_string(self) -> None:
        self.assertEqual(["Bash", "Read"],
                         normalize_tool_grants({"allowed-tools": "Bash, Read"}))

    def test_list_form(self) -> None:
        self.assertEqual(["Read", "Bash(git log:*)"],
                         normalize_tool_grants({"allowed-tools": ["Read", "Bash(git log:*)"]}))

    def test_underscore_spelling_and_absence(self) -> None:
        self.assertEqual(["Read"], normalize_tool_grants({"allowed_tools": "Read"}))
        self.assertEqual([], normalize_tool_grants({}))


class TestInspect(unittest.TestCase):
    def _data(self, **kw):
        server = ServerSpec(
            name="svc", source="/tmp/.mcp.json", client="cursor", transport="stdio",
            command="npx", args=["-y", "pkg@1.0.0"], env=kw.get("env", {}),
        )
        skill = SkillSpec(name="sk", path="/tmp/SKILL.md",
                          frontmatter={"allowed-tools": "Bash, Read"}, body="x\ny")
        tools = [ToolSpec(server="svc", name="do", description="Does a thing.")]
        return inspect_mod.build([server], [skill], tools, [])

    def test_groups_by_client_with_display_name(self) -> None:
        d = self._data()
        self.assertIn("cursor", d["clients"])
        self.assertEqual("Cursor", d["clients"]["cursor"]["name"])

    def test_totals(self) -> None:
        d = self._data()
        self.assertEqual({"clients": 1, "servers": 1, "skills": 1, "tools": 1}, d["totals"])

    def test_grants_are_not_split_into_characters(self) -> None:
        self.assertEqual(["Bash", "Read"], self._data()["skills"][0]["allowed_tools"])

    def test_secret_values_are_never_printed(self) -> None:
        token = "ghp_" + "F" * 36
        d = self._data(env={"GITHUB_TOKEN": token})
        blob = json.dumps(d) + inspect_mod.render(d)
        self.assertNotIn(token, blob)
        self.assertEqual("LITERAL SECRET",
                         d["clients"]["cursor"]["servers"][0]["env"]["GITHUB_TOKEN"])

    def test_real_key_is_not_mislabelled_a_placeholder(self) -> None:
        """AWS's key format contains the word EXAMPLE; ordering must not hide it."""
        self.assertEqual("LITERAL SECRET",
                         inspect_mod.classify_env_value("AWS_KEY", "AKIAIOSFODNN7EXAMPLE"))

    def test_env_value_classes(self) -> None:
        self.assertEqual("reference", inspect_mod.classify_env_value("T", "${env:TOKEN}"))
        self.assertEqual("placeholder", inspect_mod.classify_env_value("T", "<your-token>"))
        self.assertEqual("empty", inspect_mod.classify_env_value("T", ""))

    def test_render_makes_no_judgement(self) -> None:
        text = inspect_mod.render(self._data())
        for word in ("CRITICAL", "HIGH", "finding", "vulnerab"):
            self.assertNotIn(word, text)


class TestRuleDocs(unittest.TestCase):
    def test_every_rule_is_documented(self) -> None:
        """Adding a rule without documenting it must fail the build."""
        missing = [r.id for r in all_rules() if rule_docs.get(r.id) is None]
        self.assertEqual([], missing, f"undocumented rules: {missing}")

    def test_no_orphan_docs(self) -> None:
        known = {r.id for r in all_rules()}
        orphans = [rid for rid in rule_docs.DOCS if rid not in known]
        self.assertEqual([], orphans, f"docs for rules that do not exist: {orphans}")

    def test_docs_have_substance(self) -> None:
        for rid, doc in rule_docs.DOCS.items():
            for field_name in ("what", "why", "example", "fix"):
                value = getattr(doc, field_name)
                self.assertTrue(value and len(value) > 15, f"{rid}.{field_name} is thin")

    def test_markdown_is_pure_ascii(self) -> None:
        """A shell redirect on Windows silently mangled non-ASCII bytes once."""
        md = rule_docs.render_markdown(all_rules())
        non_ascii = [c for c in md if ord(c) > 127]
        self.assertEqual([], non_ascii, f"non-ASCII in generated docs: {set(non_ascii)}")

    def test_checked_in_docs_are_current(self) -> None:
        path = ROOT / "docs" / "rules.md"
        self.assertTrue(path.is_file(), "docs/rules.md is missing")
        expected = rule_docs.render_markdown(all_rules())
        actual = path.read_text(encoding="utf-8")
        self.assertEqual(
            expected, actual,
            "docs/rules.md is stale; regenerate with "
            "`mcp-audit rules --markdown -o docs/rules.md`",
        )

    def test_every_rule_appears_in_the_markdown(self) -> None:
        md = rule_docs.render_markdown(all_rules())
        for r in all_rules():
            self.assertIn(f"## {r.id}", md)


class TestNewCommands(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), NO_COLOR="1")
        return subprocess.run([sys.executable, "-m", "mcp_audit", *args],
                              capture_output=True, text=True, env=env, cwd=str(ROOT))

    def test_explain_known_rule(self) -> None:
        r = self._run("explain", "mcpa015")
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertIn("rug pull", r.stdout.lower())
        self.assertIn("How to fix it", r.stdout)

    def test_explain_unknown_rule_exits_nonzero(self) -> None:
        r = self._run("explain", "MCPA999")
        self.assertNotEqual(0, r.returncode)
        self.assertIn("unknown rule id", r.stderr)

    def test_inspect_json(self) -> None:
        r = self._run("inspect", "tests/fixtures/vulnerable", "--no-user-configs", "-f", "json")
        self.assertEqual(0, r.returncode, r.stderr)
        doc = json.loads(r.stdout)
        self.assertIn("clients", doc)
        self.assertGreater(doc["totals"]["servers"], 0)

    def test_inspect_never_exits_nonzero_on_findings(self) -> None:
        """inspect reports no findings, so a dangerous config is still exit 0."""
        r = self._run("inspect", "tests/fixtures/vulnerable", "--no-user-configs")
        self.assertEqual(0, r.returncode)

    def test_rules_markdown_to_stdout(self) -> None:
        r = self._run("rules", "--markdown")
        self.assertEqual(0, r.returncode)
        self.assertIn("# Rules", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
