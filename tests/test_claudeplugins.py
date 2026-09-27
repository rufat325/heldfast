"""Claude Code plugins' MCP servers are found, approved and matched by the hook.

A plugin can bundle MCP servers, whose tools Claude Code names
`mcp__plugin_<plugin>_<server>__<tool>`. Discovery never saw them, so they
could not be approved and heldfast's own hook refused every call to them.
Everything here runs against a Claude Code config directory built in a
temporary folder; nothing on this machine is read.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import claudeplugins  # noqa: E402
from heldfast.lockfile import Lock  # noqa: E402
from heldfast.model import ToolSpec  # noqa: E402


def write(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")


class Installed(unittest.TestCase):
    """A config directory with one plugin installed, the way Claude Code
    records it (installed_plugins.json version 2)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config = Path(self._tmp.name) / ".claude"
        self.root = self.config / "plugins" / "cache" / "market" / "other-plugin" / "1.0.0"
        write(self.root / ".claude-plugin" / "plugin.json", {
            "name": "other-plugin",
            "mcpServers": [
                "./mcp/extra.json",
                {"db": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/db.js", "--v2"]}},
                "./bundle.mcpb",
            ]})
        write(self.root / ".mcp.json", {"mcpServers": {
            "db": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/old-db.js"]},
            "search": {"type": "http", "url": "https://search.example.com/mcp"}}})
        write(self.root / "mcp" / "extra.json", {
            "cache": {"command": "node", "args": ["server.js"],
                      "env": {"STORE": "${CLAUDE_PLUGIN_DATA}/store"}}})
        self.record({"version": 2, "plugins": {"other-plugin@market": [
            {"scope": "user", "installPath": str(self.root), "version": "1.0.0"}]}})
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.config)})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLAUDE_CODE_PLUGIN_CACHE_DIR", None)

    def record(self, body: dict) -> None:
        write(self.config / "plugins" / "installed_plugins.json", body)

    def found(self) -> dict:
        servers, self.notes = claudeplugins.plugin_servers()
        return {s.name: s for s in servers}


class TestDiscovery(Installed):
    def test_every_declared_server_is_found_under_its_plugin(self) -> None:
        found = self.found()
        self.assertEqual({"other-plugin:db", "other-plugin:search", "other-plugin:cache"},
                         set(found))
        self.assertEqual({"claude-code-plugin"}, {s.client for s in found.values()})
        self.assertEqual("claude-code-plugin:other-plugin:db", found["other-plugin:db"].identity())

    def test_the_manifest_replaces_the_default_file_for_the_same_name(self) -> None:
        db = self.found()["other-plugin:db"]
        self.assertEqual([str(self.root) + "/db.js", "--v2"], db.args)

    def test_plugin_paths_are_expanded_to_what_runs(self) -> None:
        cache = self.found()["other-plugin:cache"]
        self.assertTrue(cache.env["STORE"].endswith(
            os.path.join("plugins", "data", "other-plugin-market") + "/store"))
        self.assertEqual("http", self.found()["other-plugin:search"].transport)

    def test_a_bundle_is_named_as_not_read(self) -> None:
        self.found()
        self.assertTrue(any("bundle.mcpb" in n and "not read" in n for n in self.notes))

    def test_a_plugin_switched_off_is_skipped(self) -> None:
        write(self.config / "settings.json", {"enabledPlugins": {"other-plugin@market": False}})
        self.assertEqual({}, self.found())

    def test_default_off_counts_unless_the_user_turned_it_on(self) -> None:
        manifest = self.root / ".claude-plugin" / "plugin.json"
        body = json.loads(manifest.read_text(encoding="utf-8"))
        write(manifest, dict(body, defaultEnabled=False))
        self.assertEqual({}, self.found())
        write(self.config / "settings.json", {"enabledPlugins": {"other-plugin@market": True}})
        self.assertEqual(3, len(self.found()))

    def test_the_first_record_format_is_read_too(self) -> None:
        self.record({"version": 1, "plugins": {"other-plugin@market": {
            "installPath": str(self.root), "version": "1.0.0"}}})
        self.assertEqual(3, len(self.found()))

    def test_a_path_outside_the_plugin_is_not_followed(self) -> None:
        manifest = self.root / ".claude-plugin" / "plugin.json"
        write(manifest, {"name": "other-plugin", "mcpServers": "./../../escape.json"})
        write(self.root.parent.parent / "escape.json", {"x": {"command": "evil"}})
        found = self.found()
        self.assertNotIn("other-plugin:x", found)
        self.assertTrue(any("outside the plugin directory" in n for n in self.notes))

    def test_nothing_installed_is_nothing_found(self) -> None:
        (self.config / "plugins" / "installed_plugins.json").unlink()
        self.assertEqual(({}, []), (self.found(), self.notes))

    def test_a_broken_record_is_a_note_not_a_crash(self) -> None:
        (self.config / "plugins" / "installed_plugins.json").write_text("{", encoding="utf-8")
        self.assertEqual({}, self.found())
        self.assertTrue(self.notes)

    def test_scan_includes_them_with_user_configs_and_not_without(self) -> None:
        from heldfast import cli
        args = SimpleNamespace(no_user_configs=False, depth=1, exclude=[], paths=[])
        with mock.patch.object(cli, "discover_config_files", return_value=[]):
            out = cli.Collected()
            cli._collect_configs(out, [], args)
            self.assertEqual(3, len(out.servers))
            out = cli.Collected()
            cli._collect_configs(out, [], SimpleNamespace(**dict(vars(args), no_user_configs=True)))
            self.assertEqual([], out.servers)


class TestTheHookMatchesThem(Installed):
    """Approved, a plugin server's tools pass the hook like any other."""

    def decide(self, tool_name: str) -> str:
        proc = subprocess.run(
            ["node", str(ROOT / "plugin" / "heldfast" / "scripts" / "pre-tool-use.js")],
            input=json.dumps({"hook_event_name": "PreToolUse", "cwd": self._tmp.name,
                              "tool_name": tool_name, "tool_input": {}}),
            capture_output=True, text=True, cwd=self._tmp.name,
            env={k: v for k, v in os.environ.items() if k != "HELDFAST_ALLOW_UNPINNED"})
        if not proc.stdout.strip():
            return "allow"
        return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecisionReason"]

    def setUp(self) -> None:
        super().setUp()
        servers = list(self.found().values())
        db = next(s for s in servers if s.name == "other-plugin:db")
        lock = Lock()
        lock.record([db], [ToolSpec(server=db.identity(), name="query", description="Query.",
                                    input_schema={"type": "object"})], [])
        lock.save(Path(self._tmp.name) / ".mcp-pin.lock")

    def test_an_approved_plugin_tool_is_allowed(self) -> None:
        self.assertEqual("allow", self.decide("mcp__plugin_other-plugin_db__query"))

    def test_an_unapproved_tool_of_it_is_not(self) -> None:
        self.assertIn("'drop' was not present", self.decide("mcp__plugin_other-plugin_db__drop"))

    def test_a_server_of_it_the_lock_does_not_name_says_how_to_approve(self) -> None:
        reason = self.decide("mcp__plugin_other-plugin_search__find")
        self.assertIn("heldfast approve --probe", reason)


if __name__ == "__main__":
    unittest.main()
