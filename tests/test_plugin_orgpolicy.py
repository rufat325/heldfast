"""The Claude Code hook refuses what the organisation policy refuses.

`wrap` and `gateway` refuse to start a denied server. Claude Code starts its
servers itself, so the hook is the only place heldfast meets a call there,
and it has to give the answer `wrap` gives (the vectors in
test_orgpolicy_parity.py hold the two decisions together). These tests hold
the hook to the rest: the policy is read on every call, a policy that cannot
be read refuses everything, a config changed under an approved name is
judged by what it now starts, and an unpinned server cannot be waved past a
policy nothing can check it against.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast.lockfile import Lock  # noqa: E402
from heldfast.model import ServerSpec, ToolSpec  # noqa: E402
from heldfast.orgpolicy import SCHEMA  # noqa: E402

PLUGIN = ROOT / "plugin" / "heldfast" / "scripts"


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class HookCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.home = self.dir / "home"
        self.home.mkdir()
        self.project = self.dir / "project"
        self.project.mkdir()

    def approve(self, args: list[str], name: str = "files") -> None:
        spec = ServerSpec(name=name, source=str(self.project / ".mcp.json"), client="claude-code",
                          transport="stdio", command="npx", args=args)
        lock = Lock()
        lock.record([spec], [ToolSpec(server=spec.identity(), name="read",
                                      description="Read a file.")], [])
        lock.save(self.project / ".mcp-pin.lock")

    def policy(self, body: object) -> Path:
        path = self.dir / "org-policy.json"
        path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
        return path

    def run_hook(self, script: str, payload: dict, policy: Path | None,
                 extra: dict | None = None) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items()
               if k not in ("HELDFAST_ORG_POLICY", "HELDFAST_ALLOW_UNPINNED")}
        env.update(HOME=str(self.home), USERPROFILE=str(self.home))
        if policy is not None:
            env["HELDFAST_ORG_POLICY"] = str(policy)
        env.update(extra or {})
        return subprocess.run(["node", str(PLUGIN / script)], input=json.dumps(payload),
                              capture_output=True, text=True, cwd=str(self.project), env=env)

    def decide(self, tool: str, policy: Path | None, extra: dict | None = None) -> str:
        proc = self.run_hook("pre-tool-use.js", {"hook_event_name": "PreToolUse",
                                                  "cwd": str(self.project), "tool_name": tool,
                                                  "tool_input": {}}, policy, extra)
        self.assertEqual(0, proc.returncode, proc.stderr)
        if not proc.stdout.strip():
            return "allow"
        return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecisionReason"]


class TestTheHookRefusesWhatThePolicyRefuses(HookCase):
    DENY_POSTMARK = {"policy": SCHEMA, "name": "Acme",
                     "deny": [{"package": "npm:postmark-mcp", "versions": ["1.0.16"],
                               "reason": "backdoored"}]}

    def test_a_denied_release_is_refused_and_an_allowed_one_is_not(self) -> None:
        policy = self.policy(self.DENY_POSTMARK)
        self.approve(["-y", "postmark-mcp@1.0.16"])
        reason = self.decide("mcp__files__read", policy)
        self.assertIn("organisation policy Acme", reason)
        self.assertIn("backdoored", reason)
        self.approve(["-y", "postmark-mcp@1.0.15"])
        self.assertEqual("allow", self.decide("mcp__files__read", policy))

    def test_no_policy_changes_nothing(self) -> None:
        self.approve(["-y", "postmark-mcp@1.0.16"])
        self.assertEqual("allow", self.decide("mcp__files__read", None))

    def test_a_policy_that_cannot_be_read_refuses_every_call(self) -> None:
        """A policy someone deployed and this cannot read is not one to guess past."""
        self.approve(["-y", "pkg@1.0.0"])
        for body in ("{ not json", json.dumps({"policy": SCHEMA, "dney": []})):
            with self.subTest(body=body):
                reason = self.decide("mcp__files__read", self.policy(body))
                self.assertIn("could not be read", reason)
        self.assertIn("could not be read",
                      self.decide("mcp__files__read", self.dir / "missing.json"))

    def test_a_config_changed_under_an_approved_name_is_judged_by_what_it_starts(self) -> None:
        """The lock approved 1.0.15; the project's .mcp.json now starts 1.0.16."""
        self.approve(["-y", "postmark-mcp@1.0.15"])
        (self.project / ".mcp.json").write_text(json.dumps({"mcpServers": {"files": {
            "command": "npx", "args": ["-y", "postmark-mcp@1.0.16"]}}}), encoding="utf-8")
        self.assertIn("backdoored", self.decide("mcp__files__read",
                                                self.policy(self.DENY_POSTMARK)))

    def test_and_so_is_one_in_the_users_claude_json(self) -> None:
        self.approve(["-y", "postmark-mcp@1.0.15"])
        (self.home / ".claude.json").write_text(json.dumps({"projects": {str(self.project): {
            "mcpServers": {"files": {"command": "npx", "args": ["-y", "postmark-mcp@1.0.16"]}}}}}),
            encoding="utf-8")
        self.assertIn("backdoored", self.decide("mcp__files__read",
                                                self.policy(self.DENY_POSTMARK)))

    def test_an_unpinned_plugin_server_cannot_be_waved_past_a_policy(self) -> None:
        self.approve(["-y", "pkg@1.0.0"])
        tool = "mcp__plugin_other_db__query"
        extra = {"HELDFAST_ALLOW_UNPINNED": "plugin_other_db"}
        self.assertEqual("allow", self.decide(tool, None, extra))
        reason = self.decide(tool, self.policy({"policy": SCHEMA}), extra)
        self.assertIn("cannot be checked against it", reason)

    def test_the_hook_gives_wraps_answer(self) -> None:
        """The same lock, the same policy: `wrap` refuses to start what the hook
        refuses to call."""
        from heldfast import guard
        from heldfast.orgpolicy import load
        policy = self.policy(self.DENY_POSTMARK)
        self.approve(["-y", "postmark-mcp@1.0.16"])
        reason = self.decide("mcp__files__read", policy)
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = guard.run(["npx", "-y", "postmark-mcp@1.0.16"],
                             lock_path=self.project / ".mcp-pin.lock",
                             server_name="claude-code:files",
                             org_policies=[(load(policy), str(policy))])
        self.assertEqual(2, code)
        self.assertIn(reason.replace("heldfast: ", ""), err.getvalue())


class TestSessionStartSaysWhatIsInForce(HookCase):
    def test_it_names_the_policy_and_what_it_refuses(self) -> None:
        self.approve(["-y", "postmark-mcp@1.0.16"])
        policy = self.policy(TestTheHookRefusesWhatThePolicyRefuses.DENY_POSTMARK)
        out = self.run_hook("session-start.js", {"cwd": str(self.project)}, policy).stdout
        self.assertIn("organisation policy Acme", out)
        self.assertIn("refuses claude-code:files", out)

    def test_an_unreadable_policy_is_announced(self) -> None:
        self.approve(["-y", "pkg@1.0.0"])
        out = self.run_hook("session-start.js", {"cwd": str(self.project)},
                            self.policy("{")).stdout
        self.assertIn("every MCP call will be refused", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ---------------------------------------------------------------------------
# The JS has no place in tests/mutants.py, which mutates the Python package.
# These are its catalogue: each edit is a fail-open the tests above exist to
# stop, applied to a copy of the plugin, and the copy must then let through
# what the real one refuses.

JS_MUTANTS = (
    ("pre-tool-use.js", "    if (refused) return deny(refused);\n", "",
     "the hook asks the policy and ignores the answer"),
    ("orgpolicy.js", "  const named = env[ENV_VAR];\n", "  const named = null;\n",
     "HELDFAST_ORG_POLICY is never read"),
    ("orgpolicy.js", "      if (!(deny && row.kind === \"hosted\")) return false;\n",
     "      return false;\n",
     "an address parsers disagree on slips past a URL deny rule"),
    ("orgpolicy.js", "  if (t.includes(\"\\\\\") || /[\\x00-\\x20\\x7f]/.test(t)) return null;\n",
     "  if (/[\\x00-\\x20\\x7f]/.test(t)) return null;\n",
     "a backslash in a path is kept, so a URL rule matches a path Node never asks for"),
)


class TestJsFailOpenEditsAreCaught(HookCase):
    def mutated_decision(self, script: str, original: str, replacement: str,
                         tool: str, policy: Path) -> str:
        copy = self.dir / "plugin-copy"
        shutil.copytree(PLUGIN, copy)
        target = copy / script
        text = target.read_text(encoding="utf-8")
        self.assertEqual(1, text.count(original), f"{script}: the mutant's snippet is stale")
        target.write_text(text.replace(original, replacement), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != "HELDFAST_ALLOW_UNPINNED"}
        env.update(HOME=str(self.home), USERPROFILE=str(self.home),
                   HELDFAST_ORG_POLICY=str(policy))
        proc = subprocess.run(["node", str(copy / "pre-tool-use.js")], capture_output=True,
                              text=True, cwd=str(self.project), env=env,
                              input=json.dumps({"cwd": str(self.project), "tool_name": tool}))
        shutil.rmtree(copy)
        return "allow" if not proc.stdout.strip() else "deny"

    def test_every_mutant_lets_through_what_the_hook_refuses(self) -> None:
        cases = {
            "pre-tool-use.js": (["-y", "postmark-mcp@1.0.16"],
                                {"deny": [{"package": "npm:postmark-mcp"}]}),
        }
        for script, original, replacement, harm in JS_MUTANTS:
            with self.subTest(harm=harm):
                if "Node never asks for" in harm:
                    url = "https://mcp.example.com/ok/x\\..\\..\\admin"
                    rules = {"allow": [{"url": "https://mcp.example.com/ok/*"}],
                             "unlisted": "deny"}
                elif "address" in harm:
                    url = "https://evil.example\\@mcp.example.com/sse"
                    rules = {"deny": [{"url": "https://evil.example/*"}]}
                else:
                    url = None
                    rules = cases["pre-tool-use.js"][1]
                spec = ServerSpec(name="files", source=str(self.project / ".mcp.json"),
                                  client="claude-code",
                                  transport="http" if url else "stdio",
                                  command=None if url else "npx",
                                  args=[] if url else cases["pre-tool-use.js"][0], url=url)
                lock = Lock()
                lock.record([spec], [ToolSpec(server=spec.identity(), name="read")], [])
                lock.save(self.project / ".mcp-pin.lock")
                policy = self.policy(dict({"policy": SCHEMA}, **rules))
                self.assertNotEqual("allow", self.decide("mcp__files__read", policy),
                                    "the real hook should refuse this")
                self.assertEqual("allow", self.mutated_decision(
                    script, original, replacement, "mcp__files__read", policy),
                    f"survived: {harm}")
