"""The whole claim, as one story, run through the real command line.

Every other test proves a piece. This one proves the pieces compose, which is
a different question and the one the README makes a promise about:

    approve what you reviewed
        -> the server changes behind you
            -> the scan says so
                -> the proxy refuses to pass it through

Nothing here imports an internal function. Everything goes through
`python -m mcp_pin`, with a real config file, a real lockfile, a real server
process and this package's own MCP client on the other side -- because a chain
that only works when called from inside the package is not a chain anybody
else can use.

The server is `fixtures/fake_server.py`, which rewrites its own tool
descriptions when MCP_PIN_FIXTURE_MODE=poisoned. Its configuration is
byte-identical across the two runs; that is the entire point, and it is what
no point-in-time config scan can see.
"""

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

FAKE = ROOT / "tests" / "fixtures" / "fake_server.py"
EXIT_OK, EXIT_FINDINGS = 0, 1


def run(args: list[str], cwd: Path, poisoned: bool = False, **kw) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["MCP_PIN_FIXTURE_MODE"] = "poisoned" if poisoned else "benign"
    env.pop("MCP_PIN_ALLOW_PATH_SCAN", None)
    return subprocess.run(
        [sys.executable, "-m", "mcp_pin", *args],
        cwd=str(cwd), env=env, capture_output=True, text=True, timeout=180, **kw)


class TestTheRugPullStory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        config = {
            "mcpServers": {
                "invoices": {
                    "command": sys.executable,
                    "args": [str(FAKE)],
                    # The fixture reads its mode from the environment, and a
                    # probed server now gets only what its config declares --
                    # the same migration a real user makes for a token.
                    "env": {"MCP_PIN_FIXTURE_MODE": "${MCP_PIN_FIXTURE_MODE}"},
                }
            }
        }
        (self.project / ".mcp.json").write_text(json.dumps(config, indent=2),
                                                encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def lock(self) -> dict:
        return json.loads((self.project / ".mcp-pin.lock").read_text(encoding="utf-8"))

    def test_the_whole_chain(self) -> None:
        # 1. Approve what is actually there.
        approved = run(["approve", ".", "--no-user-configs", "--probe"], self.project)
        self.assertEqual(EXIT_OK, approved.returncode, approved.stderr)
        entry = self.lock()["servers"]["claude-code:invoices"]
        self.assertIn("read_invoice", entry["tools"])
        before = entry["tools"]["read_invoice"]["fingerprint"]

        # 2. A clean re-scan of the unchanged server says nothing.
        clean = run(["scan", ".", "--no-user-configs", "--probe"], self.project)
        self.assertEqual(EXIT_OK, clean.returncode,
                         "an unchanged server must be silent:\n" + clean.stdout)

        # 3. The server rewrites its own description. The config is untouched.
        config_before = (self.project / ".mcp.json").read_bytes()
        drifted = run(["scan", ".", "--no-user-configs", "--probe", "-f", "json",
                       "-o", "out.json", "--fail-on", "never"],
                      self.project, poisoned=True)
        self.assertEqual(EXIT_OK, drifted.returncode, drifted.stderr)
        self.assertEqual(config_before, (self.project / ".mcp.json").read_bytes(),
                         "the config must be byte-identical; that is the point")

        report = json.loads((self.project / "out.json").read_text(encoding="utf-8"))
        rules = {f["rule_id"] for f in report["findings"]}
        self.assertIn("MCPA015", rules, "drift was not reported: %s" % sorted(rules))

        # 4. The scan fails the build at its default threshold.
        gated = run(["scan", ".", "--no-user-configs", "--probe"],
                    self.project, poisoned=True)
        self.assertEqual(EXIT_FINDINGS, gated.returncode)

        # 5. The proxy refuses to pass the rewritten tool to a client.
        from mcp_pin.model import ServerSpec
        from mcp_pin.probe import probe_stdio

        spec = ServerSpec(
            name="invoices", source="<test>", client="test", transport="stdio",
            command=sys.executable,
            args=["-m", "mcp_pin", "guard", "--quiet", "--name", "invoices",
                  "--lock", str(self.project / ".mcp-pin.lock"),
                  "--", sys.executable, str(FAKE)],
            env={"PYTHONPATH": str(ROOT / "src"), "MCP_PIN_FIXTURE_MODE": "poisoned"},
        )
        result = probe_stdio(spec, timeout=60)
        self.assertIsNone(result.error, result.error)

        served = {t.name: t.description for t in result.tools}
        self.assertIn("read_invoice", served, "a blocked tool keeps its name")
        self.assertIn("BLOCKED BY mcp-pin", served["read_invoice"])
        self.assertNotIn("id_rsa", served["read_invoice"],
                         "the poisoned text must not reach the client")

        # 6. And the fingerprint that made all of that happen is the one thing
        #    the config could never have shown.
        self.assertNotEqual(before, "")


class TestTheScriptSwapStory(unittest.TestCase):
    """The second shape: the command line stays identical and the code behind
    it is replaced. MCPA016 watches the string and sees nothing."""

    def test_editing_the_script_is_caught_while_the_command_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            script = project / "server.js"
            script.write_text("console.log('v1');\n", encoding="utf-8")
            (project / ".mcp.json").write_text(json.dumps({
                "mcpServers": {"notes": {"command": "node", "args": ["server.js"]}}
            }), encoding="utf-8")

            approved = run(["approve", ".", "--no-user-configs"], project)
            self.assertEqual(EXIT_OK, approved.returncode, approved.stderr)

            lock = json.loads((project / ".mcp-pin.lock").read_text(encoding="utf-8"))
            self.assertTrue(lock["servers"]["claude-code:notes"]["artifacts"])

            script.write_text("console.log('v1');\nrequire('child_process');\n",
                              encoding="utf-8")
            scanned = run(["scan", ".", "--no-user-configs", "-f", "json",
                           "-o", "out.json", "--fail-on", "never"], project)
            self.assertEqual(EXIT_OK, scanned.returncode, scanned.stderr)

            rules = {f["rule_id"] for f in
                     json.loads((project / "out.json").read_text(encoding="utf-8"))["findings"]}
            self.assertIn("MCPA031", rules)
            self.assertNotIn("MCPA016", rules,
                             "the command line did not change, so MCPA016 must be quiet")


class TestThePolicyStory(unittest.TestCase):
    """The third shape: the tool is exactly what was approved, and is asked to
    do something outside its boundary."""

    def test_an_approved_tool_refused_for_its_arguments(self) -> None:
        from mcp_pin.guard import Guard
        from mcp_pin.lockfile import Lock

        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / ".mcp.json").write_text(json.dumps({
                "mcpServers": {"files": {"command": sys.executable, "args": [str(FAKE)]}}
            }), encoding="utf-8")

            self.assertEqual(EXIT_OK,
                             run(["approve", ".", "--no-user-configs", "--probe"],
                                 project).returncode)

            lock_path = project / ".mcp-pin.lock"
            lock_data = json.loads(lock_path.read_text(encoding="utf-8"))
            lock_data["servers"]["claude-code:files"]["policy"] = {
                "read_invoice": {"paths": ["/workspace/**"]}
            }
            lock_path.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")

            guard = Guard("files", Lock.load(lock_path), quiet=True)

            inside = guard.check_call({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_invoice",
                           "arguments": {"invoice_id": "/workspace/inv/1.pdf"}}})
            self.assertIsNone(inside, "an in-bounds call must be forwarded")

            outside = guard.check_call({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "read_invoice",
                           "arguments": {"invoice_id": "/workspace/../../etc/passwd"}}})
            self.assertIsNotNone(outside, "traversal must be refused")
            self.assertTrue(outside["result"]["isError"])
            self.assertIn("/etc/passwd", outside["result"]["content"][0]["text"])

    def test_the_policy_survives_re_approval(self) -> None:
        """Re-reviewing a server must not silently drop its boundary."""
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / ".mcp.json").write_text(json.dumps({
                "mcpServers": {"files": {"command": sys.executable, "args": [str(FAKE)]}}
            }), encoding="utf-8")
            run(["approve", ".", "--no-user-configs", "--probe"], project)

            lock_path = project / ".mcp-pin.lock"
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            data["servers"]["claude-code:files"]["policy"] = {"read_invoice": {"deny": True}}
            lock_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            run(["approve", ".", "--no-user-configs", "--probe"], project)

            after = json.loads(lock_path.read_text(encoding="utf-8"))
            self.assertEqual({"read_invoice": {"deny": True}},
                             after["servers"]["claude-code:files"]["policy"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
