"""Reading the MCP server's own source for shell injection.

Every other rule reads what a server declares. This one reads what it is, and
the thing that makes it worth having is that it is parsed rather than grepped:
the argv form and shlex.quote() are the fixes, and a scanner that reports the
fix is worse than no scanner.

So the shape of this file is deliberate. The cases that must stay silent
outnumber the ones that must fire, and each silent case is a specific way a
line-based scanner gets it wrong.

Measured against 14 cloned MCP and security repositories: 536 Python files,
140 matching the marker, 29 holding real tool handlers, 41 handlers analyzed.
Three flows, all three inside one deliberately vulnerable fixture, and nothing
in the 38 servers that wrap nmap, sqlmap and ghidra -- those use the argv form
throughout, which is the right answer and has to read as silence.
"""

from __future__ import annotations

import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit.rules import AuditContext, run_rules  # noqa: E402
from mcp_audit.sourcescan import (analyze_source, looks_like_mcp_server,  # noqa: E402
                                  scan_source_tree)

HEADER = "from mcp.server.fastmcp import FastMCP\nimport subprocess, os, shlex, asyncio\nmcp = FastMCP('x')\n"


def flows(body: str):
    return analyze_source(HEADER + textwrap.dedent(body), "<test>")


class TestItFires(unittest.TestCase):
    def test_f_string_into_shell_true(self) -> None:
        found = flows('''
            @mcp.tool()
            def count(path: str):
                return subprocess.run(f"wc -l {path}", shell=True)
        ''')
        self.assertEqual(1, len(found))
        self.assertEqual("path", found[0].parameter)
        self.assertEqual("subprocess.run(shell=True)", found[0].sink)

    def test_concatenation_through_a_variable(self) -> None:
        found = flows('''
            @mcp.tool()
            def go(target: str):
                cmd = "nmap " + target
                os.system(cmd)
        ''')
        self.assertEqual(1, len(found))
        self.assertEqual("target", found[0].parameter)

    def test_percent_formatting(self) -> None:
        found = flows('''
            @mcp.tool()
            def go(target: str):
                out = subprocess.run("ping %s" % target, shell=True)
                return out
        ''')
        self.assertEqual(1, len(found), "a sink inside an assignment is still a sink")

    def test_the_low_level_argument_dict(self) -> None:
        """@server.call_tool() hands the handler the arguments straight off
        the wire, so the whole dict is model-controlled."""
        found = analyze_source(
            "from mcp.server import Server\nimport subprocess\nserver = Server('x')\n"
            "@server.call_tool()\n"
            "async def handle(name: str, arguments: dict):\n"
            "    subprocess.run(arguments['cmd'], shell=True)\n", "<test>")
        self.assertEqual(1, len(found))

    def test_asyncio_shell_variant(self) -> None:
        found = flows('''
            @mcp.tool()
            async def go(target: str):
                return await asyncio.create_subprocess_shell(f"ping {target}")
        ''')
        self.assertEqual(1, len(found))

    def test_one_hop_into_a_helper(self) -> None:
        """The low-level SDK shape is a dispatcher forwarding to helpers, and
        every server in the corpus is written that way. Stopping at the
        handler would find nothing outside a tutorial."""
        found = analyze_source(
            "from mcp.server import Server\nimport subprocess\nserver = Server('x')\n"
            "def run_scan(target):\n"
            "    return subprocess.run('nmap ' + target, shell=True)\n"
            "@server.call_tool()\n"
            "async def call_tool(name: str, arguments: dict):\n"
            "    return run_scan(arguments['target'])\n", "<test>")
        self.assertEqual(1, len(found))
        self.assertIn("run_scan", found[0].via)
        self.assertLess(found[0].confidence, 1.0, "a hop is less certain than a direct flow")


class TestItStaysSilent(unittest.TestCase):
    """Each of these is a way a line-based scanner reports the fix."""

    def test_the_argv_form_is_the_remediation(self) -> None:
        self.assertEqual([], flows('''
            @mcp.tool()
            def count(path: str):
                return subprocess.run(["wc", "-l", path], capture_output=True)
        '''))

    def test_shlex_quote_clears_the_taint(self) -> None:
        self.assertEqual([], flows('''
            @mcp.tool()
            def count(path: str):
                return subprocess.run(f"wc -l {shlex.quote(path)}", shell=True)
        '''))

    def test_asyncio_exec_is_argv_not_a_shell(self) -> None:
        self.assertEqual([], flows('''
            @mcp.tool()
            async def go(target: str):
                return await asyncio.create_subprocess_exec("ping", target)
        '''))

    def test_a_constant_command_is_not_tainted(self) -> None:
        self.assertEqual([], flows('''
            @mcp.tool()
            def go(target: str):
                os.system("uptime")
        '''))

    def test_a_function_that_is_not_a_tool(self) -> None:
        """Plenty of code shells out. Only a tool parameter is chosen by
        whatever is steering the agent."""
        self.assertEqual([], analyze_source(
            "import os\nfrom mcp.server import Server\n"
            "def helper(x):\n    os.system('echo ' + x)\n", "<test>"))

    def test_two_hops_are_not_followed(self) -> None:
        """A limit, asserted so it stays a decision rather than a surprise.
        Two hops needs a call graph and a half-built one invents paths."""
        self.assertEqual([], analyze_source(
            "from mcp.server.fastmcp import FastMCP\nimport os\nmcp = FastMCP('x')\n"
            "def deep(c):\n    os.system(c)\n"
            "def mid(c):\n    deep(c)\n"
            "@mcp.tool()\n"
            "def go(t: str):\n    mid(t)\n", "<test>"))

    def test_urllib_quote_is_not_a_shell_sanitizer(self) -> None:
        """Percent-encoding is not shell quoting. Treating every callable
        named quote as a sanitizer would hide findings behind a coincidence."""
        found = analyze_source(
            "from mcp.server.fastmcp import FastMCP\nimport os, urllib.parse\n"
            "mcp = FastMCP('x')\n"
            "@mcp.tool()\n"
            "def go(t: str):\n    os.system('echo ' + urllib.parse.quote(t))\n", "<test>")
        self.assertEqual(1, len(found))

    def test_a_file_that_does_not_parse_says_nothing(self) -> None:
        """Other people's repositories use syntax this interpreter may not
        have. An unparseable file is one we make no claim about."""
        self.assertEqual([], analyze_source("def broken(:\n  pass\n", "<test>"))


class TestDiscovery(unittest.TestCase):
    def test_the_marker_filter(self) -> None:
        self.assertTrue(looks_like_mcp_server("from mcp.server import Server"))
        self.assertTrue(looks_like_mcp_server("app = FastMCP('x')"))
        self.assertFalse(looks_like_mcp_server("import os\nprint(1)\n"))

    def test_scanning_a_tree(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pkg").mkdir()
            (root / "pkg" / "server.py").write_text(
                HEADER + "@mcp.tool()\ndef go(t: str):\n    os.system('ls ' + t)\n",
                encoding="utf-8")
            (root / "pkg" / "unrelated.py").write_text(
                "import os\nos.system('ls')\n", encoding="utf-8")
            found = scan_source_tree([root])
            self.assertEqual(1, len(found))
            self.assertTrue(found[0].path.endswith("server.py"))


class TestTheRule(unittest.TestCase):
    def test_a_flow_becomes_a_critical_finding(self) -> None:
        ctx = AuditContext(source_flows=flows('''
            @mcp.tool()
            def count(path: str):
                return subprocess.run(f"wc -l {path}", shell=True)
        '''))
        found = [f for f in run_rules(ctx) if f.rule_id == "MCPA030"]
        self.assertEqual(1, len(found))
        self.assertEqual("critical", found[0].severity.name.lower())
        self.assertIn("path", found[0].evidence)
        self.assertIn("shlex.quote", found[0].remediation)

    def test_no_flows_no_findings(self) -> None:
        ctx = AuditContext(source_flows=[])
        self.assertEqual([], [f for f in run_rules(ctx) if f.rule_id == "MCPA030"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
