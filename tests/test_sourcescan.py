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

from heldfast.rules import AuditContext, run_rules  # noqa: E402
from heldfast.sourcescan import (analyze_source, looks_like_mcp_server,  # noqa: E402
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


class TestTheWholeHandlerSurface(unittest.TestCase):
    """Tools are not the only thing that takes model-chosen input, which is
    the same mistake this project made once already one layer up.

    Found by enumerating the decorator styles in 1,711 Python files from the
    official MCP SDK, the official servers repository and FastMCP: 1,373
    @mcp.tool, and also 392 @mcp.resource and 174 @mcp.prompt that were going
    unread. A resource template binds its parameters from the URI the model
    asks for; a prompt's arguments arrive in prompts/get.
    """

    def test_a_resource_template_parameter_is_model_chosen(self) -> None:
        found = analyze_source(
            "from mcp.server.fastmcp import FastMCP\nimport subprocess\n"
            "mcp = FastMCP('x')\n"
            "@mcp.resource('notes://{name}')\n"
            "def note(name: str):\n"
            "    return subprocess.run(f'cat notes/{name}', shell=True)\n", "<t>")
        self.assertEqual(1, len(found))
        self.assertEqual("name", found[0].parameter)

    def test_a_prompt_argument_is_model_chosen(self) -> None:
        found = analyze_source(
            "from mcp.server.fastmcp import FastMCP\nimport os\n"
            "mcp = FastMCP('x')\n"
            "@mcp.prompt()\n"
            "def review(target: str):\n"
            "    os.system('git log ' + target)\n", "<t>")
        self.assertEqual(1, len(found))

    def test_the_low_level_read_resource_handler(self) -> None:
        found = analyze_source(
            "from mcp.server import Server\nimport subprocess\nserver = Server('x')\n"
            "@server.read_resource()\n"
            "async def read(uri: str):\n"
            "    return subprocess.run('cat ' + uri, shell=True)\n", "<t>")
        self.assertEqual(1, len(found))

    def test_a_cli_command_is_not_model_input(self) -> None:
        """click.command and app.command are driven by whoever is at the
        keyboard, not by whatever is steering the agent. 12 of them are in the
        corpus and none is an attack surface."""
        self.assertEqual([], analyze_source(
            "import click, os\nfrom mcp.server.fastmcp import FastMCP\n"
            "@click.command()\n"
            "def main(path):\n    os.system('ls ' + path)\n", "<t>"))

    def test_listing_handlers_take_no_input(self) -> None:
        self.assertEqual([], analyze_source(
            "from mcp.server import Server\nimport os\nserver = Server('x')\n"
            "@server.list_tools()\n"
            "async def ls():\n    os.system('echo hi')\n", "<t>"))

    def test_the_receiver_name_does_not_matter(self) -> None:
        """Real code writes mcp.tool, server.tool, app.tool, provider.tool,
        sub_app.tool and a dozen others; only the attribute is matched."""
        for receiver in ("mcp", "server", "app", "provider", "sub_app", "child"):
            found = analyze_source(
                "from mcp.server.fastmcp import FastMCP\nimport os\n"
                f"{receiver} = FastMCP('x')\n"
                f"@{receiver}.tool()\n"
                "def go(t: str):\n    os.system('echo ' + t)\n", "<t>")
            self.assertEqual(1, len(found), receiver)


class TestTheShapesRealPythonHandlersUse(unittest.TestCase):
    """The counterpart to the TypeScript exercise: write out how a handler
    normally touches its argument and check each one, instead of assuming the
    tested shapes are the whole set.

    Twelve of thirteen already worked, because ast.walk plus a recursive taint
    check covers most of Python's syntax for free. The thirteenth did not.
    """

    def _flows(self, body: str):
        return flows(body)

    def test_a_walrus_binds_a_name_like_any_assignment(self) -> None:
        self.assertTrue(self._flows('''
            @mcp.tool()
            def go(target: str):
                if (cmd := "ls " + target):
                    os.system(cmd)
        '''))

    def test_tuple_unpacking(self) -> None:
        self.assertTrue(self._flows('''
            @mcp.tool()
            def go(pair: str):
                a, b = pair, "x"
                os.system("echo " + a)
        '''))

    def test_dict_access_and_get(self) -> None:
        for expression in ('opts["target"]', 'opts.get("target", "")'):
            self.assertTrue(self._flows(f'''
                @mcp.tool()
                def go(opts: dict):
                    os.system("echo " + {expression})
            '''), expression)

    def test_augmented_assignment(self) -> None:
        self.assertTrue(self._flows('''
            @mcp.tool()
            def go(target: str):
                cmd = "nmap "
                cmd += target
                os.system(cmd)
        '''))

    def test_join_of_a_tainted_list(self) -> None:
        self.assertTrue(self._flows('''
            @mcp.tool()
            def go(parts: list):
                os.system(" ".join(parts))
        '''))

    def test_a_nested_function_inside_the_handler(self) -> None:
        self.assertTrue(self._flows('''
            @mcp.tool()
            def go(target: str):
                def inner():
                    os.system("ls " + target)
                inner()
        '''))

    def test_a_method_on_a_class(self) -> None:
        self.assertTrue(self._flows('''
            class Server:
                @mcp.tool()
                def go(self, target: str):
                    os.system("ls " + target)
        '''))

    def test_only_the_unsafe_branch_is_reported(self) -> None:
        found = self._flows('''
            @mcp.tool()
            def go(target: str, safe: bool):
                if safe:
                    subprocess.run(["ls", target])
                else:
                    os.system("ls " + target)
        ''')
        self.assertEqual(1, len(found))
        self.assertEqual("os.system()", found[0].sink)

    def test_inside_a_try_block(self) -> None:
        self.assertTrue(self._flows('''
            @mcp.tool()
            def go(target: str):
                try:
                    os.system("ls " + target)
                except Exception:
                    pass
        '''))

    def test_an_f_string_conversion_does_not_sanitize(self) -> None:
        """!r quotes for Python, not for a shell."""
        self.assertTrue(self._flows('''
            @mcp.tool()
            def go(target: str):
                os.system(f"ls {target!r}")
        '''))
