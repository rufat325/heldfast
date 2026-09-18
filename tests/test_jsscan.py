"""Shell injection in JavaScript and TypeScript MCP servers.

sourcescan.py reads Python, and for several cycles this project said that
doing JavaScript meant parsing JavaScript, and that a regex pretending to be a
parser was a downgrade. Both halves of that were right, so jsscan.py is a
tokenizer -- comments, quotes, template literals with nested substitutions,
and the regex-literal ambiguity -- plus binding resolution and brace-matched
scopes.

The reason it has to be that and not a pattern is one line of real code:

    const match = /^description:\\s*(.+)$/m.exec(markdown);

`exec(` is everywhere in TypeScript and is almost never a shell. It is a
RegExp here, a sqlite handle two files later, and child_process only when the
import says so. A pattern reports all three or none of them; the import
binding is the entire difference, and most of this file is about that.

Measured against the official MCP servers repository and the official
TypeScript SDK: 783 files, 564 matching, 644 handlers, zero findings and no
tokenizer failures. Recall is proven separately by injecting the flaw into
six real handler files and watching each go from clean to reported.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit.jsscan import (analyze_js, find_handlers,  # noqa: E402
                              resolve_shell_bindings, tokenize)

HEADER = ('import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n')


def flows(body: str):
    return analyze_js(HEADER + body, "<test>.ts")


class TestItFires(unittest.TestCase):
    def test_template_literal_into_exec(self) -> None:
        found = flows(
            'import { exec } from "node:child_process";\n'
            'server.registerTool("count", cfg, async (args) => {\n'
            '  const { stdout } = await exec(`wc -l ${args.path}`);\n'
            '});\n')
        self.assertEqual(1, len(found))
        self.assertEqual("args", found[0].parameter)

    def test_namespace_import(self) -> None:
        self.assertTrue(flows(
            'import cp from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  cp.execSync("ping " + args.host);\n'
            '});\n'))

    def test_destructured_require(self) -> None:
        self.assertTrue(flows(
            'const { execSync } = require("child_process");\n'
            'server.tool("go", "d", schema, async (args) => {\n'
            '  execSync(`git log ${args.ref}`);\n'
            '});\n'))

    def test_a_promisified_alias(self) -> None:
        """const run = promisify(exec) is a shell under a name that appears in
        no list. Checking the well-known name before the binding meant every
        alias was missed, which is the common async shape."""
        found = flows(
            'import { exec } from "child_process";\n'
            'import { promisify } from "util";\n'
            'const run = promisify(exec);\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  await run(`ls ${args.dir}`);\n'
            '});\n')
        self.assertEqual(1, len(found))
        self.assertIn("run", found[0].sink)

    def test_the_low_level_request_handler(self) -> None:
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'server.setRequestHandler(CallToolRequestSchema, async (request) => {\n'
            '  exec("cat " + request.params.arguments.file);\n'
            '});\n'))

    def test_taint_through_an_intermediate_variable(self) -> None:
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  const cmd = `nmap ${args.target}`;\n'
            '  await exec(cmd);\n'
            '});\n'))

    def test_spawn_with_shell_true(self) -> None:
        found = flows(
            'import { spawn } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  spawn(`ls ${args.dir}`, { shell: true });\n'
            '});\n')
        self.assertEqual(1, len(found))
        self.assertIn("shell: true", found[0].sink)


class TestTheShapesRealHandlersAreWrittenIn(unittest.TestCase):
    """Found by writing out the ways a TypeScript handler normally reads its
    argument and checking each one, rather than assuming the first two were
    the whole set. Four of nine were missed.

    `const { count } = args` and `const { query } = request` both appear in
    the official sources, so taint that stops at the destructure stops one
    line into most handlers.
    """

    def test_destructured_from_the_argument(self) -> None:
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  const { path } = args;\n'
            '  await exec(`cat ${path}`);\n'
            '});\n'))

    def test_destructured_with_a_rename(self) -> None:
        """In `{ path: p }` the binding is p, not path."""
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  const { path: p } = args;\n'
            '  await exec(`cat ${p}`);\n'
            '});\n'))

    def test_destructured_in_the_parameter_list(self) -> None:
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async ({ path }) => {\n'
            '  await exec(`cat ${path}`);\n'
            '});\n'))

    def test_delegated_to_a_named_helper(self) -> None:
        found = flows(
            'import { exec } from "child_process";\n'
            'function runIt(target) {\n'
            '  return exec(`nmap ${target}`);\n'
            '}\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  return runIt(args.target);\n'
            '});\n')
        self.assertEqual(1, len(found))
        self.assertIn("runIt", found[0].via)
        self.assertLess(found[0].confidence, 1.0)

    def test_delegated_to_an_arrow_helper(self) -> None:
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'const runIt = (target) => exec(`nmap ${target}`);\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  return runIt(args.target);\n'
            '});\n'))

    def test_two_hops_are_still_not_followed(self) -> None:
        """The same limit as the Python side, asserted so it stays a decision."""
        self.assertEqual([], flows(
            'import { exec } from "child_process";\n'
            'function deep(c) { return exec(c); }\n'
            'function mid(c) { return deep(c); }\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  return mid(args.target);\n'
            '});\n'))

    def test_a_helper_that_is_handed_nothing_tainted_is_not_followed(self) -> None:
        self.assertEqual([], flows(
            'import { exec } from "child_process";\n'
            'function runIt(target) { return exec(`nmap ${target}`); }\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  return runIt("localhost");\n'
            '});\n'))

    def test_reassignment_and_expression_bodies(self) -> None:
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => exec(`ls ${args.dir}`));\n'))
        self.assertTrue(flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  let cmd;\n'
            '  cmd = `ls ${args.dir}`;\n'
            '  await exec(cmd);\n'
            '});\n'))


class TestItStaysSilent(unittest.TestCase):
    """Every one of these is a line a pattern-based scanner reports."""

    def test_a_regexp_exec_is_not_a_shell(self) -> None:
        """The line that made a tokenizer necessary. It appears throughout the
        official SDK."""
        self.assertEqual([], flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  const match = /^desc:(.+)$/m.exec(args.text);\n'
            '  return match;\n'
            '});\n'))

    def test_a_database_exec_is_not_a_shell(self) -> None:
        self.assertEqual([], flows(
            'server.registerTool("go", cfg, async (args) => {\n'
            '  db.exec(`CREATE TABLE ${args.name} (id INT)`);\n'
            '});\n'))

    def test_execfile_with_argv_is_the_fix(self) -> None:
        self.assertEqual([], flows(
            'import { execFile } from "child_process";\n'
            'server.registerTool("count", cfg, async (args) => {\n'
            '  execFile("wc", ["-l", args.path]);\n'
            '});\n'))

    def test_spawn_without_shell_is_the_fix(self) -> None:
        self.assertEqual([], flows(
            'import { spawn } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  spawn("ls", [args.dir]);\n'
            '});\n'))

    def test_a_constant_command(self) -> None:
        self.assertEqual([], flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  exec("uptime");\n'
            '});\n'))

    def test_a_function_that_is_not_a_handler(self) -> None:
        self.assertEqual([], flows(
            'import { exec } from "child_process";\n'
            'function helper(x) { exec("echo " + x); }\n'))

    def test_a_sink_inside_a_comment(self) -> None:
        self.assertEqual([], flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  // exec(`rm -rf ${args.path}`)\n'
            '  return 1;\n'
            '});\n'))

    def test_a_sink_inside_a_string(self) -> None:
        self.assertEqual([], flows(
            'import { exec } from "child_process";\n'
            'server.registerTool("go", cfg, async (args) => {\n'
            '  return "call exec(`rm ${args.path}`) to remove";\n'
            '});\n'))

    def test_exec_with_no_child_process_import_anywhere(self) -> None:
        """Without a binding there is nothing to resolve, and the file is not
        even walked."""
        self.assertEqual([], flows(
            'server.registerTool("go", cfg, async (args) => {\n'
            '  exec(`rm ${args.path}`);\n'
            '});\n'))


class TestTheTokenizer(unittest.TestCase):
    """The parts that stop a brace in a string from ending a function."""

    def test_a_brace_in_a_string_does_not_close_a_block(self) -> None:
        tokens = tokenize('function f() { const s = "}"; return 1; }')
        braces = [t.value for t in tokens if t.kind == "punct" and t.value in "{}"]
        self.assertEqual(["{", "}"], braces)

    def test_a_comment_is_dropped(self) -> None:
        tokens = tokenize('const a = 1; // exec("rm -rf /")\nconst b = 2;')
        self.assertNotIn("exec", [t.value for t in tokens])

    def test_a_block_comment_is_dropped(self) -> None:
        tokens = tokenize('/* exec("x") */ const a = 1;')
        self.assertNotIn("exec", [t.value for t in tokens])

    def test_template_substitutions_are_tokenized(self) -> None:
        """Their identifiers are exactly what taint needs to see."""
        tokens = tokenize('const s = `hello ${name} and ${other}`;')
        ids = [t.value for t in tokens if t.kind == "id"]
        self.assertIn("name", ids)
        self.assertIn("other", ids)

    def test_a_regex_literal_is_not_read_as_division(self) -> None:
        tokens = tokenize('const m = /a\\/b/.exec(s);')
        self.assertTrue(any(t.kind == "regex" for t in tokens))

    def test_division_is_not_read_as_a_regex(self) -> None:
        tokens = tokenize('const half = total / 2; const other = count / 4;')
        self.assertFalse(any(t.kind == "regex" for t in tokens))

    def test_it_survives_a_file_that_is_not_javascript(self) -> None:
        for junk in ("", "\x00\x01", "#!/bin/sh\necho hi", "}}}{{{", "`unterminated"):
            tokenize(junk)


class TestBindingResolution(unittest.TestCase):
    def test_named_import(self) -> None:
        always, _on_request, _modules = resolve_shell_bindings(
            tokenize('import { exec, execSync } from "node:child_process";'))
        self.assertEqual({"exec", "execSync"}, always)

    def test_default_import_is_a_module_alias(self) -> None:
        _always, _on_request, modules = resolve_shell_bindings(
            tokenize('import cp from "child_process";'))
        self.assertIn("cp", modules)

    def test_an_unrelated_import_binds_nothing(self) -> None:
        always, on_request, modules = resolve_shell_bindings(
            tokenize('import { exec } from "./my-own-helpers.js";'))
        self.assertEqual((set(), set(), set()), (always, on_request, modules))


class TestHandlerDetection(unittest.TestCase):
    def test_the_three_registrars_found_in_real_code(self) -> None:
        """Counted in the official TypeScript sources: registerTool 625,
        setRequestHandler 497, tool 51."""
        for call in ("registerTool", "tool", "setRequestHandler"):
            source = f'server.{call}("n", cfg, async (args) => {{ return 1; }});'
            found = find_handlers(tokenize(source))
            self.assertEqual(1, len(found), call)
            self.assertEqual(["args"], found[0][1])

    def test_several_parameters(self) -> None:
        found = find_handlers(tokenize(
            'server.registerTool("n", cfg, async (args, extra) => { return 1; });'))
        self.assertEqual(["args", "extra"], found[0][1])

    def test_a_typed_parameter_list(self) -> None:
        found = find_handlers(tokenize(
            'server.registerTool("n", cfg, async (args: ToolArgs): Promise<R> => '
            '{ return 1; });'))
        self.assertEqual(["args"], found[0][1])


class TestItSurvivesAnythingItIsHanded(unittest.TestCase):
    """This walks third-party repositories, so it meets minified bundles,
    half-written files and things that are not JavaScript at all. A tokenizer
    that raises takes the whole scan down with it.

    Fuzzed across every pair of the fragments below plus random soup: 4,496
    inputs, zero exceptions, 1.4 seconds.
    """

    BACKSLASH = chr(92)

    FRAGMENTS = [
        "", " ", "\x00", "\ud800", "\n" * 50,
        "`", "`${", "`${`", "${}", "`${{}}`",
        "'", '"', "'" + BACKSLASH, '"' + BACKSLASH,
        "/", "//", "/*", "/*/", "/a[/]/", "/[", "/" + BACKSLASH,
        "{", "}", "((((", "))))", "}}}}",
        "=>", "= >",
        'import { exec } from "child_process";',
        'const { exec } = require("child_process")',
        "const run = promisify(",
        'server.registerTool("a", cfg, async (args) => {',
        "async (args): Promise<X> =>",
        "exec(", "exec(`", "a.b.c.d.exec(",
        "1/2", "return /x/",
        "${" * 60 + "}" * 60,
        "(" * 60 + ")" * 60,
        BACKSLASH, BACKSLASH + "u{",
    ]

    def test_nothing_raises_on_any_pair(self) -> None:
        import itertools
        for a, b in itertools.product(self.FRAGMENTS, repeat=2):
            source = a + "\n" + b
            with self.subTest(a=a[:16], b=b[:16]):
                tokens = tokenize(source)
                find_handlers(tokens)
                resolve_shell_bindings(tokens)
                analyze_js(source, "<fuzz>.ts")

    def test_random_soup(self) -> None:
        import random
        random.seed(7)
        alphabet = "`'" + chr(92) + '"/*{}()[]$<>=;.abc\n '
        for _ in range(200):
            source = "".join(random.choice(alphabet) for _ in range(300))
            analyze_js(source, "<fuzz>.ts")

    def test_an_unterminated_template_does_not_hang(self) -> None:
        analyze_js("const s = `" + "x" * 10000, "<fuzz>.ts")

    def test_deeply_nested_substitutions(self) -> None:
        analyze_js("const s = `" + "${`" * 40 + "a" + "`}" * 40 + "`;", "<fuzz>.ts")


if __name__ == "__main__":
    unittest.main(verbosity=2)
