"""The Python half of the cross-language digest contract.

`js/mcp-pin-check/test.js` loads the same vectors and asserts the same
strings. Before RFC 8785 the two implementations were hand-matched and
disagreed on five ordinary inputs -- `1.0`, `1e16`, integers above 2**53,
`-0.0`, and keys mixing BMP with astral characters -- which meant the plugin
hook reported drift on tools that had been approved correctly.

The last test here shells out to Node and compares digests directly, so a
change to one implementation that is not made to the other fails the build
rather than surfacing later as a false rug-pull alert.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.digest import canonical_json, tool_digest  # noqa: E402

VECTORS = json.loads(
    (ROOT / "tests" / "golden" / "jcs_vectors.json").read_text(encoding="utf-8"))


class TestCanonicalVectors(unittest.TestCase):
    def test_canonical_strings(self) -> None:
        for case in VECTORS["canonical"]:
            with self.subTest(why=case["why"]):
                self.assertEqual(canonical_json(case["value"]), case["expect"])

    def test_refused_values(self) -> None:
        for case in VECTORS["refuses"]:
            with self.subTest(why=case["why"]):
                value = json.loads(case["json"])
                with self.assertRaises(ValueError):
                    canonical_json(value)


class TestSurrogatesDoNotCrash(unittest.TestCase):
    """The lone surrogate that used to take `approve` and `scan` down.

    `json.loads` accepts the escape, and the old digest then called
    `.encode("utf-8")` on it, which raises UnicodeEncodeError. One hostile
    server could end the whole run -- and in `scan` that meant every other
    server's findings were lost with it.
    """

    def test_lone_surrogate_hashes(self) -> None:
        tool = json.loads(r'{"name":"t","description":"hi \ud800 there"}')
        self.assertRegex(tool_digest(tool), r"^[0-9a-f]{64}$")

    def test_surrogate_is_escaped_not_raw(self) -> None:
        self.assertEqual(canonical_json("\ud800"), r'"\ud800"')

    def test_every_surrogate_in_the_range(self) -> None:
        for code in (0xD800, 0xDBFF, 0xDC00, 0xDFFF):
            with self.subTest(code=hex(code)):
                self.assertEqual(canonical_json(chr(code)), r'"\u%04x"' % code)


class TestNumberFormatting(unittest.TestCase):
    """The five divergences, named individually so a regression says which."""

    def test_integral_float_loses_its_decimal(self) -> None:
        self.assertEqual(canonical_json(1.0), "1")
        self.assertEqual(canonical_json({"minimum": 0.0}), '{"minimum":0}')

    def test_negative_zero_folds(self) -> None:
        self.assertEqual(canonical_json(-0.0), canonical_json(0.0))

    def test_1e16_is_written_in_full(self) -> None:
        self.assertEqual(canonical_json(1e16), "10000000000000000")

    def test_lossy_integer_is_refused(self) -> None:
        # 2**53 itself is exactly representable, so it is fine. 2**53+1 is
        # the first integer a double cannot hold, and refusing is what stops
        # a lockfile recording a digest the JavaScript checker would never
        # reproduce. The old magnitude-based guard got this wrong in the
        # other direction and refused 1e16, which is exact.
        self.assertEqual(canonical_json(2**53), "9007199254740992")
        self.assertEqual(canonical_json(10**16), "10000000000000000")
        with self.assertRaises(ValueError):
            canonical_json(2**53 + 1)

    def test_key_order_is_utf16_not_code_point(self) -> None:
        # U+E000 is below U+1F600 by code point, but its UTF-16 encoding
        # (0xE000) is above the high surrogate 0xD83D, so JCS puts the
        # emoji first. Sorting by code point would give the other order.
        self.assertEqual(canonical_json({"": 1, "\U0001f600": 2}),
                         '{"\U0001f600":2,"":1}')


class TestCrossLanguageParity(unittest.TestCase):
    """Run the JavaScript implementation and compare, digest for digest."""

    def setUp(self) -> None:
        if shutil.which("node") is None:
            self.skipTest("node is not installed")

    def _node(self, script: str) -> str:
        return subprocess.run(
            ["node", "-e", script], capture_output=True, text=True,
            encoding="utf-8", cwd=str(ROOT), timeout=60, check=True).stdout

    def test_digests_agree(self) -> None:
        script = (
            "const {toolDigest}=require('./js/mcp-pin-check/index.js');"
            "const v=JSON.parse(require('fs').readFileSync("
            "'tests/golden/jcs_vectors.json','utf8'));"
            "console.log(JSON.stringify(v.digests.map(d=>toolDigest(d.tool))));"
        )
        theirs = json.loads(self._node(script))
        ours = [tool_digest(case["tool"]) for case in VECTORS["digests"]]
        for case, mine, other in zip(VECTORS["digests"], ours, theirs):
            with self.subTest(why=case["why"]):
                self.assertEqual(mine, other)

    def test_canonical_strings_agree(self) -> None:
        script = (
            "const {canonical}=require('./js/mcp-pin-check/index.js');"
            "const v=JSON.parse(require('fs').readFileSync("
            "'tests/golden/jcs_vectors.json','utf8'));"
            "console.log(JSON.stringify(v.canonical.map(c=>canonical(c.value))));"
        )
        theirs = json.loads(self._node(script))
        for case, other in zip(VECTORS["canonical"], theirs):
            with self.subTest(why=case["why"]):
                self.assertEqual(case["expect"], other)

    def test_the_claude_code_plugin_agrees_too(self) -> None:
        """The third copy of the algorithm.

        The plugin cannot import the checker -- it ships on its own -- and it
        is the copy that decides whether a PreToolUse hook denies a call. When
        it disagreed, the hook reported drift on tools that had been approved
        correctly, which is the failure that started this.
        """
        script = (
            "const {canonical,toolDigest}="
            "require('./plugin/mcp-pin/scripts/lib.js');"
            "const v=JSON.parse(require('fs').readFileSync("
            "'tests/golden/jcs_vectors.json','utf8'));"
            "console.log(JSON.stringify({"
            "c:v.canonical.map(x=>canonical(x.value)),"
            "d:v.digests.map(x=>toolDigest(x.tool))}));"
        )
        theirs = json.loads(self._node(script))
        for case, other in zip(VECTORS["canonical"], theirs["c"]):
            with self.subTest(why=case["why"]):
                self.assertEqual(case["expect"], other)
        for case, other in zip(VECTORS["digests"], theirs["d"]):
            with self.subTest(why=case["why"]):
                self.assertEqual(tool_digest(case["tool"]), other)

    def test_every_copy_agrees_on_the_tool_vectors(self) -> None:
        """All three implementations, against the tool-body vectors.

        `jcs_vectors.json` pins canonicalization. It says nothing about
        `toolBody`, which is where the wire spellings are resolved -- and that
        is where they diverged: Python falls back on `is None`, both JS copies
        used `!== undefined`, so a tool carrying `input_schema: null` beside a
        real `inputSchema` hashed two different ways. A server chooses that
        field, and the two enforcement points would have answered differently
        about the same frame. Vectors 13 and 14 are that case.
        """
        script = (
            "const a=require('./js/mcp-pin-check/index.js');"
            "const b=require('./plugin/mcp-pin/scripts/lib.js');"
            "const fs=require('fs');"
            "const out={};"
            "for (const f of fs.readdirSync('tests/golden/tools').sort()) {"
            "  const v=JSON.parse(fs.readFileSync('tests/golden/tools/'+f,'utf8'));"
            "  out[v.id]=[a.toolDigest(v.tool), b.toolDigest(v.tool)];"
            "}"
            "console.log(JSON.stringify(out));"
        )
        theirs = json.loads(self._node(script))
        vectors = {v["id"]: v for v in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted((ROOT / "tests" / "golden" / "tools").glob("*.json")))}
        self.assertEqual(sorted(theirs), sorted(vectors))
        for vid, (checker, plugin) in theirs.items():
            with self.subTest(vector=vid):
                mine = tool_digest(vectors[vid]["tool"])
                self.assertEqual(vectors[vid]["digest"], mine)
                self.assertEqual(mine, checker)
                self.assertEqual(mine, plugin)


if __name__ == "__main__":
    unittest.main()
