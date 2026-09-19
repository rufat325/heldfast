"""A function that does not fit on one page is several functions.

NASA/JPL Power of Ten rule 4. Applied to the two files the freeze said to
split, not to the whole tree: argparse flag text is long because the flags
are long, and that lives in cli_parser.py on purpose.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIMIT = 60
TARGETS = (
    ROOT / "src" / "mcp_audit" / "cli.py",
    ROOT / "src" / "mcp_audit" / "guard.py",
)


def _too_long(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        n = end - node.lineno + 1
        if n > LIMIT:
            out.append(f"{path.name}:{node.name}:{node.lineno} is {n} lines")
    return out


class TestHandlersFitOnOnePage(unittest.TestCase):
    def test_cli_and_guard_functions_stay_small(self) -> None:
        long = []
        for path in TARGETS:
            self.assertTrue(path.is_file(), path)
            long.extend(_too_long(path))
        self.assertFalse(long, "split these, do not raise the limit:\n  " + "\n  ".join(long))


if __name__ == "__main__":
    unittest.main()
