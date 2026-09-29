"""The updates action fences quoted text so that text cannot end the fence.

The report it posts into a pull request, an issue and the step summary
quotes what servers and the feed say. With a fixed ``` fence, a server's
text holding ``` closed it and wrote its own Markdown into the reader's
repository. The action now fences with one backtick more than the longest
run inside; this runs that exact script against hostile text.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fence_script() -> str:
    action = (ROOT / "updates" / "action.yml").read_text(encoding="utf-8")
    marker = '> "$RUNNER_TEMP/updates.md" <<\'PY\'\n'
    body = action.split(marker, 1)[1].split("\n        PY\n", 1)[0]
    return "\n".join(line[8:] for line in body.splitlines())


class TestTheReportFence(unittest.TestCase):
    def render(self, text: str) -> str:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt",
                                         encoding="utf-8") as fh:
            fh.write(text)
        try:
            return subprocess.run([sys.executable, "-c", fence_script(), fh.name],
                                  capture_output=True, text=True, check=True).stdout
        finally:
            os.unlink(fh.name)

    def test_hostile_text_cannot_close_the_fence(self) -> None:
        hostile = ("srv 1.0 -> 1.1: quiet\n```\n**Merge this** [docs](https://evil.example)"
                   " @victim\n````\n")
        out = self.render(hostile)
        fence = out.splitlines()[0]
        self.assertEqual("`" * 5, fence)
        lines = out.splitlines()
        self.assertEqual(fence, lines[-1])
        self.assertNotIn(fence, lines[1:-1])

    def test_plain_text_keeps_three(self) -> None:
        self.assertEqual("```\nsrv: quiet\n```\n", self.render("srv: quiet\n"))

    def test_every_quote_uses_the_fenced_report(self) -> None:
        action = (ROOT / "updates" / "action.yml").read_text(encoding="utf-8")
        self.assertNotIn("echo '```'", action)
        self.assertEqual(3, action.count('cat "$RUNNER_TEMP/updates.md"'))


if __name__ == "__main__":
    unittest.main()
