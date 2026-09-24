"""One version number, stated in six places.

`release.yml` compares the tag against `pyproject.toml` and nothing else, so
the Python wheel is the only one that could not ship wrong. The plugin's
`plugin.json`, the two npm manifests and the string `heldfast-check --version`
prints were all free to drift -- and a verifier that reports a version it is
not is a verifier whose bug reports point at the wrong code. The JS checker in
particular exists to be run somewhere the Python wheel is not, so its idea of
its own version is the only one its user has.

Nothing enforced this because it is the kind of thing a person does by hand
while cutting a release, which is to say the kind of thing that is correct
until the one time it is not.

`mcp-server-fetch==0.1.4` in the fixtures is a pinned dependency of a test
config and has nothing to do with this project's version.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import __version__  # noqa: E402


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class TestEveryStatedVersionAgrees(unittest.TestCase):
    def test_the_wheel_is_the_one_the_tag_is_checked_against(self) -> None:
        """`release.yml` refuses a tag that does not match this line, so it is
        the version the other five have to follow."""
        found = re.search(r'^version = "([^"]+)"',
                          _read("pyproject.toml"), re.M)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(__version__, found.group(1))

    def test_the_plugin_manifest_agrees(self) -> None:
        manifest = json.loads(_read("plugin/heldfast/.claude-plugin/plugin.json"))
        self.assertEqual(__version__, manifest["version"])

    def test_both_npm_manifests_agree(self) -> None:
        for relative in ("js/heldfast-check/package.json",
                         "js/heldfast-wrap/package.json"):
            with self.subTest(package=relative):
                self.assertEqual(__version__, json.loads(_read(relative))["version"])

    def test_the_checker_prints_the_version_it_is(self) -> None:
        """`--version` is what a user quotes in a bug report."""
        printed = re.search(r'heldfast-check (\d+\.\d+\.\d+)',
                            _read("js/heldfast-check/bin.js"))
        self.assertIsNotNone(printed)
        assert printed is not None
        self.assertEqual(__version__, printed.group(1))


if __name__ == "__main__":
    unittest.main()
