"""What the filesystem walk finds, and what it refuses to spend time on.

`mcp-pin` with no arguments scans the current directory. The README's first
command is exactly that, so the walk runs in whatever directory the reader
happens to be in -- quite often their home directory.

Measured there before these changes: 30 seconds in, the walk had covered 5,599
directories and was not finished, 64% of them under AppData, and it had made
67,188 is_file() calls that found nothing. Afterwards the same walk completes
in about a second.

These tests pin the three decisions that got it there. They are about cost as
much as correctness, because a scan that appears to hang does not get run
twice.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.discovery import _SKIP_DIRS, discover_config_files  # noqa: E402

CONFIG = '{"mcpServers": {"x": {"command": "node", "args": ["s.js"]}}}'


def write(path: Path, text: str = CONFIG) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestWhatItFinds(unittest.TestCase):
    def test_project_configs_at_several_depths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / ".mcp.json")
            write(root / "a" / "b" / ".cursor" / "mcp.json")
            write(root / "a" / ".vscode" / "mcp.json")

            found = discover_config_files([root], scan_user=False)
            paths = {p.name: c for p, c in found}

            self.assertEqual(3, len(found))
            self.assertEqual("claude-code", paths[".mcp.json"])

    def test_specific_client_beats_the_generic_filename(self) -> None:
        """mcp.json under .cursor/ is Cursor's, not 'generic'."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / ".cursor" / "mcp.json")

            (found,) = discover_config_files([root], scan_user=False)
            self.assertEqual("cursor", found[1])

    def test_depth_limit_is_honoured(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / "a" / "b" / "c" / "d" / ".mcp.json")

            self.assertEqual(1, len(discover_config_files([root], scan_user=False,
                                                          max_depth=6)))
            self.assertEqual(0, len(discover_config_files([root], scan_user=False,
                                                          max_depth=2)))


class TestWhatItRefusesToWalk(unittest.TestCase):
    """AppData and friends hold tens of thousands of cache directories. The
    client configs that genuinely live there are collected by exact path, so
    walking them costs everything and finds nothing."""

    def test_cache_directories_are_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / "AppData" / "Local" / "thing" / ".mcp.json")
            write(root / "node_modules" / "pkg" / ".mcp.json")
            write(root / ".cache" / "x" / ".mcp.json")
            write(root / "keep" / ".mcp.json")

            found = discover_config_files([root], scan_user=False)

            self.assertEqual(1, len(found))
            self.assertEqual("keep", found[0][0].parent.name)

    def test_an_excluded_prefix_is_not_walked(self) -> None:
        """The Security tab filled with fixture findings because self-scan
        walked tests/. --exclude is how that scan names the corpus."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / "tests" / "fixtures" / ".mcp.json")
            write(root / "keep" / ".mcp.json")
            found = discover_config_files(
                [root], scan_user=False, exclude=[root / "tests"])
            self.assertEqual(1, len(found))
            self.assertEqual("keep", found[0][0].parent.name)

    def test_a_pruned_name_is_still_scanned_when_named_directly(self) -> None:
        """Only directories *below* a root are pruned. Pointing mcp-pin at
        one has to keep working, or you could never scan inside AppData."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "AppData"
            write(root / "thing" / ".mcp.json")

            self.assertEqual(1, len(discover_config_files([root], scan_user=False)))

    def test_legacy_windows_junctions_are_pruned(self) -> None:
        """'Local Settings' points at AppData/Local and 'My Documents' at
        Documents. Pruning AppData while following the junction to it walked
        the same tree anyway -- which is what actually happened."""
        for name in ("Local Settings", "My Documents", "Application Data"):
            self.assertIn(name, _SKIP_DIRS)


def make_junction(link: Path, target: Path) -> None:
    """A junction, not a symlink. Creating one needs no elevation, and
    os.path.islink() reports False for it -- which is the whole problem."""
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise unittest.SkipTest("mklink failed: %s"
                                % (result.stdout or result.stderr).strip())


def count_visited_dirs(root: Path) -> int:
    """How many directories the walk actually enters.

    The findings dict is keyed on the resolved path, so a tree reached twice
    collapses to the same entries and the result looks correct either way.
    What a repeated walk costs is time, so that is what this measures.
    """
    visited: list[str] = []
    original = os.walk

    def counting(*args, **kwargs):
        for item in original(*args, **kwargs):
            visited.append(item[0])
            yield item

    os.walk = counting
    try:
        discover_config_files([root], scan_user=False)
    finally:
        os.walk = original
    return len(visited)


@unittest.skipUnless(sys.platform == "win32", "junctions are Windows-only")
class TestItDoesNotWalkTheSameTreeTwice(unittest.TestCase):
    """os.walk does not follow symlinks, so for a long time this looked
    unnecessary. It does follow junctions: os.path.islink() returns False for
    one, so walk's own guard never fires. That is how the home-directory walk
    ended up covering AppData/Roaming a second time under Application Data.
    """

    def test_a_junction_is_not_descended_into_a_second_time(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / "real" / ".mcp.json")
            for i in range(10):
                (root / "real" / ("d%d" % i)).mkdir()
            make_junction(root / "link", root / "real")

            # root, real, its ten children, and the junction seen once: 13.
            # Descending the junction as well would be 23.
            self.assertLessEqual(count_visited_dirs(root), 13)

    def test_a_junction_to_an_ancestor_terminates_early(self) -> None:
        """A cycle otherwise walks until the depth limit stops it."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / "a" / ".mcp.json")
            make_junction(root / "a" / "loop", root)

            self.assertLessEqual(count_visited_dirs(root), 3)


class TestItDoesNotStatEveryCandidateEverywhere(unittest.TestCase):
    """The walk used to test all 12 client paths against every directory it
    entered. That is 12 syscalls per directory to answer a question the
    directory listing already answers."""

    def test_no_candidate_stat_per_directory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i in range(40):
                (root / ("d%02d" % i)).mkdir()
            write(root / "d00" / ".mcp.json")

            calls = [0]
            original = pathlib.Path.is_file

            def counting(self, *a, **kw):  # noqa: ANN001
                calls[0] += 1
                return original(self, *a, **kw)

            pathlib.Path.is_file = counting
            try:
                found = discover_config_files([root], scan_user=False)
            finally:
                pathlib.Path.is_file = original

            self.assertEqual(1, len(found))
            self.assertLess(calls[0], 41,
                            "the walk is stat-ing candidates in directories "
                            "whose listing already rules them out")


if __name__ == "__main__":
    unittest.main(verbosity=2)
