"""Writes into a project do not follow names a repository prepared.

The lockfile, a config bumped by `updates --apply` and the audit log's head
were written through fixed temporary names, and `write_text` follows a link:
a repository shipping `.mcp-pin.lock.tmp -> ~/.bashrc` had `approve` write
into the user's shell startup file. See heldfast/fsutil.py.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from heldfast.fsutil import atomic_write  # noqa: E402
from heldfast.lockfile import Lock  # noqa: E402
from heldfast.updates import rewrite_config  # noqa: E402


def can_symlink(where: Path) -> bool:
    probe = where / "probe-link"
    try:
        probe.symlink_to(where / "nowhere")
    except (OSError, NotImplementedError):
        return False
    probe.unlink()
    return True


class TestNoFixedTemporaryName(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_a_file_at_the_old_temporary_name_is_left_alone(self) -> None:
        # The old save wrote here, then renamed it away.
        planted = self.dir / ".mcp-pin.lock.tmp"
        planted.write_text("victim", encoding="utf-8")
        Lock().save(self.dir / ".mcp-pin.lock")
        self.assertEqual("victim", planted.read_text(encoding="utf-8"))
        self.assertTrue((self.dir / ".mcp-pin.lock").is_file())

    def test_nothing_is_left_behind(self) -> None:
        atomic_write(self.dir / "x.json", b"{}")
        self.assertEqual(["x.json"], sorted(p.name for p in self.dir.iterdir()))

    def test_a_planted_link_at_the_old_name_is_not_written_through(self) -> None:
        if not can_symlink(self.dir):
            self.skipTest("no symlinks without privilege here")
        victim = self.dir / "bashrc"
        victim.write_text("export PATH=/usr/bin\n", encoding="utf-8")
        (self.dir / ".mcp-pin.lock.tmp").symlink_to(victim)
        Lock().save(self.dir / ".mcp-pin.lock")
        self.assertEqual("export PATH=/usr/bin\n", victim.read_text(encoding="utf-8"))

    def test_a_lockfile_that_is_a_link_is_replaced_not_written_through(self) -> None:
        if not can_symlink(self.dir):
            self.skipTest("no symlinks without privilege here")
        victim = self.dir / "authorized_keys"
        victim.write_text("ssh-ed25519 AAAA mine\n", encoding="utf-8")
        (self.dir / ".mcp-pin.lock").symlink_to(victim)
        Lock().save(self.dir / ".mcp-pin.lock")
        self.assertEqual("ssh-ed25519 AAAA mine\n", victim.read_text(encoding="utf-8"))
        self.assertFalse((self.dir / ".mcp-pin.lock").is_symlink())

    def test_updates_leaves_a_linked_config_alone(self) -> None:
        if not can_symlink(self.dir):
            self.skipTest("no symlinks without privilege here")
        outside = self.dir / "outside.json"
        outside.write_text('{"args": ["pkg@1.0.0"]}', encoding="utf-8")
        link = self.dir / ".mcp.json"
        link.symlink_to(outside)
        self.assertIsNone(rewrite_config(link, "pkg@1.0.0", "pkg@1.1.0"))
        self.assertIn("pkg@1.0.0", outside.read_text(encoding="utf-8"))

    def test_updates_still_edits_an_ordinary_config(self) -> None:
        config = self.dir / ".mcp.json"
        config.write_text('{"args": ["pkg@1.0.0"]}', encoding="utf-8")
        self.assertIsNotNone(rewrite_config(config, "pkg@1.0.0", "pkg@1.1.0"))
        self.assertIn("pkg@1.1.0", config.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
