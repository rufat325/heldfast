"""Packed copies of the feed, rebuilt to the checkpoint they came from.

research/feed/archive.py packs the feed for keeping outside GitHub: a
snapshot of the whole tree, then one archive a day of what changed. These
hold that the archives are deterministic, that a snapshot and the dailies
after it rebuild the tree whose manifest digest the checkpoint states, and
that a rebuild cannot be steered outside its directory.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "research" / "feed"))

import archive  # noqa: E402
import watch  # noqa: E402


@unittest.skipUnless(shutil.which("git"), "git is not on PATH")
class TestArchives(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "feed"
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.commits = [self.commit({"README.md": b"# feed\n", "events/2026-09.jsonl": b'{"a": 1}\n',
                                     "state/a.json": b"{}\n", "state/b.json": b"{}\n"}),
                        self.commit({"events/2026-09.jsonl": b'{"a": 1}\n{"b": 2}\n',
                                     "tools/ab/x.json": b'{"name": "x"}\n'}, delete=["state/b.json"]),
                        self.commit({"README.md": b"# feed, day three\n",
                                     "checkpoints/2026-09-29.json": b"{}\n"})]

    def commit(self, files: dict, delete: list | None = None) -> str:
        git = ["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@t.invalid",
               "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false"]
        for rel, body in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        for rel in delete or []:
            (self.repo / rel).unlink()
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "feed"], check=True)
        return subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True).stdout.strip()

    def digest_at(self, commit: str) -> str:
        return watch.describe("d", commit, watch.git_files(str(self.repo), commit),
                              {})["manifest_sha256"]

    def members(self, path: Path) -> dict:
        with tarfile.open(path, "r:gz") as tar:
            return {m.name: tar.extractfile(m).read() for m in tar.getmembers()}

    def test_the_same_commit_gives_the_same_bytes(self) -> None:
        a, b = self.tmp / "a.tar.gz", self.tmp / "b.tar.gz"
        first = archive.snapshot(str(self.repo), self.commits[0], "2026-09-27", str(a))
        second = archive.snapshot(str(self.repo), self.commits[0], "2026-09-27", str(b))
        self.assertEqual(first, second)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(f"{first}  a.tar.gz\n", (self.tmp / "a.tar.gz.sha256").read_text())
        self.assertEqual(first, hashlib.sha256(a.read_bytes()).hexdigest())

    def test_members_are_sorted_and_carry_no_owner_or_clock(self) -> None:
        out = self.tmp / "s.tar.gz"
        archive.snapshot(str(self.repo), self.commits[0], "2026-09-27", str(out))
        with tarfile.open(out, "r:gz") as tar:
            infos = tar.getmembers()
        names = [i.name.encode() for i in infos]
        self.assertEqual(sorted(names), names)
        self.assertEqual({(0, 0, "", "", 0o644)}, {(i.uid, i.gid, i.uname, i.gname, i.mode)
                                                  for i in infos})
        self.assertEqual(1, len({i.mtime for i in infos}))
        raw = out.read_bytes()
        self.assertEqual(b"\x00\x00\x00\x00", raw[4:8])  # gzip mtime 0, as gzip -n

    def test_a_daily_archive_is_what_changed_and_what_went(self) -> None:
        out = self.tmp / "d.tar.gz"
        archive.daily(str(self.repo), self.commits[0], self.commits[1], "2026-09-28", str(out))
        got = self.members(out)
        self.assertEqual({"events/2026-09.jsonl", "tools/ab/x.json", archive.META, archive.DELETED},
                         set(got))
        self.assertEqual(b"state/b.json\n", got[archive.DELETED])

    def test_a_snapshot_and_the_dailies_after_it_rebuild_the_checkpointed_tree(self) -> None:
        paths = [self.tmp / "snapshot-2026-09.tar.gz", self.tmp / "daily" / "2026-09-28.tar.gz",
                 self.tmp / "daily" / "2026-09-29.tar.gz"]
        archive.snapshot(str(self.repo), self.commits[0], "2026-09-27", str(paths[0]))
        archive.daily(str(self.repo), self.commits[0], self.commits[1], "2026-09-28", str(paths[1]))
        archive.daily(str(self.repo), self.commits[1], self.commits[2], "2026-09-29", str(paths[2]))
        tree = self.tmp / "rebuilt"
        meta = archive.rebuild(str(tree), [str(p) for p in paths])
        self.assertEqual(self.commits[2], meta["commit"])
        rebuilt = hashlib.sha256(watch.manifest(archive.tree_files(str(tree)))).hexdigest()
        self.assertEqual(self.digest_at(self.commits[2]), rebuilt)
        self.assertFalse((tree / "state" / "b.json").exists())

    def test_a_daily_cannot_come_first_nor_a_snapshot_later(self) -> None:
        snap, day = self.tmp / "s.tar.gz", self.tmp / "d.tar.gz"
        archive.snapshot(str(self.repo), self.commits[0], "2026-09-27", str(snap))
        archive.daily(str(self.repo), self.commits[0], self.commits[1], "2026-09-28", str(day))
        with self.assertRaises(ValueError):
            archive.rebuild(str(self.tmp / "t1"), [str(day)])
        with self.assertRaises(ValueError):
            archive.rebuild(str(self.tmp / "t2"), [str(snap), str(snap)])

    def test_a_member_that_escapes_the_tree_is_refused(self) -> None:
        evil = self.tmp / "evil.tar.gz"
        archive.pack([("../outside", b"x"), archive._meta(kind="snapshot", commit="c", day="d")],
                     "2026-09-27", str(evil))
        with self.assertRaises(ValueError):
            archive.rebuild(str(self.tmp / "t"), [str(evil)])
        self.assertFalse((self.tmp / "outside").exists())


    def test_verify_needs_no_disk_and_says_what_differs(self) -> None:
        snap, day = self.tmp / "s.tar.gz", self.tmp / "d.tar.gz"
        archive.snapshot(str(self.repo), self.commits[0], "2026-09-27", str(snap))
        archive.daily(str(self.repo), self.commits[0], self.commits[1], "2026-09-28", str(day))
        good = {"feed_commit": self.commits[1], "manifest_sha256": self.digest_at(self.commits[1])}
        self.assertIsNone(archive.verify([str(snap), str(day)], good))
        self.assertIn("manifest", archive.verify([str(snap), str(day)],
                                                 dict(good, manifest_sha256="0" * 64)))
        self.assertIn("end at", archive.verify([str(snap)], good))

    def test_paths_that_differ_only_in_case_stay_two(self) -> None:
        """The feed holds such a pair. In memory they are two files; on a disk
        that folds case, rebuild refuses rather than write one over the other."""
        folded = self.tmp / "folded.tar.gz"
        archive.pack([("state/Zugabot.json", b"A"), ("state/zugabot.json", b"a"),
                      archive._meta(kind="snapshot", commit="c", day="d")], "2026-09-27", str(folded))
        tree, _ = archive.replay([str(folded)])
        self.assertEqual({"state/Zugabot.json": b"A", "state/zugabot.json": b"a"}, tree)
        with mock.patch.object(archive, "_case_insensitive", return_value=True):
            with self.assertRaisesRegex(ValueError, "differ only in case"):
                archive.rebuild(str(self.tmp / "t-folds"), [str(folded)])
        if not archive._case_insensitive(str(self.tmp)):
            archive.rebuild(str(self.tmp / "t-keeps"), [str(folded)])
            self.assertEqual(b"a", (self.tmp / "t-keeps" / "state" / "zugabot.json").read_bytes())


class TestTheCard(unittest.TestCase):
    def test_it_licenses_only_this_projects_own_data(self) -> None:
        front_matter = archive.CARD.split("---")[1]
        self.assertIn("\nlicense: cc-by-4.0\n", front_matter)
        self.assertIn("creativecommons.org/licenses/by/4.0", archive.CARD)
        self.assertIn("are not licensed by this\nproject", archive.CARD)
        self.assertIn("belong to their authors", archive.CARD)


if __name__ == "__main__":
    unittest.main()
