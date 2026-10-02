"""lookup/all.json.gz: the plain record as a run of gzip members, one per bucket.

A gzip of the whole file shares no bytes with the previous day's, so git
stored every version in full. Compressed bucket by bucket, a bucket nothing
touched is the same bytes and git stores the day as a delta. These pin what
that costs a reader (it must follow the members), that the bytes are decided
by the input and the settings and nothing else, and what the collector says
when most buckets change bytes under unchanged text.

There is deliberately no golden hash of the compressed bytes: zlib builds
differ across operating systems, and the one place that writes the file is a
single runner. The tests below build the expectation independently instead.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "research" / "feed"))

import watch  # noqa: E402
from heldfast import feedlock  # noqa: E402

HEADER = bytes([0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x02, 0xFF])


def tool(i: int) -> dict:
    return {"name": f"tool_{i}", "description": f"Does thing number {i}.",
            "inputSchema": {"type": "object"}}


def members_of(blob: bytes) -> list[tuple[bytes, bytes]]:
    """(member bytes, inflated text) for each gzip member, parsed here from the
    format's own definition and not through watch."""
    out, pos = [], 0
    while pos < len(blob):
        assert blob[pos:pos + 10] == HEADER, f"member at {pos} has another header"
        deflate = zlib.decompressobj(-15)
        text = deflate.decompress(blob[pos + 10:])
        end = len(blob) - len(deflate.unused_data) + 8
        out.append((blob[pos:end], text))
        pos = end
    return out


def run(fn, *args) -> str:
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        fn(*args)
    return out.getvalue()


class Feed(unittest.TestCase):
    TOOLS = 60

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heldfast-gz-")
        self.addCleanup(self._tmp.cleanup)
        self.data = self.fresh("feed")
        self.publish(self.data, "pkg", range(self.TOOLS))

    def fresh(self, name: str) -> str:
        path = os.path.join(self._tmp.name, name)
        os.makedirs(path)
        return path

    def publish(self, data: str, package: str, which) -> str:
        snap = watch.snapshot(package, "1.0.0", "2026-10-01T00:00:00Z", [tool(i) for i in which])
        watch.write_catalogue(data, snap, [], measured_at="2026-10-01T06:00:00Z")
        return run(watch.write_lookup, data)

    def path(self, name: str, data: str = "") -> str:
        return os.path.join(data or self.data, "lookup", name)

    def gz(self, data: str = "") -> bytes:
        return Path(self.path("all.json.gz", data)).read_bytes()

    def plain(self, data: str = "") -> bytes:
        return Path(self.path("all.json", data)).read_bytes()


class TestFormat(Feed):
    def test_the_plain_record_is_the_one_the_feed_always_wrote(self) -> None:
        buckets = watch.lookup_buckets(self.data)
        lines = [f"{json.dumps(fp)}: {json.dumps(row, sort_keys=True)}"
                 for tools in buckets.values() for fp, row in tools.items()]
        expected = ('{"prefix_length": %d, "tools": {\n' % watch.LOOKUP_PREFIX
                    + ",\n".join(lines) + "\n}}\n").encode("utf-8")
        self.assertEqual(expected, self.plain())

    def test_every_reader_that_follows_the_members_gets_the_plain_record(self) -> None:
        plain, packed = self.plain(), self.gz()
        self.assertEqual(plain, gzip.decompress(packed))
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as fh:
            self.assertEqual(plain, fh.read())
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as fh:  # heldfast's bounded read
            self.assertEqual(plain, fh.read(len(plain) + 1))
        self.assertEqual(plain, b"".join(text for _, text in members_of(packed)))

    def test_it_is_the_header_one_member_per_bucket_and_the_footer(self) -> None:
        members = members_of(self.gz())
        buckets = len([n for n in os.listdir(self.path("")) if re.match(r"^[0-9a-f]{3}\.json$", n)])
        self.assertEqual(buckets + 2, len(members))
        self.assertTrue(members[0][1].startswith(b'{"prefix_length": 3, "tools": {\n'))
        self.assertEqual(b"}}\n", members[-1][1])
        seen = []
        for _, text in members[1:-1]:
            prefixes = {line[1:4] for line in text.splitlines()}
            self.assertEqual(1, len(prefixes), "a member holds one bucket")
            seen.append(prefixes.pop())
        self.assertEqual(sorted(seen), seen)
        self.assertEqual(len(seen), len(set(seen)))

    def test_every_member_has_the_fixed_header(self) -> None:
        """mtime 0, no name, XFL 2 (level 9), OS 255: nothing that varies."""
        for blob, _ in members_of(self.gz()):
            self.assertEqual("1f8b0800000000000" "2ff", blob[:10].hex())

    def test_every_member_is_what_the_fixed_settings_make_of_its_text(self) -> None:
        """Built here from the settings, not by calling the writer's function."""
        for blob, text in members_of(self.gz()):
            deflate = zlib.compressobj(9, zlib.DEFLATED, -15)
            expected = (HEADER + deflate.compress(text) + deflate.flush()
                        + zlib.crc32(text).to_bytes(4, "little")
                        + len(text).to_bytes(4, "little"))
            self.assertEqual(expected, blob)

    def test_an_empty_record_is_still_a_valid_one(self) -> None:
        empty = self.fresh("empty")
        run(watch.write_lookup, empty)
        self.assertEqual(self.plain(empty), gzip.decompress(self.gz(empty)))
        self.assertEqual({"prefix_length": 3, "tools": {}}, json.loads(self.plain(empty)))
        self.assertEqual(2, len(members_of(self.gz(empty))))

    def test_the_plain_record_parses_and_holds_every_definition(self) -> None:
        self.assertEqual(self.TOOLS, len(json.loads(gzip.decompress(self.gz()))["tools"]))

    def test_the_collector_accepts_it(self) -> None:
        out = run(watch.verify, type("A", (), {"data": self.data, "complete": True})())
        self.assertIn("verify: ok", out)

    def test_a_reader_that_stops_after_one_member_does_not_get_the_record(self) -> None:
        """What docs/LOOKUP.md tells readers: such a reader gets the first
        member, the header line, and nothing after it."""
        deflate = zlib.decompressobj(31)
        first = deflate.decompress(self.gz())
        self.assertEqual(b'{"prefix_length": 3, "tools": {\n', first)
        self.assertTrue(deflate.eof)
        self.assertNotEqual(self.plain(), first)


class TestDeterministic(Feed):
    def test_two_builds_in_one_process_give_identical_bytes(self) -> None:
        other = self.fresh("again")
        self.publish(other, "pkg", range(self.TOOLS))
        self.assertEqual(self.gz(), self.gz(other))
        self.assertEqual(self.plain(), self.plain(other))

    def test_writing_it_again_changes_nothing(self) -> None:
        before = self.gz()
        run(watch.write_lookup, self.data)
        self.assertEqual(before, self.gz())

    def test_a_bucket_nothing_touched_is_the_same_bytes_when_another_changes(self) -> None:
        before = dict((text, blob) for blob, text in members_of(self.gz()))
        self.publish(self.data, "other", [0])  # one definition gains a server
        after = dict((text, blob) for blob, text in members_of(self.gz()))
        kept = [text for text in before if text in after]
        self.assertGreater(len(kept), self.TOOLS - 3)
        for text in kept:
            self.assertEqual(before[text], after[text])
        self.assertLess(len(kept), len(before) + 1)

    def test_the_bytes_depend_on_the_text_and_the_settings_only(self) -> None:
        text = b'"abc": {"first_seen": "2026-10-01", "servers": 1}\n'
        self.assertEqual(watch.gzip_member(text), watch.gzip_member(text))
        self.assertNotEqual(watch.gzip_member(text), watch.gzip_member(text + b" "))
        self.assertEqual(HEADER, watch.GZIP_HEADER)
        self.assertEqual(9, watch.GZIP_LEVEL)


class TestMembersParser(Feed):
    def test_it_reads_back_what_was_written(self) -> None:
        parsed = watch._members(self.gz())
        assert parsed is not None
        self.assertEqual(self.plain(), b"".join(text for _, text in parsed.values()))

    def test_anything_else_is_not_this_layout(self) -> None:
        good = self.gz()
        old = gzip.compress(self.plain(), 9, mtime=0)
        flipped = bytearray(good)
        flipped[len(good) // 2] ^= 0xFF
        for label, blob in (("single member", old), ("truncated", good[:-5]),
                            ("corrupt", bytes(flipped)), ("garbage", b"not gzip"),
                            ("trailer", good[:-1] + bytes([good[-1] ^ 1]))):
            with self.subTest(label):
                self.assertIsNone(watch._members(blob))


class TestWarning(Feed):
    """Most buckets compressing to new bytes from the same text is what a zlib
    change on the runner looks like."""

    def rewrite(self) -> str:
        return run(watch.write_lookup, self.data)

    def recompress_differently(self):
        return mock.patch.object(watch.zlib, "Z_DEFAULT_STRATEGY", zlib.Z_HUFFMAN_ONLY)

    def test_an_unchanged_rebuild_says_nothing(self) -> None:
        self.assertNotIn("::warning::", self.rewrite())

    def test_a_different_deflate_of_the_same_text_is_reported(self) -> None:
        before = self.gz()
        with self.recompress_differently():
            out = self.rewrite()
        self.assertNotEqual(before, self.gz())  # the premise: the bytes did move
        self.assertEqual(gzip.decompress(before), gzip.decompress(self.gz()))
        self.assertIn("::warning::lookup/all.json.gz:", out)
        self.assertRegex(out, r"\d+ of \d+ buckets compressed to different bytes")
        self.assertIn("zlib", out)

    def test_the_first_build_and_the_old_single_member_file_say_nothing(self) -> None:
        fresh = self.fresh("first")
        self.assertNotIn("::warning::", self.publish(fresh, "pkg", range(self.TOOLS)))
        old = self.plain()
        Path(self.path("all.json.gz")).write_bytes(gzip.compress(old, 9, mtime=0))
        with self.recompress_differently():
            self.assertNotIn("::warning::", self.rewrite())

    def test_a_file_that_does_not_parse_says_nothing_and_is_replaced(self) -> None:
        Path(self.path("all.json.gz")).write_bytes(b"torn")
        self.assertNotIn("::warning::", self.rewrite())
        self.assertEqual(self.plain(), gzip.decompress(self.gz()))

    def test_a_day_when_the_text_really_moved_is_not_reported(self) -> None:
        """A second server showing every tool changes every line's server
        count, so no bucket has unchanged text to compare."""
        with self.recompress_differently():
            out = self.publish(self.data, "other", range(self.TOOLS))
        self.assertNotIn("::warning::", out)

    def previous_with(self, moved: int) -> tuple:
        """A previous file in which `moved` buckets hold the same text as now in
        other deflate bytes, and the rest are as written now."""
        pieces = watch.lookup_pieces(watch.lookup_buckets(self.data))
        members = [watch.gzip_member(p) for p in pieces]

        def other(text: bytes) -> bytes:
            deflate = zlib.compressobj(9, zlib.DEFLATED, -15, 8, zlib.Z_HUFFMAN_ONLY)
            return (HEADER + deflate.compress(text) + deflate.flush()
                    + zlib.crc32(text).to_bytes(4, "little") + len(text).to_bytes(4, "little"))

        previous = [other(p) if 1 <= i <= moved else m
                    for i, (p, m) in enumerate(zip(pieces, members))]
        for i in range(1, moved + 1):
            self.assertNotEqual(previous[i], members[i], "the premise: the bytes differ")
        path = os.path.join(self._tmp.name, "prev.gz")
        Path(path).write_bytes(b"".join(previous))
        return path, pieces, members

    def warned(self, moved: int) -> bool:
        path, pieces, members = self.previous_with(moved)
        out = io.StringIO()
        with redirect_stdout(out):
            watch.warn_if_recompressed(path, pieces, members)
        return "::warning::" in out.getvalue()

    def test_it_takes_more_than_half_of_the_buckets_not_half_or_a_few(self) -> None:
        self.assertEqual(self.TOOLS, len(watch.lookup_pieces(
            watch.lookup_buckets(self.data))) - 2)
        self.assertFalse(self.warned(1))
        self.assertFalse(self.warned(self.TOOLS // 2))
        self.assertTrue(self.warned(self.TOOLS // 2 + 1))
        self.assertTrue(self.warned(self.TOOLS))


class TestReaders(Feed):
    def test_heldfasts_own_fetch_reads_it(self) -> None:
        packed = self.gz()

        class Response:
            def __init__(self, body: bytes) -> None:
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *exc) -> bool:
                return False

            def read(self, n: int = -1) -> bytes:
                return self.body

        with mock.patch.object(feedlock, "urlopen", lambda *a, **k: Response(packed)):
            record = feedlock.get_json("https://x.example/lookup/all.json.gz")
        self.assertEqual(json.loads(self.plain()), record)

    @unittest.skipUnless(shutil.which("gzip"), "no gzip on this machine")
    def test_gnu_gzip_reads_it(self) -> None:
        packed = Path(self.path("all.json.gz"))
        done = subprocess.run([shutil.which("gzip") or "gzip", "-dc", str(packed)],
                              capture_output=True, check=True)
        self.assertEqual(self.plain(), done.stdout)
        subprocess.run([shutil.which("gzip") or "gzip", "-t", str(packed)], check=True)

    @unittest.skipUnless(shutil.which("node"), "no node on this machine")
    def test_nodes_gunzip_reads_it(self) -> None:
        script = ("const z=require('zlib'),c=require('crypto'),f=require('fs');"
                  "process.stdout.write(c.createHash('sha256')"
                  ".update(z.gunzipSync(f.readFileSync(process.argv[1]))).digest('hex'))")
        done = subprocess.run([shutil.which("node") or "node", "-e", script,
                               self.path("all.json.gz")], capture_output=True, check=True)
        self.assertEqual(hashlib.sha256(self.plain()).hexdigest(), done.stdout.decode())


if __name__ == "__main__":
    unittest.main()
