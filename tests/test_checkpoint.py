"""The feed's daily checkpoint, and what the job that can write takes from the
job that stamps it.

research/feed/watch.py describes a published feed commit by one digest; the
anchor job stamps that description with a third-party client and has no
write access; `admit-anchor` decides, with the code from main, what of its
upload reaches the feed. Nothing here contacts a calendar.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "research" / "feed"))

import watch  # noqa: E402

DAY = "2026-09-27"
COMMIT = "a" * 40
FILES = {
    "README.md": b"# MCP server tool changes\n",
    "events/2026-09.jsonl": b'{"package": "a"}\n{"package": "b"}\n\n',
    "state/pkg.json": b'{"package": "pkg"}\n',
    "checkpoints/2026-09-26.json": b'{"date": "2026-09-26"}\n',
}


def digest(files: dict) -> str:
    return hashlib.sha256(watch.manifest(files.items())).hexdigest()


def proof(target: bytes, complete: bool = False) -> bytes:
    """Shaped like a DetachedTimestampFile: header, version, sha256 op, digest."""
    tail = bytes.fromhex("0588960d73d71901") if complete else bytes.fromhex("83dfe30d2ef90c8e")
    return watch.OTS_SHA256 + hashlib.sha256(target).digest() + b"\xf0\x10" + b"n" * 16 + tail


def bundle(target: bytes, media: str = "application/vnd.dev.sigstore.bundle.v0.3+json") -> bytes:
    """Shaped like what cosign 3.1.3 sign-blob --bundle writes."""
    return json.dumps({"mediaType": media, "verificationMaterial": {}, "messageSignature": {
        "messageDigest": {"algorithm": "SHA2_256",
                          "digest": base64.b64encode(hashlib.sha256(target).digest()).decode()},
        "signature": "c2ln"}}).encode()


class TestManifest(unittest.TestCase):
    def test_the_same_files_in_any_order_give_the_same_digest(self) -> None:
        self.assertEqual(digest(FILES), digest(dict(reversed(list(FILES.items())))))

    def test_the_format_is_what_sha256sum_prints(self) -> None:
        # So a reader can rebuild it with standard tools (docs/TRANSPARENCY.md).
        line = watch.manifest([("README.md", b"x")]).decode()
        self.assertEqual(f"{hashlib.sha256(b'x').hexdigest()}  README.md\n", line)

    def test_sorted_by_path_bytes_not_by_arrival(self) -> None:
        lines = watch.manifest([("b", b""), ("a/z", b""), ("B", b"")]).decode().splitlines()
        self.assertEqual(["B", "a/z", "b"], [ln.split("  ", 1)[1] for ln in lines])

    def test_checkpoints_are_not_part_of_what_they_describe(self) -> None:
        without = {k: v for k, v in FILES.items() if not k.startswith("checkpoints/")}
        self.assertEqual(digest(without), digest(FILES))
        self.assertNotIn(b"checkpoints/", watch.manifest(FILES.items()))

    def test_any_byte_of_any_other_file_moves_it(self) -> None:
        for path in [p for p in FILES if not p.startswith("checkpoints/")]:
            with self.subTest(path):
                changed = dict(FILES)
                changed[path] = FILES[path][:-1] + bytes([FILES[path][-1] ^ 1])
                self.assertNotEqual(digest(FILES), digest(changed))

    def test_a_file_added_or_renamed_moves_it(self) -> None:
        self.assertNotEqual(digest(FILES), digest(dict(FILES, **{"state/new.json": b""})))
        renamed = {("state/other.json" if k == "state/pkg.json" else k): v for k, v in FILES.items()}
        self.assertNotEqual(digest(FILES), digest(renamed))

    def test_describe_counts_files_and_events(self) -> None:
        body = watch.describe(DAY, COMMIT, FILES.items(), {"heldfast": "x", "main_commit": ""})
        self.assertEqual(3, body["files"])
        self.assertEqual(2, body["events"])
        self.assertEqual(digest(FILES), body["manifest_sha256"])
        self.assertEqual(COMMIT, body["feed_commit"])


@unittest.skipUnless(shutil.which("git"), "git is not on PATH")
class TestFromGit(unittest.TestCase):
    """The checkpoint reads the commit, not whatever the checkout holds."""

    def setUp(self) -> None:
        # TemporaryDirectory, not mkdtemp + rmtree: git writes its objects
        # read-only, which rmtree cannot remove on Windows, and with
        # ignore_errors that left a folder behind on every run. The files the
        # tests write beside the repository (".." below) are inside it too.
        base = tempfile.TemporaryDirectory(prefix="heldfast-checkpoint-")
        self.addCleanup(base.cleanup)
        self.tmp = os.path.join(base.name, "feed")
        os.makedirs(self.tmp)
        git = ["git", "-C", self.tmp, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
               "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", self.tmp], check=True)
        for rel, body in FILES.items():
            os.makedirs(os.path.dirname(os.path.join(self.tmp, rel)) or self.tmp, exist_ok=True)
            with open(os.path.join(self.tmp, rel), "wb") as fh:
                fh.write(body)
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "feed"], check=True)
        self.commit = subprocess.run(["git", "-C", self.tmp, "rev-parse", "HEAD"], check=True,
                                     capture_output=True, text=True).stdout.strip()

    def run_checkpoint(self, out: str) -> dict:
        args = SimpleNamespace(data=self.tmp, commit="HEAD", day=DAY, generator_commit="b" * 40,
                               out=out)
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            self.assertEqual(0, watch.checkpoint(args))
        return dict(line.split("=", 1) for line in stdout.getvalue().splitlines())

    def test_the_commit_gives_the_digest_its_files_give(self) -> None:
        out = os.path.join(self.tmp, "..", os.path.basename(self.tmp) + "-cp.json")
        self.addCleanup(lambda: os.path.exists(out) and os.remove(out))
        printed = self.run_checkpoint(out)
        self.assertEqual(digest(FILES), printed["manifest_sha256"])
        self.assertEqual(self.commit, printed["feed_commit"])
        with open(out, "rb") as fh:
            body = fh.read()
        self.assertEqual(hashlib.sha256(body).hexdigest(), printed["checkpoint_sha256"])
        self.assertEqual({"heldfast", "main_commit"}, set(json.loads(body)["generator"]))

    def test_an_edit_in_the_working_tree_is_not_what_was_published(self) -> None:
        with open(os.path.join(self.tmp, "README.md"), "ab") as fh:
            fh.write(b"not committed\n")
        out = os.path.join(self.tmp, "..", os.path.basename(self.tmp) + "-cp2.json")
        self.addCleanup(lambda: os.path.exists(out) and os.remove(out))
        self.assertEqual(digest(FILES), self.run_checkpoint(out)["manifest_sha256"])

    def test_two_runs_write_the_same_bytes(self) -> None:
        outs = [os.path.join(self.tmp, "..", os.path.basename(self.tmp) + f"-r{i}.json")
                for i in (1, 2)]
        for out in outs:
            self.addCleanup(lambda o=out: os.path.exists(o) and os.remove(o))
            self.run_checkpoint(out)
        with open(outs[0], "rb") as a, open(outs[1], "rb") as b:
            self.assertEqual(a.read(), b.read())


class TestAdmitAnchor(unittest.TestCase):
    """What the job that can write takes from the job that ran the client."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="heldfast-anchor-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.data = os.path.join(self.tmp, "feed")
        self.incoming = os.path.join(self.tmp, "incoming")
        os.makedirs(os.path.join(self.data, "checkpoints"))
        self.checkpoint = watch._json_bytes(
            watch.describe(DAY, COMMIT, FILES.items(), {"heldfast": "x", "main_commit": ""}))
        self.manifest = json.loads(self.checkpoint)["manifest_sha256"]
        self.yesterday = b'{"date": "2026-09-26"}\n'
        self.put(self.data, "checkpoints/2026-09-26.json", self.yesterday)
        self.put(self.data, "checkpoints/2026-09-26.json.ots", proof(self.yesterday))

    def put(self, root: str, rel: str, body: bytes) -> None:
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)

    def today(self, checkpoint: bytes | None = None, ots: bytes | None = None) -> None:
        body = self.checkpoint if checkpoint is None else checkpoint
        self.put(self.incoming, f"checkpoints/{DAY}.json", body)
        self.put(self.incoming, f"checkpoints/{DAY}.json.ots", proof(body) if ots is None else ots)

    def problems(self, **override: str) -> list[str]:
        expected = dict(day=DAY, feed_commit=COMMIT, manifest_sha256=self.manifest,
                        checkpoint_sha256=hashlib.sha256(self.checkpoint).hexdigest())
        expected.update(override)
        return watch.anchor_problems(self.data, self.incoming, **expected)

    def admit(self) -> int:
        args = SimpleNamespace(data=self.data, incoming=self.incoming, day=DAY, feed_commit=COMMIT,
                               manifest_sha256=self.manifest,
                               checkpoint_sha256=hashlib.sha256(self.checkpoint).hexdigest())
        with redirect_stdout(io.StringIO()):
            return watch.admit_anchor(args)

    def test_the_checkpoint_publish_described_and_its_proof_are_taken(self) -> None:
        self.today()
        self.assertEqual([], self.problems())
        self.assertEqual(0, self.admit())
        with open(os.path.join(self.data, "checkpoints", DAY + ".json"), "rb") as fh:
            self.assertEqual(self.checkpoint, fh.read())

    def test_a_path_outside_checkpoints_is_refused(self) -> None:
        self.today()
        self.put(self.incoming, "README.md", b"# rewritten\n")
        self.assertIn("README.md: not a checkpoint or a proof", self.problems())
        self.assertEqual(1, self.admit())
        self.assertFalse(os.path.exists(os.path.join(self.data, "checkpoints", DAY + ".json")))

    def test_a_name_that_is_not_a_day_is_refused(self) -> None:
        self.put(self.incoming, "checkpoints/latest.json", self.checkpoint)
        self.assertTrue(any("latest.json" in p for p in self.problems()))

    def test_an_oversized_proof_is_refused(self) -> None:
        self.today(ots=proof(self.checkpoint) + b"\0" * watch.MAX_PROOF)
        self.assertTrue(any(p.endswith("bytes") for p in self.problems()), self.problems())
        self.assertEqual(1, self.admit())

    def test_a_proof_without_the_header_is_refused(self) -> None:
        self.today(ots=b"PK\x03\x04" + proof(self.checkpoint))
        self.assertIn(f"checkpoints/{DAY}.json.ots: not an OpenTimestamps proof", self.problems())

    def test_a_proof_of_some_other_file_is_refused(self) -> None:
        self.today(ots=proof(b"something else"))
        self.assertIn(f"checkpoints/{DAY}.json.ots: a proof of some other file", self.problems())

    def test_a_checkpoint_with_another_manifest_digest_is_refused(self) -> None:
        self.today()
        self.assertTrue(any("manifest digest" in p for p in self.problems(manifest_sha256="0" * 64)))
        self.assertEqual([], self.problems())

    def test_a_checkpoint_publish_did_not_write_is_refused(self) -> None:
        # Same manifest, same commit, one extra field: still not the bytes described.
        forged = self.checkpoint.replace(b'"date"', b'"note": "x",\n "date"')
        self.today(checkpoint=forged)
        self.assertIn(f"checkpoints/{DAY}.json: not the checkpoint publish described",
                      self.problems())

    def test_a_checkpoint_of_another_commit_is_refused(self) -> None:
        self.today()
        self.assertTrue(any("another commit" in p for p in self.problems(feed_commit="c" * 40)))

    def test_a_checkpoint_for_another_day_is_refused(self) -> None:
        self.put(self.incoming, "checkpoints/2026-09-20.json", self.checkpoint)
        self.assertTrue(any("not 2026-09-27" in p for p in self.problems()))

    def test_a_recorded_checkpoint_is_never_replaced(self) -> None:
        self.put(self.data, f"checkpoints/{DAY}.json", self.checkpoint)
        self.today()
        self.assertTrue(any("never replaced" in p for p in self.problems()))

    def test_an_upgraded_proof_for_an_earlier_day_is_taken(self) -> None:
        self.put(self.incoming, "checkpoints/2026-09-26.json.ots", proof(self.yesterday, True))
        self.assertEqual([], self.problems())
        self.assertEqual(0, self.admit())

    def test_a_proof_that_is_still_pending_does_not_replace_one(self) -> None:
        self.put(self.incoming, "checkpoints/2026-09-26.json.ots", proof(self.yesterday))
        self.assertTrue(any("Bitcoin block" in p for p in self.problems()))

    def test_a_new_proof_for_an_earlier_day_is_refused(self) -> None:
        # Stamping an old file today proves only today; it is not an upgrade.
        old = b'{"date": "2026-09-25"}\n'
        self.put(self.data, "checkpoints/2026-09-25.json", old)
        self.put(self.incoming, "checkpoints/2026-09-25.json.ots", proof(old, True))
        self.assertTrue(any("earlier day" in p for p in self.problems()))

    def test_a_proof_for_no_checkpoint_is_refused(self) -> None:
        self.put(self.incoming, f"checkpoints/{DAY}.json.ots", proof(self.checkpoint))
        self.assertTrue(any("does not hold" in p for p in self.problems()))

    def test_an_empty_upload_takes_nothing(self) -> None:
        self.assertEqual(0, self.admit())

    def test_an_argument_that_is_not_a_digest_stops_it(self) -> None:
        self.today()
        args = SimpleNamespace(data=self.data, incoming=self.incoming, day=DAY, feed_commit="",
                               manifest_sha256=self.manifest, checkpoint_sha256="")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(1, watch.admit_anchor(args))


class TestTheSigstoreWitness(TestAdmitAnchor):
    """The second witness: a Sigstore bundle, admitted only if it names the
    checkpoint beside it, only for today's, and never over one recorded."""

    def sign(self, body: bytes, day: str = DAY) -> None:
        self.put(self.incoming, f"checkpoints/{day}.json.sigstore.json", body)

    def test_a_bundle_of_todays_checkpoint_is_taken_with_it(self) -> None:
        self.today()
        self.sign(bundle(self.checkpoint))
        self.assertEqual([], self.problems())
        self.assertEqual(0, self.admit())
        self.assertTrue(os.path.exists(
            os.path.join(self.data, "checkpoints", DAY + ".json.sigstore.json")))

    def test_a_bundle_of_some_other_file_is_refused(self) -> None:
        self.today()
        self.sign(bundle(b"another file"))
        self.assertIn(f"checkpoints/{DAY}.json.sigstore.json: a signature of some other file",
                      self.problems())

    def test_something_that_is_not_a_bundle_is_refused(self) -> None:
        self.today()
        for junk in (b"{", b"[]", bundle(self.checkpoint, media="application/json")):
            with self.subTest(junk[:20]):
                self.sign(junk)
                self.assertTrue(any("not a Sigstore bundle" in p for p in self.problems()))

    def test_an_earlier_day_or_a_second_signature_is_refused(self) -> None:
        self.sign(bundle(self.yesterday), "2026-09-26")
        self.assertTrue(any("signed or recorded before" in p for p in self.problems()))
        self.setUp()
        self.put(self.data, f"checkpoints/{DAY}.json", self.checkpoint)
        self.put(self.data, f"checkpoints/{DAY}.json.sigstore.json", bundle(self.checkpoint))
        self.sign(bundle(self.checkpoint))
        self.assertTrue(any("signed or recorded before" in p for p in self.problems()))

    def test_a_bundle_for_no_checkpoint_is_refused(self) -> None:
        self.sign(bundle(self.checkpoint))
        self.assertTrue(any("does not hold" in p for p in self.problems()))


class TestTheFeedAcceptsItsCheckpoints(unittest.TestCase):
    def setUp(self) -> None:
        self.data = tempfile.mkdtemp(prefix="heldfast-verify-")
        self.addCleanup(shutil.rmtree, self.data, ignore_errors=True)
        os.makedirs(os.path.join(self.data, "checkpoints"))
        body = b'{"date": "2026-09-27"}\n'
        for rel, content in (("checkpoints/2026-09-27.json", body),
                             ("checkpoints/2026-09-27.json.ots", proof(body))):
            with open(os.path.join(self.data, rel), "wb") as fh:
                fh.write(content)

    def verify(self) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return watch.verify(SimpleNamespace(data=self.data, complete=False))

    def test_a_checkpoint_and_its_proof_verify(self) -> None:
        self.assertEqual(0, self.verify())

    def test_a_signature_bundle_verifies_and_junk_in_its_name_does_not(self) -> None:
        path = os.path.join(self.data, "checkpoints", "2026-09-27.json.sigstore.json")
        with open(path, "wb") as fh:
            fh.write(bundle(b'{"date": "2026-09-27"}\n'))
        self.assertEqual(0, self.verify())
        with open(path, "wb") as fh:
            fh.write(b'{"not": "a bundle"}')
        self.assertEqual(1, self.verify())

    def test_a_proof_that_is_not_one_does_not(self) -> None:
        with open(os.path.join(self.data, "checkpoints", "2026-09-27.json.ots"), "wb") as fh:
            fh.write(b"not a proof")
        self.assertEqual(1, self.verify())

    def test_a_measuring_shard_cannot_upload_one(self) -> None:
        shard = os.path.join(self.data, "checkpoints")
        self.assertTrue(watch._foreign(os.path.dirname(shard), {}, "npm-0"))


if __name__ == "__main__":
    unittest.main()
