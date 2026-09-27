"""Finding the feed without the API that allows sixty lookups an hour.

`resolve()` used the REST API, unauthenticated, for the feed branch's head.
GitHub allows sixty such requests an hour per address, so on a shared office,
CI or cloud address `approve --from-feed`, `updates`, `verify` and the probe's
public-record check all failed with a bare 403. The head is now read from
git's ref advertisement, the REST API is the fallback, and the whole lookup
record is fetched gzipped and cached by commit. Nothing here opens a socket.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import feedlock, lookup  # noqa: E402

REAL_CACHE_DIR = lookup.cache_dir

FIXTURE = ROOT / "tests" / "fixtures" / "feed-refs.pkt"
# What github.com/rufat325/heldfast advertised on 27 September 2026.
FEED_HEAD = "58d5e1c100ee65000067a8559a3d64e0041bad5e"
MAIN_HEAD = "dfea0fddf92a260a1524c044f49738a4c1e6bec7"
SHA = "0123456789abcdef0123456789abcdef01234567"


def pkt(text: str) -> bytes:
    body = text.encode()
    return b"%04x" % (len(body) + 4) + body


def advert(*refs: str) -> bytes:
    lines = [pkt("# service=git-upload-pack\n"), b"0000"]
    lines += [pkt(f"{sha} {name}" + ("\0multi_ack side-band-64k" if i == 0 else "") + "\n")
              for i, (sha, name) in enumerate(r.split(" ", 1) for r in refs)]
    return b"".join(lines) + b"0000"


class Answer(io.BytesIO):
    """What urlopen returns: a context manager with read(n)."""


class Network:
    """Stands in for `feedlock.urlopen`, keyed by URL; records every request."""

    def __init__(self, pages: dict) -> None:
        self.pages = pages
        self.requests: list = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        answer = self.pages.get(req.full_url)
        if isinstance(answer, BaseException):
            raise answer
        if answer is None:
            raise HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))
        return Answer(answer)

    def auth(self) -> dict:
        return {r.full_url: r.get_header("Authorization") for r in self.requests}


def rate_limited(url: str, reset: str = "1790000000") -> HTTPError:
    return HTTPError(url, 403, "rate limit exceeded",
                     {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset},
                     io.BytesIO(b"{}"))


class TestTheAdvertisement(unittest.TestCase):
    def test_the_captured_answer_names_the_branches(self) -> None:
        data = FIXTURE.read_bytes()
        self.assertEqual(FEED_HEAD, feedlock.parse_advertisement(data, "feed"))
        self.assertEqual(MAIN_HEAD, feedlock.parse_advertisement(data, "main"))

    def test_the_feed_repository_advertises_its_main(self) -> None:
        """Captured from github.com/rufat325/heldfast-feed on the day it moved."""
        data = (ROOT / "tests" / "fixtures" / "feed-repo-refs.pkt").read_bytes()
        self.assertRegex(feedlock.parse_advertisement(data), r"^[0-9a-f]{40}$")

    def test_a_branch_whose_name_only_starts_the_same_is_not_it(self) -> None:
        data = advert(f"{'a' * 40} refs/heads/{feedlock.BRANCH}-old",
                      f"{SHA} refs/heads/{feedlock.BRANCH}")
        self.assertEqual(SHA, feedlock.parse_advertisement(data))
        with self.assertRaises(feedlock.FeedError):
            feedlock.parse_advertisement(advert(f"{SHA} refs/heads/old-{feedlock.BRANCH}"))
        with self.assertRaises(feedlock.FeedError):
            feedlock.parse_advertisement(advert(f"{SHA} refs/remotes/origin/{feedlock.BRANCH}"))

    def test_a_missing_branch_is_an_error(self) -> None:
        with self.assertRaisesRegex(feedlock.FeedError, "does not advertise"):
            feedlock.parse_advertisement(advert(f"{SHA} refs/heads/elsewhere"))

    def test_malformed_input_is_an_error_not_a_crash(self) -> None:
        good = FIXTURE.read_bytes()
        cases = {
            "truncated inside a line": good[:120],
            "truncated inside a length": good[:2],
            "a length that is not hex": b"zzzz" + good[4:],
            "a length below four": b"0002" + good[4:],
            "a length past the end": b"ffff" + good[4:40],
            "not a commit id": advert(f"{'g' * 40} refs/heads/" + feedlock.BRANCH),
            "empty": b"",
        }
        for label, data in cases.items():
            with self.subTest(label):
                with self.assertRaises(feedlock.FeedError):
                    feedlock.parse_advertisement(data)

    def test_the_read_is_bounded(self) -> None:
        net = Network({feedlock.ADVERT_URL: b"0" * (feedlock.MAX_ADVERT + 1)})
        with mock.patch.object(feedlock, "urlopen", net):
            with self.assertRaisesRegex(feedlock.FeedError, "larger than"):
                feedlock.branch_head()


class TestResolveOrder(unittest.TestCase):
    def setUp(self) -> None:
        env = mock.patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_secret"})
        env.start()
        self.addCleanup(env.stop)

    def resolve(self, pages: dict, base: str | None = None):
        net = Network(pages)
        with mock.patch.object(feedlock, "urlopen", net):
            return feedlock.resolve(base), net

    def test_an_explicit_feed_asks_nobody(self) -> None:
        feed, net = self.resolve({}, "https://mirror.example/feed/")
        self.assertEqual("https://mirror.example/feed", feed.base)
        self.assertEqual("", feed.commit)
        self.assertEqual([], net.requests)

    def test_the_advertisement_first_and_nothing_else(self) -> None:
        feed, net = self.resolve({feedlock.ADVERT_URL: advert(f"{SHA} refs/heads/" + feedlock.BRANCH)})
        self.assertEqual(SHA, feed.commit)
        self.assertEqual(f"{feedlock.REPO}@{SHA}", feed.source)
        self.assertEqual([feedlock.ADVERT_URL], [r.full_url for r in net.requests])

    def test_the_api_when_the_advertisement_fails(self) -> None:
        feed, net = self.resolve({feedlock.HEAD_URL: json.dumps({"sha": SHA}).encode()})
        self.assertEqual(SHA, feed.commit)
        self.assertEqual([feedlock.ADVERT_URL, feedlock.HEAD_URL],
                         [r.full_url for r in net.requests])

    def test_the_token_goes_to_the_api_host_and_nowhere_else(self) -> None:
        _, net = self.resolve({feedlock.HEAD_URL: json.dumps({"sha": SHA}).encode()})
        self.assertEqual({feedlock.ADVERT_URL: None, feedlock.HEAD_URL: "Bearer ghp_secret"},
                         net.auth())
        feed = feedlock.Feed(feedlock.RAW_URL.format(ref=SHA), "x", SHA)
        raw = Network({f"{feed.base}/index.json": b"{}"})
        with mock.patch.object(feedlock, "urlopen", raw):
            feedlock.get_json(f"{feed.base}/index.json")
        self.assertEqual([None], list(raw.auth().values()))

    def test_no_token_no_header(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            _, net = self.resolve({feedlock.HEAD_URL: json.dumps({"sha": SHA}).encode()})
        self.assertEqual([None, None], list(net.auth().values()))

    def test_a_spent_rate_limit_is_named_with_what_to_do(self) -> None:
        with self.assertRaises(feedlock.FeedError) as caught:
            self.resolve({feedlock.HEAD_URL: rate_limited(feedlock.HEAD_URL)})
        said = str(caught.exception)
        for words in ("rate limit", "2026-09-21 14:13 UTC", "--feed URL", "GITHUB_TOKEN",
                      "try again later"):
            self.assertIn(words, said)

    def test_a_403_that_is_not_the_rate_limit_is_not_called_one(self) -> None:
        refused = HTTPError(feedlock.HEAD_URL, 403, "Forbidden", {}, io.BytesIO(b""))
        with self.assertRaises(feedlock.FeedError) as caught:
            self.resolve({feedlock.HEAD_URL: refused})
        self.assertNotIn("rate limit", str(caught.exception))

    def test_a_head_that_is_not_a_commit_is_an_error(self) -> None:
        with self.assertRaises(feedlock.FeedError):
            self.resolve({feedlock.HEAD_URL: json.dumps({"sha": "main"}).encode()})


class TestBoundedReads(unittest.TestCase):
    def get(self, url: str, body: bytes):
        with mock.patch.object(feedlock, "urlopen", Network({url: body})):
            return feedlock.get_json(url)

    def test_a_plain_body_past_the_limit_is_refused(self) -> None:
        with mock.patch.object(feedlock, "MAX_INFLATED", 64):
            with self.assertRaisesRegex(feedlock.FeedError, "larger than"):
                self.get("https://x.example/index.json", b'{"a": "' + b"x" * 100 + b'"}')
            self.assertEqual({"a": 1}, self.get("https://x.example/index.json", b'{"a": 1}'))

    def test_a_gzip_past_the_limit_is_refused(self) -> None:
        with mock.patch.object(feedlock, "MAX_INFLATED", 64):
            with self.assertRaisesRegex(feedlock.FeedError, "inflates past"):
                self.get("https://x.example/c.json.gz", gzip.compress(b'"' + b"x" * 100 + b'"'))

    def test_the_lookup_record_has_its_own_limit_both_ways(self) -> None:
        with mock.patch.object(feedlock, "MAX_INFLATED", 64):
            big = b'{"tools": {"' + b"a" * 100 + b'": {}}}'
            self.assertIn("tools", self.get("https://x.example/lookup/all.json", big))
            self.assertIn("tools", self.get("https://x.example/lookup/all.json.gz",
                                            gzip.compress(big)))
        with mock.patch.object(feedlock, "MAX_LOOKUP", 64):
            with self.assertRaises(feedlock.FeedError):
                self.get("https://x.example/lookup/all.json.gz", gzip.compress(big))

    def test_the_writer_and_the_reader_share_one_bound(self) -> None:
        sys.path.insert(0, str(ROOT / "research" / "feed"))
        import watch
        self.assertEqual(feedlock.MAX_LOOKUP, watch.MAX_LOOKUP_ALL)


class TestTheCache(unittest.TestCase):
    RECORD = {"prefix_length": 3, "tools": {"a" * 64: {"first_seen": "2026-09-01", "servers": 2}}}

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="heldfast-cache-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patch = mock.patch.object(lookup, "cache_dir", lambda: self.tmp)
        patch.start()
        self.addCleanup(patch.stop)
        self.asked: list[str] = []

    def get(self, url: str):
        self.asked.append(url)
        return self.RECORD if url.endswith("/lookup/all.json.gz") else None

    def read(self, commit: str = SHA) -> dict:
        feed = feedlock.Feed(f"https://raw.example/{commit}", "x", commit)
        with mock.patch.object(feedlock, "get_json", self.get):
            return lookup.everything(feed)

    def test_a_second_read_of_the_same_commit_downloads_nothing(self) -> None:
        self.assertEqual(self.RECORD["tools"], self.read())
        self.assertEqual(self.RECORD["tools"], self.read())
        self.assertEqual(1, len(self.asked))
        self.assertTrue((self.tmp / f"lookup-{SHA}.json.gz").exists())

    def test_another_commit_is_a_miss(self) -> None:
        self.read()
        self.read("f" * 40)
        self.assertEqual(2, len(self.asked))

    def test_a_corrupt_copy_is_fetched_again_not_used(self) -> None:
        for junk in (b"not gzip", gzip.compress(b"not json"), gzip.compress(b'{"tools": []}')):
            with self.subTest(junk[:12]):
                (self.tmp / f"lookup-{SHA}.json.gz").write_bytes(junk)
                self.asked.clear()
                self.assertEqual(self.RECORD["tools"], self.read())
                self.assertEqual(1, len(self.asked))

    def test_only_the_newest_two_are_kept(self) -> None:
        for i, commit in enumerate(("1" * 40, "2" * 40, "3" * 40)):
            self.read(commit)
            path = self.tmp / f"lookup-{commit}.json.gz"
            os.utime(path, (time.time() + i, time.time() + i))
        self.read("4" * 40)
        held = sorted(p.name for p in self.tmp.glob("lookup-*.json.gz"))
        self.assertEqual(2, len(held), held)
        self.assertIn(f"lookup-{'4' * 40}.json.gz", held)
        self.assertEqual([], list(self.tmp.glob("*.tmp")))

    def test_a_feed_someone_chose_is_not_cached(self) -> None:
        with mock.patch.object(feedlock, "get_json", self.get):
            lookup.everything(feedlock.Feed("https://mirror.example", "mirror"))
            lookup.everything(feedlock.Feed("https://mirror.example", "mirror"))
        self.assertEqual(2, len(self.asked))
        self.assertEqual([], list(self.tmp.iterdir()))

    def test_a_cache_that_cannot_be_written_costs_only_a_download(self) -> None:
        blocked = self.tmp / "file"
        blocked.write_text("x")
        with mock.patch.object(lookup, "cache_dir", lambda: blocked / "heldfast"):
            self.assertEqual(self.RECORD["tools"], self.read())

    def test_where_the_cache_lives(self) -> None:
        home = Path("/home/someone")
        cases = {
            ("linux", "XDG_CACHE_HOME", "/x/cache"): Path("/x/cache/heldfast"),
            ("linux", "", ""): home / ".cache" / "heldfast",
            ("darwin", "", ""): home / "Library" / "Caches" / "heldfast",
            ("win32", "LOCALAPPDATA", "C:/Local"): Path("C:/Local/heldfast"),
        }
        for (platform, name, value), want in cases.items():
            with self.subTest(platform=platform, name=name):
                env = {name: value} if name else {}
                with mock.patch.object(sys, "platform", platform),                         mock.patch.object(Path, "home", return_value=home),                         mock.patch.dict(os.environ, env, clear=True):
                    self.assertEqual(want, REAL_CACHE_DIR())

if __name__ == "__main__":
    unittest.main()
