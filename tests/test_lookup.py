"""The public record lookup: has anyone else been shown this exact tool?

The feed publishes every tool definition it has logged, bucketed by the
first three hex characters of the fingerprint the lockfile records. These
hold that a tool approved here is found under the fingerprint the log
computed from the same definition; that one shown on two servers counts
both, dated by the first; that a client asks only for bucket names, never
for a fingerprint; and that a tool the log never saw is reported, and fails
only under --strict. Nothing here touches the network.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "research" / "feed"))

import watch  # noqa: E402
from heldfast import feedlock, lookup  # noqa: E402
from heldfast.cli import main  # noqa: E402
from heldfast.lockfile import Lock  # noqa: E402
from heldfast.model import ServerSpec  # noqa: E402
from heldfast.probe import _parse_tools  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
BASE = f"https://raw.githubusercontent.com/rufat325/heldfast/{SHA}"


def tool(name: str, description: str) -> dict:
    return {"name": name, "description": description, "inputSchema": {"type": "object"}}


READ = tool("read_file", "Read a file from the allowed directories.")
WRITE = tool("write_file", "Write a file.")
PRIVATE = tool("deploy", "Deploy our internal service.")


def quiet(fn, *args):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return fn(*args)


class Published(unittest.TestCase):
    """A feed checkout with two servers logged, and its lookup written."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data = self._tmp.name
        with open(os.path.join(self.data, "watchlist.json"), "w", encoding="utf-8") as fh:
            json.dump({"packages": []}, fh)
        watch.write_catalogue(self.data, watch.snapshot("pkg-a", "1.0.0", "2026-03-02T00:00:00Z",
                                                        [READ, WRITE]), [], "t")
        watch.write_catalogue(self.data, watch.snapshot("pkg-b", "2.0.0", "2026-05-01T00:00:00Z",
                                                        [READ]), [], "t")
        quiet(watch.render, SimpleNamespace(data=self.data))
        self.asked: list[str] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def get(self, url: str):
        self.asked.append(url)
        if url == feedlock.HEAD_URL:
            return {"sha": SHA}
        path = os.path.join(self.data, *url[len(BASE) + 1:].split("/"))
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def fingerprint(self, raw: dict) -> str:
        return _parse_tools("x", {"result": {"tools": [raw]}})[0].fingerprint()


class TestBuckets(Published):
    def test_one_definition_on_two_servers_counts_both_and_keeps_the_first_date(self) -> None:
        fp = self.fingerprint(READ)
        with open(os.path.join(self.data, "lookup", fp[:3] + ".json"), encoding="utf-8") as fh:
            row = json.load(fh)["tools"][fp]
        self.assertEqual({"first_seen": "2026-03-02", "servers": 2}, row)

    def test_the_log_accepts_what_it_wrote_and_a_shard_may_not_write_it(self) -> None:
        self.assertEqual(0, quiet(watch.verify, SimpleNamespace(data=self.data)))
        problems = watch._foreign(self.data, {}, "npm-0")
        self.assertTrue(any(p.startswith("lookup/") for p in problems))

    def test_a_quiet_day_rewrites_no_bucket(self) -> None:
        before = {n: Path(self.data, "lookup", n).read_bytes()
                  for n in os.listdir(os.path.join(self.data, "lookup"))}
        quiet(watch.render, SimpleNamespace(data=self.data))
        after = {n: Path(self.data, "lookup", n).read_bytes()
                 for n in os.listdir(os.path.join(self.data, "lookup"))}
        self.assertEqual(before, after)


class TestClient(Published):
    def look(self, *raws: dict, mode: str = "all") -> dict:
        prints = [self.fingerprint(r) for r in raws]
        with mock.patch.object(feedlock, "get_json", self.get):
            return lookup.seen(prints, feedlock.Feed(BASE, "log"), mode)

    def test_a_logged_definition_is_found_and_a_private_one_is_not(self) -> None:
        for mode in ("all", "buckets"):
            with self.subTest(mode):
                found = self.look(READ, PRIVATE, mode=mode)
                self.assertEqual(2, found[self.fingerprint(READ)]["servers"])
                self.assertIsNone(found[self.fingerprint(PRIVATE)])

    def test_by_default_the_whole_record_is_fetched_and_nothing_else(self) -> None:
        """The set of buckets a server's tools fall in identifies the server
        for most servers, so the default asks for no bucket at all."""
        self.look(READ, WRITE, PRIVATE)
        self.assertEqual([f"{BASE}/lookup/all.json"], self.asked)

    def test_buckets_ask_only_for_bucket_names(self) -> None:
        self.look(READ, WRITE, PRIVATE, mode="buckets")
        full = {self.fingerprint(r) for r in (READ, WRITE, PRIVATE)}
        for url in self.asked:
            self.assertRegex(url, r"/lookup/[0-9a-f]{3}\.json$")
            self.assertFalse(any(fp in url for fp in full))

    def test_the_whole_record_is_every_bucket(self) -> None:
        with open(os.path.join(self.data, "lookup", "all.json"), encoding="utf-8") as fh:
            record = json.load(fh)["tools"]
        buckets = {}
        for name in os.listdir(os.path.join(self.data, "lookup")):
            if len(name) == len("abc.json"):
                with open(os.path.join(self.data, "lookup", name), encoding="utf-8") as fh:
                    buckets.update(json.load(fh)["tools"])
        self.assertEqual(buckets, record)


class TestVerify(Published):
    def run_cli(self, *argv: str) -> tuple[int, str]:
        project = Path(self._tmp.name) / "project"
        project.mkdir(exist_ok=True)
        (project / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "files": {"command": "npx", "args": ["-y", "pkg-a@1.0.0"]}}}), encoding="utf-8")
        spec = ServerSpec(name="files", source=str(project / ".mcp.json"), client="claude-code",
                          transport="stdio", command="npx", args=["-y", "pkg-a@1.0.0"])
        lock = Lock(path=project / ".mcp-pin.lock")
        lock.record([spec], _parse_tools(spec.identity(), {"result": {"tools": [READ, PRIVATE]}}),
                    [])
        lock.save()
        out = io.StringIO()
        with mock.patch.object(feedlock, "get_json", self.get), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = main([*argv, str(project), "--no-user-configs", "--no-skills"])
        self.out = out.getvalue()
        return code, self.out

    def test_approved_tools_are_looked_up_without_launching_anything(self) -> None:
        with mock.patch("heldfast.probe.probe_stdio", side_effect=AssertionError("launched")):
            code, out = self.run_cli("verify")
        self.assertEqual(0, code, out)
        self.assertIn("1 of 2 seen publicly, the oldest since 2026-03-02, on up to 2 server(s)",
                      out)
        self.assertIn("never seen publicly: deploy", out)

    def test_strict_fails_on_a_tool_never_seen_publicly(self) -> None:
        self.assertEqual(1, self.run_cli("verify", "--strict")[0])

    def test_the_default_says_nothing_about_the_tools_was_sent(self) -> None:
        code, out = self.run_cli("verify")
        self.assertIn("the whole record was downloaded", out)
        self.assertFalse([u for u in self.asked if u.endswith(".json")
                          and "/lookup/" in u and not u.endswith("/all.json")])

    def test_buckets_say_what_they_reveal(self) -> None:
        code, out = self.run_cli("verify", "--lookup", "buckets")
        self.assertIn("can identify which public servers", out)
        self.assertIn("1 of 2 seen publicly", out)

    def test_off_looks_nothing_up(self) -> None:
        code, out = self.run_cli("verify", "--lookup", "off")
        self.assertNotIn("public record", out)
        self.assertFalse([u for u in self.asked if "/lookup/" in u])

    def test_json_carries_the_record(self) -> None:
        self.run_cli("verify", "--format", "json")
        record = json.loads(self.out)["record"][0]
        self.assertEqual(["deploy"], record["unseen"])
        self.assertEqual(2, record["seen"]["read_file"]["servers"])


if __name__ == "__main__":
    unittest.main()
