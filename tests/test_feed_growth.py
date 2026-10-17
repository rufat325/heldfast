"""The drift feed keeps fitting inside its own size limits.

On 2026-10-14 the feed stopped: its tree reached the 1 GiB that `verify`
allows and a month of events the 20 MB allowed one file, so every publish was
refused. These hold what keeps it from happening again: hosted catalogues
past each server's newest few leave the tree without the lookup forgetting
what they showed, events go to one file a day and are gzipped once closed,
stats.json and index.json stop growing with every event, the whole lookup
record comes in parts, and `capacity` says when a limit is near.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "research" / "feed"))

import watch  # noqa: E402

HOSTED = {"package": "remote/io.example/tools", "kind": "remote", "url": "https://x.example/mcp"}
SIBLING = {"package": "remote/io.example/other", "kind": "remote", "url": "https://y.example/mcp"}
SHARED = {"name": "shared", "description": "Shown by two servers.", "inputSchema": {"type": "object"}}


def quiet(fn, *args):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return fn(*args)


def tool(name: str, description: str) -> dict:
    return {"name": name, "description": description, "inputSchema": {"type": "object"}}


class Feed(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data = self._tmp.name
        with open(os.path.join(self.data, "watchlist.json"), "w", encoding="utf-8") as fh:
            json.dump({"packages": [HOSTED, SIBLING]}, fh)
        self.clock = datetime(2026, 10, 1, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def read(self, row: dict, tools: list) -> dict | None:
        """One hosted reading, an hour after the last: an event when it moved."""
        self.clock += timedelta(hours=1)
        moment = self.clock

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return moment

        with mock.patch.object(watch, "measure_remote", return_value=(tools, None)), \
                mock.patch.object(watch, "datetime", Clock):
            return watch.check_remote_one(self.data, row)

    def versions(self, row: dict) -> list[str]:
        folder = os.path.join(self.data, "catalogues", watch.safe(row["package"]))
        return sorted(os.listdir(folder))

    def publish(self) -> None:
        quiet(watch.fold, SimpleNamespace(data=self.data))
        quiet(watch.retire, SimpleNamespace(data=self.data))
        quiet(watch.render, SimpleNamespace(data=self.data))


class TestRetire(Feed):
    def five_readings(self) -> list:
        events = []
        for i in range(5):
            event = self.read(HOSTED, [SHARED, tool("count", f"Reading number {i}.")])
            if event:
                events.append(event)
        self.read(SIBLING, [SHARED])
        watch.write_incoming(self.data, "remote-0", events)
        return events

    def test_a_hosted_server_keeps_its_newest_readings_and_its_current_one(self) -> None:
        self.five_readings()
        current = watch.load_state(self.data, HOSTED["package"])["version"]
        self.publish()
        held = self.versions(HOSTED)
        self.assertEqual(watch.HOSTED_KEEP, len(held))
        self.assertIn(current + ".json", held)

    def test_npm_catalogues_all_stay(self) -> None:
        for v in ("1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"):
            watch.write_catalogue(self.data, watch.snapshot("pkg", v, "2026-09-01T00:00:00Z",
                                                            [tool("read", "Read " + v)]), [], "t")
        quiet(watch.retire, SimpleNamespace(data=self.data))
        self.assertEqual(5, len(self.versions({"package": "pkg"})))

    def test_the_lookup_forgets_nothing_a_retired_catalogue_showed(self) -> None:
        self.five_readings()
        quiet(watch.fold, SimpleNamespace(data=self.data))
        before = watch.lookup_buckets(self.data)
        quiet(watch.retire, SimpleNamespace(data=self.data))
        self.assertEqual(before, watch.lookup_buckets(self.data))
        shared = [row for b in before.values() for row in b.values() if row["servers"] == 2]
        self.assertEqual(1, len(shared))

    def test_a_definition_no_catalogue_names_leaves_tools(self) -> None:
        self.five_readings()
        first = watch.tool_digest(tool("count", "Reading number 0."))
        self.assertTrue(os.path.exists(watch.tool_path(self.data, first)))
        self.publish()
        self.assertFalse(os.path.exists(watch.tool_path(self.data, first)))
        self.assertTrue(os.path.exists(watch.tool_path(self.data, watch.tool_digest(SHARED))))
        self.assertEqual(0, quiet(watch.verify, SimpleNamespace(data=self.data, complete=True)))

    def test_retiring_twice_changes_nothing(self) -> None:
        self.five_readings()
        self.publish()
        snapshot = {p: p.read_bytes() for p in Path(self.data).rglob("*") if p.is_file()}
        self.publish()
        self.assertEqual(snapshot, {p: p.read_bytes() for p in Path(self.data).rglob("*")
                                    if p.is_file()})


class TestEvents(Feed):
    def event(self, observed: str, package: str = "pkg") -> dict:
        return {"package": package, "from": "1", "to": "2", "published": "2026-01-01T00:00:00Z",
                "observed_at": observed, "changed": [], "added": [], "removed": ["x"],
                "tools_before": 1, "tools_after": 0, "whole_catalogue": False, "grade": "quiet"}

    def names(self) -> list[str]:
        return sorted(os.listdir(os.path.join(self.data, "events")))

    def test_one_file_per_day_observed_and_closed_ones_are_gzipped(self) -> None:
        os.makedirs(os.path.join(self.data, "events"))
        with open(os.path.join(self.data, "events", "2026-09.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(self.event("2026-09-20T00:00:00Z")) + "\n")
        watch.append_events(self.data, [self.event("2026-08-01T00:00:00Z"),
                                        self.event("2026-10-17T05:00:00Z")])
        self.assertEqual(["2026-08-01.jsonl", "2026-09.jsonl", "2026-10-17.jsonl"], self.names())
        self.assertEqual(2, watch.close_events(self.data))
        self.assertEqual(["2026-08-01.jsonl.gz", "2026-09.jsonl.gz", "2026-10-17.jsonl"],
                         self.names())
        self.assertEqual(3, len(watch.all_events(self.data)))
        self.assertEqual(0, quiet(watch.verify, SimpleNamespace(data=self.data)))

    def test_a_monthly_file_is_closed_at_once(self) -> None:
        """Nothing is appended to the monthly layout any more, so the month
        still under way is closed too, not left to grow a warning."""
        os.makedirs(os.path.join(self.data, "events"))
        with open(os.path.join(self.data, "events", "2026-10.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(self.event("2026-10-02T00:00:00Z")) + "\n")
        watch.append_events(self.data, [self.event("2026-10-17T05:00:00Z")])
        watch.close_events(self.data)
        self.assertEqual(["2026-10-17.jsonl", "2026-10.jsonl.gz"], self.names())

    def test_a_closed_day_is_gzipped_the_same_way_every_time(self) -> None:
        watch.append_events(self.data, [self.event("2026-08-01T00:00:00Z"),
                                        self.event("2026-10-17T05:00:00Z")])
        text = Path(self.data, "events", "2026-08-01.jsonl").read_bytes()
        watch.close_events(self.data)
        packed = Path(self.data, "events", "2026-08-01.jsonl.gz").read_bytes()
        self.assertEqual(watch.gzip_member(text), packed)
        self.assertEqual(text, gzip.decompress(packed))

    def test_an_event_for_a_closed_day_joins_its_file(self) -> None:
        watch.append_events(self.data, [self.event("2026-08-01T00:00:00Z"),
                                        self.event("2026-10-17T05:00:00Z")])
        watch.close_events(self.data)
        watch.append_events(self.data, [self.event("2026-08-01T09:00:00Z", "late")])
        watch.close_events(self.data)
        self.assertEqual(["2026-08-01.jsonl.gz", "2026-10-17.jsonl"], self.names())
        self.assertEqual(3, len(watch.all_events(self.data)))

    def test_an_npm_release_measured_late_lands_on_the_day_it_was_seen(self) -> None:
        late = dict(self.event("2026-10-17T05:00:00Z"), published="2026-07-01T00:00:00Z")
        watch.append_events(self.data, [late])
        self.assertEqual(["2026-10-17.jsonl"], self.names())

    def test_a_checkpoint_counts_events_in_every_layout(self) -> None:
        files = [("events/2026-09.jsonl", b"{}\n"),
                 ("events/2026-08.jsonl.gz", watch.gzip_member(b"{}\n{}\n")),
                 ("events/2026-10-17.jsonl", b"{}\n{}\n{}\n"),
                 ("events/2026-08-01.jsonl.gz", watch.gzip_member(b"{}\n"))]
        self.assertEqual(7, watch._entries(files)[1])

    def test_verify_refuses_a_closed_file_that_inflates_without_bound(self) -> None:
        os.makedirs(os.path.join(self.data, "events"))
        with open(os.path.join(self.data, "events", "2026-08-01.jsonl.gz"), "wb") as fh:
            fh.write(gzip.compress(b" " * (watch.MAX_INFLATED + 10)))
        self.assertEqual(1, quiet(watch.verify, SimpleNamespace(data=self.data)))


class TestStats(Feed):
    def test_fold_gives_each_event_its_kind_and_operator(self) -> None:
        self.read(HOSTED, [tool("read", "Read 1 items.")])
        event = self.read(HOSTED, [tool("read", "Read 2 items.")])
        watch.write_incoming(self.data, "remote-0", [event])
        quiet(watch.fold, SimpleNamespace(data=self.data))
        folded = watch.all_events(self.data)[0]
        self.assertEqual(("numbers-only", "x.example"), (folded["kind"], folded["operator"]))

    def test_stats_keep_answers_only_for_events_from_before(self) -> None:
        self.read(HOSTED, [tool("read", "Read 1 items.")])
        event = self.read(HOSTED, [tool("read", "Read 2 items.")])
        legacy = dict(event, to="legacy")
        watch.write_incoming(self.data, "remote-0", [event])
        quiet(watch.fold, SimpleNamespace(data=self.data))
        watch.append_events(self.data, [legacy])
        quiet(watch.render, SimpleNamespace(data=self.data))
        with open(os.path.join(self.data, "stats.json"), encoding="utf-8") as fh:
            stats = json.load(fh)
        key = f"{legacy['package']}@{legacy['from']}->legacy"
        self.assertEqual([key], list(stats["classified"]))
        self.assertEqual([key], list(stats["operator_of"]))
        self.assertEqual(2, stats["events"])


class TestIndex(Feed):
    def test_a_hosted_server_lists_its_recent_events_and_counts_them_all(self) -> None:
        events = [e for e in (self.read(HOSTED, [tool("read", f"Read v{i}.")]) for i in range(6))
                  if e]
        watch.write_incoming(self.data, "remote-0", events)
        self.publish()
        with open(os.path.join(self.data, "index.json"), encoding="utf-8") as fh:
            entry = json.load(fh)["packages"][HOSTED["package"]]
        held = {v["version"] for v in entry["versions"]}
        self.assertEqual(5, entry["events_total"])
        self.assertEqual(watch.HOSTED_KEEP, len(held))
        self.assertTrue(entry["events"])
        self.assertTrue(all(e["to"] in held for e in entry["events"]))


class TestLookupParts(Feed):
    def setUp(self) -> None:
        super().setUp()
        for i in range(40):
            watch.write_catalogue(self.data, watch.snapshot(
                f"pkg{i}", "1.0.0", "2026-09-01T00:00:00Z", [tool("t", f"Tool {i}.")]), [], "t")

    def part(self, shard: str) -> dict:
        with gzip.open(os.path.join(self.data, "lookup", f"all-{shard}.json.gz"), "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))["tools"]

    def test_the_parts_are_the_whole_record(self) -> None:
        quiet(watch.render, SimpleNamespace(data=self.data))
        with open(os.path.join(self.data, "lookup", "all.json"), encoding="utf-8") as fh:
            whole = json.load(fh)["tools"]
        joined = {}
        for shard in "0123456789abcdef":
            joined.update(self.part(shard))
        self.assertEqual(whole, joined)
        self.assertEqual(40, len(joined))

    def test_past_its_bound_the_single_file_is_no_longer_written(self) -> None:
        quiet(watch.render, SimpleNamespace(data=self.data))
        with mock.patch.object(watch, "MAX_LOOKUP_ALL", 100):
            quiet(watch.render, SimpleNamespace(data=self.data))
        self.assertFalse(os.path.exists(os.path.join(self.data, "lookup", "all.json")))
        self.assertFalse(os.path.exists(os.path.join(self.data, "lookup", "all.json.gz")))
        self.assertEqual(40, sum(len(self.part(s)) for s in "0123456789abcdef"))
        self.assertEqual(0, quiet(watch.verify, SimpleNamespace(data=self.data)))


class TestCapacity(Feed):
    def setUp(self) -> None:
        super().setUp()
        self.read(HOSTED, [tool("read", "Read things.")])
        quiet(watch.render, SimpleNamespace(data=self.data))

    def capacity(self, **kw) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = watch.capacity(SimpleNamespace(data=self.data, repo_bytes=kw.get("repo", 0),
                                                  warn=watch.CAPACITY_WARN))
        return code, out.getvalue()

    def test_a_feed_far_from_its_limits_is_quiet(self) -> None:
        code, text = self.capacity()
        self.assertEqual(0, code)
        self.assertNotIn("::warning::", text)
        self.assertIn("the whole tree", text)

    def test_a_limit_three_quarters_full_is_reported(self) -> None:
        total = sum(p.stat().st_size for p in Path(self.data).rglob("*") if p.is_file())
        with mock.patch.object(watch, "MAX_TOTAL", int(total / 0.8)):
            code, text = self.capacity()
        self.assertEqual(1, code)
        self.assertIn("::warning::the whole tree is at 80%", text)

    def test_the_repository_on_github_is_measured_when_given(self) -> None:
        code, text = self.capacity(repo=int(watch.REPO_LIMIT * 0.9))
        self.assertEqual(1, code)
        self.assertIn("the repository on GitHub", text)


if __name__ == "__main__":
    unittest.main()
