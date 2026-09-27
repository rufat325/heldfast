"""Counting the feed's churn per operator, and by what kind of change it was.

The feed's headline counted every event alike, and most of it was one
company's catalogue counter ticking. research/feed/operators.py classifies
each event (substantive, numbers only, reordered only) and keys it by
operator: a hosted server's registrable domain under the Public Suffix List,
an npm server's package. Nothing here opens a socket.
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "research" / "feed"))

import operators  # noqa: E402
import watch  # noqa: E402


def tool(name: str, description: str, enum: list | None = None) -> dict:
    schema: dict = {"type": "object"}
    if enum:
        schema["properties"] = {"kind": {"type": "string", "enum": enum}}
    return {"name": name, "description": description, "inputSchema": schema}


ROUTER = "Route a request to one of 6,402 tools across 1674 verified sources."


class TestKindOfChange(unittest.TestCase):
    def kind(self, old: dict, new: dict) -> str:
        return operators.classify_event({old["name"]: old}, {new["name"]: new})

    def test_a_counter_ticking_is_numbers_only(self) -> None:
        ticked = ROUTER.replace("6,402", "6,404").replace("1674", "1675")
        self.assertEqual("numbers-only", self.kind(tool("route", ROUTER), tool("route", ticked)))

    def test_a_reordered_list_is_reorder_only(self) -> None:
        self.assertEqual("reorder-only", self.kind(tool("s", "Search.", ["a", "b", "c"]),
                                                   tool("s", "Search.", ["c", "a", "b"])))

    def test_a_reworded_description_is_substantive(self) -> None:
        self.assertEqual("substantive", self.kind(tool("s", "Search flights."),
                                                  tool("s", "Search flights and hotels.")))

    def test_a_number_and_a_word_together_is_substantive(self) -> None:
        self.assertEqual("substantive", self.kind(tool("s", "Up to 5 results."),
                                                  tool("s", "Up to 9 hits.")))

    def test_an_added_or_removed_tool_is_substantive(self) -> None:
        a = tool("a", "Alpha.")
        self.assertEqual("substantive", operators.classify_event({"a": a}, {"a": a, "b": a}))
        self.assertEqual("substantive", operators.classify_event({"a": a, "b": a}, {"a": a}))

    def test_the_strongest_kind_in_an_event_wins(self) -> None:
        before = {"r": tool("r", ROUTER), "s": tool("s", "Search.", ["a", "b"])}
        after = {"r": tool("r", ROUTER.replace("6,402", "6,500")),
                 "s": tool("s", "Search.", ["b", "a"])}
        self.assertEqual("numbers-only", operators.classify_event(before, after))
        after["s"] = tool("s", "Search everything.")
        self.assertEqual("substantive", operators.classify_event(before, after))

    def test_both_wire_spellings_are_the_same_body(self) -> None:
        snake = {"name": "t", "description": "d", "input_schema": {"type": "object"}}
        camel = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
        self.assertEqual("identical", operators.classify_tool(snake, camel))


PSL = """// VERSION: 2026-01-01_00-00-00_UTC
// ===BEGIN ICANN DOMAINS===
com
io
uk
co.uk
*.ck
!www.ck
// ===BEGIN PRIVATE DOMAINS===
workers.dev
"""


class TestOperators(unittest.TestCase):
    def setUp(self) -> None:
        self.s = operators.Suffixes(PSL)

    def test_the_rules_of_the_list(self) -> None:
        cases = {
            "gateway.pipeworx.io": "pipeworx.io",
            "shop.example.co.uk": "example.co.uk",
            "example.uk": "example.uk",
            "a.b.ck": "a.b.ck",           # *.ck: b.ck is a suffix
            "www.ck": "www.ck",           # !www.ck: an exception to it
            "x.www.ck": "www.ck",
            "api.x.nolimit.workers.dev": "nolimit.workers.dev",
            "workers.dev": "workers.dev",
            "host.unlisted": "host.unlisted",
            "127.0.0.1": "127.0.0.1",
            "API.Example.COM.": "example.com",
        }
        for host, want in cases.items():
            with self.subTest(host):
                self.assertEqual(want, self.s.registrable(host))

    def test_each_site_on_a_shared_host_is_its_own_operator(self) -> None:
        self.assertNotEqual(self.s.registrable("a.one.workers.dev"),
                            self.s.registrable("a.two.workers.dev"))

    def test_the_vendored_list_knows_the_shared_hosts_the_feed_sees(self) -> None:
        real = operators.suffixes()
        self.assertTrue(real.version)
        self.assertIn("workers.dev", real.rules)
        self.assertEqual("nolimit-observatory.workers.dev",
                         real.registrable("x.nolimit-observatory.workers.dev"))

    def test_npm_is_keyed_by_package_and_hosted_by_domain(self) -> None:
        self.assertEqual("@scope/pkg", operators.operator("@scope/pkg", None))
        self.assertEqual("pipeworx.io", operators.operator(
            "remote/io.pipeworx/router", "https://gateway.pipeworx.io/mcp"))


def quiet(fn, *args):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return fn(*args)


class TestRendered(unittest.TestCase):
    """stats.json and the README's per-operator section, from a small feed."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data = self._tmp.name
        with open(os.path.join(self.data, "watchlist.json"), "w", encoding="utf-8") as fh:
            json.dump({"packages": []}, fh)
        events = []
        ticks = [ROUTER, ROUTER.replace("6,402", "6,403"), ROUTER.replace("6,402", "6,404")]
        for i, text in enumerate(ticks):
            snap = watch.snapshot("remote/io.pipeworx/router", f"2026-09-2{i}T000000000000",
                                  f"2026-09-2{i}T00:00:00Z", [tool("route", text)])
            watch.write_catalogue(self.data, snap, [], "t",
                                  extra={"url": "https://gateway.pipeworx.io/mcp"})
        for a, b in (("0", "1"), ("1", "2")):
            events.append(self.event("remote/io.pipeworx/router", f"2026-09-2{a}T000000000000",
                                     f"2026-09-2{b}T000000000000"))
        for v, text in (("1.0.0", "Search flights."), ("1.1.0", "Search flights and hotels.")):
            watch.write_catalogue(self.data, watch.snapshot("pkg", v, "2026-09-01", [tool("s", text)]),
                                  [], "t")
        events.append(self.event("pkg", "1.0.0", "1.1.0"))
        watch.append_events(self.data, events)
        quiet(watch.render, SimpleNamespace(data=self.data))

    @staticmethod
    def event(package: str, frm: str, to: str) -> dict:
        return {"package": package, "from": frm, "to": to, "published": "2026-09-2" + to[-1:],
                "observed_at": "2026-09-27T00:00:00+00:00", "changed": [], "added": [],
                "removed": [], "whole_catalogue": False, "grade": "quiet",
                "tools_before": 1, "tools_after": 1}

    def stats(self) -> dict:
        with open(os.path.join(self.data, "stats.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_counts_per_operator_and_kind(self) -> None:
        s = self.stats()
        self.assertEqual((3, 1, 2), (s["events"], s["npm"], s["hosted"]))
        self.assertEqual({"numbers-only": 2, "substantive": 1}, s["kinds"])
        rows = {r["operator"]: r for r in s["operators"]}
        self.assertEqual(2, rows["pipeworx.io"]["numbers-only"])
        self.assertEqual(1, rows["pkg"]["substantive"])

    def test_the_readme_has_the_section_and_says_it_is_approximate(self) -> None:
        with open(os.path.join(self.data, "README.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("## Per operator", text)
        self.assertIn("| `pipeworx.io` | 2 | 0 | 2 | 0 |", text)
        self.assertIn("Approximate", text)
        self.assertIn("2 readings of hosted servers", text)

    def test_a_second_render_writes_the_same_bytes(self) -> None:
        with open(os.path.join(self.data, "stats.json"), "rb") as fh:
            first = fh.read()
        quiet(watch.render, SimpleNamespace(data=self.data))
        with open(os.path.join(self.data, "stats.json"), "rb") as fh:
            self.assertEqual(first, fh.read())

    def test_a_known_event_is_not_read_again(self) -> None:
        """Classifying reads two catalogues; stats.json keeps the answer."""
        for name in os.listdir(os.path.join(self.data, "catalogues", "pkg")):
            os.remove(os.path.join(self.data, "catalogues", "pkg", name))
        again = watch.churn_stats(self.data, watch.all_events(self.data))
        self.assertEqual("substantive", again["classified"]["pkg@1.0.0->1.1.0"])

    def test_a_missing_catalogue_is_unclassified_not_a_crash(self) -> None:
        os.remove(os.path.join(self.data, "stats.json"))
        for name in os.listdir(os.path.join(self.data, "catalogues", "pkg")):
            os.remove(os.path.join(self.data, "catalogues", "pkg", name))
        again = watch.churn_stats(self.data, watch.all_events(self.data))
        self.assertEqual("unclassified", again["classified"]["pkg@1.0.0->1.1.0"])

    def test_verify_accepts_it_and_a_shard_cannot_upload_it(self) -> None:
        self.assertEqual(0, quiet(watch.verify, SimpleNamespace(data=self.data)))
        shard = os.path.join(self.data, "shard")
        os.makedirs(shard)
        with open(os.path.join(shard, "stats.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        self.assertTrue(watch._foreign(shard, {}, "npm-0"))


if __name__ == "__main__":
    unittest.main()
