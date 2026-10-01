"""Every number the first-week report states, computed from one sealed snapshot.

Earlier drafts of the report got numbers wrong without leaving out a single
citation: each was inferred, or typed in by hand. So the report types none.
This reads a feed snapshot -- the tree of one checkpointed heldfast-feed
commit (research/report/SNAPSHOT.json) -- and writes each figure with a
one-sentence definition, its denominator when it is a ratio, and the files it
read. research/report/check_numbers.py then refuses any number in the report
that is not one of these.

  python research/report/numbers.py --feed ../feed-snapshot --out research/report/numbers.json
  python research/report/numbers.py --feed ../feed-snapshot --verify   # C03-C05 without stats.json

The figures, by claim ID:

  C01  servers watched: npm, hosted, total; hosted share (watchlist.json)
  C02  hosted coverage from state/remote__*.json: read and current; has a
       catalogue but the latest attempt failed; never read, by recorded reason
       (attempted.why) and grouped: login or payment (HTTP 401, 402, 403), not
       found (404), other 4xx, 5xx including 530, network error (URLError,
       TimeoutError), protocol, other. Each a share of all hosted state files
  C03  change events: total, hosted, npm; npm live and seeded (the `seeded`
       flag); the live window (min and max observed_at, non-seeded); events per
       UTC day, and again without the top three operators
  C04  kinds from stats.json: substantive, numbers-only, reorder-only;
       recomputed from the events with the collector's own classifier
       (research/feed/operators.py), and the two must be equal
  C05  operators: count; the top three with counts and shares of both hosted
       and all events; hosted servers with a change; changes per changed
       server (median, distribution, exactly one); events and servers outside
       the top three; for each of the top three, the fields changed and the
       share of whole-catalogue events
  C06  grades: review and quiet; review events by the kind of signal they
       introduced (an event can carry several); every review event without a
       price signal, written to review-events.md for a person to read
  C07  prices, per server, with heldfast.driftgrade's own patterns: the
       direction of each stated-price change where one price became another;
       and the earlier claim "23 paid servers changed their prices within four
       days, some tripling", defined and tested
  C08  lookup: distinct definitions, and those seen on exactly one server
  C09  checkpoints present in the snapshot, and which proof files each has
  C10  the churn study: research/churn/analyse.py rerun and suspicious.json
       read, against the figures docs/CHURN.md states
  C11  the scan study: docs/SCAN.md's figures, quoted with their date and feed
       commit, not recomputed

Reads the snapshot and this repository. Runs nothing from the registry,
contacts nothing. A figure that cannot be computed is written as null, never
left out.
"""
from __future__ import annotations

import os
import sys

# Run as a script, this folder comes first on the path, and this file's name
# would stand in for the standard library's `numbers`, which statistics and
# decimal import. So the folder leaves the path before anything is imported.
_HERE = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(__file__))))
sys.path[:] = [p for p in sys.path
               if os.path.normcase(os.path.realpath(os.path.abspath(p or os.curdir))) != _HERE]

import argparse
import contextlib
import glob
import io
import json
import re
import statistics
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "research", "feed"))
sys.path.insert(0, os.path.join(ROOT, "research", "churn"))

import operators  # noqa: E402
import watch  # noqa: E402
from heldfast.driftgrade import PRICES, UNIT_PRICES, _amount, _priced, live_text  # noqa: E402

REMOTE = "remote/"
TOP = 3
PRICE_WINDOW_DAYS = 4

# What docs/CHURN.md states (C10). Compared, never used as a result.
CHURN_DOC = {"packages": 109, "release pairs": 522, "pin stops": 235, "pin stops pct": 45,
             "reword": 150, "reword pct": 29, "description edits": 616,
             "introduced anything": 25, "above 0.5": 4, "above 0.5 releases": 3}


class Register:
    """claim ID -> figure name -> {value, definition, denominator?, inputs}."""

    def __init__(self) -> None:
        self.claims: dict[str, dict[str, dict]] = defaultdict(dict)

    def put(self, claim: str, name: str, value, definition: str, inputs,
            denominator=None) -> None:
        row = {"value": value, "definition": definition, "inputs": sorted(set(inputs))}
        if denominator is not None:
            row["denominator"] = denominator
        self.claims[claim][name] = row

    def share(self, claim: str, name: str, count: int, of: int, of_name: str,
              definition: str, inputs) -> None:
        pct = round(100.0 * count / of, 1) if of else None
        self.put(claim, name + " pct", pct, definition + " As a percentage, one decimal.",
                 inputs, denominator=f"{of_name} ({of})")


# -- reading --------------------------------------------------------------

def load_events(feed: str) -> list[dict]:
    out = []
    for path in sorted(glob.glob(os.path.join(feed, "events", "*.jsonl"))):
        with open(path, encoding="utf-8") as fh:
            out.extend(json.loads(line) for line in fh if line.strip())
    return out


def load_json(feed: str, rel: str):
    path = os.path.join(feed, rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def hosted(e: dict) -> bool:
    return e["package"].startswith(REMOTE)


def day(stamp: str) -> str:
    return stamp[:10]


def named(body: dict | None) -> dict:
    return {str(t.get("name")): t for t in (body or {}).get("tools") or [] if isinstance(t, dict)}


def tool_text(t: dict) -> str:
    return live_text(t.get("description") or "", t.get("title") or "", t.get("annotations") or {},
                     t.get("inputSchema"), t.get("outputSchema"))


class Catalogues:
    """Both catalogues of an event, read once each, through the collector's reader."""

    KEEP = 2048  # catalogues held at once; a few servers' catalogues are large

    def __init__(self, feed: str) -> None:
        self.feed, self.cache = feed, OrderedDict()

    def get(self, package: str, version: str) -> dict | None:
        key = (package, version)
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        try:
            body = watch.read_catalogue(self.feed, package, version)
        except (OSError, ValueError, KeyError):
            body = None
        self.cache[key] = body
        if len(self.cache) > self.KEEP:
            self.cache.popitem(last=False)
        return body

    def pair(self, e: dict):
        return self.get(e["package"], e["from"]), self.get(e["package"], e["to"])


def recompute(feed: str, events: list, cats: Catalogues) -> tuple[dict, dict]:
    """kinds and operators per event key, from the catalogues alone, the way
    watch.churn_stats derives them when stats.json has no answer yet."""
    kinds, ops = {}, {}
    for e in events:
        key = operators.event_key(e)
        before, after = cats.pair(e)
        if before is None or after is None:
            kinds[key], ops[key] = "unclassified", operators.operator(e["package"], None)
            continue
        kinds[key] = operators.classify_event(named(before), named(after))
        url = after.get("url") if hosted(e) else None
        ops[key] = operators.operator(e["package"], url if isinstance(url, str) else None)
    return kinds, ops


# -- the claims -----------------------------------------------------------

def c01(r: Register, feed: str) -> None:
    w = load_json(feed, "watchlist.json") or {"packages": []}
    kinds = Counter(p.get("kind") for p in w["packages"])
    npm, remote = kinds.get("npm", 0), kinds.get("remote", 0)
    src = ["watchlist.json"]
    r.put("C01", "npm watched", npm, "npm packages on the watchlist.", src)
    r.put("C01", "hosted watched", remote, "Hosted endpoints on the watchlist.", src)
    r.put("C01", "total watched", npm + remote, "Every entry on the watchlist.", src)
    r.share("C01", "hosted watched", remote, npm + remote, "entries on the watchlist",
            "Hosted endpoints' share of the watchlist.", src)
    r.put("C01", "watchlist synced", w.get("synced_at"), "The date the watchlist was last "
          "rebuilt from the registry.", src)


REASON_GROUPS = (
    ("login or payment", lambda w: w in ("HTTP 401", "HTTP 402", "HTTP 403")),
    ("not found", lambda w: w == "HTTP 404"),
    ("other 4xx", lambda w: re.fullmatch(r"HTTP 4\d\d", w) is not None),
    ("5xx", lambda w: re.fullmatch(r"HTTP 5\d\d", w) is not None),
    ("network error", lambda w: w in ("URLError", "TimeoutError") or w.startswith("URLError")),
    ("protocol", lambda w: w in ("initialize failed", "no tools/list answer",
                                 "catalogue too large to read")),
)


def reason_group(why: str) -> str:
    for name, test in REASON_GROUPS:
        if test(why):
            return name
    return "other"


def c02(r: Register, feed: str) -> None:
    paths = sorted(glob.glob(os.path.join(feed, "state", "remote__*.json")))
    current = failing = 0
    failing_why: Counter = Counter()
    never: Counter = Counter()
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            s = json.load(fh)
        why = str((s.get("attempted") or {}).get("why") or "unknown")
        if s.get("version"):
            if "attempted" in s:
                failing += 1
                failing_why[why] += 1
            else:
                current += 1
        else:
            never[why] += 1
    total, src = len(paths), ["state/remote__*.json"]
    of = "hosted state files"
    r.put("C02", "hosted state files", total, "Hosted servers the feed holds a state file for, "
          "including ones since dropped from the watchlist.", src)
    r.put("C02", "read and current", current, "Hosted state files with a catalogue and no failed "
          "attempt since.", src)
    r.share("C02", "read and current", current, total, of, "Read and current, of all hosted "
            "state files.", src)
    r.put("C02", "catalogue but latest failed", failing, "Hosted state files with a catalogue "
          "whose latest reading attempt failed.", src)
    r.share("C02", "catalogue but latest failed", failing, total, of, "The same, of all hosted "
            "state files.", src)
    r.put("C02", "catalogue but latest failed by reason", dict(failing_why.most_common()),
          "Those, by the recorded reason (attempted.why).", src)
    n = sum(never.values())
    r.put("C02", "never read", n, "Hosted state files with no catalogue: never read.", src)
    r.share("C02", "never read", n, total, of, "Never read, of all hosted state files.", src)
    r.put("C02", "never read by reason", dict(never.most_common()),
          "Never read, by the recorded reason (attempted.why).", src)
    groups: Counter = Counter()
    for why, count in never.items():
        groups[reason_group(why)] += count
    for name, _ in REASON_GROUPS + (("other", None),):
        r.put("C02", f"never read: {name}", groups.get(name, 0),
              f"Never read, reason grouped as {name}.", src)
        r.share("C02", f"never read: {name}", groups.get(name, 0), total, of,
                f"Never read for {name}, of all hosted state files.", src)


def c03_c05(r: Register, events: list, kinds: dict, ops: dict, inputs: list) -> None:
    """C03 to C05 from per-event kinds and operators, wherever they came from."""
    key = operators.event_key
    hosted_ev = [e for e in events if hosted(e)]
    npm_ev = [e for e in events if not hosted(e)]
    seeded = [e for e in npm_ev if e.get("seeded")]
    live = [e for e in events if not e.get("seeded")]
    r.put("C03", "events", len(events), "Every change event in the snapshot's events/*.jsonl.", inputs)
    r.put("C03", "hosted events", len(hosted_ev), "Change events of hosted servers.", inputs)
    r.put("C03", "npm events", len(npm_ev), "Change events of npm servers.", inputs)
    r.put("C03", "npm events seeded", len(seeded), "npm events carried in from the churn study "
          "(`seeded`), not observed by the feed.", inputs)
    r.put("C03", "npm events live", len(npm_ev) - len(seeded), "npm events the feed observed.", inputs)
    r.put("C03", "live events", len(live), "Every event the feed observed (not seeded).", inputs)
    stamps = sorted(e["observed_at"] for e in live)
    r.put("C03", "live window start", stamps[0] if stamps else None,
          "The earliest observed_at among observed events.", inputs)
    r.put("C03", "live window end", stamps[-1] if stamps else None,
          "The latest observed_at among observed events.", inputs)

    per_op = Counter(ops.get(key(e), e["package"]) for e in hosted_ev)
    top = [op for op, _ in sorted(per_op.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP]]
    per_day = Counter(day(e["observed_at"]) for e in live)
    per_day_hosted = Counter(day(e["observed_at"]) for e in live if hosted(e))
    rest_day = Counter({d: 0 for d in per_day})
    rest_day.update(day(e["observed_at"]) for e in live
                    if ops.get(key(e), e["package"]) not in top)
    r.put("C03", "live events per UTC day", dict(sorted(per_day.items())),
          "Observed events by the UTC date of observed_at.", inputs)
    r.put("C03", "live hosted events per UTC day", dict(sorted(per_day_hosted.items())),
          "Observed hosted events by the UTC date of observed_at.", inputs)
    r.put("C03", "live events per UTC day without top three", dict(sorted(rest_day.items())),
          "The same, leaving out the three operators with the most hosted events.", inputs)
    busiest = max(per_day_hosted.items(), key=lambda kv: (kv[1], kv[0])) if per_day_hosted else (None, None)
    r.put("C03", "busiest hosted day", busiest[0], "The UTC date with the most observed hosted "
          "events.", inputs)
    r.put("C03", "busiest hosted day events", busiest[1], "Observed hosted events on that date.", inputs)

    by_kind = Counter(kinds.get(key(e), "unclassified") for e in events)
    for kind in operators.KINDS + ("unclassified",):
        r.put("C04", kind, by_kind.get(kind, 0), f"Events of kind {kind} "
              "(research/feed/operators.py: an event is substantive if a tool was added, "
              "removed or changed in substance).", inputs)

    all_ops = Counter(ops.get(key(e), e["package"]) for e in events)
    r.put("C05", "operators", len(all_ops), "Distinct operators over every event: a hosted "
          "server's registrable domain, an npm package's name (approximate; see stats.json "
          "`grouping`).", inputs)
    in_top = 0
    for rank, op in enumerate(top, 1):
        mine = [e for e in hosted_ev if ops.get(key(e), e["package"]) == op]
        in_top += len(mine)
        k = Counter(kinds.get(key(e), "unclassified") for e in mine)
        fields = Counter(f for e in mine for f in
                         {f for c in e.get("changed") or [] for f in c.get("fields") or []})
        whole = sum(1 for e in mine if e.get("whole_catalogue"))
        p = f"top {rank}"
        r.put("C05", f"{p} operator", op, f"The operator with the {rank}. most hosted events.", inputs)
        r.put("C05", f"{p} events", len(mine), f"Hosted events of {op}.", inputs)
        r.share("C05", f"{p} events of hosted", len(mine), len(hosted_ev), "hosted events",
                f"{op}'s share of hosted events.", inputs)
        r.share("C05", f"{p} events of all", len(mine), len(events), "all events",
                f"{op}'s share of all events.", inputs)
        r.put("C05", f"{p} kinds", dict(sorted(k.items())), f"{op}'s events by kind.", inputs)
        r.put("C05", f"{p} events changing each field", dict(fields.most_common()),
              f"{op}'s events in which a changed tool's field moved, per field (one event "
              "counts once per field).", inputs)
        r.put("C05", f"{p} servers", len({e['package'] for e in mine}),
              f"Distinct hosted servers of {op} with an event.", inputs)
        r.put("C05", f"{p} whole-catalogue events", whole, f"{op}'s events marked "
              "whole_catalogue (every tool changed at once).", inputs)
        r.share("C05", f"{p} whole-catalogue events", whole, len(mine), f"{op}'s hosted events",
                "The same, of the operator's hosted events.", inputs)
    r.put("C05", "top three events", in_top, "Hosted events of the top three operators together.", inputs)
    r.share("C05", "top three of hosted", in_top, len(hosted_ev), "hosted events",
            "The top three's share of hosted events.", inputs)
    r.share("C05", "top three of all", in_top, len(events), "all events",
            "The top three's share of all events.", inputs)

    per_server = Counter(e["package"] for e in hosted_ev)
    counts = sorted(per_server.values())
    r.put("C05", "hosted servers changed", len(per_server), "Distinct hosted servers with at "
          "least one event.", inputs)
    r.put("C05", "median changes per changed hosted server",
          statistics.median(counts) if counts else None,
          "The median number of events per hosted server with at least one.", inputs)
    r.put("C05", "hosted servers with exactly one change", sum(1 for c in counts if c == 1),
          "Hosted servers with exactly one event.", inputs)
    bands = (("1", 1, 1), ("2", 2, 2), ("3-5", 3, 5), ("6-10", 6, 10), ("11-100", 11, 100),
             ("over 100", 101, 10 ** 9))
    r.put("C05", "changes per changed hosted server", {name: sum(1 for c in counts if lo <= c <= hi)
                                                       for name, lo, hi in bands},
          "Hosted servers with at least one event, by how many they had.", inputs)
    rest = [e for e in hosted_ev if ops.get(key(e), e["package"]) not in top]
    r.put("C05", "hosted events outside top three", len(rest), "Hosted events of every other "
          "operator.", inputs)
    r.put("C05", "hosted servers outside top three", len({e['package'] for e in rest}),
          "Distinct hosted servers with an event, outside the top three operators.", inputs)


def introduced_kinds(e: dict) -> list[dict]:
    return [{"tool": t.get("tool"), **i} for part in ("added", "changed")
            for t in e.get(part) or [] for i in t.get("introduced") or []]


def c06(r: Register, events: list, inputs: list, out_dir: str | None) -> list[dict]:
    grades = Counter(e.get("grade") for e in events)
    review = [e for e in events if e.get("grade") == "review"]
    r.put("C06", "review", grades.get("review", 0), "Events the collector graded review: a "
          "change introduced a signal (heldfast.driftgrade).", inputs)
    r.put("C06", "quiet", grades.get("quiet", 0), "Events graded quiet.", inputs)
    by_kind: Counter = Counter()
    for e in review:
        for k in {i["kind"] for i in introduced_kinds(e)}:
            by_kind[k] += 1
    r.put("C06", "review by introduced kind", dict(sorted(by_kind.items())),
          "Review events per kind of signal introduced; an event with several kinds counts "
          "once under each.", inputs)
    priced = [e for e in review if any(i["kind"] == "price" for i in introduced_kinds(e))]
    r.put("C06", "price review events", len(priced), "Review events that introduced a price.", inputs)
    r.put("C06", "price review servers", len({e["package"] for e in priced}),
          "Distinct servers with such an event.", inputs)
    r.put("C06", "first price review", min((e["observed_at"] for e in priced), default=None),
          "The earliest observed_at of a review event that introduced a price.", inputs)
    other = [e for e in review if not any(i["kind"] == "price" for i in introduced_kinds(e))]
    r.put("C06", "review without price", len(other), "Review events that introduced no price; "
          "each is listed in research/report/review-events.md.", inputs)
    if out_dir:
        lines = ["# Review events without a price signal", "",
                 "Every event the feed graded `review` for something other than a price. "
                 "Written by numbers.py (C06) for a person to read; a signal is a lead, "
                 "not a verdict.", "",
                 "| observed | server | tool | kind | matched text |", "|---|---|---|---|---|"]
        for e in sorted(other, key=lambda e: (e["observed_at"], e["package"])):
            for i in introduced_kinds(e):
                match = str(i.get("match", "")).replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {e['observed_at']} | `{e['package']}` | `{i['tool']}` | "
                             f"{i['kind']} | {match} |")
        _write(os.path.join(out_dir, "review-events.md"), "\n".join(lines) + "\n")
    return priced


def prices(text: str) -> dict[str, list]:
    """unit -> stated amounts, with driftgrade's own price patterns and the
    same rules its `price` signal applies (a size like $80M is not a price)."""
    out: dict[str, list] = defaultdict(list)
    for pattern in PRICES:
        for m in pattern.finditer(text):
            if _priced(text, m):
                out["$"].append(float(_amount(m.group(1))))
    for unit, pattern in UNIT_PRICES:
        for m in pattern.finditer(text):
            out[unit].append(float(_amount(m.group(1))))
    return {u: sorted(v) for u, v in out.items()}


PRICE_CASES = ("changed", "added to a tool", "removed from a tool", "on a new tool")


def price_moves(e: dict, cats: Catalogues) -> tuple[list, set]:
    """(old, new, unit) for each tool whose one stated price in a unit became
    another, and which PRICE_CASES the event's changed or added tools show:
    `changed` is a tool held before and after whose stated amounts differ."""
    touched = {t.get("tool") for part in ("changed", "added") for t in e.get(part) or []}
    if not touched:
        return [], set()
    before, after = cats.pair(e)
    if before is None or after is None:
        return [], set()
    a, b = named(before), named(after)
    pairs, cases = [], set()
    for name in sorted(touched & set(b)):
        pb = prices(tool_text(b[name]))
        if name not in a:
            if pb:
                cases.add("on a new tool")
            continue
        pa = prices(tool_text(a[name]))
        if pa == pb:
            continue
        cases.add("changed" if pa and pb else "added to a tool" if pb else "removed from a tool")
        for unit in set(pa) & set(pb):
            if len(pa[unit]) == 1 and len(pb[unit]) == 1 and pa[unit][0] != pb[unit][0]:
                pairs.append((pa[unit][0], pb[unit][0], unit))
    return pairs, cases


def c07(r: Register, events: list, cats: Catalogues, inputs: list) -> None:
    pairs_by_server: dict[str, list] = defaultdict(list)
    case_servers: dict[str, set] = defaultdict(set)
    changed_at: dict[str, list] = defaultdict(list)
    readable_at: dict[str, list] = defaultdict(list)
    for e in events:
        if e.get("seeded"):
            continue
        pairs, cases = price_moves(e, cats)
        for case in cases:
            case_servers[case].add(e["package"])
        if "changed" in cases:
            changed_at[e["package"]].append(e["observed_at"])
        pairs_by_server[e["package"]].extend(pairs)
        if pairs:
            readable_at[e["package"]].append(e["observed_at"])
    for case in PRICE_CASES:
        r.put("C07", f"servers with a stated price {case}", len(case_servers.get(case, ())),
              f"Servers with an observed event in which a stated price was {case} "
              "(amounts found by heldfast.driftgrade's price patterns, per unit, in the "
              "description, title and schema text of a changed or added tool). A stated "
              "amount can be an example rather than the server's charge.", inputs)
    with_pairs = {s: p for s, p in pairs_by_server.items() if p}
    direction: Counter = Counter()
    for pairs in with_pairs.values():
        ups = sum(1 for old, new, _ in pairs if new > old)
        downs = len(pairs) - ups
        direction["up" if downs == 0 else "down" if ups == 0 else "both"] += 1
    total_pairs = sum(len(p) for p in with_pairs.values())
    biggest = max(with_pairs.items(), key=lambda kv: (len(kv[1]), kv[0]), default=(None, []))
    r.put("C07", "servers with a readable price change", len(with_pairs),
          "Servers with at least one tool whose single stated price in a unit became a "
          "different single price in that unit.", inputs)
    r.put("C07", "readable price pairs", total_pairs, "Such before-and-after pairs, per tool "
          "and event, over every server.", inputs)
    r.put("C07", "servers by direction", dict(sorted(direction.items())),
          "Servers with a readable change, by whether every pair rose, every pair fell, or both.",
          inputs)
    r.put("C07", "server with most pairs", biggest[0], "The server carrying the most readable "
          "pairs.", inputs)
    r.put("C07", "pairs on that server", len(biggest[1]), "Readable pairs on that server.", inputs)
    r.share("C07", "pairs on that server", len(biggest[1]), total_pairs, "readable price pairs",
            "That server's share of all readable pairs.", inputs)

    # The earlier claim: "23 paid servers changed their prices within four days, some tripling".
    loose, loose_start = most_in_window(changed_at)
    strict, strict_start = most_in_window(readable_at)
    tripled = sorted(s for s, p in with_pairs.items() if any(0 < old and new >= 3 * old
                                                            for old, new, _ in p))
    r.put("C07", "most servers with a stated price changed in four days", loose,
          f"The largest number of servers with a stated price changed (as above) within any "
          f"{PRICE_WINDOW_DAYS} consecutive UTC days.", inputs)
    r.put("C07", "that four-day window starts", loose_start, "The first day of that window.", inputs)
    r.put("C07", "most servers with a readable price change in four days", strict,
          f"The same, counting only readable changes (one price became another).", inputs)
    r.put("C07", "that readable four-day window starts", strict_start,
          "The first day of that window.", inputs)
    r.put("C07", "servers with a price at least tripled", len(tripled), "Servers with a readable "
          "pair whose new price is three or more times the old.", inputs)
    r.put("C07", "claim of 23 servers in four days reproduced", strict >= 23 and bool(tripled),
          "Whether at least 23 servers had a readable price change within four days and at "
          "least one price at least tripled. Counting any change in stated amounts instead "
          "is the figure two above.", inputs)


def most_in_window(at: dict) -> tuple[int, str | None]:
    """The most servers with a dated entry inside any PRICE_WINDOW_DAYS run of UTC days."""
    best, best_start = 0, None
    for start in sorted({day(t) for ts in at.values() for t in ts}):
        end = (datetime.fromisoformat(start) + timedelta(days=PRICE_WINDOW_DAYS)).date().isoformat()
        n = sum(1 for ts in at.values() if any(start <= day(t) < end for t in ts))
        if n > best:
            best, best_start = n, start
    return best, best_start


def c08(r: Register, feed: str) -> None:
    d = load_json(feed, os.path.join("lookup", "all.json"))
    tools = (d or {}).get("tools")
    items = list(tools.values()) if isinstance(tools, dict) else [v for _, v in tools or []]
    src = ["lookup/all.json"]
    r.put("C08", "distinct definitions", len(items) if d else None,
          "Entries in lookup/all.json: distinct tool definitions the log has recorded.", src)
    r.put("C08", "definitions on exactly one server",
          sum(1 for v in items if v.get("servers") == 1) if d else None,
          "Of those, the ones recorded on exactly one server.", src)


def c09(r: Register, feed: str) -> None:
    held: dict[str, list] = defaultdict(list)
    for path in sorted(glob.glob(os.path.join(feed, "checkpoints", "*"))):
        name = os.path.basename(path)
        held[name[:10]].append(name[10:] or ".json")
    r.put("C09", "checkpoints", {d: sorted(v) for d, v in sorted(held.items())},
          "Checkpoints in the snapshot tree, with the files each has (.json, .json.ots, "
          ".json.sigstore.json). The snapshot's own checkpoint is written after its commit, "
          "so it is not in its tree.", ["checkpoints/*"])


def c10(r: Register) -> None:
    import analyse
    buf, argv = io.StringIO(), sys.argv
    sys.argv = [analyse.__file__]  # its own default input, not this script's arguments
    try:
        with contextlib.redirect_stdout(buf):
            analyse.main()
    finally:
        sys.argv = argv
    text = buf.getvalue()
    block = text.split("## Third-party", 1)[1].split("##", 1)[0] if "## Third-party" in text else ""

    def grab(label: str, group: int = 1):
        m = re.search(re.escape(label) + r"[ .]*(\d+)(?: \((\d+)%\))?", block)
        return int(m.group(group)) if m and m.group(group) else None

    with open(os.path.join(ROOT, "research", "churn", "suspicious.json"), encoding="utf-8") as fh:
        sus = json.load(fh)
    serious = [h for h in sus["hits"] if h["max_confidence"] > 0.5]
    got = {"packages": grab("packages"), "release pairs": grab("release pairs"),
           "pin stops": grab("releases a pin stops on"), "pin stops pct": grab("releases a pin stops on", 2),
           "reword": grab("...that edit a description"), "reword pct": grab("...that edit a description", 2),
           "description edits": grab("description"),
           "introduced anything": len(sus["hits"]), "above 0.5": len(serious),
           "above 0.5 releases": len({(h["package"], h["to"]) for h in serious})}
    src = ["research/churn/wide.json.gz", "research/churn/suspicious.json", "docs/CHURN.md"]
    for name, value in got.items():
        r.put("C10", name, value, f"Churn study, third-party servers: {name}, from analyse.py "
              "rerun (or suspicious.json, which needs results/ that are not committed to rerun).",
              src)
    r.put("C10", "matches docs/CHURN.md", got == CHURN_DOC, "Whether every figure above equals "
          "the one docs/CHURN.md states.", src)


def c11(r: Register) -> None:
    with open(os.path.join(ROOT, "docs", "SCAN.md"), encoding="utf-8") as fh:
        text = fh.read()
    src = ["docs/SCAN.md"]
    m = re.search(r"([\d,]+) tools from ([\d,]+) servers", text)
    h = re.search(r"([\d,]+)\s+hosted endpoints and ([\d,]+) npm packages", text)
    c = re.search(r"commit `([0-9a-f]{12})`", text)
    num = lambda s: int(s.replace(",", ""))  # noqa: E731
    r.put("C11", "scan tools", num(m.group(1)) if m else None, "Tools the scan study read, "
          "quoted from docs/SCAN.md (data of 2026-09-23), not recomputed.", src)
    r.put("C11", "scan servers", num(m.group(2)) if m else None, "Servers it read, quoted.", src)
    r.put("C11", "scan hosted", num(h.group(1)) if h else None, "Of them hosted, quoted.", src)
    r.put("C11", "scan npm", num(h.group(2)) if h else None, "Of them npm, quoted.", src)
    r.put("C11", "scan feed commit", c.group(1) if c else None, "The heldfast-feed commit "
          "docs/SCAN.md names as its data.", src)


# -- output ---------------------------------------------------------------

def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def register_md(claims: dict) -> str:
    lines = ["# Claims register", "", "Generated by research/report/numbers.py from "
             "numbers.json. Do not edit by hand.", ""]
    for cid in sorted(claims):
        lines += [f"## {cid}", "", "| figure | value | denominator | definition |", "|---|---|---|---|"]
        for name, row in claims[cid].items():
            value = json.dumps(row["value"], ensure_ascii=False).replace("|", "\\|")
            lines.append(f"| {name} | {value} | {row.get('denominator', '')} | {row['definition']} |")
        lines.append("")
    return "\n".join(lines)


def compute(feed: str, out_dir: str | None, churn: bool = True) -> dict:
    r = Register()
    events = load_events(feed)
    stats = load_json(feed, "stats.json")
    ev_in = ["events/*.jsonl"]
    cats = Catalogues(feed)
    c01(r, feed)
    c02(r, feed)
    kinds = (stats or {}).get("classified") or {}
    ops = (stats or {}).get("operator_of") or {}
    c03_c05(r, events, kinds, ops, ev_in + ["stats.json"])
    stated = (stats or {}).get("kinds")
    re_kinds, _ = recompute(feed, events, cats)
    recounted = Counter(re_kinds.get(operators.event_key(e), "unclassified") for e in events)
    r.put("C04", "stats.json kinds", stated, "The kinds stats.json states.", ["stats.json"])
    r.put("C04", "recomputed kinds", dict(sorted(recounted.items())), "The kinds recomputed "
          "from both catalogues of every event with research/feed/operators.py.",
          ev_in + ["catalogues/", "tools/"])
    r.put("C04", "stats.json equals recomputed", stated == dict(sorted(recounted.items())),
          "Whether the two agree.", ev_in + ["stats.json", "catalogues/"])
    c06(r, events, ev_in, out_dir)
    c07(r, events, cats, ev_in + ["catalogues/", "tools/"])
    c08(r, feed)
    c09(r, feed)
    if churn:
        c10(r)
    c11(r)
    return dict(sorted(r.claims.items()))


def verify(feed: str, numbers_path: str) -> int:
    """C03-C05 again, from the raw events and catalogues, without stats.json."""
    with open(numbers_path, encoding="utf-8") as fh:
        stated = json.load(fh)["claims"]
    events = load_events(feed)
    kinds, ops = recompute(feed, events, Catalogues(feed))
    r = Register()
    c03_c05(r, events, kinds, ops, [])
    bad = 0
    for cid in ("C03", "C04", "C05"):
        for name, row in r.claims[cid].items():
            want = (stated.get(cid) or {}).get(name, {}).get("value")
            if want != row["value"]:
                bad += 1
                print(f"MISMATCH {cid} {name}: numbers.json {want!r}, raw {row['value']!r}")
    print("verify: " + ("every C03-C05 figure agrees" if not bad else f"{bad} mismatches"))
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--feed", required=True, help="the extracted snapshot tree")
    ap.add_argument("--out", default=os.path.join(HERE, "numbers.json"))
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--no-churn", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.verify:
        return verify(args.feed, args.out)
    out_dir = os.path.dirname(os.path.abspath(args.out))
    snapshot = load_json(HERE, "SNAPSHOT.json")
    claims = compute(args.feed, out_dir, churn=not args.no_churn)
    body = {"snapshot": snapshot, "claims": claims}
    _write(args.out, json.dumps(body, indent=1, ensure_ascii=False, sort_keys=False) + "\n")
    _write(os.path.join(out_dir, "claims.md"), register_md(claims))
    ok = claims.get("C04", {}).get("stats.json equals recomputed", {}).get("value")
    if ok is False:
        print("C04: stats.json and the recomputed kinds differ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
