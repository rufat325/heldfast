"""Who a feed event came from, and what kind of change it was.

The feed's headline was one number -- every event in which a server's tools
changed -- and most of it measured one company's catalogue counter: a router
tool whose description says "6,402 tools across 1674 verified sources" is a
new definition every time the count ticks. Published raw, that reads as
thousands of rewrites. So each event is classified, and counted per operator.

Kinds, per changed tool, over the fields the lock digest covers
(docs/LOCK.md):

  reorder-only   equal once every list of scalars is sorted
  numbers-only   equal once, as well, every run of digits is `#`
  substantive    anything else

An event is substantive if any tool was added or removed or any change was
substantive; otherwise numbers-only if any change was; otherwise
reorder-only. A numbers-only change can still matter -- a price is a number
(driftgrade's `price` signal holds those for review) -- so this sorts the
headline, it does not excuse anything.

Operators. A hosted server is keyed by its URL's registrable domain under
the Public Suffix List, private section included, so each site on a shared
host (`<account>.workers.dev`) counts as its own operator and `co.uk` is a
suffix, not an operator. That grouping is approximate: it merges different
customers of one host that the list does not name, and splits an operator
who uses several domains. An npm server is keyed by its package name.

Pure over what it is given, apart from reading the vendored list once.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
PSL_PATH = os.path.join(HERE, "public_suffix_list.dat")
KINDS = ("substantive", "numbers-only", "reorder-only")


# -- kind of change (the reference classifier, docs: FIX-BRIEF appendix A) --

def body(tool: dict) -> dict:
    """The fields the lock digest covers, as the feed stores them."""
    out = {
        "name": tool.get("name", ""),
        "title": tool.get("title", ""),
        "description": tool.get("description", ""),
        "input_schema": tool.get("input_schema", tool.get("inputSchema")) or {},
        "annotations": tool.get("annotations") or {},
    }
    output_schema = tool.get("output_schema", tool.get("outputSchema"))
    if output_schema:
        out["output_schema"] = output_schema
    if tool.get("icons"):
        out["icons"] = tool["icons"]
    return out


def canon(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sort_scalar_lists(value: object) -> object:
    if isinstance(value, dict):
        return {k: sort_scalar_lists(v) for k, v in value.items()}
    if isinstance(value, list):
        items = [sort_scalar_lists(v) for v in value]
        if all(not isinstance(v, (dict, list)) for v in items):
            return sorted(items, key=canon)
        return items
    return value


_DIGITS = re.compile(r"\d+")


def mask_digits(value: object) -> object:
    if isinstance(value, dict):
        return {k: mask_digits(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_digits(v) for v in value]
    if isinstance(value, str):
        return _DIGITS.sub("#", value)
    return value


def classify_tool(old: dict, new: dict) -> str:
    a, b = body(old), body(new)
    if canon(a) == canon(b):
        return "identical"
    if canon(sort_scalar_lists(a)) == canon(sort_scalar_lists(b)):
        return "reorder-only"
    if canon(sort_scalar_lists(mask_digits(a))) == canon(sort_scalar_lists(mask_digits(b))):
        return "numbers-only"
    return "substantive"


def classify_event(before: dict, after: dict) -> str:
    """before, after: {tool name: full definition}."""
    if set(before) != set(after):
        return "substantive"
    kinds = {classify_tool(before[name], after[name]) for name in before}
    for kind in KINDS:
        if kind in kinds:
            return kind
    return "identical"


# -- operator (a small Public Suffix List matcher) ------------------------

class Suffixes:
    """The Public Suffix List's rules: normal, wildcard (`*.ck`), exception
    (`!www.ck`). Matched the way the list's own algorithm says: the longest
    matching rule wins, an exception beats a wildcard, and an unlisted TLD
    is a suffix of one label."""

    def __init__(self, text: str) -> None:
        self.rules: set[str] = set()
        self.wild: set[str] = set()
        self.exceptions: set[str] = set()
        self.version = ""
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("// VERSION:"):
                self.version = line.split(":", 1)[1].strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            if not rule.isascii():
                # Hosts arrive as ASCII (punycode); a rule this cannot spell
                # that way can never match one.
                try:
                    rule = ".".join(part if part in ("*", "") else
                                    ("!" + part[1:].encode("idna").decode("ascii")
                                     if part.startswith("!") else
                                     part.encode("idna").decode("ascii"))
                                    for part in rule.split("."))
                except UnicodeError:
                    continue
            if rule.startswith("!"):
                self.exceptions.add(rule[1:])
            elif rule.startswith("*."):
                self.wild.add(rule[2:])
            else:
                self.rules.add(rule)

    def suffix_length(self, labels: list[str]) -> int:
        """How many trailing labels of `labels` are the public suffix."""
        best = 1
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            n = len(labels) - i
            if candidate in self.exceptions:
                return n - 1
            if candidate in self.rules:
                best = max(best, n)
            if i > 0 and ".".join(labels[i:]) in self.wild:
                best = max(best, n + 1)
        return min(best, len(labels))

    def registrable(self, host: str) -> str:
        """The registrable domain: the public suffix and one label more. A
        host that is itself a public suffix is its own key."""
        host = host.strip(".").lower()
        if not host or re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host):
            return host
        labels = host.split(".")
        n = self.suffix_length(labels)
        return ".".join(labels[-(n + 1):]) if len(labels) > n else host


_SUFFIXES: Suffixes | None = None


def suffixes() -> Suffixes:
    global _SUFFIXES
    if _SUFFIXES is None:
        with open(PSL_PATH, encoding="utf-8") as fh:
            _SUFFIXES = Suffixes(fh.read())
    return _SUFFIXES


def operator(package: str, url: str | None) -> str:
    """The key an event is counted under: a hosted server's registrable
    domain, an npm package's name."""
    if url:
        from urllib.parse import urlsplit
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        if host:
            return suffixes().registrable(host)
    return package


# -- statistics -----------------------------------------------------------

def event_key(event: dict) -> str:
    return f"{event['package']}@{event['from']}->{event['to']}"


def tally(events: list, kinds: dict, operators: dict) -> dict:
    """stats.json's body. `kinds` and `operators` map event_key -> value."""
    hosted = [e for e in events if e["package"].startswith("remote/")]
    per: dict[str, Counter] = {}
    for e in events:
        key = event_key(e)
        row = per.setdefault(operators.get(key, e["package"]), Counter())
        row["changes"] += 1
        row[kinds.get(key, "unclassified")] += 1
    table = sorted(({"operator": op, **dict(sorted(c.items()))} for op, c in per.items()),
                   key=lambda r: (-r["changes"], r["operator"]))
    by_kind = Counter(kinds.get(event_key(e), "unclassified") for e in events)
    return {
        "events": len(events), "npm": len(events) - len(hosted), "hosted": len(hosted),
        "kinds": dict(sorted(by_kind.items())),
        "operators": table,
        "grouping": ("hosted servers by registrable domain under the Public Suffix List "
                     f"({suffixes().version}), private section included; npm servers by "
                     "package. Approximate: it merges different customers of one host the "
                     "list does not name, and splits an operator who uses several domains"),
        "classified": {k: kinds[k] for k in sorted(kinds)},
        "operator_of": {k: operators[k] for k in sorted(operators)},
    }
