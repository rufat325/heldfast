"""Refuse a report number that numbers.py did not produce.

Every numeric token in the report's body must be a value in numbers.json
(separators and percent signs aside), a date, a version or an RFC number, or
a line of allowlist.txt with its reason. D1, the snapshot (SNAPSHOT.json,
carried in numbers.json), counts as a claim ID. A paragraph that says every, never,
none, always or only must carry the claim IDs that prove it.

  python research/report/check_numbers.py docs/FIRST-WEEK.md
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
STRIP = [r"```.*?```", r"`[^`]*`", r"\]\([^)]*\)", r"https?://\S+", r"\[[A-Z]?\d+\]",
         r"\d{4}-\d{2}-\d{2}(?:T[\d:+.Z-]+)?", rf"\b\d{{1,2}} (?:{MONTHS})(?: \d{{4}})?",
         rf"(?:{MONTHS}) \d{{4}}", r"\b(?:19|20)\d\d\b", r"\bv?\d+\.\d+\.\d+\b", r"\bRFC \d+",
         r"\bC\d\d\b"]
ABSOLUTE = re.compile(r"\b(every|never|none|always|only)\b", re.IGNORECASE)
NUMBER = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?%?")


def values(node, out: set) -> set:
    if isinstance(node, bool):
        return out
    if isinstance(node, (int, float)):
        out.add(float(node))
    elif isinstance(node, dict):
        for v in node.values():
            values(v, out)
    elif isinstance(node, list):
        for v in node:
            values(v, out)
    return out


def main(path: str) -> int:
    with open(os.path.join(HERE, "numbers.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    known = values([f["value"] for figs in data["claims"].values() for f in figs.values()],
                   values(data.get("snapshot") or {}, set()))
    allowed = {}
    with open(os.path.join(HERE, "allowlist.txt"), encoding="utf-8") as fh:
        for line in fh:
            token, _, reason = line.partition("#")
            if token.strip() and reason.strip():
                allowed[token.strip()] = reason.strip()
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    body = re.split(r"^## (?:References|Appendix)", text, flags=re.M)[0]
    body = re.sub(r"```.*?```", "", body, flags=re.S)
    problems = []
    for para in re.split(r"\n\s*\n", body):
        cited = re.search(r"<!--\s*(?:(?:C\d\d|D1)\s*)+-->", para) is not None
        prose = re.sub(r"<!--.*?-->", "", para, flags=re.S)
        if not cited and ABSOLUTE.search(prose):
            problems.append(f"absolute without a claim ID: {prose.strip()[:80]!r}")
        for pattern in STRIP:
            prose = re.sub(pattern, " ", prose, flags=re.S)
        for token in NUMBER.findall(prose):
            plain = token.rstrip("%").replace(",", "")
            if token in allowed or plain in allowed:
                continue
            if float(plain) not in known:
                problems.append(f"{token} is not in numbers.json: {para.strip()[:80]!r}")
            elif not cited:
                problems.append(f"{token} in a paragraph with no claim ID: {para.strip()[:80]!r}")
    for p in problems:
        print(p)
    print(f"check_numbers: {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "docs",
                                                                       "FIRST-WEEK.md")))
