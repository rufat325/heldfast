"""Every readable price pair behind the report's C07, with the words around each amount.

C07 counts a pair when a tool's one stated amount in a unit became a different
single amount in that unit. It does not check that both amounts are the same
kind of charge, so this lists each pair with about six words either side of the
amount, as the sheet script shows them (research/feed/sample_sheet.py). The
classification of the pairs by hand is in c07-audit.md.

  python research/report/audit_c07.py ../feed-snapshot research/report/audit_c07.json

On the snapshot tree (SNAPSHOT.json) it finds 414 pairs on 16 servers, 4 of
them with a price at least tripled, as numbers.json states. To see the same
window from a later, larger checkout, add the number of events the snapshot
holds (13021): events files are append-only, so the first N are the snapshot's.
"""
from __future__ import annotations

import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "feed"))
import sample_sheet  # noqa: E402  (the same price patterns and context words as the sheet)


def pairs_of(event: dict, cats, report) -> list:
    """numbers.price_moves, kept per tool so each pair can be shown with its words."""
    touched = {t.get("tool") for part in ("changed", "added") for t in event.get(part) or []}
    before, after = cats.pair(event)
    if not touched or before is None or after is None:
        return []
    a, b = report.named(before), report.named(after)
    out = []
    for name in sorted(touched & set(b)):
        if name not in a:
            continue
        text_a, text_b = report.tool_text(a[name]), report.tool_text(b[name])
        pa, pb = report.prices(text_a), report.prices(text_b)
        if pa == pb:
            continue
        for unit in set(pa) & set(pb):
            if len(pa[unit]) == 1 and len(pb[unit]) == 1 and pa[unit][0] != pb[unit][0]:
                out.append((name, unit, pa[unit][0], pb[unit][0], text_a, text_b))
    return out


def context(text: str, unit: str, amount: float) -> str:
    for key, said in sample_sheet.stated_amounts(text):
        if key == (unit, amount):
            return said
    return "?"


def main(argv: list) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    feed, out_path = argv[1], argv[2]
    report = sample_sheet._report()
    events = report.load_events(feed)
    if len(argv) > 3:
        events = events[:int(argv[3])]
    live = [e for e in events if not e.get("seeded")]
    cats = report.Catalogues(feed)
    rows = []
    for e in live:
        for name, unit, old, new, text_a, text_b in pairs_of(e, cats, report):
            rows.append(dict(server=e["package"], tool=name, unit=unit, old=old, new=new,
                             at=e["observed_at"], before=context(text_a, unit, old),
                             after=context(text_b, unit, new)))
    servers = collections.defaultdict(list)
    for r in rows:
        servers[r["server"]].append(r)
    tripled = sorted(s for s, p in servers.items() if any(0 < r["old"] and r["new"] >= 3 * r["old"] for r in p))
    print(f"events {len(events)}; pairs {len(rows)}; servers with a pair {len(servers)}; "
          f"servers with a price at least tripled {len(tripled)}")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"rows": rows, "tripled": tripled}, fh, indent=1)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
