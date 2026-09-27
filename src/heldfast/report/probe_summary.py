"""One line for the Action's job summary: whose tool definitions were checked.

Reads the JSON report's `probe` block and prints, for example:

    Tool definitions checked: 3 hosted servers. Not checked: 2 stdio servers
    (probe is off for stdio servers, which it would launch), 1 hosted server
    (could not read: HTTP 401 Unauthorized).

"No findings" means nothing about a server whose tools were never read, so
the summary says which those were. Stdlib only; action.yml runs `python -m heldfast.report.probe_summary REPORT`.
"""

from __future__ import annotations

import json
import sys
from collections import Counter


def _servers(n: int, transport: str) -> str:
    return f"{n} {transport} server{'' if n == 1 else 's'}"


def summary(report: dict) -> str:
    rows = report.get("probe") or []
    if not rows:
        return "Tool definitions checked: none (no servers configured)."
    read = Counter(r["transport"] for r in rows if r["state"] == "read")
    missed = Counter((r["transport"], r["state"], r["detail"]) for r in rows if r["state"] != "read")
    checked = ", ".join(_servers(n, t) for t, n in sorted(read.items())) or "none"
    line = f"Tool definitions checked: {checked}."
    if missed:
        parts = []
        for (transport, state, detail), n in sorted(missed.items()):
            why = f"{state}: {detail}" if state == "could not read" else detail
            parts.append(f"{_servers(n, transport)} ({why})")
        line += " Not checked: " + ", ".join(parts) + "."
    return line


def main(argv: list[str]) -> int:
    with open(argv[1], encoding="utf-8") as fh:
        print(summary(json.load(fh)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
