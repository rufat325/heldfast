"""Read every tool the drift feed holds, the way heldfast reads one.

The churn study asked how often tool definitions change. Pinning answers
"did it change since I approved it" -- it cannot answer "was it honest when
I approved it". This asks that second question of the whole ecosystem at
once: the latest catalogue of every server the feed has measured (npm
packages launched in a container, hosted endpoints read over HTTPS), run
through heldfast's own content rules, parsed by the same code `--probe` uses.

A finding here is a pattern match, not a verdict. The output is a list for a
person to read in context before anything is said about any server.

  python scan.py --feed DIR [--out DIR] [--jobs N]

Reads the feed checkout. Runs nothing, contacts nothing.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))

# The rules that read what a tool says, rather than how a server is launched.
TEXT_RULES = {"MCPA010", "MCPA011", "MCPA012", "MCPA021", "MCPA022",
              "MCPA026", "MCPA033", "MCPA038"}


def latest(feed: str) -> list[tuple[str, str]]:
    """(package, path of its latest catalogue) for every measured server."""
    out = []
    state_dir = os.path.join(feed, "state")
    for name in sorted(os.listdir(state_dir)):
        with open(os.path.join(state_dir, name), encoding="utf-8") as fh:
            state = json.load(fh)
        version = state.get("version")
        if not version:
            continue
        path = os.path.join(feed, "catalogues", name[:-len(".json")], version + ".json.gz")
        if os.path.exists(path):
            out.append((state["package"], path))
    return out


def scan_one(item: tuple[str, str]) -> dict:
    from heldfast.model import ServerSpec
    from heldfast.probe import _parse_tools
    from heldfast.rules import AuditContext, run_rules

    package, path = item
    with gzip.open(path, "rb") as fh:
        body = json.loads(fh.read().decode("utf-8"))
    remote = package.startswith("remote/")
    spec = ServerSpec(name=package, source="<feed>", client="feed",
                      transport="http" if remote else "stdio",
                      url=body.get("url") if remote else None,
                      command=None if remote else "npx",
                      args=[] if remote else ["-y", f"{package}@{body.get('version')}"])
    tools = _parse_tools(spec.identity(), {"result": {"tools": body.get("tools") or []}})
    try:
        findings = run_rules(AuditContext(servers=[spec], tools=tools), enabled=TEXT_RULES)
    except Exception as exc:  # noqa: BLE001 -- one catalogue must not end the scan
        return {"package": package, "version": body.get("version"), "tools": len(tools),
                "error": f"{type(exc).__name__}: {str(exc)[:200]}", "findings": []}
    return {
        "package": package, "version": body.get("version"), "tools": len(tools),
        "kind": "hosted" if remote else "npm", "url": body.get("url"),
        "findings": [{k: f.to_dict()[k] for k in ("rule_id", "severity", "evidence",
                                                   "snippet", "confidence")}
                     for f in findings],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--feed", required=True, help="a checkout of the feed branch")
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    # Two. Twelve took down the workstation this was first run on.
    ap.add_argument("--jobs", type=int, default=2)
    args = ap.parse_args()
    items = latest(args.feed)
    os.makedirs(args.out, exist_ok=True)
    rows = []
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        for i, row in enumerate(pool.map(scan_one, items, chunksize=32), 1):
            rows.append(row)
            if i % 2000 == 0:
                print(f"  {i}/{len(items)}", file=sys.stderr, flush=True)
    with open(os.path.join(args.out, "findings.jsonl"), "w", encoding="utf-8",
              newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    kinds = Counter(r.get("kind", "?") for r in rows)
    tools = sum(r["tools"] for r in rows)
    print(f"servers: {len(rows)} ({kinds['npm']} npm, {kinds['hosted']} hosted), tools: {tools}")
    print(f"errors: {sum(1 for r in rows if r.get('error'))}")
    by_rule = Counter()
    servers_by_rule: dict[str, set] = {}
    for r in rows:
        for f in r["findings"]:
            by_rule[(f["rule_id"], f["severity"])] += 1
            servers_by_rule.setdefault(f["rule_id"], set()).add(r["package"])
    flagged = {r["package"] for r in rows if r["findings"]}
    print(f"servers with any finding: {len(flagged)} ({100 * len(flagged) / max(len(rows), 1):.1f}%)")
    for (rule, sev), n in sorted(by_rule.items()):
        print(f"  {rule} {sev:<8} {n:>6} findings in {len(servers_by_rule[rule]):>5} servers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
