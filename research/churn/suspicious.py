"""Which of the measured changes would a reviewer want to read first?

analyse.py says how often definitions move. This says which moves look like
the attack the pin exists for: text that, between one release and the next,
gained something addressed to the agent rather than to a reader.

Only what a release *introduced* is reported. A description that has said
"do not mention this to the user" since its first version is a finding for
the scanner, not for a study of change -- and counting it here would make
every release of that server look like a new event.

Every hit is a lead for a human, not a verdict. The signals are heldfast's
own, with the confidence it gives them; a URL that appears in a new version
is usually documentation. The output says which release, which tool, and
the words that moved, so the claim can be checked in a minute.

  python suspicious.py              # results/*.json -> suspicious.json + a summary
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from heldfast.review import word_diff  # noqa: E402
from heldfast.rules.poisoning import (  # noqa: E402
    SENSITIVE_PATHS, _scan_text, invisible_runs)

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")
URL = re.compile(r"https?://([A-Za-z0-9.-]+)", re.I)


def agent_text(tool):
    """Everything in a definition the model reads, as one string.

    Descriptions are not the only channel: a property description inside the
    input schema is read too, and is where a careful attacker would put it.
    """
    raw = tool.get("raw") or {}
    parts = [raw.get("description") or "", raw.get("title") or ""]

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("description", "title") and isinstance(v, str):
                    parts.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(raw.get("inputSchema") or {})
    return "\n".join(p for p in parts if p)


def signals(text):
    out = set()
    for sig, m in _scan_text(text, strict=False):
        out.add(("signal:" + sig.category, m.group(0).strip()[:80], sig.confidence))
    for _, name, kind in invisible_runs(text):
        out.add(("hidden:" + kind, name, 0.9))
    for m in SENSITIVE_PATHS.finditer(text):
        out.add(("credential-path", m.group(0), 0.75))
    for m in URL.finditer(text):
        out.add(("new-domain", m.group(1).lower(), 0.2))
    return out


def introduced(before, after):
    """Signals in `after` whose (kind, match) pair was not in `before`."""
    had = {(k, s) for k, s, _ in before}
    return sorted(x for x in after if (x[0], x[1]) not in had)


def main():
    # Descriptions carry emoji and CJK; a Windows console codepage cannot.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    hits, pairs = [], 0
    for name in sorted(os.listdir(RESULTS)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(RESULTS, name), encoding="utf-8") as fh:
            r = json.load(fh)
        versions = sorted(r["versions"], key=lambda v: r["versions"][v]["published"])
        for a, b in zip(versions, versions[1:]):
            pairs += 1
            A, B = r["versions"][a]["tools"], r["versions"][b]["tools"]
            carried = set(A) & set(B)
            moved = [t for t in carried if A[t]["digest"] != B[t]["digest"]]
            wide = len(carried) > 1 and len(moved) == len(carried)
            for tool in sorted(set(B)):
                new_text = agent_text(B[tool])
                old_text = agent_text(A[tool]) if tool in A else ""
                if tool in A and new_text == old_text:
                    continue
                # A brand-new tool is compared against the whole old catalogue:
                # text the server already said elsewhere is not introduced.
                baseline = signals(old_text) if tool in A else set().union(
                    *(signals(agent_text(t)) for t in A.values()))
                new = introduced(baseline, signals(new_text))
                if not new:
                    continue
                hits.append({
                    "package": r["package"], "from": a, "to": b,
                    "published": r["versions"][b]["published"],
                    "tool": tool, "added_tool": tool not in A,
                    "release_moved_every_tool": wide,
                    "signals": [{"kind": k, "match": s, "confidence": c}
                                for k, s, c in new],
                    "max_confidence": max(c for _, _, c in new),
                    "words": word_diff(old_text, new_text)[:600],
                })

    hits.sort(key=lambda h: (-h["max_confidence"], h["package"], h["to"], h["tool"]))
    with open(os.path.join(HERE, "suspicious.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump({"release_pairs": pairs, "hits": hits}, fh, indent=1)

    serious = [h for h in hits if h["max_confidence"] >= 0.5]
    releases = {(h["package"], h["to"]) for h in serious}
    print(f"{pairs} release pairs; {len(hits)} changes introduced a signal; "
          f"{len(serious)} at confidence >= 0.5, in {len(releases)} releases")
    for h in serious:
        kinds = ", ".join(f"{s['kind']} {s['match']!r}" for s in h["signals"]
                          if s["confidence"] >= 0.5)
        shape = "whole-catalogue release" if h["release_moved_every_tool"] else "isolated"
        added = " (new tool)" if h["added_tool"] else ""
        print(f"\n  {h['package']} {h['from']} -> {h['to']}  [{shape}]")
        print(f"    {h['tool']}{added}: {kinds}")
        print(f"    {h['words'][:300]}")


if __name__ == "__main__":
    main()
