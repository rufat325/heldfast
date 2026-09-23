"""A running record of what the most-used MCP servers change, release by release.

docs/CHURN.md measured six releases of each server once. This keeps going:
every day it asks npm whether any watched server has published a new stable
release, launches that release, reads its catalogue, and compares it with the
last one it saw. Each release that moved something becomes an event -- which
tools changed, were added or removed, the words that moved, and what
`guard --drift graded` would make of it. The events are the product: a
history of how the servers people actually run behave, which no single scan
can produce.

The grading is mcp-pin's own (driftgrade.py), run against the full previous
text rather than a lockfile's preview, so an event marked `review` is one a
graded pin would refuse even with the complete approved version in hand.

  watch.py seed   --data DIR [--results DIR]   history from the churn study
  watch.py check  --data DIR [--jobs N]        measure new releases (runs code:
                                               in the container only)
  watch.py render --data DIR                   feed.json, feed.xml, README.md
  watch.py verify --data DIR                   refuse anything unexpected

`check` downloads and runs published npm packages, exactly as measure.py
does, and for the same reason it belongs in research/feed/Dockerfile. The
other three read and write JSON and run nothing.

Layout under DIR:
  watchlist.json           which packages, and the rule that chose them
  state/<package>.json     the last catalogue seen for each package
  events/YYYY-MM.jsonl     one line per release that changed something
  feed.json, feed.xml      the latest events, as JSON and as Atom
  README.md                the same, for a person
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "research", "churn"))

from mcp_pin.digest import tool_digest  # noqa: E402
from mcp_pin.driftgrade import introduced, live_text  # noqa: E402
from mcp_pin.review import word_diff  # noqa: E402

FEED_EVENTS = 200
README_EVENTS = 60
# The fields of a definition the model reads or a client acts on. A change
# anywhere else does not move the digest either.
FIELDS = ("description", "title", "inputSchema", "outputSchema", "annotations", "icons")
SAFE_NAME = re.compile(r"^[A-Za-z0-9@._\-]+$")
ALLOWED = re.compile(
    r"^(?:watchlist\.json|feed\.json|feed\.xml|README\.md|"
    r"state/[A-Za-z0-9@._\-]+\.json|events/\d{4}-\d{2}\.jsonl)$")
MAX_FILE = 20 * 1024 * 1024
MAX_TOTAL = 400 * 1024 * 1024
# XML 1.0 has no representation for these, and a description can contain any
# of them. Dropped from the Atom feed only; the JSON keeps the text as sent.
_NOT_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe(package: str) -> str:
    # npm names never start with a dot, so a name that does is not one --
    # and "..", on its own, would be a path.
    name = package.replace("/", "__")
    if not SAFE_NAME.match(name) or name.startswith("."):
        raise ValueError(f"package name outside the safe set: {package!r}")
    return name


def text_of(raw: dict) -> str:
    """Everything in a definition the model reads, as mcp-pin grades it."""
    return live_text(str(raw.get("description") or ""), str(raw.get("title") or ""),
                     raw.get("annotations") or {}, raw.get("inputSchema") or {},
                     raw.get("outputSchema") or {})


def snapshot(package: str, version: str, published: str, tools: list) -> dict:
    return {
        "package": package, "version": version, "published": published,
        "tools": {str(t.get("name")): {"digest": tool_digest(t), "raw": t}
                  for t in tools if isinstance(t, dict) and t.get("name")},
    }


def diff(before: dict, after: dict, observed_at: str) -> dict | None:
    """The event for one release, or None when no definition moved."""
    A, B = before["tools"], after["tools"]
    carried = sorted(set(A) & set(B))
    changed = []
    for name in carried:
        if A[name]["digest"] == B[name]["digest"]:
            continue
        old, new = A[name]["raw"], B[name]["raw"]
        found = introduced({"description_preview": text_of(old)}, text_of(new))
        changed.append({
            "tool": name,
            "fields": [f for f in FIELDS if old.get(f) != new.get(f)],
            "words": word_diff(str(old.get("description") or ""),
                               str(new.get("description") or ""))[:600],
            "introduced": [{"kind": s.kind, "match": s.match} for s in found],
        })
    # A new tool is compared with everything the old catalogue said: text the
    # server already used elsewhere is not introduced by adding it here.
    old_text = "\n".join(text_of(t["raw"]) for t in A.values())
    added = []
    for name in sorted(set(B) - set(A)):
        found = introduced({"description_preview": old_text}, text_of(B[name]["raw"]))
        added.append({"tool": name,
                      "introduced": [{"kind": s.kind, "match": s.match} for s in found]})
    removed = sorted(set(A) - set(B))
    if not changed and not added and not removed:
        return None
    flagged = any(c["introduced"] for c in changed) or any(a["introduced"] for a in added)
    return {
        "package": after["package"], "from": before["version"], "to": after["version"],
        "published": after["published"], "observed_at": observed_at,
        "tools_before": len(A), "tools_after": len(B),
        "changed": changed, "added": added, "removed": removed,
        "whole_catalogue": len(carried) > 1 and len(changed) == len(carried),
        # "review": a graded pin would refuse something in this release.
        # "quiet": it would forward every change and refuse only new tools.
        "grade": "review" if flagged else "quiet",
    }


# -- storage ---------------------------------------------------------------

def load_state(data: str, package: str) -> dict | None:
    path = os.path.join(data, "state", safe(package) + ".json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(data: str, package: str, state: dict) -> None:
    os.makedirs(os.path.join(data, "state"), exist_ok=True)
    path = os.path.join(data, "state", safe(package) + ".json")
    with open(path + ".tmp", "w", encoding="utf-8", newline="\n") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(path + ".tmp", path)


def append_events(data: str, events: list) -> None:
    os.makedirs(os.path.join(data, "events"), exist_ok=True)
    for event in sorted(events, key=lambda e: e["published"]):
        month = event["published"][:7]
        if not re.match(r"^\d{4}-\d{2}$", month):
            month = event["observed_at"][:7]
        path = os.path.join(data, "events", month + ".jsonl")
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")


def all_events(data: str) -> list:
    out = []
    folder = os.path.join(data, "events")
    if not os.path.isdir(folder):
        return out
    for name in sorted(os.listdir(folder)):
        with open(os.path.join(folder, name), encoding="utf-8") as fh:
            out.extend(json.loads(line) for line in fh if line.strip())
    return out


def load_watchlist(data: str) -> list:
    with open(os.path.join(data, "watchlist.json"), encoding="utf-8") as fh:
        return json.load(fh)["packages"]


# -- seed ------------------------------------------------------------------

def seed(args: argparse.Namespace) -> int:
    """Start the record from the churn study rather than from nothing."""
    with open(os.path.join(ROOT, "research", "churn", "sample.json"), encoding="utf-8") as fh:
        sample = json.load(fh)
    from measure import OFFICIAL  # the four the study measured alongside
    rows = [{"package": p} for p in OFFICIAL] + [
        {k: r[k] for k in ("package", "args", "required_env") if k in r}
        for r in sample["sample"]]
    os.makedirs(args.data, exist_ok=True)
    with open(os.path.join(args.data, "watchlist.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump({"rule": sample["rule"], "chosen_at": sample["taken_at"],
                   "packages": rows}, fh, indent=1)
    events, seeded = [], 0
    for row in rows:
        path = os.path.join(args.results, safe(row["package"]) + ".json")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            r = json.load(fh)
        order = sorted(r["versions"], key=lambda v: r["versions"][v]["published"])
        snaps = [snapshot(r["package"], v, r["versions"][v]["published"],
                          [s["raw"] for s in r["versions"][v]["tools"].values()])
                 for v in order]
        for a, b in zip(snaps, snaps[1:]):
            event = diff(a, b, observed_at=b["published"])
            if event:
                event["seeded"] = True
                events.append(event)
        state = snaps[-1] if snaps else {"package": r["package"], "tools": {}}
        if r.get("failures"):
            latest_failed = max(r["failures"], key=lambda v: r["failures"][v]["published"])
            if not snaps or r["failures"][latest_failed]["published"] > state.get("published", ""):
                state["attempted"] = {"version": latest_failed, "at": now(),
                                      "why": r["failures"][latest_failed]["why"]}
        state["checked_at"] = now()
        save_state(args.data, r["package"], state)
        seeded += 1
    append_events(args.data, events)
    print(f"seeded {seeded} packages and {len(events)} historical events")
    return 0


# -- check -----------------------------------------------------------------

def check_one(data: str, row: dict) -> dict | None:
    """Measure the newest stable release if it is new. Returns an event or None."""
    import measure
    package = row["package"]
    state = load_state(data, package) or {"package": package, "tools": {}}
    meta = measure.registry_meta(package)
    if meta is None:
        return None
    latest = measure.recent_versions(meta, 1)
    if not latest:
        return None
    version, published = latest[0]
    if version == state.get("version"):
        return None
    # A release that already failed to start is not retried every day; the
    # next release gets a fresh attempt.
    if (state.get("attempted") or {}).get("version") == version:
        return None
    tail = list(row.get("args") or [])
    if package.endswith("/server-filesystem"):
        import tempfile
        tail = [tempfile.gettempdir()]
    tools, why = measure.catalogue(package, version, tail, row.get("required_env") or [])
    if tools is None:
        state["attempted"] = {"version": version, "at": now(), "why": why}
        state["checked_at"] = now()
        save_state(data, package, state)
        print(f"  {package}@{version}: {why}", flush=True)
        return None
    after = snapshot(package, version, published, tools)
    event = diff(state, after, observed_at=now()) if state.get("version") else None
    after["checked_at"] = now()
    save_state(data, package, after)
    print(f"  {package} {state.get('version') or '(first)'} -> {version}: "
          f"{'no change' if event is None else event['grade']}", flush=True)
    return event


def check(args: argparse.Namespace) -> int:
    rows = load_watchlist(args.data)
    if args.only:
        rows = [r for r in rows if r["package"] in set(args.only)]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        events = [e for e in pool.map(lambda r: check_one(args.data, r), rows) if e]
    append_events(args.data, events)
    print(f"checked {len(rows)} packages; {len(events)} new event(s)")
    return 0


# -- render ----------------------------------------------------------------

def summary(event: dict) -> str:
    bits = []
    if event["changed"]:
        bits.append(f"{len(event['changed'])} changed")
    if event["added"]:
        bits.append(f"{len(event['added'])} added")
    if event["removed"]:
        bits.append(f"{len(event['removed'])} removed")
    return ", ".join(bits) + (" (every tool)" if event["whole_catalogue"] else "")


def flagged(event: dict) -> list:
    out = []
    for c in event["changed"] + event["added"]:
        for s in c["introduced"]:
            out.append(f"{c['tool']}: {s['kind']}")
    return out


def render(args: argparse.Namespace) -> int:
    events = sorted(all_events(args.data), key=lambda e: (e["published"], e["package"]),
                    reverse=True)
    generated = now()
    with open(os.path.join(args.data, "feed.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump({"generated_at": generated, "events": events[:FEED_EVENTS]}, fh, indent=1)
    with open(os.path.join(args.data, "feed.xml"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write(atom(events[:FEED_EVENTS], generated))
    with open(os.path.join(args.data, "README.md"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write(readme(events, generated, args.data))
    print(f"rendered {min(len(events), FEED_EVENTS)} of {len(events)} events")
    return 0


def _x(text: str) -> str:
    return escape(_NOT_XML.sub("", str(text)))


def atom(events: list, generated: str) -> str:
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<feed xmlns="http://www.w3.org/2005/Atom">',
           "  <title>mcp-pin: MCP server tool changes</title>",
           "  <id>tag:github.com,2026:rufat325/mcp-pin/feed</id>",
           f"  <updated>{_x(generated)}</updated>",
           '  <link href="https://github.com/rufat325/mcp-pin/tree/feed"/>']
    for e in events:
        title = f"{e['package']} {e['from']} -> {e['to']}: {summary(e)}"
        if e["grade"] == "review":
            title = "[review] " + title
        lines = [f"{c['tool']}: {', '.join(c['fields'])}"
                 + (f"  {c['words']}" if c["words"] else "") for c in e["changed"]]
        lines += [f"added {a['tool']}" for a in e["added"]]
        lines += [f"removed {r}" for r in e["removed"]]
        lines += [f"introduced -- {f}" for f in flagged(e)]
        out += ["  <entry>",
                f"    <id>tag:github.com,2026:rufat325/mcp-pin/feed/{_x(e['package'])}@{_x(e['to'])}</id>",
                f"    <title>{_x(title)}</title>",
                f"    <updated>{_x(e['published'] or e['observed_at'])}</updated>",
                f'    <link href="https://www.npmjs.com/package/{_x(e["package"])}/v/{_x(e["to"])}"/>',
                f'    <content type="text">{_x(chr(10).join(lines))}</content>',
                "  </entry>"]
    out.append("</feed>")
    return "\n".join(out) + "\n"


def readme(events: list, generated: str, data: str) -> str:
    """Counts, names and versions only. The words a server wrote stay in the
    JSON and the Atom feed, where they are data; rendering them as Markdown on
    a page people read would hand a server a formatting channel."""
    watched = len(load_watchlist(data))
    live = [e for e in events if not e.get("seeded")]
    review = [e for e in events if e["grade"] == "review"]
    lines = [
        "# MCP server tool changes", "",
        f"Generated {generated} by `research/feed/watch.py` on the `main` branch. "
        f"Watching {watched} servers: the 150 most-downloaded npm stdio servers in the "
        "official MCP registry, and the four `@modelcontextprotocol` servers.", "",
        f"{len(events)} releases that changed a tool definition "
        f"({len(live)} observed live, {len(events) - len(live)} from the "
        f"[churn study](https://github.com/rufat325/mcp-pin/blob/main/docs/CHURN.md)); "
        f"{len(review)} where `mcp-pin wrap --drift graded` would refuse something.", "",
        "Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, "
        "with the words that moved: [events/](events).", "",
        "`quiet`: a graded pin forwards every changed tool (new tools still need "
        "approval). `review`: a change introduced an agent-directed instruction, hidden "
        "character, credential path or look-alike letter. Review means read it, not "
        "that it is hostile.", "",
        "| published | package | release | tools | grade |",
        "|---|---|---|---|---|",
    ]
    for e in events[:README_EVENTS]:
        lines.append(f"| {e['published'][:10]} | `{e['package']}` | "
                     f"{e['from']} \u2192 {e['to']} | {summary(e)} | {e['grade']} |")
    return "\n".join(lines) + "\n"


# -- verify ----------------------------------------------------------------

def verify(args: argparse.Namespace) -> int:
    """What the publishing job checks before it commits anything.

    The measuring job ran other people's code. Its output is data about that
    code and nothing else: known file names, sizes a feed could plausibly
    reach, JSON that parses. Anything outside that is refused whole.
    """
    problems, total = [], 0
    for base, _dirs, files in os.walk(args.data):
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, args.data).replace(os.sep, "/")
            if rel.startswith(".git/"):
                continue
            if os.path.islink(full):
                problems.append(f"{rel}: symbolic link")
                continue
            if not ALLOWED.match(rel):
                problems.append(f"{rel}: not a file the feed writes")
                continue
            size = os.path.getsize(full)
            total += size
            if size > MAX_FILE:
                problems.append(f"{rel}: {size} bytes")
            try:
                with open(full, encoding="utf-8") as fh:
                    if rel.endswith(".jsonl"):
                        for line in fh:
                            if line.strip():
                                json.loads(line)
                    elif rel.endswith(".json"):
                        json.load(fh)
                    else:
                        fh.read()
            except (ValueError, UnicodeDecodeError) as exc:
                problems.append(f"{rel}: {exc}")
    if total > MAX_TOTAL:
        problems.append(f"total {total} bytes")
    for p in problems:
        print(f"refused: {p}", file=sys.stderr)
    print(f"verify: {'refused' if problems else 'ok'} ({total} bytes)")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("seed")
    s.add_argument("--data", required=True)
    s.add_argument("--results", default=os.path.join(ROOT, "research", "churn", "results"))
    c = sub.add_parser("check")
    c.add_argument("--data", required=True)
    c.add_argument("--jobs", type=int, default=2)
    c.add_argument("--only", action="append", default=[], metavar="PACKAGE")
    for name in ("render", "verify"):
        sub.add_parser(name).add_argument("--data", required=True)
    args = ap.parse_args()
    return {"seed": seed, "check": check, "render": render, "verify": verify}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
