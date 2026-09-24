"""A running record of what MCP servers change, release by release.

docs/CHURN.md measured six releases of each server once. This keeps going,
across the whole MCP registry: every npm server that runs over stdio, and
every hosted endpoint that answers without credentials. When one publishes a
new release (npm) or starts describing its tools differently (hosted), the
new catalogue is read, compared with the last one seen, and recorded -- which
tools changed, were added or removed, the words that moved, and what
`guard --drift graded` would make of it. The events are the product: a
history of how the servers people actually run behave, which no single scan
can produce.

The grading is heldfast's own (driftgrade.py), run against the full previous
text rather than a lockfile's preview, so an event marked `review` is one a
graded pin would refuse even with the complete approved version in hand.

Cadence. The 150 most-downloaded npm servers (the churn study's sample) and
the four official ones are checked daily. Every other npm server is checked
once a week, on a weekday fixed by a hash of its name -- no bookkeeping, so a
day on which nothing moved writes nothing. Hosted endpoints are checked daily,
because they can change without any release to announce it.

  watch.py seed         --data DIR [--results DIR]  history from the churn study
  watch.py sync         --data DIR                  rebuild the watchlist from the
                                                    registry (reads, runs nothing)
  watch.py check        --data DIR [--shard i/N] [--budget M] [--jobs N]
                                                    new npm releases (RUNS CODE:
                                                    in the container only)
  watch.py check-remote --data DIR [--shard i/N] [--jobs N]
                                                    hosted endpoints (connects)
  watch.py fold         --data DIR                  incoming/ -> events/
  watch.py render       --data DIR                  index.json, feed.*, README.md
  watch.py verify       --data DIR                  refuse anything unexpected
  watch.py admit        --data DIR --deltas DIR --into DIR
                                                    take each shard's upload only
                                                    for the servers it was given

`check` downloads and runs published npm packages, exactly as measure.py
does, and for the same reason it belongs in research/feed/Dockerfile. The
rest read and write JSON and run nothing a server wrote.

Layout under DIR:
  watchlist.json                 which servers, how often, and the rule
  state/<name>.json              the last version seen and its tool digests
  catalogues/<name>/<version>.json.gz
                                 every catalogue measured, whole, gzipped:
                                 what `heldfast approve --from-feed` pins
  incoming/<label>.jsonl         events from one run, before `fold`
  events/YYYY-MM.jsonl           one line per release that changed something
  index.json                     per server: measured versions and events
  lookup/<abc>.json              every tool definition ever logged, by the first
                                 three hex characters of its fingerprint: when
                                 first seen, on how many servers (docs/LOOKUP.md)
  feed.json, feed.xml            the latest events, as JSON and as Atom
  README.md                      the same, for a person
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "research", "churn"))

from heldfast.digest import tool_digest  # noqa: E402
from heldfast.driftgrade import introduced, live_text  # noqa: E402
from heldfast.review import word_diff  # noqa: E402

FEED_EVENTS = 200
README_EVENTS = 60
FIELDS = ("description", "title", "inputSchema", "outputSchema", "annotations", "icons")
SAFE_NAME = re.compile(r"^[A-Za-z0-9@._\-]+$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]*$")
ALLOWED = re.compile(
    r"^(?:watchlist\.json|index\.json|feed\.json|feed\.xml|README\.md|"
    r"state/[A-Za-z0-9@._\-]+\.json|events/\d{4}-\d{2}\.jsonl|"
    r"incoming/[a-z0-9\-]+\.jsonl|lookup/(?:[0-9a-f]{3}|meta)\.json|"
    r"catalogues/[A-Za-z0-9@._\-]+/[A-Za-z0-9][A-Za-z0-9._+\-]*\.json\.gz)$")
MEASURED_PROTOCOL = "2025-06-18"
MAX_FILE = 20 * 1024 * 1024
# A gzip that inflates past this is refused, not read: the text inside came
# from a server, and a server can send a catalogue built to be one.
MAX_INFLATED = 50 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
# A hosted catalogue bigger than this is not read. No real one comes close.
MAX_REMOTE_BYTES = 4 * 1024 * 1024
_NOT_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f" + chr(0xFFFE) + chr(0xFFFF) + "]")
REMOTE_PREFIX = "remote/"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe(package: str) -> str:
    # npm names never start with a dot, so a name that does is not one --
    # and "..", on its own, would be a path.
    name = package.replace("/", "__")
    if not SAFE_NAME.match(name) or name.startswith("."):
        raise ValueError(f"package name outside the safe set: {package!r}")
    return name


def _hash(text: str, salt: str) -> int:
    return int(hashlib.sha256((salt + text).encode("utf-8")).hexdigest(), 16)


def due(row: dict, day: date) -> bool:
    """Daily rows every day; the rest on one weekday fixed by their name."""
    return row.get("tier", "daily") == "daily" or _hash(row["package"], "day") % 7 == day.weekday()


def in_shard(row: dict, shard: tuple[int, int]) -> bool:
    index, of = shard
    return _hash(row["package"], "shard") % of == index


def parse_shard(text: str) -> tuple[int, int]:
    m = re.match(r"^(\d+)/(\d+)$", text or "0/1")
    if not m or int(m.group(2)) < 1 or int(m.group(1)) >= int(m.group(2)):
        raise ValueError(f"--shard wants i/N with 0 <= i < N, not {text!r}")
    return int(m.group(1)), int(m.group(2))


def text_of(raw: dict) -> str:
    """Everything in a definition the model reads, as heldfast grades it."""
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

def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "wb") as fh:
        fh.write(data)
    os.replace(path + ".tmp", path)


def _json_bytes(obj: object) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True) + "\n").encode("utf-8")


def read_gz(path: str) -> object:
    """A gzipped JSON file, refused if it inflates past MAX_INFLATED."""
    with gzip.open(path, "rb") as fh:
        raw = fh.read(MAX_INFLATED + 1)
    if len(raw) > MAX_INFLATED:
        raise ValueError(f"{path}: inflates past {MAX_INFLATED} bytes")
    return json.loads(raw.decode("utf-8"))


def catalogue_path(data: str, package: str, version: str) -> str:
    if not SAFE_VERSION.match(version):
        raise ValueError(f"version outside the safe set: {version!r}")
    return os.path.join(data, "catalogues", safe(package), version + ".json.gz")


def write_catalogue(data: str, snap: dict, args: list, measured_at: str,
                    extra: dict | None = None) -> None:
    """The whole catalogue for one version, as `tools/list` returned it.

    This is what `heldfast approve --from-feed` pins, so it is the raw wire
    objects, not the digests: the client fingerprints them itself, with the
    same code `--probe` uses, rather than trusting a digest it was handed.
    Gzipped with a fixed mtime, so the same catalogue is the same bytes.
    """
    version = str(snap["version"])
    body = {"package": snap["package"], "version": version,
            "published": snap.get("published", ""), "measured_at": measured_at,
            "protocol": MEASURED_PROTOCOL, "args": list(args or []),
            "tools": [t["raw"] for _, t in sorted(snap["tools"].items())], **(extra or {})}
    _write(catalogue_path(data, snap["package"], version),
           gzip.compress(_json_bytes(body), compresslevel=9, mtime=0))


def load_snapshot(data: str, package: str, version: str) -> dict | None:
    """The snapshot for a version the feed holds a catalogue of, or None."""
    path = catalogue_path(data, package, version)
    if not os.path.exists(path):
        return None
    body = read_gz(path)
    return snapshot(package, version, str(body.get("published") or ""), body.get("tools") or [])


def load_state(data: str, package: str) -> dict | None:
    path = os.path.join(data, "state", safe(package) + ".json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        state = json.load(fh)
    # The first layout kept whole definitions here; only digests are needed.
    tools = state.get("tools") or {}
    state["tools"] = {n: (t.get("digest") if isinstance(t, dict) else t) for n, t in tools.items()}
    return state


def save_state(data: str, package: str, state: dict) -> None:
    compact = {k: v for k, v in state.items() if k != "tools"}
    compact["tools"] = {n: (t["digest"] if isinstance(t, dict) else t)
                        for n, t in (state.get("tools") or {}).items()}
    _write(os.path.join(data, "state", safe(package) + ".json"), _json_bytes(compact))


def write_incoming(data: str, label: str, events: list) -> None:
    if not events:
        return
    if not re.match(r"^[a-z0-9\-]+$", label):
        raise ValueError(f"label outside the safe set: {label!r}")
    path = os.path.join(data, "incoming", label + ".jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        for event in events:
            fh.write(json.dumps(event, sort_keys=True) + "\n")


def append_events(data: str, events: list) -> None:
    os.makedirs(os.path.join(data, "events"), exist_ok=True)
    for event in sorted(events, key=lambda e: (e["published"], e["package"], e["to"])):
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


def fold(args: argparse.Namespace) -> int:
    """Move incoming events into the monthly logs, once, in a stable order."""
    folder = os.path.join(args.data, "incoming")
    events = []
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        path = os.path.join(folder, name)
        with open(path, encoding="utf-8") as fh:
            events.extend(json.loads(line) for line in fh if line.strip())
        os.remove(path)
    append_events(args.data, events)
    print(f"folded {len(events)} event(s)")
    return 0


# -- seed ------------------------------------------------------------------

def seed(args: argparse.Namespace) -> int:
    """Start the record from the churn study rather than from nothing."""
    with open(os.path.join(ROOT, "research", "churn", "sample.json"), encoding="utf-8") as fh:
        sample = json.load(fh)
    from measure import OFFICIAL  # the four the study measured alongside
    rows = [{"package": p, "kind": "npm", "tier": "daily"} for p in OFFICIAL] + [
        dict({k: r[k] for k in ("package", "args", "required_env") if k in r},
             kind="npm", tier="daily")
        for r in sample["sample"]]
    os.makedirs(args.data, exist_ok=True)
    _write(os.path.join(args.data, "watchlist.json"), _json_bytes(
        {"rule": sample["rule"], "chosen_at": sample["taken_at"], "packages": rows}))
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
        for sn in snaps:
            write_catalogue(args.data, sn, r.get("args") or row.get("args") or [],
                            measured_at=sample["taken_at"])
        for a, b in zip(snaps, snaps[1:]):
            event = diff(a, b, observed_at=b["published"])
            if event:
                event["seeded"] = True
                events.append(event)
        state = dict(snaps[-1]) if snaps else {"package": r["package"], "tools": {}}
        if r.get("failures"):
            latest_failed = max(r["failures"], key=lambda v: r["failures"][v]["published"])
            if not snaps or r["failures"][latest_failed]["published"] > state.get("published", ""):
                state["attempted"] = {"version": latest_failed, "at": now(),
                                      "why": r["failures"][latest_failed]["why"]}
        save_state(args.data, r["package"], state)
        seeded += 1
    append_events(args.data, events)
    print(f"seeded {seeded} packages and {len(events)} historical events")
    return 0


# -- sync ------------------------------------------------------------------

def registry_frame() -> tuple[dict, dict]:
    """(npm stdio packages, hosted endpoints) from the official registry."""
    import urllib.parse
    from sample import REGISTRY, get_json, launch_args
    npm, remotes, cursor = {}, {}, None
    while True:
        q = {"limit": "100", "version": "latest"}
        if cursor:
            q["cursor"] = cursor
        page = get_json(REGISTRY + "?" + urllib.parse.urlencode(q))
        for entry in page["servers"]:
            server = entry["server"]
            for pkg in server.get("packages") or []:
                if pkg.get("registryType") != "npm" or \
                        (pkg.get("transport") or {}).get("type") != "stdio":
                    continue
                argv, _ = launch_args(pkg)
                required = [e.get("name") for e in pkg.get("environmentVariables") or []
                            if e.get("isRequired")]
                npm.setdefault(pkg["identifier"], {"args": argv, "required_env": required})
            for i, remote in enumerate(server.get("remotes") or []):
                url = str(remote.get("url") or "")
                if (remote.get("type") != "streamable-http" or not url.startswith("https://")
                        or "{" in url
                        or any(h.get("isRequired") for h in remote.get("headers") or [])):
                    continue
                remotes.setdefault(url, f"{server['name']}{'.' + str(i) if i else ''}")
        cursor = page["metadata"].get("nextCursor")
        if not cursor:
            return npm, remotes


def sync(args: argparse.Namespace) -> int:
    """Every npm stdio server and every open hosted endpoint in the registry.

    The daily rows already in the watchlist stay daily. Everything else is
    weekly (npm) or daily (hosted). Reads the registry; launches nothing.
    Endpoints that need a credential or a URL template, or speak the old SSE
    transport, are left out: there is nothing to read without the secret.
    """
    existing = load_watchlist(args.data)
    daily = {r["package"]: r for r in existing
             if r.get("kind", "npm") == "npm" and r.get("tier", "daily") == "daily"}
    npm, remotes = registry_frame()
    rows = list(daily.values())
    for name, meta in sorted(npm.items()):
        if name in daily:
            continue
        try:
            safe(name)
        except ValueError:
            continue
        rows.append({"package": name, "kind": "npm", "tier": "weekly", **meta})
    seen = set()
    for url, regname in sorted(remotes.items()):
        key = REMOTE_PREFIX + regname
        try:
            safe(key)
        except ValueError:
            continue
        if key in seen:
            continue
        seen.add(key)
        rows.append({"package": key, "kind": "remote", "tier": "daily", "url": url})
    _write(os.path.join(args.data, "watchlist.json"), _json_bytes({
        "rule": "official MCP registry: every npm stdio package (the 150 most-downloaded "
                "and the four official ones daily, the rest weekly) and every hosted "
                "streamable-http endpoint that declares no required header (daily)",
        "synced_at": now()[:10], "packages": rows}))
    counts = {k: sum(1 for r in rows if r.get("kind") == k) for k in ("npm", "remote")}
    print(f"watchlist: {counts['npm']} npm ({len(daily)} daily), {counts['remote']} hosted")
    return 0


# -- check (npm) -----------------------------------------------------------

class Budget:
    """How many servers one run may launch. Shared by its worker threads."""

    def __init__(self, limit: int) -> None:
        self.left = limit if limit > 0 else -1
        self.lock = threading.Lock()

    def take(self) -> bool:
        with self.lock:
            if self.left == 0:
                return False
            if self.left > 0:
                self.left -= 1
            return True


def check_one(data: str, row: dict, budget: Budget | None = None) -> dict | None:
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
    if version == state.get("version") or not SAFE_VERSION.match(version):
        return None
    # A release that already failed to start is not retried every day; the
    # next release gets a fresh attempt.
    if (state.get("attempted") or {}).get("version") == version:
        return None
    if budget is not None and not budget.take():
        return None
    tail = list(row.get("args") or [])
    if package.endswith("/server-filesystem"):
        import tempfile
        tail = [tempfile.gettempdir()]
    tools, why = measure.catalogue(package, version, tail, row.get("required_env") or [])
    if tools is None:
        state["attempted"] = {"version": version, "at": now(), "why": why}
        save_state(data, package, state)
        print(f"  {package}@{version}: {why}", flush=True)
        return None
    after = snapshot(package, version, published, tools)
    before = load_snapshot(data, package, state["version"]) if state.get("version") else None
    write_catalogue(data, after, tail, measured_at=now())
    event = diff(before, after, observed_at=now()) if before else None
    save_state(data, package, dict(after, checked_at=now()))
    print(f"  {package} {state.get('version') or '(first)'} -> {version}: "
          f"{'no change' if event is None else event['grade']}", flush=True)
    return event


def _selected(args: argparse.Namespace, kind: str) -> list:
    rows = [r for r in load_watchlist(args.data) if r.get("kind", "npm") == kind]
    if args.only:
        return [r for r in rows if r["package"] in set(args.only)]
    shard = parse_shard(args.shard)
    day = date.fromisoformat(args.day) if args.day else datetime.now(timezone.utc).date()
    return [r for r in rows if in_shard(r, shard) and (kind == "remote" or due(r, day))]


def isolated(fn, data: str, row: dict, *extra: object) -> dict | None:
    """Run one server's check so that nothing it does can stop the others.

    Thousands of servers means every malformed answer the HTTP client can be
    handed, and some of those are not the exceptions anyone thinks to catch
    (http.client.IncompleteRead is not an OSError). One of them ended a shard
    of 4,600 endpoints on the first full run. Now it is that server's result:
    logged with its type, and recorded where the server's state can hold it.
    """
    try:
        return fn(data, row, *extra)
    except Exception as exc:  # noqa: BLE001 -- the point is not to choose
        why = f"error: {type(exc).__name__}"
        print(f"  {row.get('package')}: {why}: {str(exc)[:200]}", flush=True)
        try:
            state = load_state(data, row["package"]) or {"package": row["package"], "tools": {}}
            if (state.get("attempted") or {}).get("why") != why:
                state["attempted"] = {"version": state.get("version") or now()[:10],
                                      "at": now(), "why": why}
                save_state(data, row["package"], state)
        except (OSError, ValueError):
            pass
        return None


def check(args: argparse.Namespace) -> int:
    rows = _selected(args, "npm")
    budget = Budget(args.budget)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        events = [e for e in pool.map(lambda r: isolated(check_one, args.data, r, budget), rows)
                  if e]
    write_incoming(args.data, args.label, events)
    print(f"checked {len(rows)} npm server(s); {len(events)} new event(s)")
    return 0


# -- check-remote ----------------------------------------------------------

def measure_remote(url: str, timeout: float = 20.0) -> tuple[list | None, str | None]:
    """(raw tools, None) or (None, why), over Streamable HTTP. Runs nothing."""
    import http.client
    import urllib.error
    from heldfast.probe import SESSION_HEADER, _initialize_params, _post_jsonrpc, post_rpc
    try:
        init, headers = post_rpc(url, {}, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                           "params": _initialize_params()}, timeout)
        if "error" in init:
            return None, "initialize failed"
        onward = {k: v for k, v in headers.items() if k.lower() == SESSION_HEADER.lower() and v}
        listed = _post_jsonrpc(url, onward, {"jsonrpc": "2.0", "id": 2,
                                             "method": "tools/list", "params": {}}, timeout)
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        return None, type(exc).__name__
    tools = (listed.get("result") or {}).get("tools") if isinstance(listed, dict) else None
    if not isinstance(tools, list):
        return None, "no tools/list answer"
    if len(json.dumps(tools)) > MAX_REMOTE_BYTES:
        return None, "catalogue too large to read"
    return tools, None


def check_remote_one(data: str, row: dict) -> dict | None:
    """Read one hosted endpoint; record it only if what it says has moved."""
    key, stamp = row["package"], now()
    state = load_state(data, key) or {"package": key, "tools": {}}
    tools, why = measure_remote(row["url"])
    if tools is None:
        # Written once per reason, not once per day: an endpoint that has
        # wanted a login for a month is one fact, not thirty.
        if (state.get("attempted") or {}).get("why") != why:
            state["attempted"] = {"version": stamp[:10], "at": stamp, "why": why}
            save_state(data, key, state)
        return None
    # Microseconds in the version: two readings can never share a name, so a
    # catalogue is never overwritten by the next one.
    version = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S%f")
    after = snapshot(key, version, stamp, tools)
    if state.get("version") and {n: t["digest"] for n, t in after["tools"].items()} == state["tools"]:
        if state.get("attempted"):
            state.pop("attempted")
            save_state(data, key, state)
        return None
    before = load_snapshot(data, key, state["version"]) if state.get("version") else None
    write_catalogue(data, after, [], measured_at=stamp, extra={"url": row["url"]})
    event = diff(before, after, observed_at=stamp) if before else None
    save_state(data, key, dict(after, url=row["url"]))
    return event


def check_remote(args: argparse.Namespace) -> int:
    rows = _selected(args, "remote")
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        events = [e for e in pool.map(lambda r: isolated(check_remote_one, args.data, r), rows)
                  if e]
    write_incoming(args.data, args.label, events)
    print(f"checked {len(rows)} hosted endpoint(s); {len(events)} new event(s)")
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


def index(data: str, events: list) -> dict:
    """Every measured version and every event, per server, in one small file.

    What `heldfast updates` reads: which releases the feed has a catalogue
    for, and what each one changed, without fetching the catalogues to find
    out. Sizes and counts only -- the catalogues and events carry the text.
    """
    out: dict = {}
    folder = os.path.join(data, "catalogues")
    for pkg_dir in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        for name in sorted(os.listdir(os.path.join(folder, pkg_dir))):
            if not name.endswith(".json.gz"):
                continue
            body = read_gz(os.path.join(folder, pkg_dir, name))
            entry = out.setdefault(body["package"], {"versions": [], "events": []})
            # A hosted server's URL, so a client can find its record from the
            # address in its config (heldfast/transparency.py).
            if isinstance(body.get("url"), str):
                entry["url"] = body["url"]
            entry["versions"].append({"version": body["version"],
                                      "published": body.get("published", ""),
                                      "tools": len(body.get("tools") or [])})
    for e in events:
        out.setdefault(e["package"], {"versions": [], "events": []})["events"].append({
            "from": e["from"], "to": e["to"], "published": e["published"],
            "grade": e["grade"], "changed": len(e["changed"]),
            "added": len(e["added"]), "removed": len(e["removed"])})
    for entry in out.values():
        entry["versions"].sort(key=lambda v: (v["published"], v["version"]))
        entry["events"].sort(key=lambda v: (v["published"], v["to"]))
    return {"packages": out}


# Hex characters of a tool fingerprint that name its lookup bucket. Three
# gives 4,096 buckets: with a few hundred thousand tools logged, a client that
# asks for one bucket is one of a hundred-odd tools as far as the log can tell.
LOOKUP_PREFIX = 3


def lookup_buckets(data: str) -> dict[str, dict]:
    """Every tool definition the log has ever recorded, bucketed by fingerprint.

    The fingerprint is the one the lockfile records (docs/LOCK.md), computed
    by the parser `--probe` uses, so a client can look up a tool it approved
    without the log ever learning which: it asks for the bucket named by the
    first LOOKUP_PREFIX characters and searches it itself (docs/LOOKUP.md).
    Each entry says when the log first saw that exact definition and on how
    many servers. Nothing in it changes day to day unless a new definition or
    a new server appears, so a quiet day rewrites no bucket.
    """
    from heldfast.probe import _parse_tools

    seen: dict[str, dict] = {}
    folder = os.path.join(data, "catalogues")
    for pkg_dir in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        for name in sorted(os.listdir(os.path.join(folder, pkg_dir))):
            if not name.endswith(".json.gz"):
                continue
            body = read_gz(os.path.join(folder, pkg_dir, name))
            when = str(body.get("published") or body.get("measured_at") or "")[:10]
            try:
                tools = _parse_tools("feed", {"result": {"tools": body.get("tools") or []}})
                prints = {t.fingerprint() for t in tools}
            except ValueError:  # a schema the digest refuses; that server is skipped
                continue
            for fp in prints:
                row = seen.setdefault(fp, {"first_seen": when, "servers": set()})
                if when and (not row["first_seen"] or when < row["first_seen"]):
                    row["first_seen"] = when
                row["servers"].add(body["package"])
    buckets: dict[str, dict] = {}
    for fp in sorted(seen):
        bucket = buckets.setdefault(fp[:LOOKUP_PREFIX], {})
        bucket[fp] = {"first_seen": seen[fp]["first_seen"],
                      "servers": len(seen[fp]["servers"])}
    return buckets


def write_lookup(data: str) -> int:
    buckets = lookup_buckets(data)
    for prefix, tools in buckets.items():
        _write(os.path.join(data, "lookup", prefix + ".json"),
               _json_bytes({"prefix": prefix, "tools": tools}))
    _write(os.path.join(data, "lookup", "meta.json"), _json_bytes({
        "prefix_length": LOOKUP_PREFIX,
        "fingerprint": "the tool fingerprint of docs/LOCK.md, lowercase hex",
        "tools": sum(len(t) for t in buckets.values()), "buckets": len(buckets)}))
    return sum(len(t) for t in buckets.values())


def render(args: argparse.Namespace) -> int:
    """Write the derived files. Deterministic: the same events give the same
    bytes, so a day on which no watched server changed anything is a day on
    which the publishing job finds nothing to commit. Timestamps come from the
    events, not from the clock."""
    events = sorted(all_events(args.data), key=lambda e: (e["published"], e["package"]),
                    reverse=True)
    generated = max((e["observed_at"] for e in events), default="")
    _write(os.path.join(args.data, "index.json"), _json_bytes(index(args.data, events)))
    _write(os.path.join(args.data, "feed.json"), _json_bytes(
        {"updated_at": generated, "events": events[:FEED_EVENTS]}))
    _write(os.path.join(args.data, "feed.xml"), atom(events[:FEED_EVENTS], generated).encode("utf-8"))
    _write(os.path.join(args.data, "README.md"), readme(events, generated, args.data).encode("utf-8"))
    logged = write_lookup(args.data)
    print(f"rendered {min(len(events), FEED_EVENTS)} of {len(events)} events; "
          f"{logged} tool definitions in lookup/")
    return 0


def _x(text: str) -> str:
    return escape(_NOT_XML.sub("", str(text)))


def _link(e: dict) -> str:
    if e["package"].startswith(REMOTE_PREFIX):
        return "https://registry.modelcontextprotocol.io/v0/servers?search=" + \
            e["package"][len(REMOTE_PREFIX):].split("/")[0]
    return f"https://www.npmjs.com/package/{e['package']}/v/{e['to']}"


def atom(events: list, generated: str) -> str:
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<feed xmlns="http://www.w3.org/2005/Atom">',
           "  <title>heldfast: MCP server tool changes</title>",
           "  <id>tag:github.com,2026:rufat325/heldfast/feed</id>",
           f"  <updated>{_x(generated)}</updated>",
           '  <link href="https://github.com/rufat325/heldfast/tree/feed"/>']
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
                f"    <id>tag:github.com,2026:rufat325/heldfast/feed/{_x(e['package'])}@{_x(e['to'])}</id>",
                f"    <title>{_x(title)}</title>",
                f"    <updated>{_x(e['published'] or e['observed_at'])}</updated>",
                f'    <link href="{_x(_link(e))}"/>',
                f'    <content type="text">{_x(chr(10).join(lines))}</content>',
                "  </entry>"]
    out.append("</feed>")
    return "\n".join(out) + "\n"


def readme(events: list, generated: str, data: str) -> str:
    """Counts, names and versions only. The words a server wrote stay in the
    JSON and the Atom feed, where they are data; rendering them as Markdown on
    a page people read would hand a server a formatting channel."""
    rows = load_watchlist(data)
    npm = [r for r in rows if r.get("kind", "npm") == "npm"]
    daily = [r for r in npm if r.get("tier", "daily") == "daily"]
    hosted = [r for r in rows if r.get("kind") == "remote"]
    live = [e for e in events if not e.get("seeded")]
    review = [e for e in events if e["grade"] == "review"]
    lines = [
        "# MCP server tool changes", "",
        f"Last change observed {generated}. Built by `research/feed/watch.py` on the "
        f"`main` branch. Watching {len(npm)} npm servers from the official MCP registry "
        f"({len(daily)} daily, the rest weekly) and {len(hosted)} hosted endpoints (daily).", "",
        f"{len(events)} releases that changed a tool definition "
        f"({len(live)} observed live, {len(events) - len(live)} from the "
        f"[churn study](https://github.com/rufat325/heldfast/blob/main/docs/CHURN.md)); "
        f"{len(review)} where `heldfast wrap --drift graded` would refuse something.", "",
        "Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, "
        "with the words that moved: [events/](events).", "",
        "`quiet`: a graded pin forwards every changed tool (new tools still need "
        "approval). `review`: a change introduced an agent-directed instruction, hidden "
        "character, credential path or look-alike letter. Review means read it, not "
        "that it is hostile.", "",
        "| published | server | release | tools | grade |",
        "|---|---|---|---|---|",
    ]
    for e in events[:README_EVENTS]:
        lines.append(f"| {e['published'][:10]} | `{e['package']}` | "
                     f"{e['from']} -> {e['to']} | {summary(e)} | {e['grade']} |")
    return "\n".join(lines) + "\n"


# -- verify ----------------------------------------------------------------

def _check_file(full: str, rel: str) -> str | None:
    try:
        if rel.endswith(".json.gz"):
            read_gz(full)
            return None
        with open(full, encoding="utf-8") as fh:
            if rel.endswith(".jsonl"):
                for line in fh:
                    if line.strip():
                        json.loads(line)
            elif rel.endswith(".json"):
                json.load(fh)
            else:
                fh.read()
    except (ValueError, UnicodeDecodeError, OSError, EOFError) as exc:
        return str(exc)
    return None


def verify(args: argparse.Namespace) -> int:
    """What the publishing job checks before it commits anything.

    The measuring jobs ran other people's code. Their output is data about
    that code and nothing else: known file names, sizes a feed could
    plausibly reach, JSON that parses, gzip that does not inflate without
    bound. Anything outside that is refused whole.
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
            why = _check_file(full, rel)
            if why:
                problems.append(f"{rel}: {why}")
    if total > MAX_TOTAL:
        problems.append(f"total {total} bytes")
    for p in problems[:50]:
        print(f"refused: {p}", file=sys.stderr)
    print(f"verify: {'refused' if problems else 'ok'} ({total} bytes)")
    return 1 if problems else 0


# -- admit -----------------------------------------------------------------

# The shard counts of the measuring jobs in .github/workflows/feed.yml.
NPM_SHARDS, REMOTE_SHARDS = 16, 4
_DELTA = re.compile(r"^feed-delta-(npm|remote)-(\d+)$")


def _foreign(root: str, owned: dict[str, str], label: str) -> list[str]:
    """Every file in one shard's upload that is not about a server it was given.

    `owned` maps each file-system name to its package. A state file or a
    catalogue must sit under an owned name and say, inside, that it is that
    package; the one events file must carry the shard's label and only events
    about owned packages. Anything else -- the watchlist, the index, another
    shard's events -- is not a measuring job's to write.
    """
    problems = []
    for base, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            parts = rel.split("/")
            try:
                if os.path.islink(full):
                    why = "symbolic link"
                elif len(parts) == 2 and parts[0] == "state" and rel.endswith(".json"):
                    why = _owns_state(full, owned.get(parts[1][:-len(".json")]))
                elif len(parts) == 3 and parts[0] == "catalogues" and rel.endswith(".json.gz"):
                    why = _owns_catalogue(full, owned.get(parts[1]),
                                          parts[2][:-len(".json.gz")])
                elif rel == f"incoming/{label}.jsonl":
                    why = _owns_events(full, set(owned.values()))
                else:
                    why = "not a file a measuring job writes"
            except (ValueError, UnicodeDecodeError, OSError, EOFError) as exc:
                why = f"unreadable: {exc}"
            if why:
                problems.append(f"{rel}: {why}")
    return problems


def _owns_state(full: str, package: str | None) -> str | None:
    if package is None:
        return "a server this shard was not given"
    with open(full, encoding="utf-8") as fh:
        body = json.load(fh)
    return None if isinstance(body, dict) and body.get("package") == package \
        else f"does not say it is {package}"


def _owns_catalogue(full: str, package: str | None, version: str) -> str | None:
    if package is None:
        return "a server this shard was not given"
    body = read_gz(full)
    if not isinstance(body, dict) or body.get("package") != package \
            or str(body.get("version")) != version:
        return f"does not say it is {package}@{version}"
    return None


def _owns_events(full: str, packages: set[str]) -> str | None:
    with open(full, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict) or event.get("package") not in packages:
                return "an event about a server this shard was not given"
    return None


def admit(args: argparse.Namespace) -> int:
    """Take each shard's upload only for the servers that shard was given.

    `verify` checks that what arrives is shaped like feed data; it cannot see
    whose data it is. Every measuring shard runs other people's code in a
    container that can write the whole feed checkout, so without this one
    package measured anywhere could rewrite any server's catalogue, state or
    history, or the watchlist itself. Ownership is recomputed here from the
    feed branch's own watchlist -- not from anything a shard uploaded -- and an
    upload with one file outside it is refused whole: that shard's day is lost,
    not the feed. Servers measured side by side in one shard can still write
    each other's records; the isolate is per shard, not per server.
    """
    rows = load_watchlist(args.data)
    today = date.fromisoformat(args.day) if args.day else datetime.now(timezone.utc).date()
    # A shard started before midnight measured the day before's servers.
    days = (today, date.fromordinal(today.toordinal() - 1))
    os.makedirs(args.into, exist_ok=True)
    taken = refused = 0
    for name in sorted(os.listdir(args.deltas)) if os.path.isdir(args.deltas) else []:
        m = _DELTA.match(name)
        of = {"npm": args.npm_shards, "remote": args.remote_shards}.get(m.group(1)) if m else 0
        if not m or int(m.group(2)) >= of:
            print(f"::warning::refused upload {name!r}: not a measuring shard's")
            refused += 1
            continue
        kind, index = m.group(1), int(m.group(2))
        owned = {safe(r["package"]): r["package"] for r in rows
                 if r.get("kind", "npm") == kind and in_shard(r, (index, of))
                 and (kind == "remote" or any(due(r, d) for d in days))}
        problems = _foreign(os.path.join(args.deltas, name), owned, f"{kind}-{index}")
        if problems:
            for p in problems[:20]:
                print(f"::warning::refused upload {name}: {p}")
            refused += 1
            continue
        shutil.copytree(os.path.join(args.deltas, name), args.into, dirs_exist_ok=True)
        taken += 1
    print(f"admit: {taken} upload(s) taken, {refused} refused")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("seed")
    s.add_argument("--data", required=True)
    s.add_argument("--results", default=os.path.join(ROOT, "research", "churn", "results"))
    for name in ("check", "check-remote"):
        c = sub.add_parser(name)
        c.add_argument("--data", required=True)
        c.add_argument("--jobs", type=int, default=2)
        c.add_argument("--only", action="append", default=[], metavar="PACKAGE")
        c.add_argument("--shard", default="0/1", help="this run's slice, i/N")
        c.add_argument("--day", default="", help="YYYY-MM-DD to schedule for (default today)")
        c.add_argument("--label", default="local", help="name of this run's incoming file")
        c.add_argument("--budget", type=int, default=0,
                       help="launch at most this many servers (0: no limit)")
    for name in ("sync", "fold", "render", "verify"):
        sub.add_parser(name).add_argument("--data", required=True)
    a = sub.add_parser("admit")
    a.add_argument("--data", required=True, help="the feed branch checkout (its watchlist)")
    a.add_argument("--deltas", required=True, help="one folder per shard's upload")
    a.add_argument("--into", required=True, help="where the admitted uploads are merged")
    a.add_argument("--day", default="", help="YYYY-MM-DD the shards ran (default today)")
    a.add_argument("--npm-shards", type=int, default=NPM_SHARDS)
    a.add_argument("--remote-shards", type=int, default=REMOTE_SHARDS)
    args = ap.parse_args()
    return {"seed": seed, "sync": sync, "check": check, "check-remote": check_remote,
            "fold": fold, "render": render, "verify": verify,
            "admit": admit}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
