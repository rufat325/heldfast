"""A change-history sheet for a list of MCP servers, from a local feed checkout.

Someone sends a list of the MCP servers they run or sell. This looks each one
up in a checkout of the public record (rufat325/heldfast-feed) and writes what
the record holds: whether the server could be read, how many tools it showed
last, when it was first recorded, and what changed since live reading began --
split into substantive changes, changes that only moved numbers, and changes
that only reordered. A server's own text is never judged here. A signal the
collector found in a change is reported as a lead for a reader, and the sheet
says plainly what it is not.

  sample_sheet.py --feed DIR --input servers.txt [--out ./out]
                  [--title T] [--prepared-by P] [--since 2026-09-23]

Reads DIR and the input file. Writes `sheet.csv` into --out, which must not be
inside DIR. No network access of any kind: the lists it is given are
confidential, and nothing here sends them anywhere.

Each input line is one of: a registry name (`io.github.owner/name`), a hosted
URL, an npm package name, a GitHub URL. Blank lines and `#` comments are
skipped; a line with a comma is read as CSV and its first column used. They
are matched in this order, and never by resemblance:

  1. an exact package key (an npm name, or `remote/<registry name>`)
  2. a registry name, as `remote/<name>`
  3. a URL, with scheme and host in lower case and trailing slashes dropped,
     against the URLs on the watchlist
  4. an npm name, in lower case
  5. a GitHub URL, as the registry name `io.github.<owner>/<repo>` (compared
     in lower case, as GitHub does): reported as `inferred`, never as `exact`

More than one candidate is `ambiguous` and the candidates are listed, not
chosen. Nothing found is `none`: not in the record.

Whether a server is hosted or npm comes from the watchlist's `kind`, never
from a file name: some npm packages are called `remote-...`.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

import operators  # noqa: E402
import profile_index  # noqa: E402
import watch  # noqa: E402

REMOTE = "remote/"
# Live reading of hosted servers began on this date; earlier events are the
# churn study's (`seeded`), not reads by the feed. The record is sealed daily
# from SEALED_FROM.
WINDOW_START = "2026-09-23"
SEALED_FROM = "2026-09-27"
KIND_NAMES = {"npm": "npm", "remote": "hosted"}
GITHUB = re.compile(r"^(?:www\.)?github\.com$")
# A scoped npm name: a spreadsheet opened on `@scope/name` does not read it as
# a formula, so it is not changed.
SCOPED = re.compile(r"^@[a-z0-9~-][a-z0-9._~-]*/[a-z0-9~-][a-z0-9._~-]*$", re.IGNORECASE)

COLUMNS = ("input", "match", "package", "kind", "readable", "why_not", "tools_now",
           "first_recorded", "last_change", "days_since_last_change",
           "changes_since_window_start", "substantive", "numbers_only", "reorder_only",
           "unclassified", "review_events", "review_signals", "notes")


class SheetError(Exception):
    """The input or the checkout cannot be used; the message says why."""


# -- the input -------------------------------------------------------------

def read_inputs(path: str) -> list[str]:
    """One server per line; blank lines and # comments skipped; a line with a
    comma is CSV and its first column is the server."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise SheetError(f"cannot read the server list: {exc}") from exc
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            line = next(csv.reader([line]))[0].strip()
        if line:
            out.append(line)
    return out


def normalise_url(text: str) -> str | None:
    """Scheme and host in lower case, no fragment, trailing slashes dropped;
    None for something that is not a URL with a scheme and a host."""
    try:
        parts = urlsplit(text.strip())
        host = parts.hostname
    except ValueError:
        return None
    if not parts.scheme or not host:
        return None
    netloc = host + (f":{parts.port}" if parts.port else "")
    return f"{parts.scheme.lower()}://{netloc}{parts.path.rstrip('/')}" + \
        (f"?{parts.query}" if parts.query else "")


# -- the record ------------------------------------------------------------

@dataclass
class Match:
    input: str
    match: str                       # exact, inferred, ambiguous, none
    candidates: list = field(default_factory=list)
    note: str = ""

    @property
    def package(self) -> str | None:
        return self.candidates[0] if self.match in ("exact", "inferred") else None


class Record:
    """The parts of a feed checkout the sheet reads, each read once."""

    def __init__(self, path: str) -> None:
        self.path = path
        watchlist = self._json("watchlist.json")
        if not isinstance(watchlist, dict) or not isinstance(watchlist.get("packages"), list):
            raise SheetError(f"{path} has no watchlist.json: not a feed checkout")
        self.listed = {p["package"]: p for p in watchlist["packages"]
                       if isinstance(p, dict) and isinstance(p.get("package"), str)}
        try:
            events = watch.all_events(path)
        except (OSError, ValueError) as exc:
            raise SheetError(f"cannot read events/: {exc}") from exc
        self.events: dict[str, list] = defaultdict(list)
        for event in events:
            self.events[event["package"]].append(event)
        stats = self._json("stats.json") or {}
        self.classified = stats.get("classified") or {}
        index = (self._json("index.json") or {}).get("packages") or {}
        self.versions = {pkg: row.get("versions") or [] for pkg, row in index.items()}
        # Everything the record holds a history for, on the watchlist or not.
        self.kinds = {pkg: p.get("kind") for pkg, p in self.listed.items()}
        for pkg in list(self.events) + list(self.versions):
            self.kinds.setdefault(pkg, "remote" if pkg.startswith(REMOTE) else "npm")
        self.by_url: dict[str, list] = defaultdict(list)
        for pkg, p in self.listed.items():
            url = normalise_url(p["url"]) if isinstance(p.get("url"), str) else None
            if url:
                self.by_url[url].append(pkg)
        self.npm_lower: dict[str, list] = defaultdict(list)
        self.remote_lower: dict[str, list] = defaultdict(list)
        for pkg, kind in self.kinds.items():
            (self.npm_lower if kind == "npm" else self.remote_lower)[pkg.lower()].append(pkg)

    def _json(self, rel: str):
        full = os.path.join(self.path, rel)
        if not os.path.exists(full):
            return None
        try:
            with open(full, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError) as exc:
            raise SheetError(f"cannot read {rel}: {exc}") from exc

    def state(self, package: str) -> dict | None:
        try:
            return watch.load_state(self.path, package)
        except (OSError, ValueError):
            return None

    # -- matching ----------------------------------------------------------

    def match(self, text: str) -> Match:
        raw = text.strip()
        if raw in self.kinds:
            return Match(text, "exact", [raw])
        if "://" not in raw and (REMOTE + raw) in self.kinds:
            return Match(text, "exact", [REMOTE + raw])
        url = normalise_url(raw) if "://" in raw else None
        if url and url in self.by_url:
            return self._one_or_many(text, sorted(self.by_url[url]),
                                     "the URL is on the watchlist for each of these")
        if raw.lower() in self.npm_lower:
            found = sorted(self.npm_lower[raw.lower()])
            return self._one_or_many(text, found, "npm names that differ only in case",
                                     "case differs" if found != [raw] else "")
        if url:
            return self._github(text, url)
        return Match(text, "none", note="not in the record")

    @staticmethod
    def _one_or_many(text: str, found: list, why: str, note: str = "") -> Match:
        if len(found) == 1:
            return Match(text, "exact", found, note)
        return Match(text, "ambiguous", found, why)

    def _github(self, text: str, url: str) -> Match:
        parts = urlsplit(url)
        segments = [s for s in parts.path.split("/") if s]
        if not GITHUB.match(parts.hostname or "") or len(segments) < 2:
            return Match(text, "none", note="not in the record")
        owner, repo = segments[0], segments[1][:-4] if segments[1].endswith(".git") else segments[1]
        # GitHub names are not case-sensitive, so the comparison is in lower case.
        found = sorted(self.remote_lower.get(f"{REMOTE}io.github.{owner}/{repo}".lower(), []))
        if len(found) > 1:
            return Match(text, "ambiguous", found, "these registry names differ only in case")
        if not found:
            return Match(text, "none", note=f"a GitHub URL; no registry name "
                         f"io.github.{owner}/{repo} is in the record")
        return Match(text, "inferred", found,
                     f"inferred from the GitHub URL: the registry name io.github.{owner}/{repo} "
                     f"is in the record; the URL does not itself say it is the same server")


# -- what the record says about one server ---------------------------------

_numbers = None


def _reason_group(why: str) -> str:
    """The grouping research/report/numbers.py uses for a failed read."""
    global _numbers
    if _numbers is None:
        # Loaded under another name: as `numbers` it would stand in for the
        # standard library module of that name.
        spec = importlib.util.spec_from_file_location(
            "report_numbers", os.path.join(ROOT, "research", "report", "numbers.py"))
        _numbers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_numbers)
    return _numbers.reason_group(why)


PLAIN = {
    "login or payment": "answered {why}: a login or payment was asked for",
    "not found": "answered {why}: nothing was found at that address",
    "other 4xx": "answered {why}: the request was refused",
    "5xx": "answered {why}: the server reported an error",
    "network error": "could not be reached ({why}): a network error or a timeout",
    "protocol": "answered, but not with a usable tool list ({why})",
}

# How an npm server fails when the collector starts it in its sandbox, which
# has no network, no credentials and no configuration. What the server itself
# printed is never repeated: it is third-party text and it names the
# collector's own paths.
NPM_FAILURES = (
    (re.compile(r"^exited (\d+) before initialize"),
     "the server exited (status {0}) before it answered, in the collector's sandbox"),
    (re.compile(r"^spawn failed"), "the server could not be started in the collector's sandbox"),
    (re.compile(r"^download failed"), "the package could not be downloaded in the collector's sandbox"),
    (re.compile(r"^no executable to run"), "the package has no executable to run"),
    (re.compile(r"^no initialize answer"), "the server did not answer the handshake in time"),
    (re.compile(r"^initialized, no tools/list answer"), "the server connected but returned no tool list"),
    (re.compile(r"^tools/list error"), "the server answered the tool request with an error"),
)


def plain_reason(why: str) -> str:
    """A failed read in plain words. The recorded reason is the collector's own
    string; only a few shapes of it are known, and an unknown one is cut short
    and shown as recorded, never interpreted."""
    for pattern, words in NPM_FAILURES:
        found = pattern.match(why)
        if found:
            return words.format(*found.groups())
    group = _reason_group(why)
    if group in PLAIN:
        return PLAIN[group].format(why=why)
    first = clean(why.splitlines()[0] if why.strip() else "unknown")
    return "the collector recorded: " + (first if len(first) <= 80 else first[:79].rstrip() + "\u2026")


def day(stamp: str | None) -> str:
    return (stamp or "")[:10]


def clean(text: str) -> str:
    """Server text with control characters made visible as spaces."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()


def excerpt(change: dict, limit: int = 200) -> str:
    """The words that moved in a change, or the matched text when a tool was
    added, cut to `limit` characters."""
    text = (change.get("words") or change.get("schema_words")
            or " ".join(str(s.get("match") or "") for s in change.get("introduced") or []))
    text = clean(text)
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


@dataclass
class Row:
    input: str
    match: str
    package: str = ""
    kind: str = ""
    readable: str = ""
    why_not: str = ""
    tools_now: int | None = None
    first_recorded: str = ""
    last_change: str = ""
    days_since_last_change: int | None = None
    changes: int | None = None
    kinds: dict = field(default_factory=dict)
    review_events: int | None = None
    signals: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    review_items: list = field(default_factory=list)   # what the HTML lists


def readable_state(state: dict | None, kind: str) -> tuple:
    """(readable, why_not): yes when the latest read succeeded; no when a server
    read before could not be read last time; never when it was never read."""
    attempted = (state or {}).get("attempted") or {}
    why = str(attempted.get("why") or "")
    if state and state.get("version"):
        if attempted:
            return "no", plain_reason(why or "unknown")
        return "yes", ""
    if why:
        return "never", plain_reason(why)
    return "never", ("no reading recorded yet: npm packages are read weekly" if kind == "npm"
                     else "no reading recorded yet")


def server_row(rec: Record, found: Match, since: str, today: datetime.date) -> Row:
    package = found.package
    row = Row(found.input, found.match, candidates=list(found.candidates))
    if found.note:
        row.notes.append(found.note)
    if package is None:
        if found.match == "ambiguous":
            row.notes.append("candidates: " + "; ".join(found.candidates))
        return row
    row.package, row.kind = package, KIND_NAMES.get(rec.kinds.get(package), "hosted")
    if package not in rec.listed:
        row.notes.append("no longer on the watchlist; the record keeps its history")
    state = rec.state(package)
    row.readable, row.why_not = readable_state(state, rec.kinds.get(package) or "npm")
    if state and state.get("version"):
        row.tools_now = len(state.get("tools") or {})
        if row.readable == "no":
            at = (state.get("attempted") or {}).get("at") or ""
            row.notes.append(f"the latest read failed ({day(at)}); the tool count and the "
                             f"changes are from the last read ({day(state.get('published'))})")
    versions = rec.versions.get(package) or []
    row.first_recorded = min((day(v.get("published")) for v in versions if v.get("published")),
                             default="")
    events = sorted(rec.events.get(package, []), key=lambda e: e["observed_at"])
    if events:
        last = events[-1]
        row.last_change = day(last["observed_at"])
        row.days_since_last_change = (today - datetime.date.fromisoformat(row.last_change)).days
        if last.get("seeded"):
            row.notes.append("the last change is from the earlier study, not a live reading")
    live = [e for e in events if not e.get("seeded") and day(e["observed_at"]) >= since]
    count_changes(rec, row, live)
    if row.readable == "never":
        row.changes = row.review_events = None   # never read: nothing to count, not "no changes"
        row.kinds, row.signals, row.review_items = {}, {}, []
    elif row.readable == "no" and not live:
        row.changes = row.review_events = None   # last read failed: not "no changes" either
    return row


def count_changes(rec: Record, row: Row, live: list) -> None:
    """The window's changes by kind, and the review events with the kinds of
    signal they carry: each kind counted once per event that carries it, not
    once per matched phrase, so a number here is a number of events."""
    kinds: Counter = Counter()
    signals: Counter = Counter()
    review = 0
    for event in live:
        kinds[rec.classified.get(operators.event_key(event), "unclassified")] += 1
        if event.get("grade") != "review":
            continue
        review += 1
        seen: set = set()
        for change in list(event.get("changed") or []) + list(event.get("added") or []):
            for kind in dict.fromkeys(str(s.get("kind")) for s in change.get("introduced") or []):
                if (clean(change.get("tool")), kind) in seen:
                    continue
                seen.add((clean(change.get("tool")), kind))
                row.review_items.append({
                    "date": day(event["observed_at"]), "package": row.package,
                    "tool": clean(change.get("tool")), "kind": clean(kind),
                    "excerpt": excerpt(change)})
        signals.update({str(s.get("kind")) for c in list(event.get("changed") or [])
                        + list(event.get("added") or []) for s in c.get("introduced") or []})
    row.changes, row.kinds, row.review_events, row.signals = len(live), dict(kinds), review, dict(signals)


# -- the sheet ---------------------------------------------------------------

def commit_of(path: str) -> str:
    """The checkout's commit, read from .git without running git; '' if unknown."""
    try:
        with open(os.path.join(path, ".git", "HEAD"), encoding="utf-8") as fh:
            head = fh.read().strip()
        if not head.startswith("ref: "):
            return head if re.fullmatch(r"[0-9a-f]{40}", head) else ""
        ref = head[5:]
        ref_path = os.path.join(path, ".git", *ref.split("/"))
        if os.path.exists(ref_path):
            with open(ref_path, encoding="utf-8") as fh:
                return fh.read().strip()
        with open(os.path.join(path, ".git", "packed-refs"), encoding="utf-8") as fh:
            for line in fh:
                if line.strip().endswith(" " + ref):
                    return line.split()[0]
    except OSError:
        pass
    return ""


def snapshot(rec: Record) -> dict:
    folder = os.path.join(rec.path, "checkpoints")
    stamps = sorted(n[:-5] for n in os.listdir(folder) if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.json", n)) \
        if os.path.isdir(folder) else []
    live = [e["observed_at"] for evs in rec.events.values() for e in evs if not e.get("seeded")]
    return {"commit": commit_of(rec.path), "checkpoint": stamps[-1] if stamps else "",
            "newest_event": max(live, default="")}


@dataclass
class Sheet:
    rows: list
    summary: dict
    snapshot: dict
    since: str
    today: str


def build(rec: Record, inputs: list, since: str = WINDOW_START,
          today: datetime.date | None = None) -> Sheet:
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    rows = [server_row(rec, rec.match(text), since, today) for text in inputs]
    matched = [r for r in rows if r.match in ("exact", "inferred")]
    summary = {
        "submitted": len(rows),
        "matched": len(matched),
        "changed": sum(1 for r in matched if r.changes),
        "review": sum(1 for r in matched if r.review_events),
        "could_not_read": sum(1 for r in matched if r.readable in ("no", "never")),
        "not_in_record": sum(1 for r in rows if r.match == "none"),
        "ambiguous": sum(1 for r in rows if r.match == "ambiguous"),
    }
    return Sheet(rows, summary, snapshot(rec), since, today.isoformat())


def csv_safe(value: object) -> str:
    """A cell that a spreadsheet will not run as a formula. Server names come
    from a registry anyone can publish to, so a leading = + - @ is defused;
    a scoped npm name is left as it is."""
    text = "" if value is None else str(value)
    if text and text[0] in "=+-@\t\r" and not SCOPED.match(text):
        return "'" + text
    return text


def csv_row(row: Row) -> list:
    counts = [row.kinds.get(k, 0) if row.changes is not None else ""
              for k in (*operators.KINDS, "unclassified")]
    signals = "; ".join(f"{k} ({n})" for k, n in sorted(row.signals.items()))
    cells = [row.input, row.match, row.package, row.kind, row.readable, row.why_not,
             row.tools_now, row.first_recorded, row.last_change, row.days_since_last_change,
             row.changes, *counts, row.review_events, signals, " | ".join(row.notes)]
    return [csv_safe(c) if not isinstance(c, int) else c for c in cells]


def write_csv(sheet: Sheet, path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        out = csv.writer(fh, lineterminator="\n")
        out.writerow(COLUMNS)
        for row in sheet.rows:
            out.writerow(["" if c is None else c for c in csv_row(row)])


def check_out(out: str, feed: str) -> None:
    if profile_index._inside(out, feed):
        raise SheetError(f"refused: {out} is inside {feed}; this never writes into a feed checkout")


def run(feed: str, inputs: str, out: str, since: str = WINDOW_START,
        today: datetime.date | None = None) -> Sheet:
    check_out(out, feed)
    rec = Record(feed)
    sheet = build(rec, read_inputs(inputs), since, today)
    os.makedirs(out, exist_ok=True)
    write_csv(sheet, os.path.join(out, "sheet.csv"))
    return sheet


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--feed", required=True, help="a checkout of the feed (read only)")
    ap.add_argument("--input", required=True, help="the server list, one per line")
    ap.add_argument("--out", default="out", help="where to write; must be outside the feed")
    ap.add_argument("--since", default=WINDOW_START, metavar="YYYY-MM-DD",
                    help="start of the window changes are counted in")
    ap.add_argument("--today", default=None, metavar="YYYY-MM-DD",
                    help="the date days-since are counted to (default: today, UTC)")
    args = ap.parse_args(argv)
    try:
        today = datetime.date.fromisoformat(args.today) if args.today else None
        datetime.date.fromisoformat(args.since)
        sheet = run(args.feed, args.input, args.out, args.since, today)
    except (SheetError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2
    s = sheet.summary
    print(f"{s['submitted']} submitted: {s['matched']} matched, {s['ambiguous']} ambiguous, "
          f"{s['not_in_record']} not in the record; {s['changed']} changed since {sheet.since}; "
          f"{s['review']} with changes flagged for review; {s['could_not_read']} could not be read",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
