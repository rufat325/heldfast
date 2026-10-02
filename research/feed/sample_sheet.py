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

Reads DIR and the input file. Writes `sheet.csv` and a self-contained,
printable `sheet.html` into --out, which must not be inside DIR. Both come from
one computation, so a number in one is the number in the other. No network access of any kind: the lists it is given are
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
import difflib
import html
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

# readable: the three states a server can be in. They are counted apart and
# never added up: a server read before whose latest attempt failed is not a
# server that was never read.
YES, FAILED, NEVER = "yes", "yes, latest attempt failed", "never"

COLUMNS = ("input", "duplicate_of_line", "match", "package", "kind", "readable", "why_not", "tools_now",
           "first_version_published", "first_read", "latest_tool_list_recorded", "last_change",
           "days_since_last_change", "changes_since_window_start", "substantive",
           "numbers_only", "reorder_only", "unclassified", "graded_for_review",
           "review_signals", "notes")


class SheetError(Exception):
    """The input or the checkout cannot be used; the message says why."""


# -- the input -------------------------------------------------------------

def read_input_lines(path: str) -> list[tuple[int, str]]:
    """(file line number, server) for each server in the list: blank lines and #
    comments skipped, and a line with a comma read as CSV, its first column the
    server. The number is the line in the file, so a repeat can say where."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise SheetError(f"cannot read the server list: {exc}") from exc
    out = []
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            line = next(csv.reader([line]))[0].strip()
        if line:
            out.append((number, line))
    return out


def read_inputs(path: str) -> list[str]:
    return [text for _, text in read_input_lines(path)]


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
        self._catalogues = None
        watchlist = self._json("watchlist.json")
        if not isinstance(watchlist, dict) or not isinstance(watchlist.get("packages"), list):
            raise SheetError(f"{path} has no watchlist.json: not a feed checkout")
        self.listed = {p["package"]: p for p in watchlist["packages"]
                       if isinstance(p, dict) and isinstance(p.get("package"), str)}
        try:
            events = watch.all_events(path)
        except (OSError, ValueError) as exc:
            raise SheetError(f"cannot read events/: {exc}") from exc
        self.total_events = len(events)
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

    def tools_of(self, event: dict) -> tuple:
        """(tools before, tools after) of an event, each name -> definition, or
        None where the catalogue cannot be read. Read through the collector's
        reader, and held so an event is read once."""
        if self._catalogues is None:
            self._catalogues = _report().Catalogues(self.path)
        before, after = self._catalogues.pair(event)
        named = _report().named
        return (named(before) if before is not None else None,
                named(after) if after is not None else None)

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


def _report():
    """research/report/numbers.py, loaded under another name: as `numbers` it
    would stand in for the standard library module of that name. Its price,
    tool-text and catalogue readers are the ones the report's figures use."""
    global _numbers
    if _numbers is None:
        spec = importlib.util.spec_from_file_location(
            "report_numbers", os.path.join(ROOT, "research", "report", "numbers.py"))
        _numbers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_numbers)
    return _numbers


def _reason_group(why: str) -> str:
    """The grouping research/report/numbers.py uses for a failed read."""
    return _report().reason_group(why)


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


def is_transient(why: str) -> bool:
    """A failure that says nothing lasting about the server: a timeout, a
    network error, HTTP 429 or a 5xx. It may not happen on the next attempt."""
    return why == "HTTP 429" or _reason_group(why) in ("network error", "5xx")


def plain_reason(why: str) -> str:
    """A failed read in plain words, labelled `transient` where it may pass. The
    recorded reason is the collector's own string; only a few shapes of it are
    known, and an unknown one is cut short and shown as recorded, never
    interpreted."""
    for pattern, words in NPM_FAILURES:
        found = pattern.match(why)
        if found:
            return words.format(*found.groups())
    group = _reason_group(why)
    if why == "HTTP 429":
        text = "answered HTTP 429: too many requests"
    elif group in PLAIN:
        text = PLAIN[group].format(why=why)
    else:
        first = clean(why.splitlines()[0] if why.strip() else "unknown")
        return "the collector recorded: " + (first if len(first) <= 80 else first[:79].rstrip() + "\u2026")
    return "transient: " + text if is_transient(why) else text


def day(stamp: str | None) -> str:
    return (stamp or "")[:10]


def clean(text: str) -> str:
    """Server text with control characters made visible as spaces."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()


def cut(text: object, limit: int = 200) -> str:
    """Text from a server, control characters made visible and cut to `limit`."""
    text = clean(text)
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "\u2026"


FIELD_NAMES = {"description": "description", "title": "title", "inputSchema": "input schema",
               "outputSchema": "output schema", "annotations": "annotations", "icons": "icons"}


def and_join(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def money(unit: str, amount: float) -> str:
    text = ("%f" % amount).rstrip("0").rstrip(".") or "0"
    return f"${text}" if unit == "$" else f"{text} {unit}"


def added_words(old: str, new: str) -> str:
    """The words a description gained, and not the ones it lost: what a reader
    needs to see of a change that may carry an instruction."""
    a, b = (old or "").split(), (new or "").split()
    got = [" ".join(b[j1:j2]) for tag, _i1, _i2, j1, j2
           in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes()
           if tag in ("replace", "insert") and j1 != j2]
    return " \u2026 ".join(got)


def added_from_diff(diff: str) -> str:
    """The same from the collector's word diff (`-removed +added`), for an event
    whose catalogues cannot be read: tokens after a + until the next - or +."""
    out, adding = [], False
    for token in str(diff or "").split():
        if token[0] in "+-" and len(token) > 1:
            adding = token[0] == "+"
            token = token[1:]
        if adding:
            out.append(token)
    return " ".join(out)


def describe(change: dict, part: str, old: dict | None, new: dict | None) -> tuple:
    """(what happened, the words) for one tool in one event, in plain words.

    `part` is "added" or "changed"; `old` and `new` are the tool's definitions
    where the catalogues could be read. Only a price whose before and after
    are both readable is given as "$A to $B". Words are the ones a changed
    description gained, or, for a new tool, the text that matched."""
    report = _report()
    kinds = {clean(s.get("kind")) for s in change.get("introduced") or []}
    if part == "added":
        found = report.prices(report.tool_text(new)) if new else {}
        if "price" in kinds:
            shown = "; ".join(money(u, a) for u, v in sorted(found.items()) for a in v[:2])
            return "new tool with a stated price" + (f" ({shown})" if shown else ""), ""
        matched = "; ".join(clean(s.get("match")) for s in change.get("introduced") or []
                            if s.get("match"))
        return "new tool", cut(matched)
    phrases, words = [], ""
    pairs, before, after = [], {}, {}
    if old and new:
        before, after = report.prices(report.tool_text(old)), report.prices(report.tool_text(new))
        pairs = [(u, before[u][0], after[u][0]) for u in sorted(set(before) & set(after))
                 if len(before[u]) == 1 and len(after[u]) == 1 and before[u][0] != after[u][0]]
    if pairs:
        phrases.append("price changed " + "; ".join(f"{money(u, a)} to {money(u, b)}"
                                                    for u, a, b in pairs[:3]))
    elif "price" in kinds:
        phrases.append("a price was added to the text" if after and not before
                       else "a stated price was removed" if before and not after
                       else "stated prices changed")
    if not pairs or kinds - {"price"}:
        fields = [FIELD_NAMES[f] for f in change.get("fields") or [] if f in FIELD_NAMES]
        if fields:
            phrases.append(and_join(fields) + " changed")
        if "description" in (change.get("fields") or []):
            words = (added_words((old or {}).get("description"), (new or {}).get("description"))
                     if old and new else added_from_diff(change.get("words")))
    return "; ".join(phrases) or "tool changed", cut(words)


@dataclass
class Row:
    input: str
    match: str
    package: str = ""
    kind: str = ""
    readable: str = ""
    why_not: str = ""
    transient: bool = False
    tools_now: int | None = None
    first_version_published: str = ""   # npm: the release date of the earliest version held
    first_read: str = ""                # hosted: the first successful read
    latest_tool_list: str = ""        # the date of the latest read that recorded a tool list
    last_change: str = ""
    last_change_seeded: bool = False
    days_since_last_change: int | None = None
    changes: int | None = None
    kinds: dict = field(default_factory=dict)
    graded: int | None = None           # events graded for review
    signals: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    line: int = 0                       # the line of the input file it came from
    duplicate_of: int | None = None     # the line of the first input naming the same thing
    review_items: list = field(default_factory=list)   # what the HTML lists


def readable_state(state: dict | None, kind: str) -> tuple:
    """(readable, why_not, transient).

    yes: the latest attempt succeeded. `yes, latest attempt failed`: a catalogue
    was recorded before and the latest attempt did not read. never: no
    catalogue was ever recorded. A failure is recorded when its reason first
    appears and cleared by the next success, so while it is there nothing has
    been read since the date it names."""
    attempted = (state or {}).get("attempted") or {}
    why = str(attempted.get("why") or "")
    first = day(attempted.get("at"))
    when = f" (failing since {first})" if first else ""
    if state and state.get("version"):
        if attempted:
            return FAILED, plain_reason(why or "unknown") + when, is_transient(why)
        return YES, "", False
    if why:
        return NEVER, plain_reason(why) + when, is_transient(why)
    return NEVER, ("no reading recorded yet: npm packages are read weekly" if kind == "npm"
                   else "no reading recorded yet"), False


def server_row(rec: Record, found: Match, since: str, today: datetime.date) -> Row:
    package = found.package
    row = Row(found.input, found.match, candidates=list(found.candidates))
    if found.note:
        row.notes.append(found.note)
    if package is None:
        if found.match == "ambiguous":
            row.notes.append("candidates: " + "; ".join(found.candidates))
        return row
    kind = rec.kinds.get(package) or "npm"
    row.package, row.kind = package, KIND_NAMES.get(kind, "hosted")
    if package not in rec.listed:
        row.notes.append("no longer on the watchlist; the record keeps its history")
    state = rec.state(package)
    row.readable, row.why_not, row.transient = readable_state(state, kind)
    if state and state.get("version"):
        row.tools_now = len(state.get("tools") or {})
        row.latest_tool_list = day(state.get("published") if kind == "remote"
                                     else state.get("checked_at") or state.get("published"))
        if row.readable == FAILED:
            row.notes.append(f"the latest attempt failed; the tool count and the changes are as "
                             f"of the latest tool list recorded ({row.latest_tool_list})")
    first = min((day(v.get("published")) for v in rec.versions.get(package) or []
                 if v.get("published")), default="")
    if kind == "npm":
        row.first_version_published = first
    else:
        row.first_read = first
    events = sorted(rec.events.get(package, []), key=lambda e: e["observed_at"])
    if events:
        last = events[-1]
        row.last_change = day(last["observed_at"])
        row.days_since_last_change = (today - datetime.date.fromisoformat(row.last_change)).days
        row.last_change_seeded = bool(last.get("seeded"))
        if row.last_change_seeded:
            row.notes.append(f"the last change ({row.last_change}) is from the earlier study: the "
                             f"release date of the version that changed, measured later")
    live = [e for e in events if not e.get("seeded") and day(e["observed_at"]) >= since]
    count_changes(rec, row, live)
    if row.readable == NEVER:
        row.changes = row.graded = None   # never read: nothing to count, which is not "no changes"
        row.kinds, row.signals, row.review_items = {}, {}, []
    elif row.readable == FAILED and not live:
        row.changes = row.graded = None   # the latest attempt failed: not "no changes" either
    return row


def count_changes(rec: Record, row: Row, live: list) -> None:
    """The window's changes by kind, and the events graded for review with the
    kinds of signal they carry: each kind counted once per event that carries it,
    not once per matched phrase, so a number here is a number of events."""
    kinds: Counter = Counter()
    signals: Counter = Counter()
    graded = 0
    for event in live:
        kinds[rec.classified.get(operators.event_key(event), "unclassified")] += 1
        if event.get("grade") != "review":
            continue
        graded += 1
        found: set = set()
        old = new = None
        loaded = False
        for part in ("changed", "added"):
            for change in event.get(part) or []:
                seen = list(dict.fromkeys(clean(s.get("kind")) for s in change.get("introduced") or []))
                if not seen:
                    continue
                if not loaded:
                    try:
                        old, new = rec.tools_of(event)
                    except (OSError, ValueError, KeyError):
                        old = new = None
                    loaded = True
                name = change.get("tool")
                what, words = describe(change, part, (old or {}).get(name), (new or {}).get(name))
                row.review_items.append({
                    "date": day(event["observed_at"]), "package": row.package,
                    "tool": clean(name), "kinds": seen, "what": what, "words": words})
                found.update(seen)
        signals.update(found)
    row.changes, row.kinds, row.graded, row.signals = len(live), dict(kinds), graded, dict(signals)


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
    """What the sheet was read from: the commit, the newest checkpoint file, the
    newest live event, and whether the record holds events the newest checkpoint
    does not cover. A checkpoint states how many events its commit held, so any
    more than that are newer; one that does not say is compared by date."""
    folder = os.path.join(rec.path, "checkpoints")
    stamps = sorted(n[:-5] for n in os.listdir(folder) if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.json", n)) \
        if os.path.isdir(folder) else []
    live = [e["observed_at"] for evs in rec.events.values() for e in evs if not e.get("seeded")]
    newest = max(live, default="")
    unsealed = False
    if stamps:
        try:
            with open(os.path.join(folder, stamps[-1] + ".json"), encoding="utf-8") as fh:
                held = json.load(fh).get("events")
        except (OSError, ValueError, AttributeError):
            held = None
        unsealed = rec.total_events > held if isinstance(held, int) else day(newest) > stamps[-1]
    return {"commit": commit_of(rec.path), "checkpoint": stamps[-1] if stamps else "",
            "newest_event": newest, "unsealed": unsealed}


@dataclass
class Group:
    """One server, or one input that matched nothing, with every line that named it."""
    row: Row
    lines: list
    inputs: list


@dataclass
class Sheet:
    rows: list                  # one per input line, as the CSV has them
    groups: list                # one per distinct server or input, as the HTML lists them
    summary: dict
    snapshot: dict
    since: str
    today: str
    title: str = "MCP server change history"
    prepared_by: str = ""
    contact: str = ""


def build(rec: Record, inputs: list, since: str = WINDOW_START,
          today: datetime.date | None = None, title: str = "MCP server change history",
          prepared_by: str = "", contact: str = "", numbers: list | None = None) -> Sheet:
    """`inputs` are the servers as submitted; `numbers` the line of the file each
    came from (their position, when not given). A server named on more than one
    line is one group, and every line after the first says which it repeats."""
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    numbers = numbers or list(range(1, len(inputs) + 1))
    rows = [server_row(rec, rec.match(text), since, today) for text in inputs]
    groups: dict = {}
    for row, number in zip(rows, numbers):
        row.line = number
        key = row.package or ("input", row.match, row.input.strip().casefold())
        if key in groups:
            row.duplicate_of = groups[key].lines[0]
            groups[key].lines.append(number)
            if row.input not in groups[key].inputs:
                groups[key].inputs.append(row.input)
        else:
            groups[key] = Group(row, [number], [row.input])
    distinct = list(groups.values())
    matched = [g for g in distinct if g.row.package]
    summary = {
        "lines": len(rows),
        "distinct": len(distinct),
        # Every distinct entry is exactly one of these three.
        "matched": len(matched),
        "not_in_record": sum(1 for g in distinct if g.row.match == "none"),
        "ambiguous": sum(1 for g in distinct if g.row.match == "ambiguous"),
        "changed": sum(1 for g in matched if g.row.changes),
        "graded": sum(1 for g in matched if g.row.graded),
        # Two different things, counted apart and never added together.
        "never_read": sum(1 for g in matched if g.row.readable == NEVER),
        "latest_failed": sum(1 for g in matched if g.row.readable == FAILED),
    }
    return Sheet(rows, distinct, summary, snapshot(rec), since, today.isoformat(), title,
                 prepared_by, contact)


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
    cells = [row.input, row.duplicate_of, row.match, row.package, row.kind, row.readable,
             row.why_not, row.tools_now, row.first_version_published, row.first_read,
             row.latest_tool_list,
             row.last_change, row.days_since_last_change, row.changes, *counts, row.graded,
             signals, " | ".join(row.notes)]
    return [csv_safe(c) if not isinstance(c, int) else c for c in cells]


def write_csv(sheet: Sheet, path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        out = csv.writer(fh, lineterminator="\n")
        out.writerow(COLUMNS)
        for row in sheet.rows:
            out.writerow(["" if c is None else c for c in csv_row(row)])


# -- the printable sheet ---------------------------------------------------------

TITLE_DEFAULT = "MCP server change history"

# The method box, in plain words, at the end of the sheet. Each line is a
# statement the sheet depends on being true, and tests pin them.
METHOD = (
    "One anonymous reader, a few times a day. Hosted servers have been read daily since "
    "{window}; the record has been sealed daily since {sealed}. The window is short, so this "
    "sheet is a baseline, not a trend.",
    "npm servers are read when a new release appears, in a sandbox with no network, no "
    "credentials and no configuration: daily for the most downloaded, weekly for the rest. "
    "A hosted server that asks for a login or payment is read as an anonymous visitor and is "
    "listed as never read or as failing; the sheet says nothing about what it shows signed-in "
    "clients.",
    "\u201cChanged\u201d counts include changes that only moved numbers (counters, prices "
    "quoted in a description) and changes that only reordered a list. They are shown "
    "separately.",
    "\u201cGraded for review\u201d is the collector\u2019s classification of a change: it "
    "introduced a pattern a reader should look at, such as a price, a hidden character or a "
    "credential path. It is not a rating of the server. A signal is a lead for a reader, not a "
    "finding of intent.",
    "\u201cNever read\u201d and \u201clatest attempt failed\u201d are different: the second was "
    "read before. Some failures are transient (a timeout, a network error, HTTP 429, a 5xx) and "
    "are labelled. \u201cLatest tool list recorded\u201d is the date of the latest read that "
    "recorded a tool list; a read that finds nothing new leaves no record.",
    "For npm, \u201clast change\u201d is the day the feed observed the new release. A change "
    "from the earlier study is marked: its date is the release date of the version that "
    "changed, measured later.",
    "This is not a safety rating. It says nothing about what a server does, only about what it "
    "told an anonymous reader and when that changed.",
)

# Two lines that stand on the first page, whatever else is printed.
DISCLAIMER = (
    "A baseline since {window}, from one anonymous reader a few times a day: not a trend.",
    "Counters and reorderings are counted apart from substantive changes. This is not a "
    "safety rating.",
)
FEED_LINE = "A daily feed for this list is available."
UNSEALED = "Events after the newest checkpoint are not yet sealed."

EARLIER = ("\u2021 The last change is from the earlier study: the date is the release date of the "
           "version that changed, measured later.")

WHAT_LEGEND = (
    "What happened: \u201cnew tool\u201d was not in the previous tool list. \u201cprice "
    "changed A to B\u201d is the one price a tool\u2019s text stated becoming another; an "
    "amount quoted in text can be an example and not what a call costs. \u201cdescription "
    "changed\u201d is followed by the words it gained, never the words it lost. Words are the "
    "server\u2019s own, as recorded, cut to 200 characters.")

CSS = """
@page { size: A4; margin: 12mm; }
* { box-sizing: border-box; }
body { font: 8.5pt/1.4 system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
       color: #111; background: #fff; margin: 0 auto; max-width: 190mm; }
h1 { font-size: 15pt; margin: 0 0 2pt; }
h2 { font-size: 10.5pt; margin: 13pt 0 4pt; padding-bottom: 2pt; border-bottom: .6pt solid #777;
     break-after: avoid; }
p { margin: 3pt 0; }
table { border-collapse: collapse; width: 100%; font-size: 8pt; }
table.changed { table-layout: fixed; }
th, td { border-bottom: .4pt solid #bbb; padding: 2pt 4pt; text-align: left; vertical-align: top;
         overflow-wrap: anywhere; }
th { font-weight: 600; border-bottom: .8pt solid #555; overflow-wrap: normal; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
td.n { white-space: nowrap; }
td.nw, th.nw { white-space: nowrap; }
td.sig, th.sig { min-width: 28mm; overflow-wrap: normal; }
.nb { white-space: nowrap; }
sup { font-size: 7pt; }
tr, li { break-inside: avoid; }
thead { display: table-header-group; }
ul { margin: 3pt 0; padding-left: 14pt; }
.muted { color: #555; }
.words { color: #333; }
.counts span { display: inline-block; margin: 0 10pt 2pt 0; }
.counts b, .headline b { font-size: 11pt; }
.headline { margin-top: 6pt; font-size: 10pt; }
.disclaimer { margin: 2pt 0; font-weight: 600; }
.foot { margin: 10pt 0 0; color: #333; }
.details { break-before: page; }
.box { border: .8pt solid #444; padding: 6pt 9pt; background: #f4f4f4; break-inside: avoid;
       margin-top: 13pt; }
.box h2 { margin-top: 0; border: 0; }
.tag { font-size: 7.5pt; border: .4pt solid #777; padding: 0 3pt; margin-left: 3pt; }
@media screen { body { padding: 12mm 8mm; } .details { margin-top: 22pt; border-top: 1pt dashed #999; } }
"""


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _cell(value: object, cls: str = "", **data: str) -> str:
    attrs = "".join(f' data-{k}="{esc(v)}"' for k, v in data.items())
    return f'<td{f" class={chr(34)}{cls}{chr(34)}" if cls else ""}{attrs}>{esc(value)}</td>'


def _label(row: Row) -> str:
    """The server's registry name for a hosted server, its package for npm."""
    return row.package[len(REMOTE):] if row.kind == "hosted" and row.package.startswith(REMOTE) \
        else row.package


def _lines(numbers: list) -> str:
    shown = [str(n) for n in numbers]
    return "lines " + (shown[0] if len(shown) == 1 else ", ".join(shown[:-1]) + " and " + shown[-1])


def _name(group: Group) -> str:
    """The server as the sheet shows it, what was asked when that is something
    other than its name, and every line that named it when more than one did."""
    row = group.row
    out = esc(_label(row))
    if row.match == "inferred":
        out += f' <span class="tag">inferred from {esc(row.input)}</span>'
    else:
        known = (row.package.lower(), _label(row).lower())
        asked = [i for i in group.inputs if i.lower() not in known]
        if asked:
            out += f' <span class="muted">(asked as {esc(" / ".join(asked))})</span>'
    if len(group.lines) > 1:
        out += f' <span class="muted">(listed on {esc(_lines(group.lines))})</span>'
    return out


def _dated(row: Row) -> str:
    return esc(row.last_change) + (' <sup title="earlier study">\u2021</sup>'
                                    if row.last_change_seeded else "")


def _table(head: list, rows: list, cls: str = "", table_id: str = "", cols: list | None = None) -> str:
    ths = "".join(f'<th{f" class={chr(34)}{h[1]}{chr(34)}" if h[1] else ""}>{esc(h[0])}</th>'
                  for h in head)
    group = "<colgroup>" + "".join(f'<col style="width:{w}%">' for w in cols) + "</colgroup>" if cols else ""
    attrs = (f' id="{table_id}"' if table_id else "") + (f' class="{cls}"' if cls else "")
    return f"<table{attrs}>{group}<thead><tr>{ths}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _section(key: str, title: str, body: str) -> str:
    return f'<section id="{key}"><h2>{esc(title)}</h2>{body}</section>'


def _changed(sheet: Sheet) -> str:
    groups = sorted((g for g in sheet.groups if g.row.package and g.row.changes),
                    key=lambda g: (g.row.last_change, g.row.package), reverse=True)
    if not groups:
        return "<p>None.</p>"
    shown_unclassified = any(g.row.kinds.get("unclassified") for g in groups)
    head = [("Server", ""), ("Kind", "nw"), ("Last change", "nw"), ("Changes", "n"),
            ("Substantive", "n"), ("Numbers only", "n"), ("Reordered", "n")]
    widths = [34, 7, 11, 8, 11, 9, 9]
    if shown_unclassified:
        head.append(("Unclassified", "n"))
        widths.append(8)
    head.append(("Graded for review", "n"))
    widths.append(100 - sum(widths))
    body = []
    for g in groups:
        r = g.row
        mark = ' <span class="tag">latest attempt failed</span>' if r.readable == FAILED else ""
        cells = [f'<td data-col="server">{_name(g)}{mark}</td>', _cell(r.kind, "nw", col="kind"),
                 f'<td class="nw" data-col="last_change">{_dated(r)}</td>']
        counts = [("changes", r.changes), ("substantive", r.kinds.get("substantive", 0)),
                  ("numbers_only", r.kinds.get("numbers-only", 0)),
                  ("reorder_only", r.kinds.get("reorder-only", 0))]
        if shown_unclassified:
            counts.append(("unclassified", r.kinds.get("unclassified", 0)))
        counts.append(("graded_for_review", r.graded))
        cells += [_cell(v, "n", col=k) for k, v in counts]
        body.append(f'<tr data-package="{esc(r.package)}">{"".join(cells)}</tr>')
    legend = f'<p class="muted">{esc(EARLIER)}</p>' if any(g.row.last_change_seeded for g in groups) else ""
    return _table(head, body, "changed", "changed-table", widths) + legend


def _no_changes(sheet: Sheet) -> str:
    groups = [g for g in sheet.groups if g.row.readable == YES and g.row.changes == 0]
    if not groups:
        return "<p>None.</p>"
    items = []
    for g in groups:
        r = g.row
        extra = f"latest tool list recorded {r.latest_tool_list}" if r.latest_tool_list else ""
        if r.last_change:
            extra += f"; last change {r.last_change}"
        mark = ' <sup title="earlier study">\u2021</sup>' if r.last_change_seeded else ""
        items.append(f'<li data-package="{esc(r.package)}">{_name(g)} <span class="muted">'
                     f"{esc(extra.strip('; '))}{mark}</span></li>")
    legend = f'<p class="muted">{esc(EARLIER)}</p>' if any(g.row.last_change_seeded for g in groups) else ""
    return f"<ul>{''.join(items)}</ul>{legend}"


def _failed(sheet: Sheet, state: str) -> str:
    groups = [g for g in sheet.groups if g.row.readable == state]
    if not groups:
        return "<p>None.</p>"
    if state == NEVER:
        head = [("Server", ""), ("Kind", "nw"), ("Why it was not read", "")]
    else:
        head = [("Server", ""), ("Kind", "nw"), ("Latest tool list recorded", "nw"),
                ("Why the latest attempt failed", ""), ("Changes recorded", "n")]
    body = []
    for g in groups:
        r = g.row
        cells = [f'<td data-col="server">{_name(g)}</td>', _cell(r.kind, "nw", col="kind")]
        if state == FAILED:
            cells.append(_cell(r.latest_tool_list, "nw", col="latest_tool_list"))
        cells.append(_cell(r.why_not, col="why_not"))
        if state == FAILED:
            cells.append(_cell("" if r.changes is None else r.changes, "n", col="changes"))
        body.append(f'<tr data-package="{esc(r.package)}">{"".join(cells)}</tr>')
    return _table(head, body)


def _not_found(sheet: Sheet) -> str:
    groups = [g for g in sheet.groups if g.row.match in ("none", "ambiguous")]
    if not groups:
        return "<p>None.</p>"
    body = []
    for g in groups:
        r = g.row
        if r.match == "none":
            what = "not in the record"
        else:
            what = "ambiguous: more than one candidate, none chosen: " + "; ".join(r.candidates)
        listed = f" ({_lines(g.lines)})" if len(g.lines) > 1 else ""
        body.append(f'<tr data-input="{esc(r.input)}">{_cell(r.input + listed, col="input")}'
                    f"{_cell(what, col='result')}</tr>")
    return _table([("As submitted", ""), ("Result", "")], body)


def _tools(names: list, shown: int = 3) -> str:
    names = sorted(set(names))
    return ", ".join(names[:shown]) + (f" and {len(names) - shown} more ({len(names)} tools)"
                                       if len(names) > shown else "")


def _review(sheet: Sheet) -> str:
    """Each change graded for review. The tools of one server whose change on one
    day carried the same signals and the same account share a row."""
    groups: dict = {}
    for g in sheet.groups:
        for i in g.row.review_items:
            key = (i["date"], i["package"], tuple(i["kinds"]), i["what"], i["words"])
            groups.setdefault(key, (_label(g.row), []))[1].append(i["tool"])
    if not groups:
        return "<p>None.</p>"
    body = []
    for (date, package, kinds, what, words), (label, tools) in sorted(groups.items(), reverse=True):
        signals = ", ".join(f'<span class="nb">{esc(k)}</span>' for k in kinds)
        said = esc(what) + (f' <span class="words">\u201c{esc(words)}\u201d</span>' if words else "")
        body.append(
            f'<tr data-package="{esc(package)}">{_cell(date, "nw", col="date")}'
            f'{_cell(label, col="server")}'
            f'<td data-col="tool" title="{esc(", ".join(sorted(set(tools))))}">{esc(_tools(tools))}</td>'
            f'<td class="sig" data-col="signal">{signals}</td><td data-col="what">{said}</td></tr>')
    table = _table([("Date", "nw"), ("Server", ""), ("Tool", ""), ("Signal", "sig"),
                    ("What happened", "")], body)
    return table + f'<p class="muted">{esc(WHAT_LEGEND)}</p>'


def _snapshot(sheet: Sheet) -> str:
    snap = sheet.snapshot
    commit = (f'<span title="{esc(snap["commit"])}">{esc(snap["commit"][:12])}</span>'
              if snap["commit"] else "not a git checkout")
    checkpoint = esc("checkpoints/" + snap["checkpoint"] + ".json") if snap["checkpoint"] else "none"
    out = (f"Snapshot of the public record: feed commit {commit}; newest checkpoint file present: "
           f"{checkpoint}; newest event recorded: {esc(snap['newest_event'] or 'none')}.")
    return out + (f" {esc(UNSEALED)}" if snap.get("unsealed") else "")


def _footer(sheet: Sheet) -> str:
    who = ", ".join(x for x in (sheet.prepared_by, sheet.contact) if x)
    first = (f"Prepared by {esc(who)}" if sheet.prepared_by
             else f"Contact: {esc(sheet.contact)}" if sheet.contact else "")
    return ('<div id="page-one-footer">' + (f'<p class="foot">{first}</p>' if first else "")
            + f'<p class="foot">{esc(FEED_LINE)}</p></div>')


def render_html(sheet: Sheet) -> str:
    """The sheet as one self-contained page: inline CSS, no script, nothing
    fetched. The first page stands alone -- the header, the counts, a two-line
    disclaimer and the changes -- and the lists behind it start on the next,
    with the method and limits box last. Every figure comes from `sheet`, the
    object the CSV is written from, and everything a server or an input said is
    escaped."""
    s = sheet.summary
    counts = [("matched", "matched"), ("not_in_record", "not in the record"),
              ("ambiguous", "ambiguous"), ("changed", f"changed since {sheet.since}"),
              ("graded", "graded for review"), ("never_read", "never read"),
              ("latest_failed", "latest attempt failed")]
    summary = "".join(f'<span><b data-count="{k}">{s[k]}</b> {esc(label)}</span>'
                      for k, label in counts)
    headline = (f'<b data-count="lines">{s["lines"]}</b> lines, '
                f'<b data-count="distinct">{s["distinct"]}</b> distinct servers')
    disclaimer = "".join(f'<p class="disclaimer">{esc(t.format(window=WINDOW_START))}</p>'
                         for t in DISCLAIMER)
    method = "".join(f"<p>{esc(t.format(window=WINDOW_START, sealed=SEALED_FROM))}</p>"
                     for t in METHOD)
    details = "".join((
        _section("no-changes", f"Read, with no changes recorded since {sheet.since}",
                 _no_changes(sheet)),
        _section("never-read", "Never read", _failed(sheet, NEVER)),
        _section("failed", "Read before; latest attempt failed", _failed(sheet, FAILED)),
        _section("not-found", "Not in the record, or ambiguous", _not_found(sheet)),
        _section("review", "Changes graded for review", _review(sheet)),
    ))
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{esc(sheet.title)}</title><style>{CSS}</style></head><body>"
        f'<div class="first" id="first-page"><h1>{esc(sheet.title)}</h1>'
        f'<p class="muted" id="date">{esc(sheet.today)}</p>'
        f'<p class="muted" id="snapshot">{_snapshot(sheet)}</p>'
        f'<p class="headline" id="headline">{headline}</p>'
        f'<p class="counts" id="summary">{summary}</p>{disclaimer}'
        f'{_section("changed", f"Servers that changed since {sheet.since}, newest first", _changed(sheet))}'
        f"{_footer(sheet)}</div>"
        f'<div class="details" id="details">{details}'
        f'<div class="box" id="method"><h2>Method and limits</h2>{method}</div></div>'
        "</body></html>\n")


def check_out(out: str, feed: str) -> None:
    if profile_index._inside(out, feed):
        raise SheetError(f"refused: {out} is inside {feed}; this never writes into a feed checkout")


def run(feed: str, inputs: str, out: str, since: str = WINDOW_START,
        today: datetime.date | None = None, title: str = TITLE_DEFAULT,
        prepared_by: str = "", contact: str = "") -> Sheet:
    check_out(out, feed)
    rec = Record(feed)
    lines = read_input_lines(inputs)
    sheet = build(rec, [text for _, text in lines], since, today, title, prepared_by, contact,
                  [number for number, _ in lines])
    os.makedirs(out, exist_ok=True)
    write_csv(sheet, os.path.join(out, "sheet.csv"))
    with open(os.path.join(out, "sheet.html"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_html(sheet))
    return sheet


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--feed", required=True, help="a checkout of the feed (read only)")
    ap.add_argument("--input", required=True, help="the server list, one per line")
    ap.add_argument("--out", default="out", help="where to write; must be outside the feed")
    ap.add_argument("--title", default=TITLE_DEFAULT, help="the title of the page")
    ap.add_argument("--prepared-by", default="", help="who prepared it, shown at the foot of page one")
    ap.add_argument("--contact", default="", help="how to reach them, plain text, shown beside it")
    ap.add_argument("--since", default=WINDOW_START, metavar="YYYY-MM-DD",
                    help="start of the window changes are counted in")
    ap.add_argument("--today", default=None, metavar="YYYY-MM-DD",
                    help="the date days-since are counted to (default: today, UTC)")
    args = ap.parse_args(argv)
    try:
        today = datetime.date.fromisoformat(args.today) if args.today else None
        datetime.date.fromisoformat(args.since)
        sheet = run(args.feed, args.input, args.out, args.since, today, args.title,
                    args.prepared_by, args.contact)
    except (SheetError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2
    s = sheet.summary
    print(f"{s['lines']} lines, {s['distinct']} distinct: {s['matched']} matched, "
          f"{s['ambiguous']} ambiguous, {s['not_in_record']} not in the record; "
          f"{s['changed']} changed since {sheet.since}; "
          f"{s['graded']} graded for review; {s['never_read']} never read; "
          f"{s['latest_failed']} read before with the latest attempt failed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
