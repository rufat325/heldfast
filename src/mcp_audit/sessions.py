"""What the agent actually did.

The trail was write-only in practice. `verify-log` says the chain is intact,
`status` shows the last five lines, and neither answers the question anyone
has after something goes wrong: what did this agent do, which servers did it
reach, what was refused and why.

That completes the loop. scan finds it, approve pins it, guard and gateway
enforce it -- and nothing read the record back.

Two things are deliberate.

**Integrity is reported before anything else, and a broken chain is not
summarised as though it were whole.** Everything after the first bad line is
unverified, so the count of calls in it is a number somebody could have
chosen. Saying "412 calls, 3 refused" over a file that was edited would be
laundering a tampered log into a clean-looking report.

**A session with no end is reported as unterminated**, not quietly merged into
the next one. A guard that was killed mid-session is a fact worth having, and
two sessions glued together would attribute one agent's calls to another.

Arguments are not in the log by design (`auditlog` explains why), so this
answers what was called and never with what. It says so rather than leaving a
gap the reader has to interpret.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auditlog import verify


@dataclass
class Session:
    """One run of a guard or gateway, as far as the trail can tell."""

    started: str = ""
    ended: str = ""
    subject: str = ""
    detail: str = ""
    summary: str = ""
    line: int = 0
    calls: Counter = field(default_factory=Counter)
    denied: list = field(default_factory=list)
    backends: list = field(default_factory=list)
    failures: list = field(default_factory=list)
    announced: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def unterminated(self) -> bool:
        return not self.ended

    @property
    def total_calls(self) -> int:
        return sum(self.calls.values())


def _entries(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for number, raw in enumerate(handle, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(entry, dict):
                    entry["_line"] = number
                    out.append(entry)
    except OSError:
        return []
    return out


def sessions(entries: list) -> list[Session]:
    """Split the trail into sessions without merging one into the next."""
    found: list[Session] = []
    current: Session | None = None

    def start(entry: dict) -> Session:
        return Session(started=str(entry.get("time") or ""),
                       subject=str(entry.get("subject") or ""),
                       detail=str(entry.get("detail") or ""),
                       line=int(entry.get("_line") or 0))

    for entry in entries:
        event = str(entry.get("event") or "")
        subject = str(entry.get("subject") or "")
        detail = str(entry.get("detail") or "")

        if event == "session_start":
            if current is not None:
                found.append(current)   # the previous one never ended
            current = start(entry)
            continue

        if current is None:
            # A trail that begins mid-session: still worth reporting, and
            # inventing a start time for it would be worse than admitting it.
            current = Session(started="", subject="(before this file begins)",
                              line=int(entry.get("_line") or 0))

        if event == "session_end":
            current.ended = str(entry.get("time") or "")
            current.summary = detail
            found.append(current)
            current = None
        elif event == "request":
            current.calls[subject or detail or "(unnamed)"] += 1
        elif event in ("denied", "budget_exhausted"):
            current.denied.append({"subject": subject, "event": event,
                                   "detail": detail})
        elif event == "backend_started":
            current.backends.append(subject)
        elif event == "backend_failed":
            current.failures.append({"subject": subject, "detail": detail})
        elif event == "client_announced":
            current.announced.append({"subject": subject, "detail": detail})
        elif event == "transport_error":
            current.errors.append(detail)

    if current is not None:
        found.append(current)
    return found


def build(path: Path) -> dict[str, Any]:
    result = verify(path)
    entries = _entries(path)

    # Nothing past the first broken line is evidence of anything, so it is not
    # counted. A total that includes unverified lines is a number an attacker
    # picked.
    cutoff = None
    if not result.ok and result.problems:
        cutoff = result.problems[0].line
        entries = [e for e in entries if e["_line"] < cutoff]

    found = sessions(entries)
    return {
        "path": str(path),
        "integrity": {
            "intact": result.ok,
            "entries": result.entries,
            "summary": result.summary(),
            "verified_through_line": (cutoff - 1) if cutoff else None,
        },
        "sessions": [
            {
                "started": s.started, "ended": s.ended,
                "subject": s.subject, "detail": s.detail,
                "summary": s.summary,
                "unterminated": s.unterminated,
                "calls": s.total_calls,
                "by_tool": dict(s.calls.most_common()),
                "denied": s.denied,
                "backends": s.backends,
                "failures": s.failures,
                "announced": s.announced,
                "errors": s.errors,
            }
            for s in found
        ],
        "totals": {
            "sessions": len(found),
            "calls": sum(s.total_calls for s in found),
            "denied": sum(len(s.denied) for s in found),
            "unterminated": sum(1 for s in found if s.unterminated),
        },
    }


def render(data: dict[str, Any], color: bool = True, verbose: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color and code else text

    lines: list[str] = [""]
    integrity = data["integrity"]

    if not integrity["intact"]:
        # Before anything else, and loudly. Everything below is a partial
        # reading of a file that was altered.
        lines += [
            "  " + paint("CHAIN BROKEN", "\033[31m") + "  " + integrity["summary"],
            "",
            "  Only the entries before that line are shown. Nothing after it is",
            "  evidence of anything, so it is not counted here.",
            "",
        ]
    else:
        lines.append("  %s  %s" % (paint("chain intact", "\033[32m"),
                                   f"{integrity['entries']} entries"))
        lines.append("")

    if not data["sessions"]:
        lines += ["  No sessions recorded.", ""]
        return "\n".join(lines)

    for session in data["sessions"]:
        when = session["started"] or "(start not in this file)"
        who = session["subject"] or "gateway"
        mark = "  " + paint("UNTERMINATED", "\033[33m") if session["unterminated"] else ""
        lines.append(f"  {when}  as {who}{mark}")
        if session["detail"]:
            lines.append(f"    {session['detail']}")

        for item in session["announced"]:
            lines.append("    client claimed to be %r  (%s)"
                         % (item["subject"], item["detail"]))
        if session["backends"]:
            lines.append("    started   " + ", ".join(session["backends"]))
        for failure in session["failures"]:
            lines.append("    " + paint("failed", "\033[33m") + "    %s -- %s"
                         % (failure["subject"], failure["detail"]))

        if session["calls"]:
            lines.append("    %d call(s)" % session["calls"])
            shown = list(session["by_tool"].items())
            for name, count in (shown if verbose else shown[:6]):
                lines.append("      %4d  %s" % (count, name))
            if not verbose and len(shown) > 6:
                lines.append("      ...   %d more (-v for all)" % (len(shown) - 6))
        else:
            lines.append("    no tool calls")

        for refusal in session["denied"]:
            label = "budget" if refusal["event"] == "budget_exhausted" else "refused"
            lines.append("    " + paint(label, "\033[31m") + "   %s%s"
                         % (refusal["subject"],
                            f" -- {refusal['detail']}" if refusal["detail"] else ""))
        for error in session["errors"]:
            lines.append("    transport  " + error)
        lines.append("")

    totals = data["totals"]
    lines.append("  %d session(s), %d call(s), %d refused"
                 % (totals["sessions"], totals["calls"], totals["denied"]))
    if totals["unterminated"]:
        # Why it has no end depends on which of two things happened, and
        # blaming a killed process for a truncation this report performed
        # would be inventing a cause.
        reason = ("the record stops at the break, so the end of it is not shown"
                  if not integrity["intact"]
                  else "the process was killed or is still running")
        lines.append("  %d session(s) have no end: %s"
                     % (totals["unterminated"], reason))
    lines.append("")
    lines.append("  Arguments are never recorded, so this says what was called and")
    lines.append("  not with what. That is the log's design, not a gap in it.")
    lines.append("")
    return "\n".join(lines)
