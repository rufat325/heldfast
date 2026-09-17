"""Human-readable terminal output."""

from __future__ import annotations

import os
import sys
from typing import Iterable

from ..findings import Finding, Severity, atlas_title

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_DIM = "\033[90m"
_BOLD = "\033[1m"


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("CI") and not os.environ.get("GITHUB_ACTIONS"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class _Paint:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text

    def sev(self, severity: Severity) -> str:
        return self(f"{severity.label.upper():<8}", _COLORS[severity])

    def dim(self, text: str) -> str:
        return self(text, _DIM)

    def bold(self, text: str) -> str:
        return self(text, _BOLD)


def render_terminal(
    findings: list[Finding],
    *,
    scanned_configs: int = 0,
    scanned_servers: int = 0,
    scanned_tools: int = 0,
    scanned_skills: int = 0,
    errors: Iterable[str] = (),
    lock_present: bool = False,
    probed: bool = False,
    color: bool | None = None,
    verbose: bool = False,
    suppressed: list | None = None,
    ignore_path: str | None = None,
) -> str:
    paint = _Paint(use_color() if color is None else color)
    out: list[str] = []
    add = out.append

    add("")
    add(paint.bold("  mcp-audit"))
    add(paint.dim(
        f"  {scanned_configs} config file(s), {scanned_servers} server(s), "
        f"{scanned_tools} tool(s), {scanned_skills} skill(s)"
    ))
    add("")

    for err in errors:
        add(f"  {paint('parse error', _COLORS[Severity.MEDIUM])} {err}")
    if errors:
        add("")

    if not findings:
        add(paint("  No findings.", "\033[32m"))
    else:
        current: Severity | None = None
        for f in findings:
            if f.severity != current:
                current = f.severity
                count = sum(1 for x in findings if x.severity == current)
                add(paint(f"  {current.label.upper()} ({count})", _COLORS[current]))
                add("")
            add(f"  {paint.sev(f.severity)} {paint.bold(f.rule_id)}  {f.title}")
            loc = str(f.location)
            if f.server:
                loc = f"{f.server} @ {loc}"
            add(f"           {paint.dim(loc)}")
            for line in f.evidence.splitlines():
                add(f"           {line}")
            if f.confidence < 1.0:
                add(f"           {paint.dim(f'confidence {f.confidence:.0%}')}")
            if verbose:
                if f.atlas:
                    mapped = ", ".join(f"{a} ({atlas_title(a)})" for a in f.atlas)
                    add(f"           {paint.dim('ATLAS: ' + mapped)}")
                if f.cwe:
                    add(f"           {paint.dim('CWE:   ' + ', '.join(f.cwe))}")
            add(f"           {paint.dim('-> ' + f.remediation)}")
            add("")

    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = "  ".join(
        paint(f"{counts[s]} {s.label}", _COLORS[s])
        for s in sorted(Severity, reverse=True) if counts[s]
    )
    add(paint.dim("  " + "-" * 64))
    add(f"  {summary}" if summary else paint.dim("  clean"))

    # Suppressed findings are reported as a count, never silently dropped:
    # a reader has to be able to see that something was excluded.
    if suppressed:
        add(paint.dim(
            f"  {len(suppressed)} finding(s) suppressed"
            + (f" by {ignore_path}" if ignore_path else "")
        ))
        if verbose:
            for f, rule in suppressed:
                why = f" ({rule.reason})" if rule.reason else ""
                add(paint.dim(f"    {f.rule_id} {f.server or ''} <- line {rule.source_line}{why}"))

    hints: list[str] = []
    if not lock_present:
        hints.append(
            "No approval lockfile. Run `mcp-audit approve` to record the current state; "
            "later scans will then flag tool descriptions that change behind your back."
        )
    elif not probed:
        hints.append(
            "Ran without --probe, so tool descriptions were not re-read and drift "
            "detection was limited to configuration."
        )
    if any(f.confidence < 1.0 for f in findings):
        hints.append("Some findings are heuristic (confidence below 100%); verify before acting.")
    for hint in hints:
        add("")
        add(paint.dim(f"  note: {hint}"))
    add("")
    return "\n".join(out)
