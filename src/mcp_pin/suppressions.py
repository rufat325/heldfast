"""Suppression file support.

Several rules are deliberately heuristic -- MCPA008 cannot tell a genuinely
open endpoint from one that negotiates OAuth at connect time, and telling
someone to live with a permanent false positive is how a scanner gets removed
from CI. So the advice to "suppress this" has to be backed by a mechanism.

Lockfile theorems (MCPA014-017, 019, 020, 031, 036) cannot be suppressed. A pin
that a committed one-line file can switch off is not a pin.

Format (`.mcp-pin-ignore`), one rule per line:

    MCPA008                     # suppress this rule everywhere
    MCPA008 open-endpoint       # suppress it for one server
    MCPA003 *                   # explicit everywhere, same as bare rule id
    # comments and blank lines are ignored

Suppressions are recorded in the report rather than silently dropped, so a
reader can always see what was excluded and why.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding

DEFAULT_IGNORE_NAME = ".mcp-pin-ignore"
LEGACY_IGNORE_NAME = ".mcp-audit-ignore"

# Lockfile theorems. The ignore file exists for heuristic false positives
# (MCPA008). A pin that a committed one-line file can switch off is not a pin.
PINNED = frozenset({
    "MCPA014", "MCPA015", "MCPA016", "MCPA017", "MCPA019", "MCPA020", "MCPA031",
    "MCPA036",
    # MCPA037 is the "nothing verified this" report, and it is here for the
    # same reason as the rest: `--require-integrity` exists so a build can
    # refuse to pass on an unverified artifact, and a committed one-line
    # ignore file would turn that flag back into the fail-open it replaced.
    # An offline runner does not need to suppress it -- it is low by default
    # and does not fail `--fail-on high` unless that flag was asked for.
    "MCPA037",
})


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    server: str  # glob; "*" means every server, including findings with none
    reason: str
    source_line: int

    def matches(self, f: Finding) -> bool:
        if f.rule_id != self.rule_id:
            return False
        if self.server == "*":
            return True
        return bool(f.server) and fnmatch.fnmatch(f.server, self.server)


def parse_ignore_file(path: Path) -> tuple[list[Suppression], list[str]]:
    """Return (suppressions, errors)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"{path}: cannot read ignore file ({exc})"]

    out: list[Suppression] = []
    errors: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line, _, comment = raw.partition("#")
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        rule_id = parts[0].upper()
        if not (rule_id.startswith("MCPA") and rule_id[4:].isdigit()):
            errors.append(f"{path}:{lineno}: {parts[0]!r} is not a rule id")
            continue
        if rule_id in PINNED:
            errors.append(
                f"{path}:{lineno}: {rule_id} cannot be suppressed "
                "(it is a lockfile theorem, not a heuristic)")
            continue
        server = parts[1] if len(parts) > 1 else "*"
        out.append(Suppression(rule_id, server, comment.strip(), lineno))
    return out, errors


def apply(findings: list[Finding], suppressions: list[Suppression]
          ) -> tuple[list[Finding], list[tuple[Finding, Suppression]]]:
    """Split findings into (kept, suppressed_with_their_rule)."""
    if not suppressions:
        return findings, []
    kept: list[Finding] = []
    dropped: list[tuple[Finding, Suppression]] = []
    for f in findings:
        if f.rule_id in PINNED:
            kept.append(f)
            continue
        rule = next((s for s in suppressions if s.matches(f)), None)
        if rule is None:
            kept.append(f)
        else:
            dropped.append((f, rule))
    return kept, dropped


def load(explicit: str | None, roots: list[Path]) -> tuple[list[Suppression], list[str], Path | None]:
    """Find and parse the ignore file. Explicit path wins; else look in roots."""
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            return [], [f"{p}: ignore file not found"], None
        sup, errs = parse_ignore_file(p)
        return sup, errs, p
    for root in roots:
        base = root if root.is_dir() else root.parent
        for name in (DEFAULT_IGNORE_NAME, LEGACY_IGNORE_NAME):
            candidate = base / name
            if candidate.is_file():
                sup, errs = parse_ignore_file(candidate)
                return sup, errs, candidate
    for name in (DEFAULT_IGNORE_NAME, LEGACY_IGNORE_NAME):
        cwd_candidate = Path.cwd() / name
        if cwd_candidate.is_file():
            sup, errs = parse_ignore_file(cwd_candidate)
            return sup, errs, cwd_candidate
    return [], [], None
