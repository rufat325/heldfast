"""What is approved, what has moved, and what happened.

Everything here was already on disk. The lockfile knows what was approved and
when; the audit trail knows what the gateway did; the scan knows what has
drifted since. Nothing put them on one page, so operating this meant reading
three files and holding the join in your head.

This is the operator's view, not another analysis. It computes nothing the
other commands do not already compute -- it answers "where do things stand"
in one place, which is the question somebody actually has at the point of
using this.

Deliberately not a dashboard. It is a command that prints, so it works over
ssh, in CI output, and in a terminal that is the only interface a lot of this
will ever have.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auditlog import verify
from .secrets import safe_name
from .findings import Finding, Severity
from .enforcement import behind_gateway, fronting_clients, is_gateway
from .identity import all_identities
from .lockfile import Lock


@dataclass
class ServerStatus:
    identity: str
    name: str
    approved_at: str = ""
    tools: int = 0
    has_policy: bool = False
    has_artifacts: bool = False
    configured: bool = False
    approved: bool = False
    fronted: bool = False
    probe: str = ""
    pins_nothing: bool = False
    # "" (nothing recorded) | "verified" | "unverified" | "changed".
    # Read from the local package cache, never the network: `status` does not
    # probe and must not quietly start making outbound calls either.
    integrity: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    @property
    def state(self) -> str:
        """One word, chosen so the important ones are visually distinct.

        Approval is read from the lockfile rather than from MCPA014 having
        fired. The rule and the lockfile agree today, but a status page that
        says "ok" because a rule was filtered out is worse than no page: this
        is the one screen where absence of an approval has to be visible on
        its own terms.
        """
        if not self.configured:
            # In the recommended setup an approved server is named only in the
            # lockfile: the client points at the gateway, which fronts it. That
            # read as GONE, so the correct configuration reported as a pile of
            # missing servers and the tool punished its own advice.
            if self.fronted:
                return "gateway"
            return "GONE"
        if not self.approved:
            return "UNAPPROVED"
        drift = {"MCPA015", "MCPA016", "MCPA017", "MCPA019", "MCPA020", "MCPA031",
                 "MCPA036"}
        if any(f.rule_id in drift for f in self.findings):
            return "DRIFTED"
        if self.worst is not None and self.worst >= Severity.HIGH:
            return "FINDINGS"
        # An approval covering a server that does not start. The lockfile
        # records the probe outcome and `coverage` has always said this;
        # `status` read the same file and printed "ok", which is the worse of
        # the two to get wrong because it is the page an operator opens first.
        if self.probe.startswith("no response"):
            return "FAILED"
        # Approved without --probe, so nothing the server says is pinned and
        # nothing can drift. Not a fault, but "ok" overstates it: there is no
        # baseline here to compare against.
        if self.pins_nothing:
            return "UNPINNED"
        return "ok"


def _integrity_state(entry: dict) -> str:
    """Whether this machine can still vouch for the recorded tarball.

    Recorded and verified are two claims. `status` printed neither, so a
    lockfile carrying a hash nobody had checked since the day it was written
    looked exactly like one confirmed a second ago.
    """
    recorded = entry.get("integrity")
    if not isinstance(recorded, dict) or not recorded:
        return ""
    from .pkgcache import check
    urls = entry.get("artifact_urls")
    checks = check(recorded, urls if isinstance(urls, dict) else None)
    if any(c.state == "changed" for c in checks):
        return "changed"
    if checks and all(c.state == "verified" for c in checks):
        return "verified"
    return "unverified"


def build(lock: Lock, servers: list, findings: list[Finding],
          log_path: Path | None = None, probed: bool = False) -> dict[str, Any]:
    """The whole picture as data, so the renderer stays dumb."""
    by_name: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.server:
            by_name.setdefault(finding.server, []).append(finding)

    configured = {s.identity(): s for s in servers}
    fronting = fronting_clients(servers)
    rows: list[ServerStatus] = []

    for key, entry in sorted(lock.servers.items()):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or key)
        rows.append(ServerStatus(
            identity=key,
            name=name,
            approved_at=str(entry.get("approved_at") or ""),
            tools=len(entry.get("tools") or {}),
            has_policy=isinstance(entry.get("policy"), dict) and bool(entry["policy"]),
            has_artifacts=bool(entry.get("artifacts")),
            configured=key in configured,
            approved=True,
            fronted=behind_gateway(key, entry, fronting),
            probe=str(entry.get("probe") or ""),
            integrity=_integrity_state(entry),
            # Every channel a server controls, not just tools: one that offers
            # only prompts or resources has a real baseline pinned.
            pins_nothing=not any(entry.get(k) for k in
                                 ("tools", "prompts", "resources", "instructions")),
            findings=by_name.get(name, []),
        ))

    # Configured but never approved: the case the lockfile cannot show, and
    # the one most worth seeing.
    known = {row.identity for row in rows}
    for key, spec in sorted(configured.items()):
        if key in known:
            continue
        if is_gateway(spec):
            # The gateway entry itself. Approving the thing that enforces
            # approvals is circular, so it has none by design and reporting it
            # as unapproved would flag the one entry that is doing the work.
            continue
        rows.append(ServerStatus(identity=key, name=spec.name, configured=True,
                                 findings=by_name.get(spec.name, [])))

    trail: dict[str, Any] = {}
    if log_path is not None and log_path.exists():
        result = verify(log_path)
        trail = {"path": str(log_path), "entries": result.entries,
                 "intact": result.ok, "summary": result.summary(),
                 "events": _recent_events(log_path)}

    return {
        # Whether the live definitions were read at all. Without it this page
        # prints "ok" beside a server whose tool descriptions have been
        # rewritten, because the drift check compares the lockfile against
        # what was observed and nothing was observed. A page that cannot tell
        # "checked and fine" from "did not look" is the failure this project
        # keeps naming, and it had it on its own front screen.
        "probed": probed,
        "lockfile": {
            "path": str(lock.path) if lock.path else "",
            "exists": bool(lock.servers or lock.skills),
            "generated": lock.generated,
            "servers": len(lock.servers),
            "skills": len(lock.skills),
        },
        "identities": {
            name: {
                "servers": ident.servers,
                "deny": ident.deny,
                "description": ident.description,
            }
            for name, ident in sorted(all_identities(lock).items())
        },
        "servers": [
            {
                "identity": safe_name(r.identity), "name": safe_name(r.name),
                "state": r.state,
                "approved_at": r.approved_at, "tools": r.tools,
                "policy": r.has_policy, "artifacts": r.has_artifacts,
                "integrity": r.integrity,
                "configured": r.configured,
                # The state word alone is what made this wrong: "ok" next to a
                # server that does not start read as a clean bill of health.
                "note": (
                    r.probe[13:].strip() if r.probe.startswith("no response")
                    else "approved without --probe, so nothing it says is pinned"
                    if r.pins_nothing and r.state == "UNPINNED" else ""
                ),
                "findings": [
                    {"rule_id": safe_name(f.rule_id),
                     "severity": f.severity.label,
                     "title": safe_name(f.title)}
                    for f in sorted(r.findings, key=lambda f: -f.severity.value)[:4]
                ],
            }
            for r in rows
        ],
        "trail": trail,
    }


def _recent_events(path: Path, limit: int = 5) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                events.append({"time": safe_name(entry.get("time", "")),
                               "event": safe_name(entry.get("event", "")),
                               "subject": safe_name(entry.get("subject", "")),
                               "decision": safe_name(entry.get("decision", ""))})
    except OSError:
        return []
    return events[-limit:]


_STATE_COLOR = {
    "DRIFTED": "\033[31m",
    "UNAPPROVED": "\033[33m",
    "GONE": "\033[33m",
    "gateway": "\033[32m",
    "FAILED": "\033[33m",
    "UNPINNED": "\033[33m",
    "FINDINGS": "\033[33m",
    "ok": "\033[32m",
}


def render(data: dict[str, Any], color: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color and code else text

    lines: list[str] = [""]
    lock = data["lockfile"]

    if not lock["exists"]:
        lines += [
            "  No approval lockfile.",
            "",
            "  Nothing is pinned, so nothing can have drifted and the gateway has",
            "  nothing to serve. Run `mcp-pin approve --probe` to record what is",
            "  here now.",
            "",
        ]
        return "\n".join(lines)

    lines.append(f"  approved {lock['generated']}   "
                 f"{lock['servers']} server(s), {lock['skills']} skill(s)")
    if not data.get("probed", False):
        lines.append("  " + paint(
            "tool definitions were not read, so drift is unchecked -- "
            "re-run with --probe", "\033[33m"))
    lines.append("")

    width = max((len(s["identity"]) for s in data["servers"]), default=10)
    for server in data["servers"]:
        state = server["state"]
        lines.append("  %s  %-*s  %2d tool(s)%s%s" % (
            paint("%-10s" % state, _STATE_COLOR.get(state, "")),
            width, server["identity"], server["tools"],
            "  policy" if server["policy"] else "",
            "  pinned-code" if server["artifacts"] else "",
        ))
        mark = server.get("integrity") or ""
        if mark == "verified":
            lines.append("              " + paint(
                "registry artifact verified against the local package cache",
                "\033[32m"))
        elif mark == "unverified":
            lines.append("              " + paint(
                "registry hash recorded at approval; nothing here could verify "
                "it (this page does not contact a registry)", "\033[36m"))
        elif mark == "changed":
            lines.append("              " + paint(
                "the package cache holds different bytes than were approved "
                "-- see MCPA036", "\033[31m"))
        if server.get("note"):
            lines.append("              %s" % server["note"])
        for finding in server["findings"]:
            lines.append("              %-8s %s" % (finding["rule_id"], finding["title"]))
    lines.append("")

    if data["identities"]:
        lines.append("  identities")
        for name, ident in data["identities"].items():
            scope = ("every approved server" if ident["servers"] is None
                     else ", ".join(ident["servers"]) or "no servers")
            lines.append(f"    {name:<14} {scope}")
            if ident["deny"]:
                lines.append(f"    {'':<14} denies {', '.join(ident['deny'])}")
        lines.append("")

    trail = data.get("trail") or {}
    if trail:
        mark = "intact" if trail["intact"] else "BROKEN"
        lines.append("  audit trail  %s  (%d entries, %s)" % (
            trail["path"], trail["entries"],
            paint(mark, "\033[32m" if trail["intact"] else "\033[31m")))
        for event in trail.get("events", []):
            lines.append("    %s  %-16s %s %s" % (
                event["time"], event["event"], event["subject"],
                event["decision"]))
        lines.append("")

    return "\n".join(lines)
