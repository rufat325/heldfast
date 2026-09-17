"""Rules that compare current state against the approval lockfile.

These are the only rules with memory. Everything else asks "is this config
dangerous"; these ask "is this the config you agreed to". A rug pull is
invisible to the first question and obvious to the second.

All of these no-op when no lock exists, so a first run is never noisy.
"""

from __future__ import annotations

from typing import Iterable

from ..findings import Finding, Location, Severity
from .base import AuditContext, rule


def _lock(ctx: AuditContext) -> dict:
    lock = ctx.lock or {}
    servers = lock.get("servers") or {}
    skills = lock.get("skills") or {}
    if not servers and not skills:
        return {}
    return {"servers": servers, "skills": skills}


@rule("MCPA014", "Server is not in the approval lockfile", Severity.MEDIUM)
def unapproved_server(ctx: AuditContext) -> Iterable[Finding]:
    """A server appeared that was never reviewed."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]
    for s in ctx.servers:
        if s.identity() in known:
            continue
        yield Finding(
            rule_id="MCPA014",
            title="Server is not in the approval lockfile",
            severity=Severity.MEDIUM,
            location=Location(path=s.source, line=s.line, snippet=s.command_line[:200] or (s.url or "")),
            evidence=f"server {s.identity()!r} is configured but absent from the lockfile",
            remediation=(
                "Review the server, then run `mcp-audit approve` to record it. An MCP server "
                "nobody reviewed is the plain definition of shadow MCP."
            ),
            server=s.name,
            atlas=["AML.T0010"],
            tags=["drift", "shadow-mcp"],
        )


@rule("MCPA015", "Tool definition changed since approval (possible rug pull)", Severity.CRITICAL)
def tool_drift(ctx: AuditContext) -> Iterable[Finding]:
    """A server silently changed what its tools tell the agent to do."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]

    observed: dict[str, dict[str, object]] = {}
    for t in ctx.tools:
        observed.setdefault(t.server, {})[t.name] = t

    for server_name, current_tools in observed.items():
        entry = next(
            (e for ident, e in known.items()
             if isinstance(e, dict) and e.get("name") == server_name),
            None,
        )
        if not entry or "tools" not in entry:
            continue
        locked_tools = entry.get("tools") or {}
        source = str(entry.get("source") or "")

        for name, tool in sorted(current_tools.items()):
            locked = locked_tools.get(name)
            if locked is None:
                yield Finding(
                    rule_id="MCPA015",
                    title="Tool added since approval",
                    severity=Severity.HIGH,
                    location=Location(path=source, line=0, snippet=f"{server_name}/{name}"),
                    evidence=f"tool {name!r} is advertised by {server_name!r} but was not present at approval",
                    remediation=(
                        "Read the new tool's description and schema before the agent uses it. "
                        "Adding a tool post-approval is how a server expands its reach without "
                        "touching the config file you reviewed."
                    ),
                    server=server_name,
                    atlas=["AML.T0010", "AML.T0053"],
                    tags=["drift", "rug-pull"],
                )
                continue
            current_fp = tool.fingerprint()  # type: ignore[attr-defined]
            if current_fp == locked.get("fingerprint"):
                continue
            was = str(locked.get("description_preview") or "")
            now = (getattr(tool, "description", "") or "")[:160]
            yield Finding(
                rule_id="MCPA015",
                title="Tool definition changed since approval (possible rug pull)",
                severity=Severity.CRITICAL,
                location=Location(path=source, line=0, snippet=f"{server_name}/{name}"),
                evidence=(
                    f"tool {name!r} fingerprint changed\n"
                    f"      was: {was!r}\n"
                    f"      now: {now!r}"
                ),
                remediation=(
                    "Diff the full definition before using this server again. The config file "
                    "did not change, so nothing else would have told you. This is the pattern "
                    "where a server behaves for long enough to be trusted, then changes what "
                    "its descriptions instruct the agent to do."
                ),
                server=server_name,
                atlas=["AML.T0010", "AML.T0051.001", "AML.T0053"],
                cwe=["CWE-494"],
                tags=["drift", "rug-pull"],
            )

        for name in sorted(set(locked_tools) - set(current_tools)):
            yield Finding(
                rule_id="MCPA015",
                title="Tool removed since approval",
                severity=Severity.LOW,
                location=Location(path=source, line=0, snippet=f"{server_name}/{name}"),
                evidence=f"tool {name!r} was approved but is no longer advertised by {server_name!r}",
                remediation="Confirm the removal was an intentional upstream change, then re-approve.",
                server=server_name,
                tags=["drift"],
            )


@rule("MCPA016", "Server launch command changed since approval", Severity.HIGH)
def command_drift(ctx: AuditContext) -> Iterable[Finding]:
    """How the server starts is no longer what was approved."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]
    for s in ctx.servers:
        entry = known.get(s.identity())
        if not isinstance(entry, dict):
            continue
        for field_name, current in (("command_line", s.command_line), ("url", s.url)):
            previous = entry.get(field_name)
            if previous in (None, "") and current in (None, ""):
                continue
            if previous == current:
                continue
            yield Finding(
                rule_id="MCPA016",
                title="Server launch command changed since approval",
                severity=Severity.HIGH,
                location=Location(path=s.source, line=s.line, snippet=str(current or "")[:200]),
                evidence=(
                    f"{s.identity()} {field_name} changed\n"
                    f"      was: {previous!r}\n"
                    f"      now: {current!r}"
                ),
                remediation=(
                    "Confirm you made this change. A modified launch command means different "
                    "code runs on the next agent start, under the approval you gave the old one."
                ),
                server=s.name,
                atlas=["AML.T0010.001"],
                tags=["drift"],
            )


@rule("MCPA017", "Skill content changed since approval", Severity.HIGH)
def skill_drift(ctx: AuditContext) -> Iterable[Finding]:
    """A skill's instructions changed after it was reviewed."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["skills"]
    if not known:
        return
    for sk in ctx.skills:
        entry = known.get(sk.path)
        if not isinstance(entry, dict):
            continue
        if entry.get("fingerprint") == sk.fingerprint():
            continue
        yield Finding(
            rule_id="MCPA017",
            title="Skill content changed since approval",
            severity=Severity.HIGH,
            location=Location(path=sk.path, line=0, snippet=sk.name),
            evidence=f"skill {sk.name!r} content fingerprint differs from the approved value",
            remediation=(
                "Diff the skill before running it again. A skill body is executed as "
                "instructions, so an edit is a behavior change, not a documentation change."
            ),
            atlas=["AML.T0010", "AML.T0051.001"],
            tags=["drift", "skills"],
        )
