"""Rules that compare current state against the approval lockfile.

These are the only rules with memory. Everything else asks "is this config
dangerous"; these ask "is this the config you agreed to". A rug pull is
invisible to the first question and obvious to the second.

MCPA015–017, 019, 020, 031 no-op when no lock exists: there is no
baseline to drift from. MCPA014 does the opposite. Without a lock every
configured server is unapproved, which is the state a CI job that never
ran `approve` would otherwise report as clean.
"""

from __future__ import annotations

from typing import Any, Iterable, Iterator

from ..findings import Finding, Location, Severity
from ..model import instructions_fingerprint
from .base import AuditContext, rule


def _lock(ctx: AuditContext) -> dict:
    lock = ctx.lock or {}
    servers = lock.get("servers") or {}
    skills = lock.get("skills") or {}
    if not servers and not skills:
        return {}
    return {"servers": servers, "skills": skills}


@rule("MCPA014", "Server is not in the approval lockfile", Severity.HIGH)
def unapproved_server(ctx: AuditContext) -> Iterable[Finding]:
    """A server appeared that was never reviewed."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]
    for s in ctx.servers:
        if s.disabled:
            continue
        if s.identity() in known:
            continue
        yield Finding(
            rule_id="MCPA014",
            title="Server is not in the approval lockfile",
            severity=Severity.HIGH,
            location=Location(path=s.source, line=s.line, snippet=s.command_line[:200] or (s.url or "")),
            evidence=f"server {s.identity()!r} is configured but absent from the lockfile",
            remediation=(
                "Review the server, then run `mcp-pin approve` to record it. An MCP server "
                "nobody reviewed is the plain definition of shadow MCP."
            ),
            server=s.name,
            atlas=["AML.T0010"],
            tags=["drift", "shadow-mcp"],
        )


def unpinned_findings(servers: list) -> list[Finding]:
    """MCPA014 for a scan that has servers and no lockfile.

    The rule itself still no-ops without a lock so a unit test of some other
    rule does not also fail this one, and so `--probe` is not gated on
    "you have not approved this yet" -- launching is opt-in, the CI failure
    is the scan's.
    """
    out: list[Finding] = []
    for s in servers:
        if getattr(s, "disabled", False):
            continue
        out.append(Finding(
            rule_id="MCPA014",
            title="Server is not in the approval lockfile",
            severity=Severity.HIGH,
            location=Location(path=s.source, line=getattr(s, "line", 0),
                              snippet=s.command_line[:200] or (s.url or "")),
            evidence=(f"no approval lockfile; server {s.identity()!r} "
                      "has not been reviewed"),
            remediation=(
                "Review the server, then run `mcp-pin approve` to record it. An MCP server "
                "nobody reviewed is the plain definition of shadow MCP."
            ),
            server=s.name,
            atlas=["AML.T0010"],
            tags=["drift", "shadow-mcp"],
        ))
    return out


@rule("MCPA015", "Tool definition changed since approval (possible rug pull)", Severity.CRITICAL)
def tool_drift(ctx: AuditContext) -> Iterable[Finding]:
    """A server silently changed what its tools tell the agent to do."""
    lock = _lock(ctx)
    if not lock:
        return
    if ctx.lock.get("stale_digests"):
        # The lock predates the RFC 8785 digest change, so every fingerprint
        # in it would compare unequal. Reporting that as a rug pull on every
        # tool at once is both wrong and the kind of noise that teaches
        # people to ignore this rule. Say what actually happened instead.
        yield Finding(
            rule_id="MCPA015",
            title="Lockfile predates the current digest algorithm",
            severity=Severity.MEDIUM,
            location=Location(path=".mcp-pin.lock", line=0, snippet="version 1"),
            evidence=(
                "this lockfile was written with the pre-RFC 8785 digest, whose "
                "fingerprints are not comparable with the ones computed now, so "
                "drift cannot be checked against it"
            ),
            remediation=(
                "Re-run `mcp-pin approve` to record the current state with the new "
                "digest. Review the diff as usual: the fingerprints all change "
                "because the algorithm changed, but the description previews beside "
                "them do not, and those are what tell you a tool actually moved."
            ),
            tags=["drift", "lockfile"],
        )
        return
    known = lock["servers"]

    observed: dict[str, dict[str, object]] = {}
    for t in ctx.tools:
        observed.setdefault(t.server, {})[t.name] = t

    for server_name, current_tools in observed.items():
        entry = _entry_for(known, server_name)
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


def _entry_for(known: dict, server_name: str) -> dict | None:
    """The lock entry for this server, or none if that would be a guess.

    Keys are `client:name`. Taking the first bare-name match is how Cursor's
    github was compared against Claude's.
    """
    hit = known.get(server_name)
    if isinstance(hit, dict):
        return hit
    matches = [e for e in known.values()
               if isinstance(e, dict) and e.get("name") == server_name]
    if len(matches) == 1:
        return matches[0]
    return None


@rule("MCPA019", "Server instructions changed since approval", Severity.CRITICAL)
def instructions_drift(ctx: AuditContext) -> Iterable[Finding]:
    """The server rewrote the text that may become the agent's system prompt."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]

    for server_name, text in sorted(ctx.instructions.items()):
        entry = _entry_for(known, server_name)
        if not entry or "instructions" not in entry:
            continue
        recorded = entry["instructions"]
        if not isinstance(recorded, dict):
            continue
        if recorded.get("fingerprint") == instructions_fingerprint(text):
            continue
        yield Finding(
            rule_id="MCPA019",
            title="Server instructions changed since approval",
            severity=Severity.CRITICAL,
            location=Location(path=str(entry.get("source") or ""), line=0,
                              snippet=f"{server_name} (instructions)"),
            evidence=(
                f"server {server_name!r} changed its `instructions`\n"
                f"      was: {str(recorded.get('preview') or '')!r}\n"
                f"      now: {text[:160]!r}"
            ),
            remediation=(
                "Read the new text in full before using this server again. The protocol "
                "permits a client to add `instructions` to the system prompt, so this is "
                "the highest-privilege text the server controls -- a change here rewrites "
                "the agent's standing orders, not just one tool's description."
            ),
            server=server_name,
            atlas=["AML.T0051.001", "AML.T0053"],
            cwe=["CWE-77"],
            tags=["drift", "rug-pull", "instructions"],
        )


@rule("MCPA020", "Prompt or resource changed since approval", Severity.HIGH)
def prompt_resource_drift(ctx: AuditContext) -> Iterable[Finding]:
    """A prompt template or resource description changed after approval."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]

    groups: dict[str, dict[str, object]] = {}
    for p in ctx.prompts:
        groups.setdefault(p.server, {}).setdefault("prompts", {})[p.name] = p  # type: ignore[index]
    for r in ctx.resources:
        groups.setdefault(r.server, {}).setdefault("resources", {})[r.uri] = r  # type: ignore[index]

    for server_name, observed in sorted(groups.items()):
        entry = _entry_for(known, server_name)
        if not entry:
            continue
        source = str(entry.get("source") or "")
        for kind, label in (("prompts", "prompt"), ("resources", "resource")):
            current = observed.get(kind) or {}
            locked = entry.get(kind)
            if not isinstance(locked, dict):
                continue
            for key, spec in sorted(current.items()):  # type: ignore[union-attr]
                recorded = locked.get(key)
                if recorded is None:
                    yield Finding(
                        rule_id="MCPA020",
                        title=f"{label.capitalize()} added since approval",
                        severity=Severity.MEDIUM,
                        location=Location(path=source, line=0, snippet=f"{server_name}/{key}"),
                        evidence=f"{label} {key!r} was not present at approval",
                        remediation=f"Review the new {label}, then re-approve.",
                        server=server_name,
                        atlas=["AML.T0010"],
                        tags=["drift", label],
                    )
                    continue
                if recorded.get("fingerprint") == spec.fingerprint():  # type: ignore[union-attr]
                    continue
                yield Finding(
                    rule_id="MCPA020",
                    title=f"{label.capitalize()} changed since approval",
                    severity=Severity.HIGH,
                    location=Location(path=source, line=0, snippet=f"{server_name}/{key}"),
                    evidence=(
                        f"{label} {key!r} fingerprint changed\n"
                        f"      was: {str(recorded.get('description_preview') or '')!r}\n"
                        f"      now: {getattr(spec, 'description', '')[:160]!r}"
                    ),
                    remediation=(
                        f"Diff the {label} before using it again. Prompt and resource text "
                        "reaches the model the same way a tool description does."
                    ),
                    server=server_name,
                    atlas=["AML.T0010", "AML.T0051.001"],
                    tags=["drift", "rug-pull", label],
                )


@rule("MCPA031", "Server script changed since approval", Severity.HIGH)
def artifact_drift(ctx: AuditContext) -> Iterable[Finding]:
    """The launch command is unchanged; the code it starts is not."""
    from ..artifacts import artifact_digests

    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]
    for s in ctx.servers:
        entry = known.get(s.identity())
        if not isinstance(entry, dict):
            continue
        recorded = entry.get("artifacts")
        if not isinstance(recorded, dict) or not recorded:
            continue

        current = artifact_digests(s)
        for path, approved in sorted(recorded.items()):
            now = current.get(path)
            if now == approved:
                continue
            if now is None:
                detail = "is no longer readable at that path"
            else:
                detail = f"now hashes to {now[:16]}, was {str(approved)[:16]}"
            yield Finding(
                rule_id="MCPA031",
                title="Server script changed since approval",
                severity=Severity.HIGH,
                location=Location(path=s.source, line=s.line, snippet=path),
                evidence=f"{s.identity()} starts {path}, which {detail}",
                remediation=(
                    "Confirm you made this change. The launch command in the config is "
                    "identical to the one you approved, so nothing else here would "
                    "report it -- and editing a script nobody diffs is easier than "
                    "editing a config somebody committed. Re-run `mcp-pin approve "
                    "--probe` once you have read the change."
                ),
                server=s.name,
                atlas=["AML.T0010.001"],
                cwe=["CWE-494"],
                tags=["drift", "supply-chain"],
            )


def _recorded_integrity(ctx: AuditContext) -> Iterator[tuple]:
    """(server, recorded hashes, recorded urls) for every pinned registry launch."""
    lock = _lock(ctx)
    if not lock:
        return
    known = lock["servers"]
    for s in ctx.servers:
        entry = known.get(s.identity())
        if not isinstance(entry, dict):
            continue
        recorded = entry.get("integrity")
        if not isinstance(recorded, dict) or not recorded:
            continue
        urls = entry.get("artifact_urls")
        yield s, recorded, urls if isinstance(urls, dict) else {}


def _ask_registry(ctx: AuditContext, server: Any) -> Any:
    """What the registry publishes now, fetched at most once per scan.

    Two rules read the same answer. Without the memo, MCPA036 and MCPA037
    would each open a socket for every server, which doubles both the
    latency and the number of times a scan tells a registry what you run.
    """
    from ..integrity import Published, published

    if ctx.options.get("offline"):
        # `--safe` promises to execute nothing and connect to nothing. A
        # registry lookup is a connection, so the promise wins and the scan
        # reports that it could not see rather than pretending it looked.
        return Published("unreachable",
                         detail="--safe was given, so no registry was contacted")
    seen = ctx.options.setdefault("_integrity_seen", {})
    key = server.identity()
    if key not in seen:
        seen[key] = published(server)
    return seen[key]


@rule("MCPA036", "Registry artifact changed since approval", Severity.HIGH)
def integrity_drift(ctx: AuditContext) -> Iterable[Finding]:
    """The version string is unchanged; the tarball it names is not."""
    from ..pkgcache import check as cache_check

    for s, recorded, urls in _recorded_integrity(ctx):
        # What the machine already holds is the stronger evidence: those are
        # the bytes a launch would actually run, and reading them needs no
        # network. The registry answer is the second opinion.
        local = {c.key: c for c in cache_check(recorded, urls)}
        answer = _ask_registry(ctx, s)
        # By the string form: a lockfile is hand-edited, `run_rules` does not
        # catch a rule exception, and a mixed-type mapping would take the
        # whole scan down rather than report anything.
        for key, approved in sorted(recorded.items(), key=lambda kv: str(kv[0])):
            held = local.get(key)
            if held is not None and held.state == "changed":
                yield _integrity_finding(s, key, held.detail, local=True)
                continue
            now = answer.hashes.get(key)
            if now is None or now == approved:
                continue
            yield _integrity_finding(
                s, key,
                f"the registry now serves {str(now)[:24]}, "
                f"{str(approved)[:24]} was approved")


def _integrity_finding(s: Any, key: str, detail: str, *,
                       local: bool = False) -> Finding:
    where = ("the copy on this machine" if local
             else "the copy the registry serves")
    return Finding(
        rule_id="MCPA036",
        title="Registry artifact changed since approval",
        severity=Severity.HIGH,
        location=Location(path=s.source, line=s.line, snippet=str(key)),
        evidence=f"{s.identity()} fetches {key}; {where} is not the approved one -- {detail}",
        remediation=(
            "The version in the launch command is the same; the bytes behind "
            "it are not. On npm and PyPI a published version cannot be "
            "replaced, so this points at a private registry, a mirror or "
            "caching proxy, a `--registry` override, or something "
            "intercepting the fetch. Confirm the publish before you accept "
            "it, then `mcp-pin approve --probe --yes`."
        ),
        server=s.name,
        atlas=["AML.T0010.001"],
        cwe=["CWE-494"],
        tags=["drift", "supply-chain"],
    )


@rule("MCPA037", "Registry artifact could not be verified", Severity.LOW)
def integrity_unverified(ctx: AuditContext) -> Iterable[Finding]:
    """A hash was approved and this run could not check it against anything.

    Separate from MCPA036 on purpose. "Verified unchanged" and "could not
    look" are different facts, and reporting them as one hands silence to
    anyone who can make the lookup fail -- and to an offline CI runner, which
    produces the same silence by accident. `--require-integrity` raises this
    to HIGH so a runner that must not guess can fail the build on it.
    """
    from ..pkgcache import check as cache_check

    strict = bool(ctx.options.get("require_integrity"))
    for s, recorded, urls in _recorded_integrity(ctx):
        local = {c.key: c for c in cache_check(recorded, urls)}
        answer = _ask_registry(ctx, s)
        for key in sorted(recorded, key=str):
            held = local.get(key)
            if held is not None and held.state in ("verified", "changed"):
                continue
            if answer.hashes.get(key):
                continue
            reason = answer.detail or "the registry did not answer"
            if held is not None:
                reason = f"{reason}; locally, {held.detail}"
            yield Finding(
                rule_id="MCPA037",
                title="Registry artifact could not be verified",
                severity=Severity.HIGH if strict else Severity.LOW,
                location=Location(path=s.source, line=s.line, snippet=str(key)),
                evidence=(
                    f"{s.identity()} pins {key}, and this run could not "
                    f"confirm the bytes behind it: {reason}"
                ),
                remediation=(
                    "This is not a report that something changed -- it is a "
                    "report that nothing checked. The recorded hash still "
                    "stands. Re-run where the registry is reachable, or on a "
                    "machine whose package cache holds the artifact. A build "
                    "that must not proceed unverified should pass "
                    "`--require-integrity`, which makes this HIGH."
                ),
                server=s.name,
                atlas=["AML.T0010.001"],
                cwe=["CWE-494"],
                tags=["drift", "supply-chain", "coverage"],
            )
