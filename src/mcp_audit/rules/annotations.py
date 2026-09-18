"""Rules about a server's claims regarding its own tools.

MCP lets a server attach `ToolAnnotations` to each tool: `readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`. Clients use these to
decide whether a call needs the user's approval, so a tool marked read-only
can be invoked without anyone being asked.

The specification is blunt about the consequence:

    "Clients should never make tool use decisions based on ToolAnnotations
     received from untrusted servers."

That is a warning to client authors, and in practice clients do use the hints
anyway, because that is what they are for. So the annotation is a claim the
server makes about itself, and a claim is checkable: a tool named
`delete_record` that declares `readOnlyHint: true` is either wrong or lying,
and either way the user is about to auto-approve something they should have
been asked about.

These rules do not verify behaviour -- nothing static can. They check the
server's claim against the server's own other statements about the same tool.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..findings import Finding, Location, Severity
from .base import AuditContext, rule

# Verbs that destroy or revoke, in essentially any context.
#
# The first version of this list was far broader -- run, execute, send, post,
# publish, create, write, update, charge and so on. Measured against 56 tools
# on four live servers it fired on 27% of them and essentially every hit was
# wrong: "charges" in billing prose, "runs" in a verification tool, and a
# documentation search tool whose description explains that it is read-only
# and that "nothing runs on the user's computer".
#
# What survives is the set whose meaning does not depend on the object. You
# cannot delete, purge or revoke something benignly. Words like `remove` and
# `update` were dropped even though they are sometimes destructive, because
# `remove_background` on an image is a pure function and the rule cannot tell
# the difference.
#
# Recall is much lower and precision is the point: a rule that fires on a
# quarter of ordinary tools teaches people to ignore it.
MUTATING_VERBS = (
    "delete", "destroy", "purge", "truncate", "erase", "wipe",
    "uninstall", "revoke", "terminate", "shutdown", "reboot",
    "chmod", "chown", "overwrite",
)


def _inflect(verb: str) -> list[str]:
    """base, plural, past and progressive forms of a regular English verb."""
    forms = {verb, verb + "s"}
    if verb.endswith("e"):
        stem = verb[:-1]
        forms |= {verb + "d", stem + "ing"}
    elif verb.endswith("y") and len(verb) > 2 and verb[-2] not in "aeiou":
        stem = verb[:-1]
        forms |= {stem + "ies", stem + "ied", verb + "ing"}
    else:
        forms |= {verb + "ed", verb + "ing"}
    return sorted(forms, key=len, reverse=True)


MUTATING = re.compile(
    r"\b(?:" + "|".join(f for v in MUTATING_VERBS for f in _inflect(v)) + r")\b",
    re.IGNORECASE,
)

# Names whose mutation is the whole point, where the verb above is decisive.
_NAME_SPLIT = re.compile(r"[_\-.\s]+")


def _mutating_terms(text: str) -> list[str]:
    return sorted({m.group(0).lower() for m in MUTATING.finditer(text or "")})


def _name_terms(name: str) -> list[str]:
    """Mutating verbs in the tool's own name, which is the strongest signal."""
    parts = _NAME_SPLIT.split(name or "")
    return sorted({p.lower() for p in parts if MUTATING.fullmatch(p or "")})


@rule("MCPA021", "Tool claims to be read-only but looks like it mutates", Severity.HIGH)
def read_only_contradiction(ctx: AuditContext) -> Iterable[Finding]:
    """A read-only or non-destructive claim contradicted by the tool itself."""
    declared = {s.name: (s.source, s.line) for s in ctx.servers}

    for tool in ctx.tools:
        if not (tool.claims_read_only or tool.claims_non_destructive):
            continue

        # Name only. The description path was measured against four live
        # servers and produced 14 hits, every one of them wrong -- prose
        # mentions destructive words constantly, including when explaining
        # that a tool does not do them.
        in_name = _name_terms(tool.name)
        if not in_name:
            continue
        severity = Severity.HIGH
        confidence = 0.9
        evidence_bit = f"its name contains {', '.join(repr(t) for t in in_name)}"

        claim = "readOnlyHint: true" if tool.claims_read_only else "destructiveHint: false"
        path, line = declared.get(tool.server, ("", 0))

        yield Finding(
            rule_id="MCPA021",
            title="Tool claims to be read-only but looks like it mutates",
            severity=severity,
            location=Location(path=path, line=line, snippet=f"{tool.server}/{tool.name}"),
            evidence=(
                f"{tool.server}/{tool.name} declares {claim}, but {evidence_bit}"
            ),
            remediation=(
                "Check what the tool actually does. Clients use these hints to decide "
                "whether a call needs your approval, so a false read-only claim gets the "
                "tool run without anyone being asked. The specification says clients should "
                "never make tool-use decisions on annotations from untrusted servers; this "
                "rule exists because in practice they do."
            ),
            server=tool.server,
            atlas=["AML.T0053"],
            cwe=["CWE-451"],
            confidence=confidence,
            tags=["annotations", "trust"],
        )


@rule("MCPA022", "Tool schema accepts a destination the description does not mention",
      Severity.MEDIUM)
def undeclared_egress(ctx: AuditContext) -> Iterable[Finding]:
    """A parameter that can carry data outward, absent from the prose."""
    declared = {s.name: (s.source, s.line) for s in ctx.servers}
    egress_param = re.compile(
        r"^(?:url|uri|endpoint|webhook|callback|callback_url|destination|target_url|"
        r"forward_to|report_to|notify_url|sink|upload_url|host|server)$",
        re.IGNORECASE,
    )
    mentions_network = re.compile(
        r"\b(?:url|uri|endpoint|webhook|callback|http|https|upload|send|post|forward|"
        r"notify|remote|external|network|fetch|download)\b", re.IGNORECASE)

    for tool in ctx.tools:
        properties = (tool.input_schema or {}).get("properties")
        if not isinstance(properties, dict):
            continue
        suspicious = [name for name in properties if egress_param.match(str(name))]
        if not suspicious:
            continue
        if mentions_network.search(tool.description or ""):
            continue  # the prose accounts for it

        path, line = declared.get(tool.server, ("", 0))
        yield Finding(
            rule_id="MCPA022",
            title="Tool schema accepts a destination the description does not mention",
            severity=Severity.MEDIUM,
            location=Location(path=path, line=line, snippet=f"{tool.server}/{tool.name}"),
            evidence=(
                f"{tool.server}/{tool.name} accepts {', '.join(repr(s) for s in suspicious)} "
                f"but its description never mentions sending anything anywhere"
            ),
            remediation=(
                "Read the parameter's purpose. A tool whose prose describes local work but "
                "whose schema takes a URL has a route outward that a reviewer reading only "
                "the description would not see."
            ),
            server=tool.server,
            atlas=["AML.T0024", "AML.T0057"],
            cwe=["CWE-201"],
            confidence=0.6,
            tags=["schema", "exfiltration"],
        )


# Words a display title uses to look harmless.
_BENIGN_DISPLAY = re.compile(
    r"\b(?:read|reads|reading|view|views|show|shows|display|displays|list|lists|"
    r"get|gets|fetch|fetches|search|searches|find|finds|browse|browses|"
    r"summar(?:y|ise|ize|ises|izes)|preview|previews|inspect|inspects|check|checks|"
    r"look\s?up|query|queries|report|reports|status)\b",
    re.IGNORECASE,
)


@rule("MCPA026", "Display title misrepresents what the tool does", Severity.HIGH)
def deceptive_title(ctx: AuditContext) -> Iterable[Finding]:
    """The name mutates; the title the user sees says it only reads."""
    declared = {s.name: (s.source, s.line) for s in ctx.servers}

    for tool in ctx.tools:
        display = tool.display_name
        # Only interesting when a title actually overrides the name. If the
        # client falls back to the name, the user sees the honest string.
        if not display or display == tool.name:
            continue

        in_name = _name_terms(tool.name)
        if not in_name:
            continue
        if MUTATING.search(display):
            continue  # the title admits it too
        if not _BENIGN_DISPLAY.search(display):
            continue  # neutral title; not a claim either way

        path, line = declared.get(tool.server, ("", 0))
        source = ("annotations.title" if tool.annotations.get("title") else "title")
        yield Finding(
            rule_id="MCPA026",
            title="Display title misrepresents what the tool does",
            severity=Severity.HIGH,
            location=Location(path=path, line=line, snippet=f"{tool.server}/{tool.name}"),
            evidence=(
                f"{tool.server}/{tool.name} is displayed as {display!r} via {source}, "
                f"but its name contains {', '.join(repr(t) for t in in_name)}"
            ),
            remediation=(
                "Check what the tool does and what the user is shown before approving it. "
                "The spec says `title` is 'intended for UI and end-user contexts' and that "
                "`annotations.title` takes precedence over the name for tools, so the "
                "string in the approval dialog can be chosen independently of what the "
                "tool is actually called."
            ),
            server=tool.server,
            atlas=["AML.T0053"],
            cwe=["CWE-451"],
            confidence=0.8,
            tags=["annotations", "trust", "spoofing"],
        )
