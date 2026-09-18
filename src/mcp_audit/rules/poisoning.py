"""Rules about text the agent reads as instructions.

A tool description is not documentation -- it is injected verbatim into the
model's context, which makes it an instruction channel that the user never
sees. The same is true of a skill body. These rules look for text that is
addressed to the *agent* rather than describing the tool to a reader.

A note on false positives: a SKILL.md is *supposed* to instruct the agent, so
imperative mood there is normal and is not flagged. In a tool description it
is anomalous. The `strict` flag below encodes that difference, and it is the
main reason this scanner can run on skills without drowning the user.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable, NamedTuple

from ..findings import Finding, Location, Severity
from .base import AuditContext, rule


class Signal(NamedTuple):
    category: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    # True  -> anomalous anywhere, including inside a skill body
    # False -> only meaningful in a tool description
    universal: bool
    note: str


SIGNALS: list[Signal] = [
    Signal(
        "concealment",
        re.compile(
            r"\b(?:do\s+not|don't|never)\s+(?:mention|tell|inform|reveal|disclose|show|display|"
            r"report|notify|alert|explain)\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human|operator|"
            r"anyone|them)\b|"
            # "without asking" alone is ordinary prose ("what you get without asking"),
            # so the concealment reading requires an explicit person as the object.
            r"\bwithout\s+(?:telling|informing|notifying|alerting|asking|consulting)\s+"
            r"(?:the\s+)?(?:user|human|operator|owner|anyone|them)\b|"
            r"\b(?:keep|hide)\s+(?:this|it|that)\s+(?:secret|hidden|confidential|quiet)\b|"
            r"\bdo\s+not\s+(?:log|record|output|print)\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, 0.95, True,
        "instructs the agent to conceal behavior from the user",
    ),
    Signal(
        "override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+|any\s+|the\s+)?"
            r"(?:previous|prior|preceding|above|earlier|other|system|original)\s+"
            r"(?:instruction|prompt|rule|direction|guideline|constraint|message)s?\b|"
            r"\bignore\s+everything\s+(?:above|before)\b",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, 0.95, True,
        "attempts to override the agent's existing instructions",
    ),
    Signal(
        "role-hijack",
        re.compile(
            r"(?:^|\n)\s*(?:<\s*/?\s*(?:system|assistant|human)\s*>|\[/?INST\]|"
            r"<\|(?:im_start|im_end|system|endoftext)\|>|###\s*(?:System|Instruction)\s*:?)",
            re.IGNORECASE,
        ),
        Severity.HIGH, 0.9, True,
        "embeds chat-template or role markers that can restructure the prompt",
    ),
    Signal(
        "mandated-side-effect",
        re.compile(
            r"\b(?:before|prior to)\s+(?:using|calling|invoking|running)\s+"
            r"(?:any\s+other|this|the)\s+tool\b|"
            r"\b(?:you\s+must|always|first)\s+(?:read|open|load|cat|fetch|retrieve)\s+"
            r"(?:the\s+)?(?:file|contents?|~|/|\.)",
            re.IGNORECASE,
        ),
        Severity.HIGH, 0.8, False,
        "requires the agent to take an unrelated action before using the tool",
    ),
    Signal(
        "exfiltration",
        re.compile(
            r"\b(?:send|post|upload|transmit|forward|exfiltrate|report|submit)\b"
            r"[^.\n]{0,60}?\b(?:to)\s+(?:https?://|[\w.\-]+@[\w.\-]+\.\w+|"
            r"(?:our|the|an?)\s+(?:server|endpoint|api|webhook|collector))",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, 0.85, True,
        "directs data to an external destination",
    ),
    Signal(
        "agent-addressed-imperative",
        re.compile(
            r"\b(?:you\s+(?:must|should|need\s+to|are\s+required\s+to)|"
            r"it\s+is\s+(?:essential|mandatory|critical|imperative)\s+that\s+you)\b",
            re.IGNORECASE,
        ),
        Severity.MEDIUM, 0.5, False,
        "addresses the agent directly rather than describing the tool",
    ),
]

# Paths whose appearance in agent-facing text is almost never innocent.
SENSITIVE_PATHS = re.compile(
    r"(?:~|\$HOME|%USERPROFILE%)?[/\\]?\.(?:ssh(?:[/\\]|\b)|aws[/\\]credentials|"
    r"git-credentials|npmrc|pypirc|netrc|docker[/\\]config\.json|kube[/\\]config|"
    r"config[/\\]gcloud|env(?:\.local|\.production)?\b)|"
    r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b|/etc/(?:passwd|shadow)\b|"
    r"\bLogin\.keychain(?:-db)?\b|\bCookies\.binarycookies\b",
    re.IGNORECASE,
)


def invisible_runs(text: str) -> list[tuple[int, str, str]]:
    """Return (index, char_name, kind) for characters the user cannot see."""
    out: list[tuple[int, str, str]] = []
    for idx, ch in enumerate(text):
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            out.append((idx, f"U+{cp:04X}", "unicode tag character"))
        elif cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E):
            out.append((idx, f"U+{cp:04X}", "zero-width character"))
        elif 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            out.append((idx, f"U+{cp:04X}", "bidirectional override"))
        elif 0xE000 <= cp <= 0xF8FF:
            out.append((idx, f"U+{cp:04X}", "private use character"))
        elif unicodedata.category(ch) == "Cf":
            out.append((idx, f"U+{cp:04X}", "format control character"))
    return out


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _excerpt(text: str, match: re.Match[str], width: int = 90) -> str:
    start = max(match.start() - 25, 0)
    end = min(match.end() + 45, len(text))
    frag = text[start:end].replace("\n", " ").replace("\r", " ")
    frag = re.sub(r"\s{2,}", " ", frag).strip()
    return ("..." if start else "") + frag[:width] + ("..." if end < len(text) else "")


def _scan_text(text: str, strict: bool) -> Iterable[tuple[Signal, re.Match[str]]]:
    for sig in SIGNALS:
        if strict and not sig.universal:
            continue
        for m in sig.pattern.finditer(text):
            yield sig, m


class Target(NamedTuple):
    kind: str          # tool | tool-param | skill | skill-frontmatter
    label: str         # server/tool or skill name, for the evidence line
    path: str          # file a reader should open
    anchor: int        # line in that file, 0 when unknown
    text: str
    strict: bool       # skip description-only signals (see module docstring)
    server: str | None


def _targets(ctx: AuditContext) -> list[Target]:
    """Everything carrying agent-facing text, anchored to a file a human can open."""
    # A tool description does not live in a file, so findings about it are
    # anchored to the config that declares the server. Anchoring to the
    # server *name* would produce a location nothing can open.
    declared: dict[str, tuple[str, int]] = {
        s.name: (s.source, s.line) for s in ctx.servers
    }

    out: list[Target] = []

    # Server instructions first: the spec says this MAY be added to the system
    # prompt, which outranks every tool description on the server. Treated
    # like a skill body -- imperative mood is its job, so only the universal
    # signals (concealment, override, exfiltration) apply.
    for server_name, text in ctx.instructions.items():
        if not text:
            continue
        path, line = declared.get(server_name, ("", 0))
        out.append(Target("server-instructions", f"{server_name} (instructions)",
                          path, line, text, True, server_name))

    for p in ctx.prompts:
        path, line = declared.get(p.server, ("", 0))
        if p.title:
            out.append(Target("prompt-title", f"{p.server}/{p.name}.title",
                              path, line, p.title, False, p.server))
        if p.description:
            out.append(Target("prompt", f"{p.server}/{p.name}", path, line,
                              p.description, False, p.server))
        for arg in p.arguments:
            desc = arg.get("description") if isinstance(arg, dict) else None
            if desc:
                out.append(Target("prompt-arg",
                                  f"{p.server}/{p.name}.{arg.get('name', '?')}",
                                  path, line, str(desc), False, p.server))

    for r in ctx.resources:
        path, line = declared.get(r.server, ("", 0))
        if r.title:
            out.append(Target("resource-title", f"{r.server}/{r.name or r.uri}.title",
                              path, line, r.title, False, r.server))
        if r.description:
            out.append(Target("resource", f"{r.server}/{r.name or r.uri}", path, line,
                              r.description, False, r.server))

    for t in ctx.tools:
        path, line = declared.get(t.server, ("", 0))
        # The display title is what the user reads before approving. It is
        # separate from the description and was previously unscanned.
        for label, text in (("title", t.title),
                            ("annotation-title", t.annotations.get("title"))):
            if isinstance(text, str) and text.strip():
                out.append(Target("tool-title", f"{t.server}/{t.name}.{label}",
                                  path, line, text, False, t.server))
        if t.description:
            out.append(Target("tool", f"{t.server}/{t.name}", path, line,
                              t.description, False, t.server))
        for prop, meta in (t.input_schema.get("properties") or {}).items():
            desc = (meta or {}).get("description") if isinstance(meta, dict) else None
            if desc:
                out.append(Target("tool-param", f"{t.server}/{t.name}.{prop}", path, line,
                                  str(desc), False, t.server))
    for sk in ctx.skills:
        out.append(Target("skill", sk.name, sk.path, 0, sk.body, True, None))
        desc = sk.frontmatter.get("description")
        if isinstance(desc, str) and desc:
            out.append(Target("skill-frontmatter", sk.name, sk.path, 0, desc, False, None))
    return out


def _locate(t: Target, text: str, offset: int, snippet: str) -> Location:
    """Anchor inside a file for skills; at the server declaration for tools."""
    line = t.anchor if t.kind.startswith("tool") else _line_of(text, offset)
    return Location(path=t.path, line=line, snippet=snippet)


@rule("MCPA010", "Agent-directed instruction in tool or skill text", Severity.CRITICAL)
def tool_poisoning(ctx: AuditContext) -> Iterable[Finding]:
    """Text aimed at steering the agent rather than describing the tool."""
    for tgt in _targets(ctx):
        for sig, m in _scan_text(tgt.text, tgt.strict):
            yield Finding(
                rule_id="MCPA010",
                title=f"Agent-directed instruction in {tgt.kind} text ({sig.category})",
                severity=sig.severity,
                location=_locate(tgt, tgt.text, m.start(), _excerpt(tgt.text, m)),
                evidence=f"{tgt.label}: {sig.note} -- matched {m.group(0)[:80]!r}",
                remediation=(
                    "Read the full text and confirm it is intentional. Tool descriptions are "
                    "injected into the model's context without the user ever seeing them, so "
                    "this text executes as instruction. If the server is third-party, treat "
                    "this as a compromise indicator and pin or remove the server."
                ),
                server=tgt.server,
                atlas=["AML.T0051.001", "AML.T0053"],
                cwe=["CWE-77"],
                confidence=sig.confidence,
                tags=["poisoning", sig.category],
            )


@rule("MCPA011", "Invisible characters in agent-facing text", Severity.HIGH)
def hidden_characters(ctx: AuditContext) -> Iterable[Finding]:
    """Text the model reads but a human reviewer cannot see."""
    for tgt in _targets(ctx):
        hits = invisible_runs(tgt.text)
        if not hits:
            continue
        kinds = sorted({k for _, _, k in hits})
        first_idx = hits[0][0]
        # Unicode tag characters have essentially one use in the wild.
        severity = (Severity.CRITICAL if any("tag" in k for k in kinds)
                    else Severity.HIGH if len(hits) > 4 else Severity.MEDIUM)
        yield Finding(
            rule_id="MCPA011",
            title="Invisible characters in agent-facing text",
            severity=severity,
            location=_locate(
                tgt, tgt.text, first_idx,
                tgt.text[max(first_idx - 20, 0):first_idx + 20].replace("\n", " "),
            ),
            evidence=(
                f"{tgt.label}: {len(hits)} invisible character(s) ({', '.join(kinds)}); "
                f"first at offset {first_idx} ({hits[0][1]})"
            ),
            remediation=(
                "Strip these characters and diff the result. The model reads them; a human "
                "reviewing the same text in an editor does not. Unicode tag characters in "
                "particular have no legitimate use in a tool description."
            ),
            server=tgt.server,
            atlas=["AML.T0051.001"],
            cwe=["CWE-451"],
            tags=["poisoning", "obfuscation"],
        )


@rule("MCPA012", "Sensitive credential path referenced in agent-facing text", Severity.HIGH)
def sensitive_path_reference(ctx: AuditContext) -> Iterable[Finding]:
    """A tool or skill points the agent at private keys or credential files."""
    for tgt in _targets(ctx):
        for m in SENSITIVE_PATHS.finditer(tgt.text):
            yield Finding(
                rule_id="MCPA012",
                title="Sensitive credential path referenced in agent-facing text",
                severity=Severity.HIGH,
                location=_locate(tgt, tgt.text, m.start(), _excerpt(tgt.text, m)),
                evidence=f"{tgt.label}: references {m.group(0)!r}",
                remediation=(
                    "Confirm the tool has a legitimate reason to name this path. Credential "
                    "paths in a description are how a poisoned tool gets the agent to read "
                    "secrets and pass them as an ordinary-looking argument."
                ),
                server=tgt.server,
                atlas=["AML.T0055", "AML.T0057"],
                cwe=["CWE-522"],
                confidence=0.75,
                tags=["poisoning", "credentials"],
            )


# Tool grants that hand a skill broad local execution.
_BROAD_GRANT = re.compile(r"^(?:Bash|Shell|Execute|Terminal|Run)(?:\(\s*(?:\*|\*\s*:\s*\*)?\s*\))?$",
                          re.IGNORECASE)
_DANGEROUS_GRANT = re.compile(
    r"Bash\(\s*(?:curl|wget|rm|chmod|chown|sudo|ssh|scp|nc|ncat|eval|base64|"
    r"powershell|iex)\b", re.IGNORECASE)


@rule("MCPA013", "Skill requests broad or dangerous tool permissions", Severity.MEDIUM)
def skill_permissions(ctx: AuditContext) -> Iterable[Finding]:
    """A skill's frontmatter grants unrestricted execution."""
    for sk in ctx.skills:
        # Shared with `inspect`, so the two cannot disagree about what a
        # grant list is.
        from ..parsers import normalize_tool_grants
        for grant in normalize_tool_grants(sk.frontmatter):
            grant = str(grant)
            broad = bool(_BROAD_GRANT.match(grant.strip()))
            dangerous = bool(_DANGEROUS_GRANT.search(grant))
            if not (broad or dangerous):
                continue
            yield Finding(
                rule_id="MCPA013",
                title="Skill requests broad or dangerous tool permissions",
                severity=Severity.HIGH if dangerous else Severity.MEDIUM,
                location=Location(path=sk.path, line=0, snippet=grant),
                evidence=f"skill {sk.name!r} declares allowed-tools entry {grant!r}",
                remediation=(
                    "Narrow the grant to the specific commands the skill needs, e.g. "
                    "Bash(git status:*). An unrestricted Bash grant means any instruction "
                    "that reaches this skill's context reaches your shell."
                ),
                atlas=["AML.T0011"],
                cwe=["CWE-269"],
                tags=["skills", "permissions"],
            )


# Severity for a model verdict. A classifier is a heuristic tier, so even a
# confident "malicious" never reaches the certainty of a deterministic match.
_VERDICT_SEVERITY = {
    ("malicious", True): Severity.CRITICAL,
    ("malicious", False): Severity.HIGH,
    ("suspicious", True): Severity.MEDIUM,
    ("suspicious", False): Severity.MEDIUM,
}


@rule("MCPA018", "Semantic classifier flagged agent-facing text", Severity.HIGH)
def llm_semantic(ctx: AuditContext) -> Iterable[Finding]:
    """Model-judged poisoning: paraphrase, logic drift, implicit exfiltration."""
    verdicts = ctx.llm_verdicts
    if not verdicts:
        return
    by_label = {t.label: t for t in _targets(ctx)}

    for label, v in sorted(verdicts.items()):
        verdict = getattr(v, "verdict", None)
        if verdict not in ("suspicious", "malicious"):
            continue
        tgt = by_label.get(label)
        confidence = min(float(getattr(v, "confidence", 0.5)), 0.95)
        severity = _VERDICT_SEVERITY[(verdict, confidence >= 0.8)]
        quote = (getattr(v, "quote", "") or "").strip()
        reasoning = (getattr(v, "reasoning", "") or "").strip()

        evidence = f"{label}: [{getattr(v, 'category', 'none')}] {reasoning}"
        if quote:
            evidence += f"\n      quoted: {quote[:160]!r}"

        yield Finding(
            rule_id="MCPA018",
            title=f"Semantic classifier flagged agent-facing text ({verdict})",
            severity=severity,
            location=(Location(path=tgt.path, line=tgt.anchor, snippet=quote[:200])
                      if tgt else Location(path="", line=0, snippet=quote[:200])),
            evidence=evidence,
            remediation=(
                "Read the full text yourself before acting. This finding comes from a "
                "model judging the text, not from a deterministic match, so treat it as "
                "a prompt to review rather than a verdict. If the text is legitimate, "
                "suppress MCPA018 for this server and record why."
            ),
            server=tgt.server if tgt else None,
            atlas=["AML.T0051.001", "AML.T0053"],
            cwe=["CWE-77"],
            confidence=confidence,
            tags=["poisoning", "llm", str(getattr(v, "category", "none"))],
        )


def classifier_targets(ctx: AuditContext, min_chars: int = 40) -> list[tuple[str, str]]:
    """(label, text) pairs worth sending to the semantic classifier.

    Tool descriptions come first: they are the surface nobody reviews, and if
    a run hits its item cap that is where the budget should go. Very short
    texts are skipped -- the blatant one-liners are already the regex tier's
    job, and the classifier earns its cost on nuance, which needs length.
    """
    tools, skills = [], []
    for t in _targets(ctx):
        text = t.text.strip()
        if len(text) < min_chars:
            continue
        (tools if t.kind.startswith("tool") else skills).append((t.label, text))
    return tools + skills
