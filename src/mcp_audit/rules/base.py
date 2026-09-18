"""Rule registry and the context object every rule receives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..findings import Finding, Severity
from ..model import PromptSpec, ResourceSpec, ServerSpec, SkillSpec, ToolSpec


@dataclass
class AuditContext:
    servers: list[ServerSpec] = field(default_factory=list)
    skills: list[SkillSpec] = field(default_factory=list)
    tools: list[ToolSpec] = field(default_factory=list)
    prompts: list[PromptSpec] = field(default_factory=list)
    resources: list[ResourceSpec] = field(default_factory=list)
    # server name -> the `instructions` string from its initialize response.
    # The spec permits a client to paste this into the system prompt, so it is
    # the highest-privilege text a server controls.
    instructions: dict[str, str] = field(default_factory=dict)
    # Shell-injection flows found by reading the servers' own source.
    # Populated only when a path was scanned, never by the user-config sweep.
    source_flows: list = field(default_factory=list)
    config_errors: list[str] = field(default_factory=list)
    # Populated by the lockfile stage; rules for rug-pull detection read it.
    lock: dict[str, Any] = field(default_factory=dict)
    # Populated by the optional --llm stage, keyed by target label. Empty
    # unless the classifier ran, so MCPA018 stays silent by default.
    llm_verdicts: dict[str, Any] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)


RuleFn = Callable[[AuditContext], Iterable[Finding]]


@dataclass
class Rule:
    id: str
    name: str
    default_severity: Severity
    fn: RuleFn
    description: str = ""


_REGISTRY: dict[str, Rule] = {}


def rule(rule_id: str, name: str, severity: Severity, description: str = ""):
    """Decorator registering a rule function."""

    def wrap(fn: RuleFn) -> RuleFn:
        if rule_id in _REGISTRY:
            raise RuntimeError(f"duplicate rule id {rule_id}")
        _REGISTRY[rule_id] = Rule(
            id=rule_id, name=name, default_severity=severity, fn=fn,
            description=description or (fn.__doc__ or "").strip().splitlines()[0]
            if (fn.__doc__ or "").strip() else description,
        )
        return fn

    return wrap


def all_rules() -> list[Rule]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def get_rule(rule_id: str) -> Rule | None:
    return _REGISTRY.get(rule_id)


def run_rules(ctx: AuditContext, enabled: set[str] | None = None,
              disabled: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for r in all_rules():
        if enabled is not None and r.id not in enabled:
            continue
        if disabled and r.id in disabled:
            continue
        findings.extend(r.fn(ctx))
    # Deduplicate, then sort worst-first with a stable secondary ordering.
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        k = f.key()
        if k in seen:
            continue
        seen.add(k)
        unique.append(f)
    unique.sort(key=lambda f: (-int(f.severity), f.rule_id, f.location.path, f.location.line))
    return unique
