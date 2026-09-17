"""Finding model, severity ordering, and MITRE ATLAS mapping.

Every rule emits Findings. Everything downstream (terminal, JSON, SARIF)
consumes them, so this module is the one place that defines what a result
*is*. Keep it dependency-free and boring.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any

from .secrets import redact


class Severity(enum.IntEnum):
    """Ordered so that `max()` and sorting behave the obvious way."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; expected one of "
                + ", ".join(s.label for s in cls)
            ) from None

    # SARIF only has error/warning/note, so collapse into that.
    @property
    def sarif_level(self) -> str:
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


@dataclass(frozen=True)
class Location:
    """Where a finding lives. `line` is 1-indexed; 0 means 'file-level'."""

    path: str
    line: int = 0
    snippet: str = ""

    def __str__(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    location: Location
    evidence: str
    remediation: str
    server: str | None = None
    atlas: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    # Rules that use the optional LLM classifier set this below 1.0 so
    # consumers can filter out model-derived guesses if they want to.
    confidence: float = 1.0
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Single chokepoint: every Finding is scrubbed at construction, so a
        # rule author cannot leak a credential into a report by forgetting to.
        # Rules that intentionally show a truncated preview are unaffected,
        # because a truncated token no longer matches a full token pattern.
        self.evidence = redact(self.evidence)
        if self.location.snippet:
            self.location = replace(self.location, snippet=redact(self.location.snippet))

    def key(self) -> tuple:
        """Identity for dedup and for baseline suppression."""
        return (self.rule_id, self.server or "", self.location.path,
                self.location.line, self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "server": self.server,
            "path": self.location.path,
            "line": self.location.line,
            "snippet": self.location.snippet,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "atlas": list(self.atlas),
            "cwe": list(self.cwe),
            "confidence": self.confidence,
            "tags": list(self.tags),
        }


# MITRE ATLAS technique titles for the IDs the rules reference. Mapping
# findings to ATLAS is what lets a report drop into an enterprise threat
# model instead of being one more bespoke scanner output.
ATLAS_TITLES: dict[str, str] = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0010.001": "AI Supply Chain Compromise: AI Software",
    "AML.T0010.003": "AI Supply Chain Compromise: Model",
    "AML.T0011": "User Execution",
    "AML.T0011.001": "User Execution: Unsafe AI-Generated Code",
    "AML.T0012": "Valid Accounts",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0029": "Denial of AI Service",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0057": "LLM Data Leakage",
}


def atlas_title(technique_id: str) -> str:
    return ATLAS_TITLES.get(technique_id, technique_id)
