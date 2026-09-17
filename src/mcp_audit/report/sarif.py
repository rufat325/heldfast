"""SARIF 2.1.0 output.

This is the format that makes the tool portable: GitHub code scanning, Azure
DevOps, DefectDojo and most enterprise aggregators ingest SARIF directly. It
is also the difference between "a CLI printed some warnings" and an artifact
that can be attached to an audit -- which matters more than the terminal
output for anyone who has to show their work.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePath

from ..findings import Finding, Severity, atlas_title
from ..rules.base import all_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/rufat325/mcp-audit"


def _uri(path: str, base: Path | None) -> tuple[str, str | None]:
    """Return (uri, uriBaseId). Relative when inside `base`, else absolute file URI."""
    if not path:
        return "unknown", None
    p = Path(path)
    if base is not None:
        try:
            rel = p.resolve().relative_to(base.resolve())
            return PurePath(rel).as_posix(), "%SRCROOT%"
        except (ValueError, OSError):
            pass
    try:
        return p.resolve().as_uri(), None
    except (ValueError, OSError):
        return PurePath(path).as_posix(), None


def _partial_fingerprint(f: Finding) -> str:
    """Stable across line moves so GitHub can track a finding over time."""
    basis = "|".join([f.rule_id, f.server or "", PurePath(f.location.path).name, f.evidence])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def _rule_descriptors() -> tuple[list[dict], dict[str, int]]:
    descriptors: list[dict] = []
    index: dict[str, int] = {}
    for i, r in enumerate(all_rules()):
        index[r.id] = i
        descriptors.append(
            {
                "id": r.id,
                "name": "".join(w.capitalize() for w in r.name.replace("-", " ").split() if w.isalnum() or w.isalpha()),
                "shortDescription": {"text": r.name},
                "fullDescription": {"text": r.description or r.name},
                "defaultConfiguration": {"level": r.default_severity.sarif_level},
                "properties": {
                    "security-severity": _security_severity(r.default_severity),
                    "tags": ["security", "mcp", "ai-agent"],
                },
            }
        )
    return descriptors, index


def _security_severity(severity: Severity) -> str:
    """GitHub sorts by this numeric CVSS-like band."""
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "7.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[severity]


def render_sarif(findings: list[Finding], *, base: Path | None = None,
                 version: str = "0.1.0") -> str:
    descriptors, index = _rule_descriptors()
    results = []
    for f in findings:
        uri, base_id = _uri(f.location.path, base)
        artifact: dict = {"uri": uri}
        if base_id:
            artifact["uriBaseId"] = base_id
        region: dict = {"startLine": max(f.location.line, 1)}
        if f.location.snippet:
            region["snippet"] = {"text": f.location.snippet}

        message = f.evidence
        if f.server:
            message = f"[{f.server}] {message}"
        message = f"{message}\n\nRemediation: {f.remediation}"

        result: dict = {
            "ruleId": f.rule_id,
            "level": f.severity.sarif_level,
            "message": {"text": message},
            "locations": [
                {"physicalLocation": {"artifactLocation": artifact, "region": region}}
            ],
            "partialFingerprints": {"mcpAudit/v1": _partial_fingerprint(f)},
            "properties": {
                "severity": f.severity.label,
                "security-severity": _security_severity(f.severity),
                "confidence": f.confidence,
                "tags": list(f.tags),
                "atlas": [{"id": a, "title": atlas_title(a)} for a in f.atlas],
                "cwe": list(f.cwe),
            },
        }
        if f.rule_id in index:
            result["ruleIndex"] = index[f.rule_id]
        results.append(result)

    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit",
                        "version": version,
                        "informationUri": INFORMATION_URI,
                        "rules": descriptors,
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
            }
        ],
    }
    if base is not None:
        doc["runs"][0]["originalUriBaseIds"] = {
            "%SRCROOT%": {"uri": base.resolve().as_uri().rstrip("/") + "/"}
        }
    if os.environ.get("GITHUB_SHA"):
        doc["runs"][0]["versionControlProvenance"] = [
            {
                "repositoryUri": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', '')}",
                "revisionId": os.environ["GITHUB_SHA"],
            }
        ]
    return json.dumps(doc, indent=2) + "\n"
