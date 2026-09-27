"""Machine-readable JSON output."""

from __future__ import annotations

import json
import platform
import time
from typing import Iterable

from .. import __version__
from ..findings import Finding, Severity


def render_json(
    findings: list[Finding],
    *,
    scanned_configs: int = 0,
    scanned_servers: int = 0,
    scanned_tools: int = 0,
    scanned_skills: int = 0,
    errors: Iterable[str] = (),
    lock_present: bool = False,
    probed: bool = False,
    version: str = __version__,
    suppressed: list | None = None,
    probe: list | None = None,
) -> str:
    counts = {s.label: sum(1 for f in findings if f.severity == s) for s in Severity}
    doc = {
        "tool": "heldfast",
        "version": version,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "scan": {
            "configs": scanned_configs,
            "servers": scanned_servers,
            "tools": scanned_tools,
            "skills": scanned_skills,
            "probed": probed,
            "lock_present": lock_present,
        },
        "summary": {
            "total": len(findings),
            "suppressed": len(suppressed or []),
            "by_severity": counts,
            "highest": max((f.severity for f in findings), default=Severity.INFO).label,
        },
        "errors": list(errors),
        # Per server: whether its tool definitions were read ("read"), not
        # asked for ("not read") or asked for and not answered ("could not
        # read"). "No findings" covers only the first.
        "probe": list(probe or []),
        "suppressed": [
            {**f.to_dict(), "suppressed_by": {"rule": r.rule_id, "server": r.server,
                                              "line": r.source_line, "reason": r.reason}}
            for f, r in (suppressed or [])
        ],
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2) + "\n"
