"""Rules about credentials sitting in agent configuration.

MCP configs are ordinary JSON files in a home directory. They are not secret
stores, they are rarely mode 600, they get copied into dotfile repos, and
they are read by every agent on the machine. A live token in one is a real
exposure, not a style complaint.
"""

from __future__ import annotations

import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Iterable

from ..findings import Finding, Location, Severity
from ..secrets import SECRET_KEY_HINT, TOKEN_PATTERNS, preview
from .base import AuditContext, rule

# Values that look like secrets but are references or placeholders. These are
# the *correct* pattern, so flagging them would train people to ignore us.
_INDIRECTION = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_:.\-]*\}?$|\$\{(?:env|input|localEnv):")
_PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|your[_\-\s]|xxx+|placeholder|changeme|example|dummy|test|none|null|"
    r"insert[_\-]|todo|fixme|\.\.\.|\*+)",
    re.IGNORECASE,
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_indirect_or_placeholder(value: str) -> bool:
    v = value.strip()
    if not v or len(v) < 8:
        return True
    if _INDIRECTION.match(v) or "${" in v:
        return True
    if _PLACEHOLDER.match(v):
        return True
    if v.startswith("$") and v[1:].replace("_", "").isalnum():
        return True
    return False


def classify_secret(key: str, value: str) -> tuple[str, float] | None:
    """Return (description, confidence) if `value` looks like a live secret."""
    if is_indirect_or_placeholder(value):
        return None
    for label, pattern in TOKEN_PATTERNS:
        if pattern.search(value):
            return label, 1.0
    # Fall back to entropy, but only where the key name says "secret".
    if SECRET_KEY_HINT.search(key) and len(value) >= 20:
        ent = shannon_entropy(value)
        if ent >= 3.6 and re.search(r"[A-Za-z]", value) and re.search(r"[0-9]", value):
            return f"high-entropy value ({ent:.1f} bits/char) under a secret-shaped key", 0.6
    return None


@rule("MCPA005", "Credential stored in plaintext in agent config", Severity.HIGH)
def plaintext_credentials(ctx: AuditContext) -> Iterable[Finding]:
    """A live-looking token is sitting in a plaintext config file."""
    for s in ctx.servers:
        fields: list[tuple[str, str, str]] = []
        for k, v in s.env.items():
            fields.append(("env", k, v))
        for k, v in s.headers.items():
            fields.append(("headers", k, v))
        for idx, arg in enumerate(s.args):
            fields.append(("args", f"[{idx}]", arg))
        if s.url:
            fields.append(("url", "url", s.url))

        for where, key, value in fields:
            hit = classify_secret(key, value)
            if not hit:
                continue
            label, confidence = hit
            yield Finding(
                rule_id="MCPA005",
                title="Credential stored in plaintext in agent config",
                severity=Severity.HIGH if confidence >= 1.0 else Severity.MEDIUM,
                location=Location(path=s.source, line=s.line, snippet=f"{where}.{key}"),
                evidence=f"{label} in {where}.{key}: {preview(value)}",
                remediation=(
                    "Move the value into an environment variable or secret manager and "
                    "reference it indirectly (e.g. \"${env:GITHUB_TOKEN}\"). If this token "
                    "was ever committed or synced, rotate it -- the config file is not a "
                    "secret store and is read by every agent on the machine."
                ),
                server=s.name,
                atlas=["AML.T0055"],
                cwe=["CWE-798", "CWE-312"],
                confidence=confidence,
                tags=["credentials"],
            )


@rule("MCPA006", "Config file containing credentials is readable by other users", Severity.MEDIUM)
def config_permissions(ctx: AuditContext) -> Iterable[Finding]:
    """A config holding a secret is group- or world-readable."""
    if sys.platform == "win32":
        return  # POSIX mode bits are not meaningful here; ACL checks are out of scope.

    with_secrets: set[str] = set()
    for s in ctx.servers:
        pairs = list(s.env.items()) + list(s.headers.items())
        if any(classify_secret(k, v) for k, v in pairs):
            with_secrets.add(s.source)

    for path_str in sorted(with_secrets):
        try:
            mode = os.stat(path_str).st_mode
        except OSError:
            continue
        exposed = mode & (stat.S_IRGRP | stat.S_IROTH)
        if not exposed:
            continue
        yield Finding(
            rule_id="MCPA006",
            title="Config file containing credentials is readable by other users",
            severity=Severity.MEDIUM,
            location=Location(path=path_str, line=0),
            evidence=f"mode {stat.filemode(mode)} on a config file that contains a credential",
            remediation=f"chmod 600 {Path(path_str).name} (or move the secret out of the file).",
            atlas=["AML.T0055"],
            cwe=["CWE-732"],
            tags=["credentials", "filesystem"],
        )
