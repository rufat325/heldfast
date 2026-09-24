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


# Placeholder markers anywhere in the value, not only at the start. Real
# configs write "0x<your-wallet-private-key>" and "0xYOUR_PRIVATE_KEY_HERE",
# both of which the start-anchored check missed and reported as live secrets.
# A prefix like "0x" or "sk-" in front of the placeholder is common enough
# that anchoring to position 0 is simply the wrong test.
_BRACKETED = re.compile(r"<[^<>]{2,}>")

_ANYWHERE_PLACEHOLDER = re.compile(
    r"<[^<>]{2,}>"                       # <your-key>
    r"|your[_\-. ]"                      # YOUR_PRIVATE_KEY
    r"|[_\-. ]here\b"                    # ..._KEY_HERE
    r"|replace[_\-. ]?(?:me|this|with)"  # REPLACE_ME
    r"|paste[_\-. ]"                     # PASTE_TOKEN
    r"|placeholder|changeme|example|xxxx",
    re.IGNORECASE,
)


def is_indirect_or_placeholder(value: str) -> bool:
    v = value.strip()
    if not v or len(v) < 8:
        return True
    if _INDIRECTION.match(v) or "${" in v:
        return True
    if _PLACEHOLDER.match(v) or _ANYWHERE_PLACEHOLDER.search(v):
        return True
    if v.startswith("$") and v[1:].replace("_", "").isalnum():
        return True
    return False


def classify_secret(key: str, value: str) -> tuple[str, float] | None:
    """Return (description, confidence) if `value` looks like a live secret.

    Order matters. The provider token shapes are high-precision structural
    matches -- `ghp_` plus 36 base62 characters is not something a human types
    by accident -- so they are checked first and are NOT second-guessed by the
    placeholder word list. Doing it the other way round meant a value
    containing "example" or "xxxx" suppressed a real key match, and a missed
    credential is a far worse outcome for this tool than a flagged dummy one.

    The fuzzy entropy fallback is the opposite case: it has no structure to
    rely on, so it gets the full placeholder filtering.
    """
    # Coerced rather than assumed. The config parser turns every env value
    # into a string, so nothing in the CLI reaches here with anything else --
    # but this is a library function a later rule may call with unparsed
    # input, and a scan that raises is worse than one that reports nothing.
    v = str(value or "").strip()
    if not v:
        return None

    # Indirection is never a secret regardless of what it wraps.
    if _INDIRECTION.match(v) or "${" in v:
        return None

    for label, pattern in TOKEN_PATTERNS:
        m = pattern.search(v)
        if not m:
            continue
        # One narrow exception: a token shape sitting inside angle brackets is
        # documentation, e.g. "<ghp_your_token_here>".
        if _BRACKETED.search(v):
            return None
        return label, 1.0

    # Fall back to entropy, but only where the key name says "secret".
    if is_indirect_or_placeholder(v):
        return None
    if SECRET_KEY_HINT.search(key) and len(v) >= 20:
        ent = shannon_entropy(v)
        if ent >= 3.6 and re.search(r"[A-Za-z]", v) and re.search(r"[0-9]", v):
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
                server=s.identity(),
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
