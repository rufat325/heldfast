"""Credential patterns, shared by the detection rule and the output scrubber.

These live outside the rules package because two very different callers need
them: `rules.credentials` uses them to *find* secrets, and `findings` uses
them to make sure no secret ever reaches the report. A scanner that prints
the tokens it discovers into a CI log has manufactured the exposure it was
hired to detect, so the scrubbing side is not optional.
"""

from __future__ import annotations

import re

# High-precision provider token shapes. Each is a strong signal on its own,
# so neither caller needs an entropy heuristic to act on a match.
TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("GitHub personal access token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{60,}")),
    ("GitLab personal access token", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Slack app token", re.compile(r"xapp-[0-9]-[A-Za-z0-9\-]{10,}")),
    ("AWS access key id", re.compile(r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Google OAuth token", re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}")),
    ("Stripe secret key", re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{20,}")),
    ("SendGrid API key", re.compile(r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")),
    ("npm access token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("DigitalOcean token", re.compile(r"dop_v1_[a-f0-9]{64}")),
    ("Hugging Face token", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(
        r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]

# Keys whose value is expected to be a credential.
SECRET_KEY_HINT = re.compile(
    r"(?:^|_|\b)(?:token|secret|password|passwd|pwd|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|credential|auth|bearer|session|cookie|dsn)(?:$|_|\b)",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Replace any recognizable credential in `text` with a labeled marker."""
    if not text:
        return text
    for label, pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda m, _l=label: f"[REDACTED {_l}]", text)
    return text


def preview(value: str) -> str:
    """A short, non-recoverable rendering of a secret, for evidence strings."""
    v = value.strip()
    if len(v) <= 12:
        return v[:2] + "*" * max(len(v) - 2, 0)
    return f"{v[:6]}...{v[-2:]} ({len(v)} chars)"
