"""Named default-block classes on tool results.

`scan_untrusted_text` is best-effort fencing: a search hit that says
"ignore previous instructions" is data, so the default is to wrap it
rather than drop it. These three are different. They are short, they have
stable IDs, and when they match the text is withheld even under
`--result-policy annotate`.

    RS-ANSI        a CSI/OSC sequence that rewrites a terminal
    RS-SECRET      a high-precision credential shape echoed back
    RS-EXFIL-HOST  a well-known collection host in the body

A miss on the English-injection pile is not a CVE. A miss here is.
"""

from __future__ import annotations

import re

from .secrets import TOKEN_PATTERNS

RS_ANSI = "RS-ANSI"
RS_SECRET = "RS-SECRET"
RS_EXFIL = "RS-EXFIL-HOST"

# CSI (`ESC [ ... letter`) and OSC (`ESC ] ... BEL` / ST). The erase
# sequences (`2K`, `1A`) are the ones that delete a line of the report
# above the result; matching the whole CSI family is cheaper than
# enumerating verbs, and ordinary tool output does not contain ESC.
_CSI = re.compile(
    r"(?:\x1b|\x9b)\[[0-9;?]*[ -/]*[@-~]"
    r"|\x1b\].*?(?:\x07|\x1b\\)",
)

# Hosts whose only job is to collect whatever is posted to them.
# Suffix-matched so `foo.webhook.site` counts and `notwebhook.site.example`
# does not.
EXFIL_HOSTS = (
    "webhook.site",
    "requestbin.com",
    "requestbin.net",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "pastebin.com",
    "transfer.sh",
    "pipedream.net",
    "beeceptor.com",
    "smee.io",
    "burpcollaborator.net",
)


# One host, with optional subdomains, not glued to a longer label.
#
# The boundary used to be an allowlist of the character before the host --
# `./:@ ` -- which is not how hostnames end. Six ordinary spellings walked
# past it: a newline before the host (the common case in real tool output),
# a quote, an `=`, a `(`, a `,`, a tab. This asks the question the other way
# round, which is the only way that is exhaustive: the character before must
# not be part of a label, and neither must the character after.
#
# A leading `.` is still a match, because `foo.webhook.site` is the host's own
# subdomain and the docstring has always said so. A trailing `.` is not,
# because `webhook.site.example` is somebody else's domain.
_EXFIL_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)*(?:"
    + "|".join(re.escape(host) for host in EXFIL_HOSTS)
    + r")(?![A-Za-z0-9.-])",
    re.IGNORECASE,
)


def _has_exfil_host(text: str) -> bool:
    return bool(_EXFIL_RE.search(text))


def classify(text: str) -> list[str]:
    """Stable IDs for default-block result classes. Empty means pass."""
    if not text:
        return []
    hits: list[str] = []
    if _CSI.search(text):
        hits.append(RS_ANSI)
    for _label, pattern in TOKEN_PATTERNS:
        if pattern.search(text):
            hits.append(RS_SECRET)
            break
    if _has_exfil_host(text):
        hits.append(RS_EXFIL)
    return hits


def withheld(ids: list[str]) -> str:
    joined = ", ".join(ids)
    return (
        "[WITHHELD BY mcp-pin] This tool returned content matching "
        f"{joined}. It has been withheld rather than shown to the model."
    )
