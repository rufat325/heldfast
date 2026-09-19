"""What the approval dialog shows, as opposed to what the model reads.

Everything else in this package screens text bound for the model. This screens
the other direction: the picture rendered beside a tool's name in the dialog
where a person decides whether to allow the call.

Icons arrived with the 2025-11-25 revision and carry a warning in the spec's
own type -- consumers "SHOULD ensure icon URLs come from a trusted domain and
SHOULD take appropriate precautions when consuming SVGs (which can contain
script)". A client fetches every one of them to render it, which makes the
`src` three things at once: a request the server observes, content the client
parses, and the image a person reads the tool by.

They were found by enumerating the spec's own definition types against what
this tool parses, the same way `outputSchema` was. FastMCP supports them on
tools, prompts and resources across 72 files, so this is live rather than
speculative.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..findings import Finding, Location, Severity
from .base import AuditContext, rule
from .transport import DANGEROUS_SCHEMES, SAFE_SCHEMES

# `data:` is on the dangerous list for server URLs and is *ordinary* for an
# icon -- inlining a small PNG avoids a fetch, which is the better privacy
# answer. So it is judged on what it inlines rather than on being data:.
_SVG = re.compile(r"image/svg|\.svg(?:$|[?#])", re.IGNORECASE)

# A script-bearing SVG is the case the spec warns about. Matching on the
# payload rather than the mime type, because the mime type is the server's
# claim about its own content.
_SVG_SCRIPT = re.compile(
    r"<\s*script|on(?:load|error|click|mouseover)\s*=|javascript:|<\s*foreignObject",
    re.IGNORECASE)


def _iter_icons(ctx: AuditContext) -> Iterable[tuple[str, str, Any, dict]]:
    """(kind, label, owner, icon) for every declared icon."""
    for t in ctx.tools:
        for icon in t.icons or []:
            yield "tool", f"{t.server}/{t.name}", t, icon
    for p in ctx.prompts:
        for icon in p.icons or []:
            yield "prompt", f"{p.server}/{p.name}", p, icon
    for r in ctx.resources:
        for icon in r.icons or []:
            yield "resource", f"{r.server}/{r.name or r.uri}", r, icon


def _decoded(src: str) -> str:
    """The inline payload of a data: URI, best effort, for inspection only."""
    if not src.lower().startswith("data:"):
        return ""
    _, _, rest = src.partition(",")
    if ";base64" in src.split(",", 1)[0].lower():
        import base64
        try:
            return base64.b64decode(rest + "===", validate=False).decode(
                "utf-8", "replace")
        except (ValueError, TypeError):
            return ""
    from urllib.parse import unquote
    return unquote(rest)


def _location(owner: Any, snippet: str) -> Location:
    return Location(path=getattr(owner, "source", "") or "<probed>",
                    line=0, snippet=snippet[:200])


@rule("MCPA033", "Icon source is unsafe for a client to fetch or render",
      Severity.HIGH)
def unsafe_icon_source(ctx: AuditContext) -> Iterable[Finding]:
    """An icon a client will fetch and draw next to a tool it is asking about.

    Three shapes, and only three, because everything else about an icon is
    ordinary. A remote https icon is not reported: that is what icons are.
    """
    for kind, label, owner, icon in _iter_icons(ctx):
        src = str(icon.get("src") or "").strip()
        if not src:
            continue
        scheme = urlsplit(src).scheme.lower()
        mime = str(icon.get("mimeType") or icon.get("mime_type") or "")
        server = getattr(owner, "server", None)

        # 1. A scheme that is not a way to fetch a picture.
        if scheme and scheme not in SAFE_SCHEMES and scheme != "data":
            reason = DANGEROUS_SCHEMES.get(scheme, "is not a way to fetch an image")
            yield Finding(
                rule_id="MCPA033",
                title="Icon source uses a dangerous scheme",
                severity=Severity.CRITICAL,
                location=_location(owner, src),
                evidence=(
                    f"{kind} {label} declares an icon with a {scheme}: source -- "
                    f"{reason}. The client fetches this to render the approval dialog."
                ),
                remediation=(
                    "Serve the icon over https, or inline a small raster image as a "
                    "data: URI. A client that resolves an arbitrary scheme to draw an "
                    "icon is running the server's choice of handler."
                ),
                server=server,
                atlas=["AML.T0011"],
                cwe=["CWE-79", "CWE-749"],
                tags=["presentation", "icon", "scheme"],
            )
            continue

        # 2. An SVG carrying script, which is the case the spec calls out.
        payload = _decoded(src)
        looks_svg = bool(_SVG.search(src) or _SVG.search(mime)
                         or "<svg" in payload.lower())
        if looks_svg and _SVG_SCRIPT.search(payload):
            yield Finding(
                rule_id="MCPA033",
                title="Icon inlines an SVG containing script",
                severity=Severity.CRITICAL,
                location=_location(owner, src),
                evidence=(
                    f"{kind} {label} inlines an SVG icon containing script. The "
                    f"protocol's own guidance says consumers should take precautions "
                    f"with SVGs because they can contain script."
                ),
                remediation=(
                    "Use a raster icon, or an SVG with no script, no event handlers "
                    "and no foreignObject. A client that renders this inline gives the "
                    "server execution in the surface the user approves from."
                ),
                server=server,
                atlas=["AML.T0011"],
                cwe=["CWE-79"],
                tags=["presentation", "icon", "svg"],
            )
            continue

        # 3. Plain http. The dialog is where a person decides to trust a call;
        # fetching the picture for it over a channel anyone on the path can
        # rewrite is the one network property worth naming here.
        if scheme == "http":
            yield Finding(
                rule_id="MCPA033",
                title="Icon is fetched over plaintext http",
                severity=Severity.MEDIUM,
                location=_location(owner, src),
                evidence=(
                    f"{kind} {label} declares an icon served over http://. Anyone on "
                    f"the path can replace the image shown in the approval dialog."
                ),
                remediation="Serve the icon over https.",
                server=server,
                atlas=["AML.T0011"],
                cwe=["CWE-319"],
                confidence=0.9,
                tags=["presentation", "icon", "transport"],
            )
