"""The one opener every outbound request goes through, and why not `urlopen`.

`urllib.request.urlopen` uses the default opener, and the default opener
follows redirects with the original headers attached. `HTTPRedirectHandler`
strips exactly two of them -- `content-length` and `content-type` -- so an
`Authorization`, `X-Api-Key` or `X-Auth-Token` header configured for one
backend is handed to whatever host a `Location:` names. Those are the same
header names `rules/transport.py` already recognises as credentials, which is
the whole reason they are worth guarding here.

Two things were wrong with going through the default opener, and they compound:

**A redirect could downgrade the transport.** `gateway` refuses to front a
non-loopback server over cleartext `http://`, but it checks the URL it was
configured with. A backend on `https://` answering `302 Location: http://...`
moved every later call onto cleartext, and T-HOSTED-TLS said it could not.
The scheme check therefore has to run again on each hop, not once at startup.

**A redirect could move the credential.** `https://backend.example/mcp`
answering `302 Location: http://attacker.example/` collected the bearer token
on the way past. Reproduced against two local servers before this existed.

So: same-origin hops keep their headers, cross-origin hops lose the credential
ones, and any hop that lands on cleartext without being loopback is refused
outright rather than followed. Refusing the *hop* rather than the whole
redirect is deliberate -- the MCP Streamable HTTP spec has clients follow
redirects, so a client that refuses all of them is a client that does not work.

Nothing here is a defence against a backend that is itself hostile. It already
has whatever was sent to it. This stops a backend handing that to a third
party, and stops a redirect quietly undoing a guarantee made at startup.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

# Requests that carry one of these must not cross an origin boundary while
# still carrying it. Kept in step with AUTH_HEADERS in rules/transport.py;
# that one decides whether a *config* holds a credential, this one decides
# whether a *request* does.
CREDENTIAL_HEADERS = frozenset({
    "authorization", "proxy-authorization", "x-api-key", "api-key",
    "x-auth-token", "x-access-token", "x-goog-api-key", "authentication",
    "cookie",
})

# Schemes a redirect may land on at all. The base handler also permits `ftp`,
# which has no business answering for an MCP backend.
ALLOWED_SCHEMES = frozenset({"http", "https"})


def origin_of(url: str) -> tuple[str, str, int | None]:
    """(scheme, host, port), which is what "same origin" means here."""
    try:
        parts = urlsplit(url)
        return (parts.scheme.lower(), (parts.hostname or "").lower(), parts.port)
    except ValueError:
        return ("", "", None)


def transport_refusal(url: str) -> str | None:
    """Why this URL must not be fetched, or None.

    The same rule `gateway` applies to a configured backend, applied again to
    every redirect target: cleartext is for loopback only.
    """
    from .rules.transport import is_loopback

    scheme, host, _ = origin_of(url)
    if scheme not in ALLOWED_SCHEMES:
        return f"redirect to a {scheme or 'schemeless'} URL is not followed"
    if scheme != "https" and not is_loopback(host):
        return ("redirect would move this request onto cleartext http for a "
                "non-loopback host; see MCPA007")
    return None


class GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows redirects, but not off a cliff."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Any:
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        refusal = transport_refusal(newurl)
        if refusal:
            raise urllib.error.HTTPError(newurl, code, refusal, headers, fp)
        if origin_of(req.full_url) != origin_of(newurl):
            # Header keys arrive capitalised by Request.add_header, so the
            # comparison is on the lowered name rather than the stored one.
            new.headers = {key: value for key, value in new.headers.items()
                           if key.lower() not in CREDENTIAL_HEADERS}
        return new


def build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(GuardedRedirectHandler)


_OPENER = build_opener()


def urlopen(req: Any, timeout: float) -> Any:
    """`urlopen`, through the opener above. Same call, different redirects."""
    return _OPENER.open(req, timeout=timeout)
