"""Rules about how the client reaches a remote server, and what it exposes.

Unauthenticated, internet-reachable MCP servers are the most consistently
reported exposure class in this ecosystem, and they are almost always an
accident of defaults rather than a decision anyone made.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable
from urllib.parse import parse_qs, urlsplit

from ..findings import Finding, Location, Severity
from .base import AuditContext, rule

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0000:0000:0000:0000:0000:0000:0000:0001",
                  "host.docker.internal"}

# Header names that carry an actual credential.
AUTH_HEADERS = re.compile(
    r"^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|"
    r"x-access-token|x-goog-api-key|authentication)$",
    re.IGNORECASE,
)

# Query parameters that carry a credential in the URL itself.
AUTH_QUERY_PARAMS = {"token", "api_key", "apikey", "access_token", "key", "auth", "secret"}

# Config keys that indicate an auth flow is configured out of band.
AUTH_CONFIG_KEYS = {"oauth", "auth", "authProvider", "authorization", "credentials",
                    "clientId", "client_id", "apiKey", "bearer", "token"}

BIND_ALL = re.compile(r"(?:^|[=\s])(?:0\.0\.0\.0|\[::\]|::)(?::\d+)?(?:$|[\s,])")


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def is_loopback(host: str) -> bool:
    if not host:
        return False
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host.endswith((".local", ".internal", ".lan", ".home", ".corp")):
            return True
        # A single-label hostname ("homeassistant", "nas") has no public DNS
        # meaning -- it can only resolve on a local network. Real configs use
        # these constantly, and treating them as internet-facing overstated
        # the severity of every finding about them.
        return "." not in host
    return ip.is_private or ip.is_link_local


def _remote_servers(ctx: AuditContext):
    return [s for s in ctx.servers if s.is_remote and s.url and not s.disabled]


@rule("MCPA007", "Remote server reached over cleartext HTTP", Severity.HIGH)
def cleartext_transport(ctx: AuditContext) -> Iterable[Finding]:
    """Tool traffic and any bearer token travel unencrypted."""
    for s in _remote_servers(ctx):
        scheme = urlsplit(s.url).scheme.lower()
        host = _host_of(s.url)
        if scheme != "http" or is_loopback(host):
            continue
        carries_token = any(AUTH_HEADERS.match(k) for k in s.headers)
        # Cleartext on a LAN host is a real weakness but not the same exposure
        # as cleartext across the internet, so it does not reach CRITICAL.
        if is_private(host):
            severity = Severity.MEDIUM if not carries_token else Severity.HIGH
        else:
            severity = Severity.CRITICAL if carries_token else Severity.HIGH
        yield Finding(
            rule_id="MCPA007",
            title="Remote server reached over cleartext HTTP",
            severity=severity,
            location=Location(path=s.source, line=s.line, snippet=s.url),
            evidence=(
                f"{s.url} uses http:// to a non-loopback host"
                + (" while sending an Authorization-style header" if carries_token else "")
            ),
            remediation=(
                "Use https://. Every tool call, argument, and result on this connection is "
                "readable and modifiable in transit -- and a tampered tool *description* "
                "rewrites what the agent believes it is allowed to do."
            ),
            server=s.name,
            atlas=["AML.T0051.001"],
            cwe=["CWE-319"],
            tags=["transport"],
        )


@rule("MCPA008", "Remote server configured without authentication", Severity.MEDIUM)
def unauthenticated_remote(ctx: AuditContext) -> Iterable[Finding]:
    """No credential is configured for a non-local MCP endpoint."""
    for s in _remote_servers(ctx):
        host = _host_of(s.url)
        if is_loopback(host):
            continue
        if any(AUTH_HEADERS.match(k) for k in s.headers):
            continue
        query = parse_qs(urlsplit(s.url).query)
        if any(p in AUTH_QUERY_PARAMS for p in query):
            continue
        if any(k in s.raw for k in AUTH_CONFIG_KEYS):
            continue
        yield Finding(
            rule_id="MCPA008",
            title="Remote server configured without authentication",
            # Always MEDIUM. Measured across 83 real-world configs, this rule's
            # hits were dominated by public read-only endpoints that are
            # unauthenticated on purpose -- including the one in Anthropic's own
            # servers repo. The scanner cannot see what an endpoint exposes, so
            # it should prompt a look rather than assert a problem.
            severity=Severity.MEDIUM,
            location=Location(path=s.source, line=s.line, snippet=s.url),
            evidence=f"no auth header, auth query parameter, or auth block configured for {s.url}",
            remediation=(
                "Confirm the endpoint authenticates callers. If it negotiates OAuth at "
                "connect time this finding is expected and can be suppressed; if it does "
                "not, anyone who can reach the URL can drive the same tools your agent can."
            ),
            server=s.name,
            atlas=["AML.T0012"],
            cwe=["CWE-306"],
            confidence=0.7,
            tags=["transport", "exposure"],
        )


@rule("MCPA009", "Server is bound to all network interfaces", Severity.HIGH)
def bind_all_interfaces(ctx: AuditContext) -> Iterable[Finding]:
    """A locally launched server is listening beyond loopback."""
    for s in ctx.servers:
        if s.disabled:
            continue
        # Search args and env separately, and never put an env *value* into the
        # evidence string. A scanner that prints the secrets it finds into CI
        # logs has created the exposure it was hired to detect.
        in_args = BIND_ALL.search(" ".join(s.args))
        env_hits = [k for k, v in s.env.items() if BIND_ALL.search(v)]
        if not in_args and not env_hits:
            continue
        if in_args:
            where = f"args: {' '.join(s.args)[:180]}"
        else:
            where = f"env: {', '.join(sorted(env_hits))}"
        yield Finding(
            rule_id="MCPA009",
            title="Server is bound to all network interfaces",
            severity=Severity.HIGH,
            location=Location(path=s.source, line=s.line, snippet=s.command_line[:200]),
            evidence=f"listen address 0.0.0.0 / :: in server configuration -- {where}",
            remediation=(
                "Bind to 127.0.0.1 unless the server is deliberately published. An MCP "
                "server on 0.0.0.0 is reachable by anything that can route to this host, "
                "and MCP servers are typically written assuming a trusted local caller."
            ),
            server=s.name,
            atlas=["AML.T0012"],
            cwe=["CWE-1327"],
            tags=["transport", "exposure"],
        )


# The MCP security guidance is explicit that a client "MUST only allow http://
# and https:// schemes" for URLs a server supplies, and "MUST reject
# javascript:, data:, file:, vbscript:, and other potentially dangerous
# schemes". A configured server URL is the same class of input.
DANGEROUS_SCHEMES = {
    "javascript": "executes script in the client's context (XSS, and on some clients RCE)",
    "vbscript": "executes script in the client's context",
    "data": "inlines content the client may render or execute",
    "file": "reads from the local filesystem instead of a server",
    "jar": "loads a remote archive into a local handler",
    "blob": "references client-internal storage",
}

SAFE_SCHEMES = {"http", "https", "ws", "wss"}


@rule("MCPA023", "Server URL uses a dangerous scheme", Severity.CRITICAL)
def dangerous_url_scheme(ctx: AuditContext) -> Iterable[Finding]:
    """A configured URL that is not http(s) at all."""
    for s in ctx.servers:
        if not s.url:
            continue
        scheme = urlsplit(s.url).scheme.lower()
        if not scheme or scheme in SAFE_SCHEMES:
            continue
        reason = DANGEROUS_SCHEMES.get(scheme, "is not an HTTP transport")
        yield Finding(
            rule_id="MCPA023",
            title="Server URL uses a dangerous scheme",
            severity=Severity.CRITICAL if scheme in DANGEROUS_SCHEMES else Severity.HIGH,
            location=Location(path=s.source, line=s.line, snippet=s.url[:200]),
            evidence=f"{scheme}: URL configured as an MCP endpoint -- {reason}",
            remediation=(
                "Remove it. An MCP endpoint is http:// or https://. The protocol's own "
                "security guidance says clients MUST reject javascript:, data:, file: and "
                "vbscript: URLs, because a client that opens one hands the page's author "
                "execution in the client's context."
            ),
            server=s.name,
            atlas=["AML.T0011"],
            cwe=["CWE-79", "CWE-749"],
            tags=["transport", "scheme"],
        )


# 169.254.0.0/16 is link-local. 169.254.169.254 is the cloud instance metadata
# endpoint on AWS, GCP and Azure, and returns IAM credentials to anything that
# can reach it. Nothing legitimately configures it as an MCP server.
_METADATA_HOSTS = {
    "169.254.169.254": "cloud instance metadata (AWS/GCP/Azure) -- returns IAM credentials",
    "metadata.google.internal": "GCP instance metadata -- returns service account tokens",
    "169.254.170.2": "ECS task metadata -- returns task role credentials",
    "100.100.100.200": "Alibaba Cloud instance metadata",
}


@rule("MCPA024", "Server URL targets a cloud metadata or link-local address", Severity.CRITICAL)
def metadata_endpoint(ctx: AuditContext) -> Iterable[Finding]:
    """A URL pointing at the instance metadata service."""
    for s in ctx.servers:
        if not s.url:
            continue
        host = _host_of(s.url)
        if not host:
            continue

        described = _METADATA_HOSTS.get(host)
        if described is None:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                continue
            if not ip.is_link_local:
                continue
            described = "a link-local address, the range cloud metadata services live in"

        yield Finding(
            rule_id="MCPA024",
            title="Server URL targets a cloud metadata or link-local address",
            severity=Severity.CRITICAL,
            location=Location(path=s.source, line=s.line, snippet=s.url[:200]),
            evidence=f"{s.url} points at {described}",
            remediation=(
                "Remove this server. A configured MCP endpoint on the metadata service is "
                "not a server -- it is a request for the agent to fetch cloud credentials "
                "and hand them back as tool output."
            ),
            server=s.name,
            atlas=["AML.T0055", "AML.T0024"],
            cwe=["CWE-918"],
            tags=["transport", "ssrf", "credentials"],
        )


_BROAD_SCOPE = re.compile(r"^(?:\*|all|full[_\-]?access|admin|root|everything|.*:\*)$",
                          re.IGNORECASE)
_SCOPE_KEYS = ("scope", "scopes", "oauthScopes", "oauth_scopes", "requiredScopes")


@rule("MCPA025", "Server requests an over-broad OAuth scope", Severity.MEDIUM)
def broad_scope(ctx: AuditContext) -> Iterable[Finding]:
    """A wildcard or omnibus scope in the server's configuration."""
    for s in ctx.servers:
        for key in _SCOPE_KEYS:
            raw = s.raw.get(key)
            if raw is None:
                continue
            values = (re.split(r"[,\s]+", raw) if isinstance(raw, str)
                      else [str(v) for v in raw] if isinstance(raw, (list, tuple))
                      else [])
            broad = [v.strip() for v in values if v.strip() and _BROAD_SCOPE.match(v.strip())]
            if not broad:
                continue
            yield Finding(
                rule_id="MCPA025",
                title="Server requests an over-broad OAuth scope",
                severity=Severity.MEDIUM,
                location=Location(path=s.source, line=s.line, snippet=f"{key}: {broad}"),
                evidence=f"{key} includes {', '.join(repr(b) for b in broad)}",
                remediation=(
                    "Request the narrowest scopes the server actually needs. A stolen "
                    "omnibus token gives an attacker everything at once, and revoking it "
                    "breaks every workflow rather than one."
                ),
                server=s.name,
                atlas=["AML.T0012"],
                cwe=["CWE-250"],
                tags=["oauth", "scope"],
            )
