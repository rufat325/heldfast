"""Findings that exist in the combination of servers, not in any one of them.

Every other scanner in this space examines one server at a time, so these are
invisible to them by construction. mcp-pin already reads every client's
config on the machine in a single pass, which means it holds the one thing the
per-server tools do not: the whole set an agent can reach at once.

Two things live here.

Tool shadowing: two servers in the same client offering the same tool name.
The agent picks by name, so the second definition competes with the first for
every call, and a server added later can take over a name a trusted server
already had.

Exfiltration reach: one server that can read the user's home directory and
another that can post to an arbitrary URL, in the same client. Neither is
malicious, neither is misconfigured on its own, and together they are both
halves of a credential exfiltration path.

Capability is read from structure -- the launch command, the package name, the
input schema -- and never from description prose. Tools that infer capability
by looking for "run" or "read" or "api" in a description fire on almost
everything: this project deleted exactly that kind of signal in an earlier
cycle after it matched "charges" in billing prose and "runs" in a verification
tool. The lesson cost a release and is not being re-learned here.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from ..findings import Finding, Location, Severity
from ..model import ServerSpec, config_anchors
from ..enforcement import subcommand
from .base import AuditContext, rule

# Packages and binaries that grant filesystem access. Matched against the
# launch command and arguments, which are facts about how the server starts,
# rather than against anything the server says about itself.
_FILESYSTEM_MARKERS = re.compile(
    r"(?:^|[\s/@._-])(?:server-)?(?:filesystem|files?|fs)(?=$|[\s/@._-])", re.IGNORECASE)

# Directories whose contents are credentials by definition.
_CREDENTIAL_DIRS = ("/.ssh", "/.aws", "/.gnupg", "/.kube", "/.docker", "/.config/gh")

# A parameter name that carries data outward. Kept in step with MCPA022, which
# reads the same shapes for a different question.
_EGRESS_PARAM = re.compile(
    r"^(?:url|uri|endpoint|webhook|callback|callback_url|destination|target_url|"
    r"forward_to|report_to|notify_url|sink|upload_url)$",
    re.IGNORECASE,
)


def _clients_by_server(ctx: AuditContext) -> dict[str, set[str]]:
    """Server name -> the clients that configure it.

    Shadowing only matters inside one client's tool namespace. Two servers
    configured in different clients are two different agents and cannot
    compete for the same call.
    """
    out: dict[str, set[str]] = defaultdict(set)
    for server in ctx.servers:
        if not server.disabled:
            out[server.name].add(server.client)
            out[server.identity()].add(server.client)
    return out


def _normalized_paths(server: ServerSpec) -> list[str]:
    """Path-looking arguments, in a form that compares the same everywhere."""
    paths = []
    for arg in server.args:
        text = str(arg)
        if not text or text.startswith("-"):
            continue
        if "/" not in text and "\\" not in text and not text.startswith("~"):
            continue
        paths.append(text.replace("\\", "/").rstrip("/").lower())
    return paths


def _reads_the_home_directory(server: ServerSpec) -> str | None:
    """The argument granting access at or above the user's home, if any.

    A filesystem server scoped to one project is a normal, well-configured
    thing and must not be reported. The finding is about a root that contains
    the user's credentials.
    """
    command_line = " ".join([server.command or ""] + [str(a) for a in server.args])
    if not _FILESYSTEM_MARKERS.search(command_line):
        return None

    for path in _normalized_paths(server):
        if path in ("~", "/", "", "/home", "/users", "c:"):
            return path or "/"
        # ~, $HOME and an expanded home directory all mean the same thing.
        if path.startswith("~") and path.count("/") <= 1:
            return path
        if "$home" in path or "%userprofile%" in path:
            return path
        if re.match(r"^(?:/home/[^/]+|/users/[^/]+|c:/users/[^/]+)$", path):
            return path
        if any(path.endswith(d) or (d + "/") in (path + "/") for d in _CREDENTIAL_DIRS):
            return path
    return None


def _arbitrary_destination_tools(ctx: AuditContext) -> dict[str, list[str]]:
    """Server -> tools whose schema takes a destination the caller chooses.

    This is a structural read of the declared input schema. A tool that
    accepts `url` can be pointed anywhere by whatever is driving the agent,
    which is the property that matters here -- not whether its description
    sounds like networking.
    """
    out: dict[str, list[str]] = defaultdict(list)
    for tool in ctx.tools:
        properties = (tool.input_schema or {}).get("properties")
        if not isinstance(properties, dict):
            continue
        if any(_EGRESS_PARAM.match(str(name)) for name in properties):
            out[tool.server].append(tool.name)
    return out


@rule("MCPA027", "Two servers in one client expose the same tool name",
      Severity.MEDIUM)
def tool_shadowing(ctx: AuditContext) -> Iterable[Finding]:
    """The agent selects a tool by name, so a duplicate name is a contest."""
    declared = config_anchors(ctx.servers)
    clients = _clients_by_server(ctx)

    by_name: dict[str, set[str]] = defaultdict(set)
    for tool in ctx.tools:
        by_name[tool.name.strip()].add(tool.server)

    for tool_name, servers in sorted(by_name.items()):
        if not tool_name or len(servers) < 2:
            continue

        # Only a client that configures two of them has the ambiguity. The
        # same server reached from two clients is not shadowing anything.
        shared = sorted(
            {client for client in set().union(*(clients.get(s, set()) for s in servers))
             if len([s for s in servers if client in clients.get(s, set())]) > 1}
        )
        if not shared:
            continue

        for client in shared:
            competing = sorted(s for s in servers if client in clients.get(s, set()))
            path, line = declared.get(competing[0], ("", 0))
            yield Finding(
                rule_id="MCPA027",
                title="Two servers in one client expose the same tool name",
                severity=Severity.MEDIUM,
                location=Location(path=path, line=line,
                                  snippet=f"{tool_name} from {', '.join(competing)}"),
                evidence=(
                    f"{client} configures {len(competing)} servers that each expose a tool "
                    f"named '{tool_name}': {', '.join(competing)}"
                ),
                remediation=(
                    "Decide which server should own the name and remove or rename the "
                    "tool on the other. The agent chooses by name and nothing tells it "
                    "which definition you meant, so a server added later can take over "
                    "calls a server you trusted used to answer."
                ),
                server=competing[0],
                atlas=["AML.T0051"],
                cwe=["CWE-1321"],
                tags=["composition", "shadowing"],
            )


@rule("MCPA028", "One server reads the home directory while another can post anywhere",
      Severity.HIGH)
def exfiltration_reach(ctx: AuditContext) -> Iterable[Finding]:
    """Both halves of an exfiltration path, held by one agent."""
    clients = _clients_by_server(ctx)
    destinations = _arbitrary_destination_tools(ctx)
    if not destinations:
        return

    readers: list[tuple[ServerSpec, str]] = []
    for server in ctx.servers:
        if server.disabled:
            continue
        root = _reads_the_home_directory(server)
        if root:
            readers.append((server, root))
    if not readers:
        return

    seen: set[tuple[str, str, str]] = set()
    for reader, root in readers:
        for sender, tool_names in sorted(destinations.items()):
            if sender == reader.name:
                continue  # one server doing both is a different rule's problem
            shared = sorted(clients.get(reader.name, set()) & clients.get(sender, set()))
            for client in shared:
                key = (client, reader.name, sender)
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    rule_id="MCPA028",
                    title="One server reads the home directory while another can post anywhere",
                    severity=Severity.HIGH,
                    location=Location(path=reader.source, line=reader.line,
                                      snippet=f"{reader.name} + {sender}"),
                    evidence=(
                        f"in {client}: '{reader.name}' is granted {root!r}, which contains "
                        f"the user's credentials, and '{sender}' exposes "
                        f"{', '.join(repr(t) for t in sorted(tool_names)[:3])} taking a "
                        f"caller-chosen destination. One agent holds both."
                    ),
                    remediation=(
                        "Scope the filesystem server to the directory you actually work "
                        "in instead of the home directory. Neither server is "
                        "misconfigured by itself, which is why this is worth saying out "
                        "loud: the reach belongs to the pair, and anything that can "
                        "steer the agent can read a key with one and send it with the "
                        "other."
                    ),
                    server=reader.identity(),
                    atlas=["AML.T0024", "AML.T0057"],
                    cwe=["CWE-200"],
                    confidence=0.9,
                    tags=["composition", "exfiltration"],
                )


# --------------------------------------------------------------------------
# Enforcement that is configured and bypassable.


# Only fires once the gateway is configured. Reporting every unguarded server
# would be reporting "you have not adopted this tool", which is not a finding
# and is how a scanner earns a permanent --ignore line. The signal is narrower
# and much stronger: enforcement has been set up, and there is a way around it.
@rule("MCPA032", "Approved server is also reachable without the gateway", Severity.HIGH)
def bypassable_gateway(ctx: AuditContext) -> Iterable[Finding]:
    """A gateway entry beside the direct entries it was meant to replace.

    `mcp-pin gateway` is one endpoint in front of every approved server, and
    the client is supposed to point at it *instead of* at the servers. Adding
    it without removing what it replaces leaves both paths live: the agent
    sees each tool twice, and the second copy answers without passing the
    lockfile, the argument policy, the identity grant or the call budget.

    The lockfile then describes enforcement that is not happening, which is
    worse than no enforcement -- it is a committed artifact saying the
    boundary holds.
    """
    approved = set((ctx.lock or {}).get("servers") or {})
    if not approved:
        return  # nothing approved, so the gateway fronts nothing to bypass

    by_client: dict[str, list[ServerSpec]] = defaultdict(list)
    for server in ctx.servers:
        if not server.disabled:
            by_client[server.client].append(server)

    for client, servers in sorted(by_client.items()):
        subcommands = {s.name: subcommand(s) for s in servers}
        if "gateway" not in subcommands.values():
            continue
        fronted = sorted(
            name for name, sub in subcommands.items()
            if not sub and f"{client}:{name}" in approved
        )
        if not fronted:
            continue
        for server in servers:
            if server.name not in fronted:
                continue
            yield Finding(
                rule_id="MCPA032",
                title="Approved server is also reachable without the gateway",
                severity=Severity.HIGH,
                location=Location(path=server.source, line=server.line,
                                  snippet=server.command_line),
                evidence=(
                    f"in {client}: a gateway is configured, and {server.name!r} is also "
                    f"configured directly. The agent can reach it on either path, and "
                    f"the direct one answers without the lockfile, the argument policy, "
                    f"the identity grant or the call budget."
                ),
                remediation=(
                    "Remove the direct entry. The gateway already exposes this server as "
                    f"'{server.name}__<tool>'; leaving the original beside it means the "
                    "agent sees every tool twice and one copy is unenforced. The lockfile "
                    "otherwise describes a boundary that is not in the path, which is "
                    "worse than having no boundary -- it is a committed artifact "
                    "asserting one."
                ),
                server=server.identity(),
                atlas=["AML.T0051"],
                cwe=["CWE-693"],
                confidence=0.95,
                tags=["composition", "enforcement"],
            )
