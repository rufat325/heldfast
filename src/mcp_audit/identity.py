"""Which agent is allowed to reach which servers, and with what limits.

The gateway knows *what* was called. It does not know *who* called it, and
until it does there is one boundary rather than access control: every agent
pointed at the gateway gets the same tool surface, so the finance agent and
the scratch agent are the same principal.

This adds the missing half. An identity is declared in the lockfile and
selected on the command line:

    "identities": {
      "finance": {
        "servers": ["github", "postgres"],
        "deny": ["github__delete_repository"],
        "policy": {"postgres__query": {"sql": ["SELECT"]}}
      }
    }

    mcp-audit gateway --as finance

WHAT THIS IS AND IS NOT
-----------------------
It is *operator-declared* identity. Whoever writes the client configuration
chooses which identity that client runs under, and the lockfile says what the
identity may do. That is real, because the person configuring the agent is the
person entitled to decide its authority.

It is not authentication. A client also announces itself in `initialize` via
`clientInfo`, and that field is worth recording and worth nothing as a
credential: the client picks it, so anything that can talk to the gateway can
claim to be anything. It goes in the audit trail and never into a decision.
Treating a self-declared name as authorization is how an access control layer
becomes decoration.

FAIL CLOSED
-----------
`--as` naming an identity the lockfile does not define is an error, not a
fallback to full access. The whole point of asking for a restricted principal
is that a typo must not silently produce an unrestricted one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import Policy


class UnknownIdentity(ValueError):
    """Raised when --as names something the lockfile does not define."""


class MalformedIdentity(UnknownIdentity):
    """Raised when the lockfile defines it but not in a shape that can be read.

    A subclass, so every existing caller that refuses on an unknown identity
    refuses on an unreadable one too. Those are the same decision: the
    operator asked for a restricted principal and the file cannot say what the
    restriction is, and guessing is how an access-control layer becomes
    decoration.
    """


def _clean(value: Any) -> str:
    """A name as written, minus the whitespace nobody meant to type.

    No tool or server name meaningfully carries leading or trailing space, so
    stripping it can only help -- and `"deny": ["wipe "]` silently matching
    nothing is the kind of failure that looks like the rule simply not
    working.
    """
    return str(value if value is not None else "").strip()


def _as_names(value: Any) -> list:
    """A list of names from whatever the lockfile actually holds."""
    if value is None:
        return []
    if isinstance(value, str):
        return [_clean(value)] if _clean(value) else []
    if not isinstance(value, (list, tuple, set)):
        return []
    return [_clean(v) for v in value if _clean(v)]


@dataclass
class Identity:
    """One principal's authority over the gateway's tool surface."""

    name: str
    # None means "every approved server". An empty list means none, which is
    # a different thing and is honoured as written.
    servers: list[str] | None = None
    deny: list[str] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    @classmethod
    def from_lock(cls, lock: Any, name: str) -> "Identity":
        entries = getattr(lock, "identities", None) or {}
        entry = entries.get(name)
        if not isinstance(entry, dict):
            known = ", ".join(sorted(entries)) or "none are defined"
            raise UnknownIdentity(
                f"identity {name!r} is not in the lockfile ({known}). Refusing to "
                f"fall back to full access -- a typo in --as must not quietly "
                f"produce an unrestricted agent."
            )

        servers = entry.get("servers")
        if servers is not None and not isinstance(servers, list):
            # Absent means "every server", so a malformed grant used to be
            # read as *no restriction at all* -- `"servers": "alpha"` instead
            # of `["alpha"]` silently turned a restricted identity into an
            # unrestricted one. That is the inversion this class's other error
            # message promises not to make, in a file the project expects to
            # be hand-edited. It refuses now.
            raise MalformedIdentity(
                f"identity {name!r} has a malformed 'servers' entry: expected a "
                f"list of server names, found {type(servers).__name__}. Refusing "
                f"to guess -- absent means every server, so reading a broken "
                f"grant leniently would hand this agent everything."
            )
        return cls(
            name=name,
            servers=[_clean(s) for s in servers] if servers is not None else None,
            # A bare string is what somebody means by one entry. Iterating it
            # produced ['w','i','p','e'], which denies nothing: the same
            # character-splitting bug this codebase already has a test for
            # elsewhere, repeated here.
            deny=_as_names(entry.get("deny")),
            policy=entry.get("policy") if isinstance(entry.get("policy"), dict) else {},
            description=str(entry.get("description") or ""),
        )

    def may_use_server(self, server_name: str) -> bool:
        """Exact, and deliberately not case-folded.

        Folding here would *widen* a grant, and the two lists err in opposite
        directions on purpose: a grant that matches too much hands out access
        nobody wrote down, while a deny that matches too much refuses a call
        loudly and is fixed in one line.
        """
        if self.servers is None:
            return True
        return _clean(server_name) in self.servers

    def denies_tool(self, namespaced: str, bare: str) -> bool:
        """Deny entries may be written namespaced or bare.

        `github__delete_repository` names one tool on one server.
        `delete_repository` denies it wherever it appears, which is what
        somebody writing a fleet-wide rule means.

        Matched case-insensitively, unlike a grant. MCP tool names are
        case-sensitive, so this can refuse a genuinely different tool -- but an
        operator who writes `Wipe` meaning `wipe` gets a refusal they can see
        rather than a call they tried to prevent.
        """
        wanted = {_clean(namespaced).lower(), _clean(bare).lower()}
        return any(d.lower() in wanted for d in self.deny)

    def policy_for(self, namespaced: str, bare: str) -> Policy:
        """The identity's extra argument limits for this tool.

        Looked up under both spellings for the same reason as `deny`. This
        stacks on top of the server's own policy rather than replacing it:
        an identity can narrow what a tool may be asked to do, never widen it.
        """
        rules: dict[str, Any] = {}
        for key in (namespaced, bare):
            entry = self.policy.get(key)
            if isinstance(entry, dict):
                # The tool is addressed by its bare name inside Policy, which
                # is what the guard hands it.
                rules[bare] = {**rules.get(bare, {}), **entry}
        return Policy(rules)


def all_identities(lock: Any) -> dict[str, Identity]:
    """Every declared identity, including the ones that cannot be read.

    A malformed entry is kept rather than skipped, granting nothing and
    saying why. Dropping it would leave `status` and `coverage` showing a
    clean page for a lockfile the gateway refuses to start against -- two
    surfaces reading one file and disagreeing, which is a mistake this
    project has already made once.
    """
    entries = getattr(lock, "identities", None) or {}
    out: dict[str, Identity] = {}
    for name in entries:
        try:
            out[name] = Identity.from_lock(lock, name)
        except MalformedIdentity as exc:
            out[name] = Identity(name=name, servers=[],
                                 description=f"MALFORMED -- {exc}")
        except UnknownIdentity:      # pragma: no cover - name came from the keys
            continue
    return out
