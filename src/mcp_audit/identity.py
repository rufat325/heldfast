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
            servers = None
        return cls(
            name=name,
            servers=[str(s) for s in servers] if servers is not None else None,
            deny=[str(d) for d in entry.get("deny") or [] if isinstance(d, str)],
            policy=entry.get("policy") if isinstance(entry.get("policy"), dict) else {},
            description=str(entry.get("description") or ""),
        )

    def may_use_server(self, server_name: str) -> bool:
        if self.servers is None:
            return True
        return server_name in self.servers

    def denies_tool(self, namespaced: str, bare: str) -> bool:
        """Deny entries may be written namespaced or bare.

        `github__delete_repository` names one tool on one server.
        `delete_repository` denies it wherever it appears, which is what
        somebody writing a fleet-wide rule means.
        """
        return namespaced in self.deny or bare in self.deny

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
    entries = getattr(lock, "identities", None) or {}
    out: dict[str, Identity] = {}
    for name in entries:
        try:
            out[name] = Identity.from_lock(lock, name)
        except UnknownIdentity:      # pragma: no cover - name came from the keys
            continue
    return out
