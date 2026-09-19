"""Normalized view of an MCP server declaration.

Every client (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed,
Cline...) spells its config slightly differently. Parsers flatten all of them
into ServerSpec so rules never have to care which client a server came from.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ServerSpec:
    name: str
    source: str                       # absolute path of the config file
    client: str                       # "claude-desktop", "cursor", ...
    line: int = 0                     # line of the server's key in `source`
    transport: str = "unknown"        # stdio | http | sse | unknown
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    disabled: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_remote(self) -> bool:
        return self.transport in ("http", "sse") or bool(self.url)

    @property
    def argv(self) -> list[str]:
        """Full command line as a token list."""
        return ([self.command] if self.command else []) + list(self.args)

    @property
    def command_line(self) -> str:
        """Human-readable reconstruction, for evidence strings."""
        return " ".join(shlex.quote(tok) for tok in self.argv)

    def identity(self) -> str:
        """Stable id across config files: client + name."""
        return f"{self.client}:{self.name}"


@dataclass
class ToolSpec:
    """A tool advertised by a server. Populated by probing or from the lock."""

    server: str
    name: str
    description: str = ""
    # `title` is the display name the user actually sees. The spec calls it
    # "intended for UI and end-user contexts", and for a tool
    # `annotations.title` takes precedence over it. A tool can therefore be
    # named honestly and displayed as something else entirely.
    title: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    # ToolAnnotations from the spec: readOnlyHint, destructiveHint,
    # idempotentHint, openWorldHint, title. Clients use these to decide
    # whether a call needs the user's approval, which is exactly why the spec
    # says "Clients should never make tool use decisions based on
    # ToolAnnotations received from untrusted servers."
    annotations: dict[str, Any] = field(default_factory=dict)
    # The structure a tool says its results will have. Model-facing exactly
    # like the input schema is: the client hands it to the model so it knows
    # what to expect, and the `description` on each property lands in context
    # the same way. It was unparsed, unfingerprinted and unscanned -- found by
    # enumerating the keys real servers put on a tool definition rather than
    # by remembering, which is how the last two channel gaps were found too.
    output_schema: dict[str, Any] = field(default_factory=dict)
    # Icons shown beside this tool in the approval dialog. The spec's own type
    # carries a warning -- consumers "SHOULD ensure icon URLs come from a
    # trusted domain and SHOULD take appropriate precautions when consuming
    # SVGs (which can contain script)" -- and a client fetches every one of
    # them to render it. See MCPA033.
    icons: list[dict[str, Any]] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        """What a client shows the user, in the precedence the spec defines."""
        return (self.annotations.get("title") or self.title or self.name or "")

    @property
    def claims_read_only(self) -> bool:
        return self.annotations.get("readOnlyHint") is True

    @property
    def claims_non_destructive(self) -> bool:
        return self.annotations.get("destructiveHint") is False

    def fingerprint(self) -> str:
        """Hash of everything the model actually sees.

        Description and schema are both injected into the agent's context, so
        a change in either is a change in what the agent was told to do. That
        is precisely what a rug pull looks like, so both are in the hash.
        """
        body: dict[str, Any] = {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "input_schema": self.input_schema,
            # In the hash deliberately: a server flipping readOnlyHint to
            # true after approval escalates its own privileges without
            # touching a description, and that must register as drift.
            "annotations": self.annotations,
        }
        # Both schemas, for the same reason: a server that adds an output
        # schema after approval, or rewrites the descriptions inside one, has
        # changed what the model was told, and with only the input schema
        # hashed none of that was drift.
        #
        # Added only when present, which is not cosmetic. Writing the key
        # unconditionally changes the hash of every tool that has no output
        # schema -- which is most of them -- so upgrading would have reported
        # a CRITICAL rug pull on every tool in every existing lockfile. A wave
        # of false criticals is the failure this project ranks first, and it
        # would have arrived on an upgrade rather than on a change.
        if self.output_schema:
            body["output_schema"] = self.output_schema
        # Same conditional, same reason. An icon swapped after approval changes
        # what the user sees in the dialog they approve from, which is the same
        # argument that put `title` in the hash.
        if self.icons:
            body["icons"] = self.icons
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class SkillSpec:
    """A SKILL.md-style agent skill file."""

    name: str
    path: str
    frontmatter: dict[str, Any] = field(default_factory=dict)
    body: str = ""

    def fingerprint(self) -> str:
        payload = json.dumps(
            {"frontmatter": self.frontmatter, "body": self.body},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class PromptSpec:
    """A prompt template a server advertises via prompts/list.

    Prompts are templates the user can invoke; their text and argument
    descriptions reach the model exactly like a tool description does.
    """

    server: str
    name: str
    title: str = ""
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)
    icons: list[dict[str, Any]] = field(default_factory=list)

    def fingerprint(self) -> str:
        body: dict[str, Any] = {
            "name": self.name, "title": self.title,
            "description": self.description, "arguments": self.arguments,
        }
        if self.icons:
            body["icons"] = self.icons
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ResourceSpec:
    """A resource a server advertises via resources/list."""

    server: str
    uri: str
    name: str = ""
    title: str = ""
    description: str = ""
    mime_type: str = ""
    # resources/templates/list entries are the same shape with a uriTemplate.
    is_template: bool = False
    icons: list[dict[str, Any]] = field(default_factory=list)

    def fingerprint(self) -> str:
        payload = json.dumps(
            {"uri": self.uri, "name": self.name, "title": self.title,
             "description": self.description, "mime_type": self.mime_type,
             "is_template": self.is_template,
             **({"icons": self.icons} if self.icons else {})},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def instructions_fingerprint(text: str) -> str:
    """Hash of a server's `instructions` string.

    The spec says this "MAY be added to the system prompt", which makes it the
    highest-privilege text a server controls -- above tool descriptions, which
    at least arrive as tool metadata. A server that changes it has changed the
    agent's standing orders.
    """
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()
