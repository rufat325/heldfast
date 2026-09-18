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
    input_schema: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Hash of everything the model actually sees.

        Description and schema are both injected into the agent's context, so
        a change in either is a change in what the agent was told to do. That
        is precisely what a rug pull looks like, so both are in the hash.
        """
        payload = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "input_schema": self.input_schema,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
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
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)

    def fingerprint(self) -> str:
        payload = json.dumps(
            {"name": self.name, "description": self.description,
             "arguments": self.arguments},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ResourceSpec:
    """A resource a server advertises via resources/list."""

    server: str
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""

    def fingerprint(self) -> str:
        payload = json.dumps(
            {"uri": self.uri, "name": self.name, "description": self.description,
             "mime_type": self.mime_type},
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
