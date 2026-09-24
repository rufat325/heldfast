"""Where each MCP client keeps its configuration.

This used to be a hand-maintained list of paths inside `discovery.py`, which
rotted the moment a client changed layout and gave no way to say *which*
client a finding belonged to beyond a bare string. It is a declarative
registry now: one entry per client, with its platform-specific user paths,
its project-relative paths, and the keys it stores servers under.

Adding a client is a single entry here and nothing else.

Path templates use these placeholders:

    {home}          the user's home directory
    {appdata}       %APPDATA%              (Windows only)
    {localappdata}  %LOCALAPPDATA%         (Windows only)
    {config}        the platform config dir -- %APPDATA% on Windows,
                    ~/Library/Application Support on macOS, $XDG_CONFIG_HOME
                    or ~/.config elsewhere

An entry whose paths do not resolve on this platform is simply skipped.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Keys a client may store its server map under.
MCP_SERVERS = ("mcpServers",)
VSCODE_KEYS = ("servers", "mcpServers")
ZED_KEYS = ("context_servers",)


@dataclass(frozen=True)
class ClientDef:
    id: str
    name: str
    keys: tuple[str, ...] = MCP_SERVERS
    # Platform -> path templates. "*" applies to every platform.
    user_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # Paths relative to a project root.
    project_paths: tuple[str, ...] = ()
    # Set when the config is not JSON and therefore is not parsed.
    unsupported_format: str = ""
    notes: str = ""

    def resolved_user_paths(self) -> list[Path]:
        out: list[Path] = []
        for platform in ("*", sys.platform):
            for template in self.user_paths.get(platform, ()):
                expanded = _expand(template)
                if expanded is not None:
                    out.append(expanded)
        return out


def _expand(template: str) -> Path | None:
    home = Path.home()
    values = {"home": str(home)}

    appdata = os.environ.get("APPDATA")
    localappdata = os.environ.get("LOCALAPPDATA")
    if appdata:
        values["appdata"] = appdata
    if localappdata:
        values["localappdata"] = localappdata

    if sys.platform == "win32":
        config = appdata
    elif sys.platform == "darwin":
        config = str(home / "Library" / "Application Support")
    else:
        config = os.environ.get("XDG_CONFIG_HOME") or str(home / ".config")
    if config:
        values["config"] = config

    try:
        return Path(template.format(**values))
    except KeyError:
        return None  # a placeholder this platform cannot supply


# VS Code extension storage differs per platform; these clients live inside it.
_VSCODE_GLOBAL_STORAGE = {
    "win32": "{appdata}/Code/User/globalStorage",
    "darwin": "{home}/Library/Application Support/Code/User/globalStorage",
    "linux": "{config}/Code/User/globalStorage",
}


def _vscode_ext(extension: str, filename: str) -> dict[str, tuple[str, ...]]:
    return {
        platform: (f"{base}/{extension}/settings/{filename}",)
        for platform, base in _VSCODE_GLOBAL_STORAGE.items()
    }


CLIENTS: tuple[ClientDef, ...] = (
    ClientDef(
        id="claude-desktop",
        name="Claude Desktop",
        user_paths={
            "win32": ("{appdata}/Claude/claude_desktop_config.json",),
            "darwin": ("{home}/Library/Application Support/Claude/claude_desktop_config.json",),
            "linux": ("{config}/Claude/claude_desktop_config.json",),
        },
        project_paths=("claude_desktop_config.json",),
    ),
    ClientDef(
        id="claude-code",
        name="Claude Code",
        user_paths={"*": ("{home}/.claude.json", "{home}/.claude/settings.json")},
        project_paths=(".mcp.json", ".claude/settings.json", ".claude/settings.local.json"),
        notes="~/.claude.json also holds a per-project server map under 'projects'.",
    ),
    ClientDef(
        id="cursor",
        name="Cursor",
        user_paths={"*": ("{home}/.cursor/mcp.json",)},
        project_paths=(".cursor/mcp.json",),
    ),
    ClientDef(
        id="vscode",
        name="VS Code",
        keys=VSCODE_KEYS,
        user_paths={
            "win32": ("{appdata}/Code/User/mcp.json",),
            "darwin": ("{home}/Library/Application Support/Code/User/mcp.json",),
            "linux": ("{config}/Code/User/mcp.json",),
        },
        project_paths=(".vscode/mcp.json",),
        notes="Stores servers under 'servers' rather than 'mcpServers'.",
    ),
    ClientDef(
        id="windsurf",
        name="Windsurf",
        user_paths={"*": ("{home}/.codeium/windsurf/mcp_config.json",)},
    ),
    ClientDef(
        id="zed",
        name="Zed",
        keys=ZED_KEYS,
        user_paths={"*": ("{config}/zed/settings.json",)},
        project_paths=(".zed/settings.json",),
        notes="Stores servers under 'context_servers'.",
    ),
    ClientDef(
        id="cline",
        name="Cline",
        user_paths=_vscode_ext("saoudrizwan.claude-dev", "cline_mcp_settings.json"),
    ),
    ClientDef(
        id="roo",
        name="Roo Code",
        user_paths=_vscode_ext("rooveterinaryinc.roo-cline", "mcp_settings.json"),
        project_paths=(".roo/mcp.json",),
    ),
    ClientDef(
        id="kilo",
        name="Kilo Code",
        user_paths=_vscode_ext("kilocode.kilo-code", "mcp_settings.json"),
    ),
    ClientDef(
        id="continue",
        name="Continue",
        user_paths={"*": ("{home}/.continue/config.json",)},
        project_paths=(".continue/config.json",),
    ),
    ClientDef(
        id="lmstudio",
        name="LM Studio",
        user_paths={"*": ("{home}/.lmstudio/mcp.json",)},
    ),
    ClientDef(
        id="opencode",
        name="opencode",
        user_paths={"*": ("{config}/opencode/opencode.json",)},
        project_paths=("opencode.json", ".opencode.json"),
    ),
    ClientDef(
        id="gemini-cli",
        name="Gemini CLI",
        user_paths={"*": ("{home}/.gemini/settings.json",)},
        project_paths=(".gemini/settings.json",),
    ),
    ClientDef(
        id="amp",
        name="Amp",
        user_paths={"*": ("{config}/amp/settings.json",)},
    ),
    ClientDef(
        id="witsy",
        name="Witsy",
        user_paths={"*": ("{config}/Witsy/settings.json",)},
    ),
    ClientDef(
        id="goose",
        name="Goose",
        user_paths={"*": ("{config}/goose/config.yaml",)},
        unsupported_format="YAML",
        notes="Config is YAML. Discovered and reported, but not parsed.",
    ),
    ClientDef(
        id="codex",
        name="Codex CLI",
        user_paths={"*": ("{home}/.codex/config.toml",)},
        unsupported_format="TOML",
        notes="Config is TOML. Discovered and reported, but not parsed.",
    ),
)

BY_ID = {c.id: c for c in CLIENTS}

# Last date this table was checked against live installs. Frozen on purpose:
# this is not a discoverer race. See docs/CLIENTS.md.
CLIENTS_VERIFIED = "2026-09-21"


# Filenames that are a project-level MCP config regardless of which client
# wrote them, used when walking a tree.
GENERIC_PROJECT_FILENAMES = {
    ".mcp.json": "claude-code",
    "mcp.json": "generic",
    "mcp_config.json": "generic",
    "cline_mcp_settings.json": "cline",
    "claude_desktop_config.json": "claude-desktop",
}


def server_keys_for(client_id: str) -> tuple[str, ...]:
    client = BY_ID.get(client_id)
    return client.keys if client else MCP_SERVERS


def display_name(client_id: str) -> str:
    client = BY_ID.get(client_id)
    return client.name if client else client_id


def is_parseable(client_id: str) -> bool:
    client = BY_ID.get(client_id)
    return not (client and client.unsupported_format)
