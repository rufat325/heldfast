"""MCP servers that come with a Claude Code plugin, so they can be pinned.

A plugin can bundle MCP servers, and Claude Code names their tools
`mcp__plugin_<plugin>_<server>__<tool>`. Discovery read client configs only,
so these servers were never approved, and heldfast's own hook refused every
call to them. This finds them the way Claude Code does:

  - what is installed: `installed_plugins.json` under the plugins root
    (`$CLAUDE_CODE_PLUGIN_CACHE_DIR`, else `<config>/plugins`, where the
    config directory is `$CLAUDE_CONFIG_DIR` or `~/.claude`), version 2
    (`{"plugins": {"name@marketplace": [{"installPath": ...}, ...]}}`) or
    version 1 (one object per plugin)
  - what is switched off: `enabledPlugins` in the user settings, and a
    manifest's `defaultEnabled: false` when the user never set it
  - what each declares: `.mcp.json` at the plugin root, then the manifest's
    `mcpServers` -- a `.json` path, an inline map, or an array of them -- a
    later name replacing an earlier one, as Claude Code merges them

Each server is recorded as client `claude-code-plugin`, name
`<plugin>:<server>` (the plugin's manifest name), so its identity is
`claude-code-plugin:<plugin>:<server>` and the hook can write it the way
Claude Code does. `${CLAUDE_PLUGIN_ROOT}` and `${CLAUDE_PLUGIN_DATA}` are
expanded, so the command recorded is the one that runs.

Not read, and said so: MCP bundles (`.mcpb`, `.dxt`, an https URL), which
are archives rather than configs; plugins synced from claude.ai, which have
no install record; project-scope `enabledPlugins`. Read-only; opens no socket.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .model import ServerSpec
from .parsers import _as_str_map, _infer_transport

CLIENT = "claude-code-plugin"


def config_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def plugins_root() -> Path:
    override = os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR")
    return Path(override) if override else config_dir() / "plugins"


def _load(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _installs(record: Any) -> list[tuple[str, Path]]:
    """(plugin id, install path) for every install the record lists."""
    plugins = record.get("plugins") if isinstance(record, dict) else None
    out = []
    for plugin_id, value in (plugins or {}).items() if isinstance(plugins, dict) else ():
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            path = entry.get("installPath") if isinstance(entry, dict) else None
            if isinstance(path, str) and path:
                out.append((str(plugin_id), Path(path)))
    return out


def _switched_off(plugin_id: str, manifest: dict, enabled: dict) -> bool:
    if plugin_id in enabled:
        return enabled[plugin_id] is False
    return manifest.get("defaultEnabled") is False


def _data_dir(plugin_id: str) -> str:
    return str(plugins_root() / "data" / re.sub(r"[^A-Za-z0-9_-]", "-", plugin_id))


def _expand(value: str, root: Path, data: str) -> str:
    return value.replace("${CLAUDE_PLUGIN_ROOT}", str(root)).replace("${CLAUDE_PLUGIN_DATA}", data)


def _server_maps(root: Path, manifest: dict) -> tuple[list[tuple[Path, dict]], list[str]]:
    """(file the map came from, map) in load order, and what was not read."""
    maps: list[tuple[Path, dict]] = []
    skipped: list[str] = []
    default = root / ".mcp.json"
    if default.is_file():
        maps.append((default, _as_map(_load(default))))
    declared = manifest.get("mcpServers")
    for item in declared if isinstance(declared, list) else [declared] if declared else []:
        if isinstance(item, dict):
            maps.append((root / ".claude-plugin" / "plugin.json", item))
        elif isinstance(item, str) and item.endswith(".json") and not item.startswith("https://"):
            path = (root / item).resolve()
            if root.resolve() not in path.parents:
                skipped.append(f"{item}: outside the plugin directory")
            elif path.is_file():
                maps.append((path, _as_map(_load(path))))
            else:
                skipped.append(f"{item}: no such file")
        else:
            skipped.append(f"{item}: an MCP bundle, which this does not unpack")
    return maps, skipped


def _as_map(data: Any) -> dict:
    if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"]
    return data if isinstance(data, dict) else {}


def enabled(plugin: str) -> bool:
    """Whether a plugin of this name is installed and switched on here.

    Read from the same record and settings `plugin_servers` reads, so the two
    cannot disagree about what Claude Code will load.
    """
    try:
        installs = _installs(_load(plugins_root() / "installed_plugins.json"))
    except (OSError, ValueError):
        return False
    try:
        settings = _load(config_dir() / "settings.json")
    except (OSError, ValueError):
        settings = {}
    switches = settings.get("enabledPlugins") if isinstance(settings, dict) else None
    switches = switches if isinstance(switches, dict) else {}
    for plugin_id, root in installs:
        if plugin_id.split("@", 1)[0] != plugin:
            continue
        try:
            manifest_path = root / ".claude-plugin" / "plugin.json"
            manifest = _load(manifest_path) if manifest_path.is_file() else {}
        except (OSError, ValueError):
            manifest = {}
        if not _switched_off(plugin_id, manifest if isinstance(manifest, dict) else {},
                             switches):
            return True
    return False


def plugin_servers() -> tuple[list[ServerSpec], list[str]]:
    """(servers, notes) for every enabled installed plugin's MCP servers."""
    record_path = plugins_root() / "installed_plugins.json"
    if not record_path.is_file():
        return [], []
    notes: list[str] = []
    try:
        installs = _installs(_load(record_path))
    except (OSError, ValueError) as exc:
        return [], [f"{record_path}: {exc}"]
    try:
        settings = _load(config_dir() / "settings.json")
    except (OSError, ValueError):
        settings = {}
    enabled = settings.get("enabledPlugins") if isinstance(settings, dict) else None
    enabled = enabled if isinstance(enabled, dict) else {}

    servers: dict[tuple[str, str], ServerSpec] = {}
    for plugin_id, root in installs:
        try:
            manifest_path = root / ".claude-plugin" / "plugin.json"
            manifest = _load(manifest_path) if manifest_path.is_file() else {}
            manifest = manifest if isinstance(manifest, dict) else {}
            if _switched_off(plugin_id, manifest, enabled):
                continue
            plugin = str(manifest.get("name") or plugin_id.split("@", 1)[0])
            maps, skipped = _server_maps(root, manifest)
        except (OSError, ValueError) as exc:
            notes.append(f"plugin {plugin_id}: {exc}")
            continue
        notes += [f"plugin {plugin_id}: not read -- {why}" for why in skipped]
        data = _data_dir(plugin_id)
        for source, server_map in maps:
            for server, entry in server_map.items():
                if not isinstance(entry, dict):
                    notes.append(f"{source}: server {server!r} is not an object")
                    continue
                args = entry.get("args") or []
                args = args if isinstance(args, list) else [args]
                url = entry.get("url")
                command = entry.get("command")
                # A later declaration of the same name replaces the earlier one.
                servers[(plugin, str(server))] = ServerSpec(
                    name=f"{plugin}:{server}", source=str(source), client=CLIENT,
                    transport=_infer_transport(entry),
                    command=_expand(str(command), root, data) if command else None,
                    args=[_expand(str(a), root, data) for a in args],
                    env={k: _expand(v, root, data)
                         for k, v in _as_str_map(entry.get("env")).items()},
                    url=_expand(str(url), root, data) if url else None,
                    headers=_as_str_map(entry.get("headers")),
                    disabled=bool(entry.get("disabled", False)), raw=entry)
    return list(servers.values()), notes
