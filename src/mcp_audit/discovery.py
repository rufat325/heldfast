"""Find and parse MCP configuration wherever the clients hide it.

`mcp-audit` with no arguments should find everything on the machine, because
the whole premise of "shadow MCP" is that nobody knows what is installed.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from .model import ServerSpec, SkillSpec

# ---------------------------------------------------------------------------
# Tolerant JSON (JSONC): VS Code and friends allow comments and trailing commas
# ---------------------------------------------------------------------------

_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_jsonc(text: str) -> str:
    """Remove comments and trailing commas without touching string contents."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
            i += 1
            continue
        if ch in "\"'":
            in_str, quote = True, ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                while i < n and text[i] not in "\r\n":
                    i += 1
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                i = n if end == -1 else end + 2
                continue
        out.append(ch)
        i += 1
    return _TRAILING_COMMA.sub(r"\1", "".join(out))


def load_jsonc(path: Path) -> tuple[dict[str, Any], str]:
    """Return (parsed, raw_text). Raises ValueError with a useful message."""
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        return json.loads(raw), raw
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_strip_jsonc(raw)), raw
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON/JSONC ({exc.msg} at line {exc.lineno})") from None


def find_key_line(raw: str, key: str) -> int:
    """Best-effort 1-indexed line of `"key"` in the raw text.

    Used to anchor SARIF results. Approximate by design -- a full JSON
    tokenizer with positions would be more precise than this problem needs.
    """
    needle = re.compile(r'"' + re.escape(key) + r'"\s*:')
    for idx, line in enumerate(raw.splitlines(), start=1):
        if needle.search(line):
            return idx
    return 0


# ---------------------------------------------------------------------------
# Known config locations
# ---------------------------------------------------------------------------

def _home() -> Path:
    return Path.home()


def _appdata() -> Path | None:
    v = os.environ.get("APPDATA")
    return Path(v) if v else None


def candidate_config_paths() -> list[tuple[Path, str]]:
    """(path, client) pairs for every well-known MCP config location."""
    home = _home()
    out: list[tuple[Path, str]] = []

    def add(p: Path | None, client: str) -> None:
        if p is not None:
            out.append((p, client))

    # Claude Desktop
    if sys.platform == "win32":
        ad = _appdata()
        add(ad / "Claude" / "claude_desktop_config.json" if ad else None, "claude-desktop")
    elif sys.platform == "darwin":
        add(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            "claude-desktop")
    else:
        add(home / ".config" / "Claude" / "claude_desktop_config.json", "claude-desktop")

    # Claude Code
    add(home / ".claude.json", "claude-code")
    add(home / ".claude" / "settings.json", "claude-code")

    # Cursor
    add(home / ".cursor" / "mcp.json", "cursor")

    # Windsurf
    add(home / ".codeium" / "windsurf" / "mcp_config.json", "windsurf")

    # Zed
    add(home / ".config" / "zed" / "settings.json", "zed")

    # Cline / Roo (VS Code extension global storage)
    for variant in ("saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"):
        if sys.platform == "win32":
            ad = _appdata()
            base = ad / "Code" / "User" / "globalStorage" if ad else None
        elif sys.platform == "darwin":
            base = home / "Library" / "Application Support" / "Code" / "User" / "globalStorage"
        else:
            base = home / ".config" / "Code" / "User" / "globalStorage"
        if base is not None:
            add(base / variant / "settings" / "cline_mcp_settings.json", "cline")

    return out


# Project-local config files, found by walking a project tree.
PROJECT_CONFIG_NAMES: dict[str, str] = {
    ".mcp.json": "claude-code",
    "mcp.json": "generic",
    "claude_desktop_config.json": "claude-desktop",
    "mcp_config.json": "generic",
    "cline_mcp_settings.json": "cline",
}

PROJECT_CONFIG_RELPATHS: dict[str, str] = {
    ".cursor/mcp.json": "cursor",
    ".vscode/mcp.json": "vscode",
    ".zed/settings.json": "zed",
}

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "site-packages", ".next", "target",
}


def discover_config_files(roots: Iterable[Path], scan_user: bool = True,
                          max_depth: int = 6) -> list[tuple[Path, str]]:
    """Return (path, client) for every config file we can find."""
    found: dict[Path, str] = {}

    if scan_user:
        for path, client in candidate_config_paths():
            if path.is_file():
                found[path.resolve()] = client

    for root in roots:
        root = Path(root).resolve()
        if root.is_file():
            client = PROJECT_CONFIG_NAMES.get(root.name, "generic")
            found[root] = client
            continue
        if not root.is_dir():
            continue
        for rel, client in PROJECT_CONFIG_RELPATHS.items():
            p = root / rel
            if p.is_file():
                found[p.resolve()] = client
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            if len(here.parts) - root_depth >= max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".venv")]
            for fn in filenames:
                if fn in PROJECT_CONFIG_NAMES:
                    found[(here / fn).resolve()] = PROJECT_CONFIG_NAMES[fn]
            # .cursor/mcp.json and .vscode/mcp.json nested in subprojects
            for rel, client in PROJECT_CONFIG_RELPATHS.items():
                p = here / rel
                if p.is_file():
                    found[p.resolve()] = client

    return sorted(found.items(), key=lambda kv: str(kv[0]))
