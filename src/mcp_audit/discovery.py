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

from .clients import CLIENTS, GENERIC_PROJECT_FILENAMES


def candidate_config_paths() -> list[tuple[Path, str]]:
    """(path, client_id) for every known per-user config location.

    Driven entirely by the registry in clients.py, so adding a client is one
    entry there rather than another branch here.
    """
    out: list[tuple[Path, str]] = []
    for client in CLIENTS:
        for path in client.resolved_user_paths():
            out.append((path, client.id))
    return out


def project_relative_paths() -> list[tuple[str, str]]:
    """(relative_path, client_id) for project-local config locations."""
    out: list[tuple[str, str]] = []
    for client in CLIENTS:
        for rel in client.project_paths:
            out.append((rel, client.id))
    return out


_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "site-packages", ".next", "target",
    ".gradle", ".idea", "vendor", "Pods", ".terraform",
}


def discover_config_files(roots: Iterable[Path], scan_user: bool = True,
                          max_depth: int = 6) -> list[tuple[Path, str]]:
    """Return (path, client_id) for every config file we can find."""
    found: dict[Path, str] = {}

    if scan_user:
        for path, client_id in candidate_config_paths():
            if path.is_file():
                found[path.resolve()] = client_id

    project_rels = project_relative_paths()

    for root in roots:
        root = Path(root).resolve()
        if root.is_file():
            found[root] = GENERIC_PROJECT_FILENAMES.get(root.name, "generic")
            continue
        if not root.is_dir():
            continue

        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            if len(here.parts) - root_depth >= max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if d not in _SKIP_DIRS and not d.startswith(".venv")]

            for fn in filenames:
                if fn in GENERIC_PROJECT_FILENAMES:
                    # Do not clobber a specific attribution with the generic
                    # one: .cursor/mcp.json is Cursor's, and the bare filename
                    # match would otherwise relabel it "generic".
                    resolved = (here / fn).resolve()
                    if found.get(resolved) in (None, "generic"):
                        found[resolved] = GENERIC_PROJECT_FILENAMES[fn]

            # Client-specific project paths such as .cursor/mcp.json. Checked
            # at every level so nested workspaces are covered too.
            for rel, client_id in project_rels:
                candidate = here / rel
                if candidate.is_file():
                    found[candidate.resolve()] = client_id  # specific wins

    return sorted(found.items(), key=lambda kv: str(kv[0]))
