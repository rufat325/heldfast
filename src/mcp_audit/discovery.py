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


# Directories that never hold a project's MCP config and cost a great deal to
# walk. AppData and ~/Library are the expensive ones: they contain tens of
# thousands of cache directories, and the client configs that genuinely live
# there are collected by exact path in candidate_config_paths(), so walking
# them turns up nothing the scan does not already have.
#
# Only directories *below* a root are pruned, so pointing mcp-audit straight
# at a path inside one of these still scans it.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "site-packages", ".next", "target",
    ".gradle", ".idea", "vendor", "Pods", ".terraform",
    # User-level caches and package stores.
    "AppData", "Application Data", "Library", ".cache", ".local", ".npm",
    ".nvm", ".cargo", ".rustup", ".gem", ".m2", ".nuget", ".conda", ".pyenv",
    ".rbenv", ".docker", ".ollama",
    "$Recycle.Bin", "System Volume Information",
    # Windows keeps legacy junctions in the profile that point back at
    # directories already covered -- Local Settings at AppData/Local, My
    # Documents at Documents. Following them walks the same tree twice.
    "Local Settings", "My Documents", "My Pictures", "My Music", "My Videos",
    "NetHood", "PrintHood", "Recent", "SendTo", "Start Menu", "Templates",
    "Cookies",
}


def discover_config_files(roots: Iterable[Path], scan_user: bool = True,
                          max_depth: int = 6) -> list[tuple[Path, str]]:
    """Return (path, client_id) for every config file we can find."""
    found: dict[Path, str] = {}

    if scan_user:
        for path, client_id in candidate_config_paths():
            if path.is_file():
                found[path.resolve()] = client_id

    # Split the client project paths by shape so the walk can answer most of
    # them from the directory listing it already has. Stat-ing every candidate
    # in every directory cost 12 syscalls per directory, and on a home
    # directory that dominated the runtime -- 67k stats that found nothing.
    bare: dict[str, str] = {}
    nested: dict[str, list[tuple[str, str]]] = {}
    for rel, client_id in project_relative_paths():
        parts = Path(rel).parts
        if len(parts) > 1:
            nested.setdefault(parts[0], []).append((rel, client_id))
        else:
            bare[parts[0]] = client_id

    seen: set[str] = set()

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

            # Junctions and symlinks make one tree appear under several names
            # -- on Windows ~/Application Data points back into
            # ~/AppData/Roaming -- so without this the walk repeats itself,
            # and a loop would never end.
            real = os.path.realpath(dirpath)
            if real in seen:
                dirnames[:] = []
                continue
            seen.add(real)

            dirnames[:] = [d for d in dirnames
                           if d not in _SKIP_DIRS and not d.startswith(".venv")]
            names = set(filenames)

            for fn in names:
                if fn in GENERIC_PROJECT_FILENAMES:
                    # Do not clobber a specific attribution with the generic
                    # one: .cursor/mcp.json is Cursor's, and the bare filename
                    # match would otherwise relabel it "generic".
                    resolved = (here / fn).resolve()
                    if found.get(resolved) in (None, "generic"):
                        found[resolved] = GENERIC_PROJECT_FILENAMES[fn]

            # Client-specific project paths such as .cursor/mcp.json. Checked
            # at every level so nested workspaces are covered too. The bare
            # filenames come out of the listing; the nested ones are stat-ed
            # only where the directory they sit in actually exists.
            for fn, client_id in bare.items():
                if fn in names:
                    found[(here / fn).resolve()] = client_id  # specific wins
            for sub in dirnames:
                for rel, client_id in nested.get(sub, ()):
                    candidate = here / rel
                    if candidate.is_file():
                        found[candidate.resolve()] = client_id  # specific wins

    return sorted(found.items(), key=lambda kv: str(kv[0]))
