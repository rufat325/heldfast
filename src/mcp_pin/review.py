"""What the new pin would change, before it is written.

`approve` used to overwrite the lock as soon as you asked. A legitimate
upstream bump and a poisoned description then look the same: "approved
14 tools". This names the words that moved and the grade of the move,
and lets approve refuse to write until `--yes`.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from .lockfile import Lock

_CRITICAL_NEEDLES = (
    "id_rsa", ".ssh/", ".aws/", "begin private", "ignore previous",
    "exfiltrat", "~/.cursor", "do not tell the user",
)


@dataclass(frozen=True)
class Change:
    identity: str
    kind: str
    name: str
    old: str
    new: str
    grade: str  # critical | high | note


def grade(text: str) -> str:
    lowered = (text or "").lower()
    if any(needle in lowered for needle in _CRITICAL_NEEDLES):
        return "critical"
    return "high"


def word_diff(old: str, new: str) -> str:
    """The words that moved, not a whole-line replace."""
    a, b = (old or "").split(), (new or "").split()
    if a == b:
        return ""
    bits: list[str] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b).get_opcodes():
        if tag in ("replace", "delete") and i1 != i2:
            bits.append("-" + " ".join(a[i1:i2]))
        if tag in ("replace", "insert") and j1 != j2:
            bits.append("+" + " ".join(b[j1:j2]))
    return " ".join(bits)


def acknowledged(moved: list[Change], *, yes: bool,
                 yes_tools: list[str] | None = None) -> bool:
    """True if every change has been named.

    `--yes` names them all. `--yes-tool` names one tool. A digest or
    command change is not a tool and still needs `--yes`.
    """
    if not moved or yes:
        return True
    named = set(yes_tools or [])
    if not named:
        return False
    for item in moved:
        if item.kind == "tool" and item.name in named:
            continue
        return False
    return True


def changes(previous: Lock, current: Lock) -> list[Change]:
    out: list[Change] = []
    out.extend(_server_changes(previous, current))
    out.extend(_skill_changes(previous, current))
    return out


def _server_changes(previous: Lock, current: Lock) -> list[Change]:
    out: list[Change] = []
    old_ids, new_ids = set(previous.servers), set(current.servers)
    for ident in sorted(new_ids - old_ids):
        out.append(Change(ident, "server", ident, "", "added", "note"))
    for ident in sorted(old_ids - new_ids):
        out.append(Change(ident, "server", ident, "removed", "", "note"))
    for ident in sorted(old_ids & new_ids):
        out.extend(_entry_changes(ident, previous.servers[ident],
                                  current.servers[ident]))
    return out


def _skill_changes(previous: Lock, current: Lock) -> list[Change]:
    out: list[Change] = []
    old, new = previous.skills, current.skills
    for path in sorted(set(new) - set(old)):
        out.append(Change(path, "skill", path, "", "added", "note"))
    for path in sorted(set(old) - set(new)):
        out.append(Change(path, "skill", path, "removed", "", "note"))
    for path in sorted(set(old) & set(new)):
        a, b = old[path], new[path]
        if not isinstance(a, dict) or not isinstance(b, dict):
            continue
        if a.get("fingerprint") != b.get("fingerprint"):
            out.append(Change(path, "skill", str(b.get("name") or path),
                              str(a.get("fingerprint") or "")[:16],
                              str(b.get("fingerprint") or "")[:16], "high"))
    return out


def _entry_changes(ident: str, old: object, new: object) -> list[Change]:
    if not isinstance(old, dict) or not isinstance(new, dict):
        return []
    out: list[Change] = []
    if (old.get("command_line") or "") != (new.get("command_line") or ""):
        out.append(Change(ident, "command", ident,
                          str(old.get("command_line") or ""),
                          str(new.get("command_line") or ""), "high"))
    if (old.get("artifacts") or {}) != (new.get("artifacts") or {}):
        out.append(Change(ident, "code", ident, "digest moved",
                          "digest moved", "high"))
    out.extend(_named_map_changes(ident, "tool", old.get("tools"), new.get("tools")))
    out.extend(_named_map_changes(ident, "prompt", old.get("prompts"),
                                  new.get("prompts")))
    out.extend(_named_map_changes(ident, "resource", old.get("resources"),
                                  new.get("resources")))
    old_ins = (old.get("instructions") or {}).get("fingerprint") if isinstance(
        old.get("instructions"), dict) else None
    new_ins = (new.get("instructions") or {}).get("fingerprint") if isinstance(
        new.get("instructions"), dict) else None
    if old_ins != new_ins and (old_ins or new_ins):
        preview = ""
        if isinstance(new.get("instructions"), dict):
            preview = str(new["instructions"].get("preview") or "")
        out.append(Change(ident, "instructions", ident,
                          str(old_ins or "")[:16], str(new_ins or "")[:16],
                          grade(preview)))
    return out


def _named_map_changes(ident: str, kind: str, old: object, new: object) -> list[Change]:
    old_map = old if isinstance(old, dict) else {}
    new_map = new if isinstance(new, dict) else {}
    out: list[Change] = []
    for name in sorted(set(new_map) - set(old_map)):
        meta = new_map[name] if isinstance(new_map[name], dict) else {}
        preview = str(meta.get("description_preview") or "")
        out.append(Change(ident, kind, name, "", preview or "added", grade(preview)))
    for name in sorted(set(old_map) - set(new_map)):
        out.append(Change(ident, kind, name, "removed", "", "high"))
    for name in sorted(set(old_map) & set(new_map)):
        a, b = old_map[name], new_map[name]
        if not isinstance(a, dict) or not isinstance(b, dict):
            continue
        if a.get("fingerprint") == b.get("fingerprint"):
            continue
        old_p = str(a.get("description_preview") or "")
        new_p = str(b.get("description_preview") or "")
        out.append(Change(ident, kind, name, old_p, new_p, grade(new_p)))
    return out


def render(moved: list[Change]) -> str:
    if not moved:
        return ""
    lines = [
        f"mcp-pin: {len(moved)} change(s) since the last pin.",
        "         A credential path is not a typo. Pass --yes if you reviewed them.",
        "",
    ]
    for item in moved:
        lines.append(f"  {item.grade:<8} {item.kind:<12} {item.identity}  {item.name}")
        delta = word_diff(item.old, item.new)
        if delta:
            lines.append(f"           {delta}")
        elif item.old or item.new:
            if item.old:
                lines.append(f"           - {item.old[:160]}")
            if item.new:
                lines.append(f"           + {item.new[:160]}")
    return "\n".join(lines) + "\n"
