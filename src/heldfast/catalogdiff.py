"""What a release changes, as the clients that pinned the last one will see it.

For the people who publish an MCP server. Every client that pinned your last
release recorded each tool's fingerprint, and the next time it connects it
compares. Under the default pin, any tool you changed or added is withheld
until someone re-approves it. Under `--drift graded`, a changed tool is
forwarded when the change introduced nothing aimed at the agent, and withheld
-- with the reason -- when it did. Nearly half of upgrades across the
most-downloaded registry servers change a tool (docs/CHURN.md), so which of the
two a release lands in is the difference between a quiet upgrade and a support
ticket from every customer who pins.

This answers that before the release, from two `tools/list` results: the one
you shipped and the one you are about to. The verdicts are not a second
opinion. Each one is asked of a `Guard` holding a lock recorded from the old
catalogue -- the object `wrap` and `gateway` ask at runtime -- so this report
and a pinned client cannot disagree.

The old side may be a lockfile instead (a customer's, say), since that is what
a client actually compares against. The new side must be the full
definitions: a lockfile keeps a preview of each description and a fingerprint
of everything else, and grading a preview would call quiet a change that
introduced something in a schema the preview never held.

Pure apart from reading the two files.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .lockfile import Lock
from .model import ServerSpec, ToolSpec
from .review import word_diff
from .secrets import safe_name, safe_text

# The parts of a tool a fingerprint covers, as ToolSpec spells them.
_FIELDS = (("description", "description"), ("title", "title"),
           ("input_schema", "inputSchema"), ("output_schema", "outputSchema"),
           ("annotations", "annotations"), ("icons", "icons"))
CATALOG_KEY = "catalog:server"
MARKER = "<!-- heldfast-diff -->"


@dataclass
class ToolChange:
    name: str
    change: str                 # added | removed | changed
    pinned: str                 # what the default pin does: withheld | -
    graded: str                 # what --drift graded does: forwarded | withheld | -
    why: str
    fields: list[str] = field(default_factory=list)
    diff: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.name, "change": self.change, "default_pin": self.pinned,
                "drift_graded": self.graded, "why": self.why, "fields": self.fields,
                "description_diff": self.diff}


@dataclass
class Side:
    lock: Lock
    key: str
    # Full definitions by name, when the side was a catalogue.
    tools: dict[str, ToolSpec] | None
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Reading


def _tool_list(data: Any) -> list[Any] | None:
    """The tools of a `tools/list` result in any of its usual wrappings."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("tools"), list):
            return list(data["tools"])
        result = data.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return list(result["tools"])
    return None


def _catalog(path: Path, tools: list[Any]) -> Side:
    from .probe import _parse_tools  # the parser --probe uses, so digests agree
    parsed = [t for t in _parse_tools(CATALOG_KEY, {"result": {"tools": tools}}) if t.name]
    notes = []
    by_name: dict[str, ToolSpec] = {}
    for tool in parsed:
        if tool.name in by_name:
            notes.append(f"{path}: two tools are named {tool.name!r}; the last is used")
        by_name[tool.name] = tool
    spec = ServerSpec(name="server", source=str(path), client="catalog", transport="stdio")
    lock = Lock()
    lock.record([spec], list(by_name.values()), [])
    return Side(lock, CATALOG_KEY, by_name, notes)


def _from_lock(path: Path, server: str | None) -> Side:
    lock = Lock.load(path)
    keys = sorted(lock.servers)
    if server:
        chosen = [k for k in keys if k == server or str(
            (lock.servers[k] or {}).get("name") if isinstance(lock.servers[k], dict)
            else "") == server]
    else:
        chosen = keys
    if len(chosen) != 1:
        names = ", ".join(keys) or "none"
        raise ValueError(f"{path}: name one server with --server (it records: {names})")
    return Side(lock, chosen[0], None)


def load(path: Path, *, server: str | None = None, full: bool = False) -> Side:
    """One side of the comparison. `full` requires a catalogue."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{path}: cannot read ({type(exc).__name__}: {exc})") from None
    if isinstance(data, dict) and isinstance(data.get("servers"), dict) and "version" in data:
        if full:
            raise ValueError(
                f"{path} is a lockfile. The new side has to be the full tool "
                f"definitions (a tools/list result): a lockfile keeps a preview of "
                f"each description, and grading a preview would miss what a change "
                f"put in a schema")
        return _from_lock(path, server)
    tools = _tool_list(data)
    if tools is None:
        raise ValueError(f"{path}: neither a tools/list result nor a lockfile")
    return _catalog(path, tools)


def wire(tool: ToolSpec) -> dict[str, Any]:
    """A tool as a `tools/list` entry holding exactly what its fingerprint
    covers, so reading it back gives the same digest."""
    out: dict[str, Any] = {"name": tool.name}
    if tool.title:
        out["title"] = tool.title
    out["description"] = tool.description
    out["inputSchema"] = tool.input_schema
    if tool.output_schema:
        out["outputSchema"] = tool.output_schema
    if tool.annotations:
        out["annotations"] = tool.annotations
    if tool.icons:
        out["icons"] = tool.icons
    return out


# ---------------------------------------------------------------------------
# Comparing


def _fields(old: ToolSpec, new: ToolSpec) -> list[str]:
    def canon(value: Any) -> str:
        return json.dumps(value, sort_keys=True, default=str)
    return [wire for attr, wire in _FIELDS
            if canon(getattr(old, attr)) != canon(getattr(new, attr))]


def _old_text(old: Side, name: str) -> str:
    if old.tools is not None and name in old.tools:
        return old.tools[name].description
    entry = old.lock.servers.get(old.key)
    tools = entry.get("tools") if isinstance(entry, dict) else None
    record = tools.get(name) if isinstance(tools, dict) else None
    return str(record.get("description_preview") or "") if isinstance(record, dict) else ""


def compare(old: Side, new: Side) -> list[ToolChange]:
    """Every tool that differs, with the verdict each kind of pin gives it."""
    from .guard import Guard

    assert new.tools is not None, "the new side must be full definitions"
    graded = Guard(old.key, old.lock, drift="graded", quiet=True)
    blocked = Guard(old.key, old.lock, drift="block", quiet=True)
    entry = old.lock.servers.get(old.key)
    recorded = entry.get("tools") if isinstance(entry, dict) else None
    before = set(recorded) if isinstance(recorded, dict) else set()
    out: list[ToolChange] = []
    for name in sorted(new.tools):
        tool = new.tools[name]
        g_verdict, g_reason = graded._verdict(tool)
        b_verdict, _ = blocked._verdict(tool)
        if name not in before:
            out.append(ToolChange(name, "added", "withheld", "withheld",
                                  "not present at approval; every pin withholds it "
                                  "until it is approved"))
            continue
        if b_verdict == "allow":
            continue  # same fingerprint: nothing a pin would notice
        fields = (_fields(old.tools[name], tool)
                  if old.tools is not None and name in old.tools else [])
        out.append(ToolChange(
            name, "changed", "withheld",
            "forwarded" if g_verdict == "allow" else "withheld",
            "the change introduced nothing aimed at the agent" if g_verdict == "allow"
            else g_reason.replace("tool definition changed since approval and the "
                                  "change introduced ", "introduced "),
            fields, word_diff(_old_text(old, name), tool.description)))
    for name in sorted(before - set(new.tools)):
        out.append(ToolChange(name, "removed", "-", "-",
                              "gone; a client that called it gets an unknown tool"))
    # What every graded client will withhold first: that is what a reviewer
    # has to decide about. Removals last.
    return sorted(out, key=lambda c: (c.graded != "withheld", c.change == "removed", c.name))


def summary(changes: list[ToolChange], total: int) -> dict[str, int]:
    return {
        "tools": total,
        "changed": sum(c.change == "changed" for c in changes),
        "added": sum(c.change == "added" for c in changes),
        "removed": sum(c.change == "removed" for c in changes),
        "withheld_by_default_pin": sum(c.pinned == "withheld" for c in changes),
        "withheld_under_graded": sum(c.graded == "withheld" for c in changes),
        "forwarded_under_graded": sum(c.graded == "forwarded" for c in changes),
    }


def failed(changes: list[ToolChange], fail_on: str) -> bool:
    if fail_on == "change":
        return bool(changes)
    if fail_on == "withheld":
        return any(c.graded == "withheld" for c in changes)
    return False


# ---------------------------------------------------------------------------
# Rendering


def _headline(s: dict[str, int]) -> str:
    moved = s["changed"] + s["added"]
    if not moved and not s["removed"]:
        return f"No tool changes: all {s['tools']} tool(s) match, so no pin notices."
    parts = []
    if moved:
        them = "it" if moved == 1 else f"all {moved}"
        parts.append(f"{moved} of {s['tools']} tool(s) changed or added. A client on the "
                     f"default pin withholds {them} until it re-approves; under "
                     f"`--drift graded` {s['forwarded_under_graded']} pass and "
                     f"{s['withheld_under_graded']} withheld.")
    if s["removed"]:
        parts.append(f"{s['removed']} tool(s) removed.")
    return " ".join(parts)


def render_text(changes: list[ToolChange], s: dict[str, int], notes: list[str]) -> str:
    lines = ["", "  " + _headline(s), ""]
    for c in changes:
        lines.append(f"  {c.change:<8} {safe_name(c.name):<28} graded: {c.graded:<9} {c.why}")
        if c.fields:
            lines.append(f"           moved: {', '.join(c.fields)}")
        if c.diff:
            lines.append(f"           {safe_text(c.diff, 400)}")
    lines += [f"  note: {safe_name(n, 500)}" for n in notes]
    return "\n".join(lines) + "\n"


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()!<>|~#])")
_PLAIN_NAME = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")


def _cell(text: str) -> str:
    """Server-supplied text for Markdown, rendered as the characters it is.

    A tool description is the server's to write, and a pull request comment
    renders Markdown: an image link in one would load a tracking pixel for
    everyone who opens the PR, and a `|` would end the table cell. Every
    punctuation mark CommonMark acts on is backslash-escaped, which CommonMark
    renders as the character itself.
    """
    return _MD_SPECIAL.sub(r"\\\1", safe_name(text, 500))


def _name(text: str) -> str:
    return f"`{text}`" if _PLAIN_NAME.match(text) else _cell(text)


def render_markdown(changes: list[ToolChange], s: dict[str, int], notes: list[str]) -> str:
    lines = [MARKER, "### heldfast: this release, as a pinned client sees it", "",
             _headline(s), ""]
    if changes:
        lines += ["| tool | change | default pin | `--drift graded` | why |",
                  "|---|---|---|---|---|"]
        for c in changes:
            graded = f"**{c.graded}**" if c.graded == "withheld" else c.graded
            lines.append(f"| {_name(c.name)} | {c.change} | {c.pinned} | {graded} | "
                         f"{_cell(c.why)} |")
        diffs = [c for c in changes if c.diff or c.fields]
        if diffs:
            lines += ["", "<details><summary>What moved</summary>", ""]
            for c in diffs:
                moved = f" ({_cell(', '.join(c.fields))})" if c.fields else ""
                lines.append(f"- {_name(c.name)}{moved}" + (
                    f": {_cell(c.diff)}" if c.diff else ""))
            lines += ["", "</details>"]
    for note in notes:
        lines += ["", f"_note: {_cell(note)}_"]
    lines += ["", "<sub>Verdicts come from the same check `heldfast wrap` and "
                  "`heldfast gateway` run. Graded mode is a heuristic about what a "
                  "change introduced, not a review of it.</sub>"]
    return "\n".join(lines) + "\n"
