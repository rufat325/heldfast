"""What an approved tool is allowed to be *asked to do*.

The lockfile answers "is this the tool I approved". That is integrity, and it
is not the same question as authority. A `delete_file` tool whose definition
has not changed by one byte is still the tool that deletes `~/.ssh/id_rsa` if
something talks the agent into asking for that.

So policy constrains arguments, not identity:

    "delete_file": {"paths": ["/workspace/**"]}
    "query":       {"sql": ["SELECT"]}
    "fetch":       {"domains": ["api.github.com"]}
    "run_command": {"deny": true}

It lives in `.mcp-audit.lock` next to the fingerprints, deliberately. One
committed file already governs code review, CI and runtime enforcement; a
second policy file in a different format would let the thing a reviewer read
and the thing a machine enforces drift apart, which is the failure this
project exists to catch.

Three properties this has to hold, in order of how badly they fail:

Deterministic. No model decides anything here. A policy that sometimes allows
a call is not a boundary, and an argument check that needs an API key is not
one either.

Fail-closed per constraint. If a tool has a `paths` policy, *every* path-like
argument must be inside it. A single unmatched value denies the call, because
the interesting request is the one that hides a second path in a field nobody
thought about.

Normalized before matching. `/workspace/../../etc/passwd` is not inside
`/workspace`, and a checker that compares the string it was handed is
decoration. Paths are resolved before they are matched, never after.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

# Leading keyword of a statement, used for both the SQL check and to decide
# whether a string is SQL at all.
_SQL_LEAD = re.compile(
    r"^\s*(?:--[^\n]*\n|/\*.*?\*/|\s)*([A-Za-z]+)", re.DOTALL)
_SQL_KEYWORDS = {
    "select", "insert", "update", "delete", "drop", "alter", "create",
    "truncate", "grant", "revoke", "merge", "replace", "call", "execute",
    "with", "explain", "show", "describe", "pragma", "attach", "vacuum",
}
_URL_LIKE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_WINDOWS_ABS = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    constraint: str = ""
    value: str = ""

    def __bool__(self) -> bool:  # `if decision:` reads as "was it allowed"
        return self.allowed


ALLOWED = Decision(True)


def looks_like_path(value: str) -> bool:
    if not value or _URL_LIKE.match(value):
        return False
    if value.startswith(("/", "~/", "./", "../")) or value in ("~", ".", ".."):
        return True
    if _WINDOWS_ABS.match(value):
        return True
    return "/" in value or "\\" in value


def looks_like_url(value: str) -> bool:
    return bool(_URL_LIKE.match(value or ""))


def looks_like_sql(value: str) -> bool:
    match = _SQL_LEAD.match(value or "")
    return bool(match) and match.group(1).lower() in _SQL_KEYWORDS


def normalize_path(value: str) -> str:
    """A comparable form of a path, with traversal already resolved.

    Matching the string as given is what makes a path allowlist theatre:
    `/workspace/../../etc/passwd` starts with `/workspace` and is not in it.
    """
    text = value.replace("\\", "/").strip()
    if text.startswith("~"):
        # ~ is the user's home whatever that expands to, and the point of a
        # path allowlist is usually to keep a tool out of it. Given a stable
        # stand-in it cannot match /workspace/** by accident.
        text = "/~/" + text[1:].lstrip("/")
    drive = ""
    if _WINDOWS_ABS.match(text):
        drive, text = text[:2], text[2:]
    normalized = posixpath.normpath(text)
    if normalized == ".":
        normalized = ""
    return (drive + normalized).rstrip("/") or "/"


def _segments_match(pattern: str, path: str) -> bool:
    """Glob match where `**` spans directories and `*` does not.

    fnmatch alone will not do: its `*` matches `/` as happily as anything
    else, so `/workspace/*` would quietly authorise `/workspace/../../etc`
    once someone stopped normalizing. Segment semantics are what people mean
    when they write these patterns.
    """
    pattern_parts = [p for p in pattern.replace("\\", "/").split("/")]
    path_parts = [p for p in path.split("/")]

    def walk(pi: int, si: int) -> bool:
        while pi < len(pattern_parts):
            part = pattern_parts[pi]
            if part == "**":
                if pi + 1 == len(pattern_parts):
                    return True
                for skip in range(si, len(path_parts) + 1):
                    if walk(pi + 1, skip):
                        return True
                return False
            if si >= len(path_parts):
                return False
            if not fnmatch.fnmatchcase(path_parts[si], part):
                return False
            pi += 1
            si += 1
        return si == len(path_parts)

    return walk(0, 0)


def path_is_allowed(value: str, patterns: list[str]) -> bool:
    candidate = normalize_path(value)
    for pattern in patterns:
        normalized = normalize_path(pattern) if "*" not in pattern else \
            pattern.replace("\\", "/")
        if _segments_match(normalized, candidate):
            return True
        # A bare directory authorises what is under it.
        base = normalized.rstrip("/")
        if base and (candidate == base or candidate.startswith(base + "/")):
            return True
    return False


def host_is_allowed(value: str, domains: list[str]) -> bool:
    host = (urlsplit(value).hostname or "").lower().rstrip(".")
    if not host:
        return False
    for allowed in domains:
        allowed = allowed.lower().lstrip("*.").rstrip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def sql_is_allowed(value: str, operations: list[str]) -> tuple[bool, str]:
    """(allowed, why not). Stacked statements are refused outright."""
    permitted = {op.lower() for op in operations}
    statements = [s for s in _split_statements(value) if s.strip()]
    if len(statements) > 1:
        return False, "more than one statement in a single argument"
    match = _SQL_LEAD.match(value)
    if not match:
        return False, "no recognizable SQL statement"
    keyword = match.group(1).lower()
    if keyword not in permitted:
        return False, f"{keyword.upper()} is not a permitted operation"
    return True, ""


def _split_statements(sql: str) -> list[str]:
    """Split on semicolons that are not inside a string literal."""
    out, current, quote = [], [], ""
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            current.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    current.append(sql[index + 1])
                    index += 2
                    continue
                quote = ""
        elif char in "'\"":
            quote = char
            current.append(char)
        elif char == ";":
            out.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    out.append("".join(current))
    return out


def _strings_in(value: Any, depth: int = 0) -> list[str]:
    """Every string anywhere in the arguments, nesting included.

    A constraint that only reads top-level arguments checks the field the
    author expected and misses the one an attacker chose.
    """
    if depth > 12:
        return []
    if isinstance(value, str):
        return [value]
    out: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            out.extend(_strings_in(item, depth + 1))
    elif isinstance(value, (list, tuple)):
        for item in value:
            out.extend(_strings_in(item, depth + 1))
    return out


class Policy:
    """The per-tool argument rules recorded for one server."""

    def __init__(self, rules: dict[str, Any] | None = None) -> None:
        self.rules = {str(k): v for k, v in (rules or {}).items()
                      if isinstance(v, dict)}

    def __bool__(self) -> bool:
        return bool(self.rules)

    @classmethod
    def from_lock_entry(cls, entry: Any) -> "Policy":
        if isinstance(entry, dict) and isinstance(entry.get("policy"), dict):
            return cls(entry["policy"])
        return cls()

    def tools(self) -> list[str]:
        return sorted(self.rules)

    def check(self, tool: str, arguments: Any) -> Decision:
        rule = self.rules.get(tool)
        if not rule:
            return ALLOWED

        if rule.get("deny") is True:
            return Decision(False, "the policy denies this tool outright", "deny", tool)

        values = _strings_in(arguments)

        paths = rule.get("paths")
        if isinstance(paths, list) and paths:
            for value in values:
                if looks_like_path(value) and not path_is_allowed(value, paths):
                    return Decision(
                        False,
                        f"{normalize_path(value)} is outside the approved paths "
                        f"({', '.join(paths)})",
                        "paths", value)

        domains = rule.get("domains")
        if isinstance(domains, list) and domains:
            for value in values:
                if looks_like_url(value) and not host_is_allowed(value, domains):
                    host = urlsplit(value).hostname or value
                    return Decision(
                        False,
                        f"{host} is not an approved destination "
                        f"({', '.join(domains)})",
                        "domains", value)

        operations = rule.get("sql")
        if isinstance(operations, list) and operations:
            for value in values:
                if looks_like_sql(value):
                    ok, why = sql_is_allowed(value, operations)
                    if not ok:
                        return Decision(
                            False,
                            f"{why}; permitted here: "
                            f"{', '.join(o.upper() for o in operations)}",
                            "sql", value)

        return ALLOWED


# ---------------------------------------------------------------------------
# Proposing a starter policy
# ---------------------------------------------------------------------------
#
# A policy nobody writes protects nothing, and writing one from scratch means
# reading every tool's schema by hand. This proposes one from what a probe
# already saw, so the job becomes reviewing and tightening rather than
# starting from an empty object.
#
# Everything it proposes is deliberately a placeholder that will not work
# until someone edits it. A generated policy that silently permitted the
# machine's actual home directory would be worse than no policy: it would read
# like a boundary and be a rubber stamp.

_PATH_PARAM = re.compile(
    r"^(?:path|paths|file|files|filename|filepath|dir|directory|folder|"
    r"source|destination|target|src|dst|location)$", re.IGNORECASE)
_URL_PARAM = re.compile(
    r"^(?:url|uri|endpoint|webhook|callback|callback_url|target_url|"
    r"upload_url|host|address)$", re.IGNORECASE)
_SQL_PARAM = re.compile(
    r"^(?:sql|query|statement|command_text|expression)$", re.IGNORECASE)

PATH_PLACEHOLDER = "/REPLACE-ME/**"
DOMAIN_PLACEHOLDER = "replace-me.example.com"


def _property_names(schema: Any) -> list[str]:
    properties = (schema or {}).get("properties") if isinstance(schema, dict) else None
    return [str(name) for name in properties] if isinstance(properties, dict) else []


def suggest(tools: Any, destructive_verbs: tuple = ()) -> dict[str, dict[str, Any]]:
    """A starter policy for these tools, as {tool: constraints}.

    Only tools whose schema actually takes a path, a destination or a query
    get a constraint. Proposing something for every tool would train people
    to delete most of the file, and the ones they kept would be the ones they
    stopped reading.
    """
    out: dict[str, dict[str, Any]] = {}
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        properties = _property_names(getattr(tool, "input_schema", None))
        rule: dict[str, Any] = {}

        if any(_PATH_PARAM.match(p) for p in properties):
            rule["paths"] = [PATH_PLACEHOLDER]
        if any(_URL_PARAM.match(p) for p in properties):
            rule["domains"] = [DOMAIN_PLACEHOLDER]
        if any(_SQL_PARAM.match(p) for p in properties):
            rule["sql"] = ["SELECT"]

        lowered = name.lower()
        if any(verb in lowered for verb in destructive_verbs):
            # Named like it destroys something. Denying outright is the safe
            # proposal; whoever reviews this can downgrade it to a path limit
            # if the tool is genuinely needed.
            rule = {"deny": True}

        if rule:
            out[name] = rule
    return dict(sorted(out.items()))
