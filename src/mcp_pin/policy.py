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

It lives in `.mcp-pin.lock` next to the fingerprints, deliberately. One
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
from urllib.parse import unquote, urlsplit

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

# Constraint keys this tool knows how to enforce. Anything else in a rule is
# a hand-edit for a checker that does not exist, and ignoring it would fail
# *open* on the one field somebody thought they had covered.
KNOWN_CONSTRAINTS = frozenset({"deny", "paths", "domains", "sql"})


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
    # Unmasked first, or `/*!50000 DROP*/ TABLE t` is not recognised as SQL
    # at all and the whole rule is skipped for it -- the gate mattering more
    # than the check behind it.
    match = _SQL_LEAD.match(unmask_sql(value))
    if match is None:
        return False
    return match.group(1).lower() in _SQL_KEYWORDS


def _decoded(value: str, rounds: int = 3) -> str:
    """Percent-decoding applied until it stops changing anything.

    `/workspace/%2e%2e/etc/passwd` is only an escape for a server that decodes
    its argument -- one taking the path from a URI does, one calling open()
    does not -- and `%252e%252e` is the same trick with one more layer. The
    cost of decoding is a file genuinely named `%2e%2e` becoming unreachable,
    which is a trade worth making in the direction of refusing.

    Bounded, because "until stable" on hostile input is a loop somebody can
    make expensive.
    """
    text = str(value or "")
    for _ in range(rounds):
        nxt = unquote(text)
        if nxt == text:
            break
        text = nxt
    return text


def normalize_path(value: str) -> str:
    """A comparable form of a path, with traversal already resolved.

    Matching the string as given is what makes a path allowlist theatre:
    `/workspace/../../etc/passwd` starts with `/workspace` and is not in it.
    """
    text = _decoded(value).replace("\\", "/").strip()
    if text.startswith("~"):
        # ~ is the user's home whatever that expands to, and the point of a
        # path allowlist is usually to keep a tool out of it. Given a stable
        # stand-in it cannot match /workspace/** by accident.
        text = "/~/" + text[1:].lstrip("/")
    drive = ""
    if _WINDOWS_ABS.match(text):
        # `c:` and `C:` are the same drive, so the letter is folded here
        # rather than left for the comparison to worry about.
        drive, text = text[:2].upper(), text[2:]
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
    """Whether this path is inside one of the approved patterns.

    Windows paths compare without case, because there they name the same file
    -- a policy allowing C:/workspace that refuses c:/workspace is not
    stricter, only broken, and over-blocking is what gets a tool switched off.
    POSIX paths stay case-sensitive, because there /Workspace really is a
    different directory.
    """
    candidate = normalize_path(value)
    for pattern in patterns:
        normalized = normalize_path(pattern) if "*" not in pattern else \
            pattern.replace("\\", "/")
        windows = bool(_WINDOWS_ABS.match(candidate) or _WINDOWS_ABS.match(normalized))
        left, right = (normalized.lower(), candidate.lower()) if windows else \
            (normalized, candidate)
        if _segments_match(left, right):
            return True
        # A bare directory authorises what is under it.
        base = left.rstrip("/")
        if base and (right == base or right.startswith(base + "/")):
            return True
    return False


def host_is_allowed(value: str, domains: list[str]) -> bool:
    """Whether a URL's host is approved.

    Both the host extraction and the backslash defence live in `host_of`, so
    there is one copy of each. Two copies would mean either could be removed
    without the other noticing, which is the same as having none.
    """
    return host_allowed(host_of(value) or "", domains)


def host_allowed(host: str, domains: list[str]) -> bool:
    """Whether an already-extracted host is in the allowlist.

    Split out from `host_is_allowed` so the schemeless forms -- a bare
    `evil.example` in a `host` parameter, `//evil.example/x` -- are matched
    by exactly the same suffix rule rather than a second copy of it.
    """
    if not host:
        return False
    for allowed in domains:
        allowed = allowed.lower().lstrip("*.").rstrip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


# MySQL runs what is inside `/*! ... */` and `/*!50000 ... */`. Treating it
# as a comment is how `/*!50000 DROP*/ TABLE t` reached a database while the
# policy read the remainder and saw no statement it recognised at all.
_MYSQL_EXEC_COMMENT = re.compile(r"/\*!\d*\s?(.*?)\*/", re.DOTALL)

# A SELECT that writes a file. The operation allowlist sees SELECT and is
# satisfied; the engine writes to disk as the server's user.
_SELECT_WRITES = re.compile(r"\binto\s+(?:out|dump)file\b", re.IGNORECASE)


def unmask_sql(value: str) -> str:
    """SQL as the engine will read it, not as a comment-stripper sees it."""
    return _MYSQL_EXEC_COMMENT.sub(r" \1 ", str(value or ""))


def _without_literals(sql: str) -> str:
    """The statement with quoted contents blanked out.

    Keyword matching has to ignore string literals or it reports the data
    rather than the query: `WHERE note = 'into outfile'` is a search for a
    phrase, not a write. Found by the precision case in the same commit that
    added the check.
    """
    out, quote = [], ""
    for ch in str(sql or ""):
        if quote:
            if ch == quote:
                quote = ""
            out.append(" " if ch != quote else ch)
        elif ch in "'\"`":
            quote = ch
            out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def sql_is_allowed(value: str, operations: list[str]) -> tuple[bool, str]:
    """(allowed, why not). Stacked statements are refused outright."""
    permitted = {op.lower() for op in operations}
    value = unmask_sql(value)
    statements = [s for s in _split_statements(value) if s.strip()]
    if len(statements) > 1:
        return False, "more than one statement in a single argument"
    match = _SQL_LEAD.match(value)
    if not match:
        return False, "no recognizable SQL statement"
    keyword = match.group(1).lower()
    if keyword not in permitted:
        return False, f"{keyword.upper()} is not a permitted operation"
    if keyword == "select" and _SELECT_WRITES.search(_without_literals(value)):
        return False, ("SELECT ... INTO OUTFILE writes a file; permitting SELECT "
                       "permits reading, not writing")
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


MAX_ARGUMENT_DEPTH = 12


class PolicyTooDeep(Exception):
    """Arguments nested deeper than the policy will walk.

    Raised rather than returning what was found so far. Returning the partial
    list made the depth cap a bypass: anything below level 12 was simply not
    seen, and "we stopped looking" gave the same verdict as "there was nothing
    to find". A constraint that fails open on input whose shape the attacker
    chooses is not a constraint.
    """

    def __init__(self, depth: int) -> None:
        super().__init__(f"arguments nested deeper than {depth} levels")
        self.depth = depth


def _values_in(value: Any, name: str = "", depth: int = 0) -> list[tuple[str, str]]:
    """Every string in the arguments, paired with the key it sits under.

    The name matters as much as the value. Classifying purely by shape means
    a rule limiting `paths` never looks at a parameter called `path` whose
    value happens not to look like one -- `.env` has no separator, so it read
    as ordinary text and went straight through a paths allowlist, while
    `./.env`, the same file, was refused.

    A string inside a list keeps the list's own key, because `{"paths": [..]}`
    is how these parameters usually arrive.
    """
    if depth > MAX_ARGUMENT_DEPTH:
        raise PolicyTooDeep(depth)
    if isinstance(value, str):
        return [(name, value)]
    out: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            out.extend(_values_in(item, str(key), depth + 1))
    elif isinstance(value, (list, tuple)):
        for item in value:
            out.extend(_values_in(item, name, depth + 1))
    return out


def file_url_path(value: str) -> str | None:
    """The local path a `file:` URL names, or None if it is not one.

    `file:///etc/passwd` is a URL, so `looks_like_path` skipped it; on a rule
    with `paths` and no `domains`, nothing else looked at it either. It names
    a local file as plainly as `/etc/passwd` does, so it is checked as one.
    """
    if not value.lower().startswith("file:"):
        return None
    path = unquote(urlsplit(value).path)
    # file:///C:/x parses with a leading slash before the drive letter.
    if _WINDOWS_ABS.match(path.lstrip("/")[:3]):
        path = path.lstrip("/")
    return path or None


def host_of(value: str) -> str | None:
    """The host a string names, whether or not it carries a scheme.

    `looks_like_url` requires `scheme://`, so a domain allowlist ignored
    `evil.example/upload`, `//evil.example/x`, and a bare `evil.example` in a
    `host` parameter. A server handed any of those reaches the same place.
    """
    text = (value or "").strip()
    if not text:
        return None
    # A backslash in the authority is a parser differential, not a URL.
    # Python reads `https://evil.io\@api.github.com/x` as userinfo `evil.io\`
    # on host api.github.com; WHATWG parsers -- browsers, Node's `new URL`,
    # Go -- treat `\` as `/`, which ends the authority at evil.io. So the
    # policy would approve one host and the server would fetch another.
    # Nothing legitimate needs it, so no host is named for it at all.
    if "\\" in text.split("?", 1)[0]:
        return None
    if _URL_LIKE.match(text):
        candidate = text
    elif text.startswith("//"):
        candidate = "http:" + text
    else:
        candidate = "http://" + text
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    return (host or "").lower().rstrip(".") or None


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

        # Any truthy value, not just `True`. `deny` is the one boolean among
        # four keys that are otherwise all lists, so `"deny": ["wipe"]` is the
        # natural hand-edit -- and reading it strictly meant that entry denied
        # nothing at all while looking like it denied something.
        if rule.get("deny"):
            return Decision(False, "the policy denies this tool outright", "deny", tool)

        unknown = [key for key in rule if key not in KNOWN_CONSTRAINTS]
        if unknown:
            return Decision(
                False,
                f"unknown policy constraint {unknown[0]!r}; "
                f"refusing rather than ignoring it",
                "unknown", unknown[0])

        try:
            pairs = _values_in(arguments)
        except PolicyTooDeep as exc:
            # Refuse rather than check a prefix of the arguments. The depth
            # cap exists to bound the walk, not to define a region the policy
            # does not apply to.
            return Decision(
                False,
                f"arguments nest deeper than {exc.depth} levels; refusing "
                f"rather than checking only part of them",
                "depth", "")
        values = [text for _, text in pairs]

        # Policy is hand-written, so it arrives malformed sooner or later --
        # a null left in a list, a string where a list belongs. Non-strings
        # are dropped rather than crashed on: this runs inside the proxy's
        # pump, and an exception here would hang the agent rather than
        # failing open the way the guard promises to.
        def entries(value: Any) -> list[str]:
            if not isinstance(value, list):
                return []
            return [item for item in value if isinstance(item, str) and item.strip()]

        paths = entries(rule.get("paths"))
        if paths:
            for name, value in pairs:
                # By name as well as by shape. A parameter the schema calls
                # `path` holds a path whatever the value looks like, which is
                # what `.env` exploited; and a `file:` URL names a local file
                # however it is spelled.
                named = bool(_PATH_PARAM.match(name))
                candidate = file_url_path(value)
                if candidate is None:
                    if not (named or looks_like_path(value)):
                        continue
                    candidate = value
                if not candidate.strip():
                    continue
                if not path_is_allowed(candidate, paths):
                    return Decision(
                        False,
                        f"{normalize_path(candidate)} is outside the approved "
                        f"paths ({', '.join(paths)})",
                        "paths", value)

        domains = entries(rule.get("domains"))
        if domains:
            for name, value in pairs:
                named = bool(_URL_PARAM.match(name))
                if not (named or looks_like_url(value)):
                    continue
                host = host_of(value)
                if host is None:
                    # A parameter that should name a destination and does not
                    # resolve to one. Refusing beats guessing: the server will
                    # resolve it somehow, and this is the one chance to say no.
                    return Decision(
                        False,
                        f"{value!r} does not name a resolvable host; approved "
                        f"destinations are {', '.join(domains)}",
                        "domains", value)
                if not host_allowed(host, domains):
                    return Decision(
                        False,
                        f"{host} is not an approved destination "
                        f"({', '.join(domains)})",
                        "domains", value)

        operations = entries(rule.get("sql"))
        if operations:
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


def suggest(tools: Any, destructive_verbs: tuple[str, ...] = ()) -> dict[str, dict[str, Any]]:
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
