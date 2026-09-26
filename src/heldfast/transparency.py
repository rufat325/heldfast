"""Is this hosted server showing you what it shows everyone?

Every supply-chain check there is starts from a package: a name and a
version, code to download and read. That is how every malicious MCP release
so far was caught. Two in three servers in the official MCP registry have
no package. A hosted server is a URL: nothing to download, no version, and
what it tells your agent can change between one request and the next -- or
differ between one client and the next. A server that shows every scanner
a clean tool and shows one company a poisoned one leaves nothing for any
scanner to find, because the scanners are shown the clean one.

The web had this problem with certificates, and solved it with a public
log: a certificate nobody else has seen is not trusted. The drift feed is
that log for hosted MCP servers. It reads each registry-listed endpoint
every day, as an anonymous client, and keeps every tool list it was given.
This compares what a server shows you with that record:

- **same** -- every tool you see, the public log has recorded, definition
  for definition;
- **differs** -- a tool the public knows by that name, whose definition as
  shown to you the log has never recorded. The server is telling you
  something it has not told anyone else. This is the shape of a targeted
  attack, and approve refuses it unless the tool is named with --yes-tool;
- **unlogged** -- a tool the public log has never seen at all. Expected
  when you are signed in and the public is not; worth reading, not proof;
- **not in the log** -- the feed does not read this URL (it reads servers
  listed in the registry that answer without credentials).

What it trusts: the log is the feed branch's git history, read at one
commit, so a record cannot change without the commit changing -- but it is
published by one party, not yet witnessed by others. See docs/TRANSPARENCY.md.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from . import feedlock
from .feedlock import Feed, FeedError
from .model import ToolSpec

# How far back a definition you see is looked for, in logged versions of
# that server. A tool list that was public last week was public.
DEPTH = 10


@dataclass
class Witness:
    identity: str
    url: str
    # same | differs | unlogged | not-in-log | unreachable
    status: str = "not-in-log"
    log_name: str = ""
    logged_at: str = ""
    versions_read: int = 0
    # How often the log saw this server change its tools. A server whose
    # definitions move on their own will also read as "differs" between
    # readings, and a reader deciding what a difference means should know.
    changes_logged: int = 0
    same: list[str] = field(default_factory=list)
    differs: list[str] = field(default_factory=list)
    unseen: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"server": self.identity, "url": self.url, "status": self.status,
                "log_name": self.log_name, "logged_at": self.logged_at,
                "versions_read": self.versions_read,
                "changes_logged": self.changes_logged, "same": self.same,
                "differs": self.differs, "unseen": self.unseen,
                "missing": self.missing, "note": self.note}


def normalize(url: str) -> str:
    """The form two readings of one endpoint agree on: scheme and host
    lowercased, no fragment, no trailing slash on the path."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def public(url: str) -> bool:
    """Could a public log hold this URL at all? Not a loopback, private or
    link-local address, and not a name only a local network resolves -- the
    feed reads the internet, and asking it about these would only leak them."""
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal",
                                                          ".lan", ".home.arpa")):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "." in host
    return ip.is_global


def url_index(index: dict[str, Any]) -> dict[str, str]:
    """normalized URL -> the feed's name for that hosted server."""
    out: dict[str, str] = {}
    for name, entry in index.items():
        url = entry.get("url") if isinstance(entry, dict) else None
        if isinstance(url, str) and url:
            out.setdefault(normalize(url), name)
    return out


def _logged_tools(feed: Feed, name: str, version: str, identity: str) -> list[tuple[str, str]]:
    """(tool name, lockfile fingerprint) for one logged reading.

    The current layout lists each tool's fingerprint beside its digest, so
    nothing more is fetched; the first layout carries the definitions, which
    are fingerprinted here by the parser --probe uses.
    """
    from .probe import _parse_tools

    base = f"{feed.base}/catalogues/{name.replace('/', '__')}/{version}"
    body = feedlock.get_json(base + ".json")
    if isinstance(body, dict) and isinstance(body.get("tools"), list):
        if body.get("package") != name or str(body.get("version")) != version:
            raise FeedError(f"{base}.json: not a catalogue for {name}@{version}")
        return [(str(e.get("name")), str(e.get("fingerprint")))
                for e in body["tools"] if isinstance(e, dict) and e.get("fingerprint")]
    body = feedlock.get_json(base + ".json.gz")
    if body is None:
        return []
    if (not isinstance(body, dict) or body.get("package") != name
            or str(body.get("version")) != version or not isinstance(body.get("tools"), list)):
        raise FeedError(f"{base}.json.gz: not a catalogue for {name}@{version}")
    return [(t.name, t.fingerprint())
            for t in _parse_tools(identity, {"result": {"tools": body["tools"]}})]


def witness(identity: str, url: str, live: list[ToolSpec], log_name: str,
            entry: dict[str, Any], feed: Feed, depth: int = DEPTH) -> Witness:
    """Compare the tools a server showed this client with the public log."""
    out = Witness(identity, url, log_name=log_name,
                  changes_logged=len(entry.get("events") or []))
    versions = [str(v.get("version")) for v in entry.get("versions") or []
                if isinstance(v, dict) and v.get("version")][-depth:]
    if not versions:
        out.note = "the log holds no reading of this server"
        return out
    out.logged_at = str((entry["versions"][-1] or {}).get("published") or versions[-1])
    names: set[str] = set()
    prints: set[str] = set()
    latest: set[str] = set()
    wanted = {t.fingerprint() for t in live}
    # Newest first, stopping as soon as everything shown has been found.
    for i, version in enumerate(reversed(versions)):
        logged = _logged_tools(feed, log_name, version, identity)
        out.versions_read += 1
        if i == 0:
            latest = {n for n, _ in logged}
        names |= {n for n, _ in logged}
        prints |= {fp for _, fp in logged}
        if wanted <= prints:
            break
    for t in sorted(live, key=lambda t: t.name):
        if t.fingerprint() in prints:
            out.same.append(t.name)
        elif t.name in names:
            out.differs.append(t.name)
        else:
            out.unseen.append(t.name)
    out.missing = sorted(latest - {t.name for t in live})
    out.status = "differs" if out.differs else "unlogged" if out.unseen else "same"
    return out


def check(servers: list, tools: list[ToolSpec], index: dict[str, Any], feed: Feed,
          errors: dict[str, str] | None = None) -> list[Witness]:
    """A Witness for every hosted server among `servers`."""
    by_url = url_index(index)
    errors = errors or {}
    out = []
    for spec in servers:
        if spec.disabled or not spec.is_remote or not spec.url:
            continue
        ident = spec.identity()
        live = [t for t in tools if t.server == ident]
        name = by_url.get(normalize(spec.url))
        if not live:
            out.append(Witness(ident, spec.url, "unreachable",
                               note=errors.get(ident) or "not probed"))
        elif not public(spec.url):
            out.append(Witness(ident, spec.url, note=(
                "a local or private address; no public log can hold it")))
        elif name is None:
            out.append(Witness(ident, spec.url, note=(
                "not in the public log: the feed reads the hosted servers listed in the "
                "MCP registry that answer without credentials, and this URL is not one")))
        else:
            out.append(witness(ident, spec.url, live, name, index[name], feed))
    return out


def render(found: list[Witness], source: str) -> str:
    lines = [f"heldfast verify -- public log {source}", ""]
    for w in found:
        head = f"  {w.identity:<28}"
        if w.status == "same":
            lines.append(f"{head} same as the public log: {len(w.same)} tool(s), "
                         f"last logged {w.logged_at[:10]}")
        elif w.status == "differs":
            lines.append(f"{head} DIFFERS from the public log")
            lines.append(f"      shows you a definition the public log has never recorded: "
                         f"{', '.join(w.differs)}")
            lines.append("      the server is telling you something it has not told anyone "
                         "else. Read these tools before any agent uses them.")
            if w.changes_logged >= 2:
                lines.append(f"      the log saw this server change its tools {w.changes_logged} "
                             f"times; a definition that moves on its own reads this way too, "
                             f"so compare the words")
        elif w.status == "unlogged":
            lines.append(f"{head} {len(w.unseen)} tool(s) the public log has never seen: "
                         f"{', '.join(w.unseen)}")
            lines.append("      expected if you are signed in and the public is not; "
                         "read them")
        elif w.status == "unreachable":
            lines.append(f"{head} not checked: the server did not answer ({w.note})")
        else:
            lines.append(f"{head} {w.note}")
        if w.missing and w.status in ("same", "differs", "unlogged"):
            lines.append(f"      the public sees {len(w.missing)} tool(s) you do not: "
                         f"{', '.join(w.missing[:8])}{' ...' if len(w.missing) > 8 else ''}")
    differs = [w for w in found if w.status == "differs"]
    lines.append("")
    if not found:
        lines.append("No hosted server is configured; the public log covers hosted servers.")
    elif differs:
        lines.append(f"{len(differs)} server(s) show you tools the public log has never "
                     f"recorded.")
    else:
        lines.append("No server shows you a definition the public log has not recorded.")
    return "\n".join(lines) + "\n"
