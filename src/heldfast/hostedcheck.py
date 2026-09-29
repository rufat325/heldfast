"""Which approved tools of hosted servers read differently now.

The Claude Code hook sees a tool's name and never its definition, so on its
own it cannot notice a tool rewritten under an approved name. At session
start it can ask this: for every hosted (HTTP) server the lock records, read
its tool list the way `scan --probe --no-stdio-probe` does -- which runs none
of the server's code -- and compare each tool's fingerprint with the lock.
The hook then refuses the drifted tools for that session.

Only the recorded URL is used, with no headers: a server that wants a login
cannot be read here, and is reported as unverified rather than as drifted,
so it is not refused on that account. Stdio servers are not read at all:
reading one means launching it, which is `wrap`'s job, not a hook's. This
never writes the lock.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .model import ServerSpec


def _hosted(lock_servers: dict[str, Any]) -> list[tuple[str, dict]]:
    return [(key, entry) for key, entry in sorted(lock_servers.items())
            if isinstance(entry, dict) and isinstance(entry.get("url"), str) and entry["url"]
            and str(entry.get("transport") or "http") in ("http", "sse", "streamable-http")]


def check_one(key: str, entry: dict, timeout: float) -> dict[str, Any]:
    from .probe import probe_http
    if "[REDACTED" in entry["url"]:
        # The lock keeps a URL's credential out of the repository, so this
        # reading cannot reconnect with it. Unverified, not drifted.
        return {"state": "unverified", "drifted": [],
                "why": "the lockfile keeps this URL redacted; its credential is not stored"}
    spec = ServerSpec(name=str(entry.get("name") or key.split(":", 1)[-1]),
                      source=str(entry.get("source") or ""),
                      client=str(entry.get("client") or key.split(":", 1)[0]),
                      transport="http", url=entry["url"])
    result = probe_http(spec, timeout)
    if result.error:
        return {"state": "unverified", "why": str(result.error)[:200], "drifted": []}
    approved = entry.get("tools") if isinstance(entry.get("tools"), dict) else {}
    drifted = sorted(t.name for t in result.tools
                     if t.name in approved and isinstance(approved[t.name], dict)
                     and approved[t.name].get("fingerprint") != t.fingerprint())
    return {"state": "read", "drifted": drifted}


def check(lock_servers: dict[str, Any], timeout: float = 5.0) -> dict[str, dict[str, Any]]:
    """{lock key: {"state": "read" | "unverified", "drifted": [tool names], "why"?}}"""
    hosted = _hosted(lock_servers)
    if not hosted:
        return {}
    with ThreadPoolExecutor(max_workers=min(8, len(hosted))) as pool:
        answers = pool.map(lambda item: (item[0], check_one(item[0], item[1], timeout)), hosted)
        return dict(answers)
