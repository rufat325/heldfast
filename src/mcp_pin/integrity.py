"""The tarball behind `npx pkg@1.2.3`, not the version string.

A version pin is a name lookup. The registry can serve different bytes for
the same name. npm and PyPI publish an integrity hash with each artifact;
this records it at approval and a later scan compares. Stdlib only.

Three outcomes, and keeping them apart is the whole design. `{}` used to mean
both "this launch fetches nothing from a registry" and "the registry did not
answer", which made silence ambiguous: anyone able to break the lookup bought
quiet, and an air-gapped CI runner bought the same quiet by accident. A
`Published` now says which happened, `scan` reports the difference, and
`--require-integrity` turns "could not see" into a failure for the runners
that need it.

The artifact URL is recorded alongside the hash because `pkgcache` needs it
to find the same file in the local package cache, which is how the pin
reaches launch time rather than stopping at scan time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .rules.execution import _FLOATING, extract_package, split_package

TIMEOUT = 8.0
_UA = "mcp-pin (+https://github.com/rufat325/mcp-pin)"

# What `state` can be.
ANSWERED = "answered"
UNREACHABLE = "unreachable"
NOT_REGISTRY = "not-registry"


@dataclass(frozen=True)
class Published:
    """What a registry says about this server's artifact, or why it did not."""

    state: str = NOT_REGISTRY
    hashes: dict[str, str] = field(default_factory=dict)
    urls: dict[str, str] = field(default_factory=dict)
    detail: str = ""


def get_json(url: str) -> dict[str, Any] | None:
    """GET JSON, or None. Tests replace this."""
    try:
        req = Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        with urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, URLError, ValueError, TimeoutError):
        return None


def published(server: Any) -> Published:
    """Ask the registry what it serves for this server's pinned package.

    Opens a socket. Callers that promised not to (`--safe`) must not call it;
    see `cli._stamp_integrity` and the MCPA036/037 rules.
    """
    found = extract_package(server)
    if not found:
        return Published(detail="the launch command fetches no registry package")
    runner, token = found
    name, version = split_package(token, runner)
    if not name or not version or _FLOATING.match(version):
        return Published(detail="no version is pinned, so there is nothing to "
                                "record a hash against (MCPA003)")
    version = version.lstrip("=@ ")
    if runner in {"uvx", "pipx"}:
        return _pypi(name, version)
    return _npm(name, version)


def lookup(server: Any) -> dict[str, str]:
    """{ecosystem:name@version: integrity} for a pinned registry launch.

    Kept because it is the narrow question most callers ask. A failed fetch
    and a launch with no package both answer `{}` here; anything that must
    tell those apart asks `published` instead.
    """
    return published(server).hashes


def _npm(name: str, version: str) -> Published:
    enc = quote(name, safe="@")
    data = get_json(f"https://registry.npmjs.org/{enc}/{quote(version, safe='')}")
    if not data:
        return Published(UNREACHABLE,
                         detail=f"registry.npmjs.org did not answer for {name}@{version}")
    key = f"npm:{name}@{version}"
    dist = data.get("dist") if isinstance(data.get("dist"), dict) else {}
    urls = {}
    tarball = str(dist.get("tarball") or "")
    if tarball.startswith(("https://", "http://")):
        urls[key] = tarball
    integrity = str(dist.get("integrity") or "")
    if not integrity:
        shasum = str(dist.get("shasum") or "")
        integrity = f"sha1-{shasum}" if shasum else ""
    if not integrity:
        return Published(UNREACHABLE, urls=urls,
                         detail=f"npm published no integrity hash for {name}@{version}")
    return Published(ANSWERED, {key: integrity}, urls)


def _pypi(name: str, version: str) -> Published:
    data = get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json")
    if not data:
        return Published(UNREACHABLE,
                         detail=f"pypi.org did not answer for {name}=={version}")
    urls = data.get("urls")
    if not isinstance(urls, list):
        return Published(UNREACHABLE,
                         detail=f"pypi.org returned no files for {name}=={version}")
    key = f"pypi:{name}=={version}"
    for item in urls:
        if not isinstance(item, dict):
            continue
        digests = item.get("digests") if isinstance(item.get("digests"), dict) else {}
        sha = str(digests.get("sha256") or "")
        if not sha:
            continue
        where = str(item.get("url") or "")
        found = {key: where} if where.startswith(("https://", "http://")) else {}
        return Published(ANSWERED, {key: f"sha256-{sha}"}, found)
    return Published(UNREACHABLE,
                     detail=f"no file on PyPI for {name}=={version} publishes a sha256")
