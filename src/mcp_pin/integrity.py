"""The tarball behind `npx pkg@1.2.3`, not the version string.

A version pin is a name lookup. The registry can serve different bytes for
the same name. npm and PyPI publish an integrity hash with each artifact;
this records it at approval and a later scan compares. Stdlib only. A
failed fetch is not a finding -- it is "we could not see" -- and the
version string remains the pin.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .rules.execution import _FLOATING, extract_package, split_package

TIMEOUT = 8.0
_UA = "mcp-pin (+https://github.com/rufat325/mcp-pin)"


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


def lookup(server: Any) -> dict[str, str]:
    """{ecosystem:name@version: integrity} for a pinned registry launch."""
    found = extract_package(server)
    if not found:
        return {}
    runner, token = found
    name, version = split_package(token, runner)
    if not name or not version or _FLOATING.match(version):
        return {}
    version = version.lstrip("=@ ")
    if runner in {"uvx", "pipx"}:
        digest = _pypi(name, version)
        if digest:
            return {f"pypi:{name}=={version}": digest}
        return {}
    digest = _npm(name, version)
    if digest:
        return {f"npm:{name}@{version}": digest}
    return {}


def _npm(name: str, version: str) -> str | None:
    enc = quote(name, safe="@")
    data = get_json(f"https://registry.npmjs.org/{enc}/{quote(version, safe='')}")
    if not data:
        return None
    dist = data.get("dist") if isinstance(data.get("dist"), dict) else {}
    integrity = str(dist.get("integrity") or "")
    if integrity:
        return integrity
    shasum = str(dist.get("shasum") or "")
    return f"sha1-{shasum}" if shasum else None


def _pypi(name: str, version: str) -> str | None:
    data = get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json")
    if not data:
        return None
    urls = data.get("urls")
    if not isinstance(urls, list):
        return None
    for item in urls:
        if not isinstance(item, dict):
            continue
        digests = item.get("digests") if isinstance(item.get("digests"), dict) else {}
        sha = str(digests.get("sha256") or "")
        if sha:
            return f"sha256-{sha}"
    return None
