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

import base64
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request

from .fetch import USER_AGENT, urlopen
from .rules.execution import _FLOATING, extract_package, split_package

TIMEOUT = 8.0
_UA = USER_AGENT  # one copy, in fetch.py

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


def _sri_from_shasum(shasum: str) -> str:
    """`dist.shasum` as an SRI string, which means base64 and not hex.

    Packages published before npm 5 carry only `dist.shasum`. It is hex; SRI
    digests are base64, and npm's own cache stores this same hash in the
    base64 form. Recording the hex produced a value that could never match
    the cache, so `pkgcache` compared the two, found a shared `sha1`
    algorithm, saw different text and reported `changed` -- which refuses the
    launch unconditionally. The package had not moved by one byte.

    sha1 is a weak pin and this does not pretend otherwise. MCPA036 exists for
    a registry, mirror or caching proxy serving different bytes for a name,
    and a chosen-prefix sha1 collision is within that adversary's reach. It is
    recorded because it is what npm published for this version, not because it
    settles the question.
    """
    if not shasum:
        return ""
    try:
        return "sha1-" + base64.b64encode(bytes.fromhex(shasum)).decode("ascii")
    except ValueError:
        # Not hex, so not a shasum this understands. Saying nothing is right:
        # `published` turns an empty hash into UNREACHABLE, which is reported
        # as unverifiable rather than as a pass.
        return ""


def expects_hash(server: Any) -> bool:
    """Whether this launch fetches a pinned registry artifact at spawn time.

    The question `--require-integrity` needs and could not ask. `refusal`
    only ever saw the recorded hashes, so it could tell "recorded and
    unverifiable" from "recorded and fine" -- and could not tell either from
    "never recorded at all", which it read as nothing to check and passed.

    That is the wrong way round. A lock with no hash for `npx pkg@1.2.3` is
    not a launch with nothing to verify; it is the one case where nothing was
    even looked at. `approve --safe` produces exactly that lock, and so does
    approving on a machine the registry could not be reached from -- the
    air-gapped runner the README says will fail on this.
    """
    found = extract_package(server)
    if not found:
        return False
    runner, token = found
    name, version = split_package(token, runner)
    return bool(name and version and not _FLOATING.match(version))


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
        integrity = _sri_from_shasum(str(dist.get("shasum") or ""))
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
    for item in _installable_first(urls):
        digests = item.get("digests") if isinstance(item.get("digests"), dict) else {}
        sha = str(digests.get("sha256") or "")
        if not sha:
            continue
        where = str(item.get("url") or "")
        found = {key: where} if where.startswith(("https://", "http://")) else {}
        return Published(ANSWERED, {key: f"sha256-{sha}"}, found)
    return Published(UNREACHABLE,
                     detail=f"no file on PyPI for {name}=={version} publishes a sha256")


def _installable_first(urls: list[Any]) -> list[dict[str, Any]]:
    """The release's files, wheels before sdists.

    A release carries every distribution PyPI holds for it, and the order is
    the API's, not a preference. `uvx` and `pipx` install a wheel when one
    fits, so recording whichever file happened to come first could pin the
    sdist while the wheel is what runs -- and then `pkgcache` looks up a URL
    the machine never fetched and answers `absent`, which under
    `--require-integrity` refuses the launch.

    This does not attempt to pick the *right* wheel: platform tags, ABI and
    Python version all decide that, and this has no business resolving it
    offline. Preferring a wheel is the part that is knowable here, and it is
    the part that was wrong.
    """
    files = [item for item in urls if isinstance(item, dict)]
    wheels = [f for f in files if str(f.get("packagetype") or "") == "bdist_wheel"]
    return wheels + [f for f in files if f not in wheels]
