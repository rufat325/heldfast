"""The artifact the package manager already holds, not the one the registry
describes.

`integrity.py` asks a registry what it publishes for `pkg@1.2.3` and compares
that to what was approved. That is a report about a remote fact. It is not a
pin, for a reason worth stating plainly: `npx -y pkg@1.2.3` resolves and
fetches on its own at spawn time, so checking published metadata checks
something adjacent to -- not identical to -- the bytes that run. Between the
scan and the spawn there is a window, and the thing being asked about is not
the thing being executed.

This module closes the part of that window which can be closed without a
network call: both package managers keep the artifact on disk, and both name
it in a way that can be derived rather than searched.

npm's `_cacache` has two halves and both are read. An index entry per request
URL, sharded as `index-v5/<h[0:2]>/<h[2:4]>/<h[4:]>` where `h` is sha256 of
the cache key `make-fetch-happen:request-cache:<tarball url>`, carries the SRI
of the body it holds -- the same string npm's registry publishes as
`dist.integrity`. The body itself lives under
`content-v2/<algo>/<hex[0:2]>/<hex[2:4]>/<hex[4:]>`, keyed by that digest
decoded from base64 to hex, and it is hashed here rather than trusted.

Reading only the index would compare the cache's *claim* about its content,
and the cache is writable by the same user who owns everything else on the
machine: an index entry can be edited to name the approved hash while the blob
beside it is something else. npm would fail that on read, but this module
would have answered "verified" first, and a verdict that can be wrong is not a
pin. Hashing the blob costs 2.7ms per artifact, measured over 777 of them.

pip's `http-v2` stores the response body beside its metadata, sharded as
`<h[0]>/<h[1]>/<h[2]>/<h[3]>/<h[4]>/<h>.body` where `h` is sha224 of the
artifact URL. The body is the wheel, byte for byte, so its sha256 is the
digest PyPI publishes. That half was always read as bytes.

Both derivations were confirmed against the real caches on a developer
machine -- all 777 npm tarball entries verified down to their content blobs,
and three pip wheels whose cached bytes matched the sha256 PyPI publishes for
them -- rather than read off a blog.

What is still *not* proven, and is deliberately not claimed: that the bytes
the package manager finally executes are these bytes. This says the cache
agrees with the approval at the moment of the check. A cache entry written
between the check and the fetch, or a package manager that ignores its cache,
is outside what any pre-spawn read of the disk can see.

What this cannot do is in `state`:

    verified  the cache holds this artifact and its bytes are the approved ones
    changed   the cache holds this artifact and its bytes are NOT the approved
              ones. This is the refusal; it is the whole point of the module
    absent    nothing on disk answers for it. The next launch will fetch, and
              what arrives is unseen until it has already run
    unsupported  no derivable cache for this ecosystem (uv, pipx venvs)

`absent` is not a pass and is never reported as one. A caller that needs the
strong claim asks for it with `require=True` and gets a refusal instead.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Hashing a body to compare it is cheap; hashing an arbitrarily large file
# found in a cache directory is not the job. A wheel above this is not the
# case this exists for, and is reported as unverifiable rather than read.
MAX_BODY = 256 * 1024 * 1024

_NPM_PREFIX = "make-fetch-happen:request-cache:"
_DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"


@dataclass(frozen=True)
class CacheCheck:
    """One recorded artifact, and whether the machine can still vouch for it."""

    key: str
    state: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.state == "verified"


def _npm_roots() -> list[Path]:
    """Where npm keeps `_cacache`, most specific first."""
    out: list[Path] = []
    for var in ("npm_config_cache", "NPM_CONFIG_CACHE"):
        raw = os.environ.get(var)
        if raw:
            out.append(Path(raw) / "_cacache")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        out.append(Path(local) / "npm-cache" / "_cacache")
    out.append(Path.home() / ".npm" / "_cacache")
    return out


def _pip_roots() -> list[Path]:
    """Where pip keeps its HTTP cache, most specific first."""
    out: list[Path] = []
    raw = os.environ.get("PIP_CACHE_DIR")
    if raw:
        out.append(Path(raw))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        out.append(Path(local) / "pip" / "Cache")
    out.append(Path.home() / ".cache" / "pip")
    return out


def npm_tarball_url(name: str, version: str,
                    registry: str = _DEFAULT_NPM_REGISTRY) -> str:
    """The URL npm fetches for `name@version`.

    A scoped package drops the scope from the filename:
    `@babel/runtime` is served as `@babel/runtime/-/runtime-7.29.7.tgz`.
    Taken from real cache entries, not from the docs.
    """
    base = name.rsplit("/", 1)[-1]
    return f"{registry.rstrip('/')}/{name}/-/{base}-{version}.tgz"


def _index_path(root: Path, url: str) -> Path:
    digest = hashlib.sha256((_NPM_PREFIX + url).encode("utf-8")).hexdigest()
    return root / "index-v5" / digest[0:2] / digest[2:4] / digest[4:]


def _read_index(path: Path) -> str | None:
    """The integrity string cacache holds for this key, or None.

    An index file is append-only and may carry several entries for one key;
    the last valid one is current. A deletion is written as an entry with no
    integrity, which is why a falsy value clears rather than keeps.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    found: str | None = None
    for line in text.splitlines():
        if "\t" not in line:
            continue
        try:
            entry = json.loads(line.split("\t", 1)[1])
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        found = str(entry.get("integrity") or "") or None
    return found


def _sri_matches(approved: str, found: str) -> bool | None:
    """True/False when the two SRI strings can be compared, None when not.

    An SRI may carry several hashes. Two strings are comparable only where
    they share an algorithm; `sha512-x` against `sha1-y` says nothing, and
    saying 'changed' there would refuse a launch over a format difference.
    """
    def parse(value: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for token in str(value or "").split():
            algo, sep, digest = token.partition("-")
            if sep and digest:
                out[algo.lower()] = digest
        return out

    mine, theirs = parse(approved), parse(found)
    shared = set(mine) & set(theirs)
    if not shared:
        return None
    return all(mine[algo] == theirs[algo] for algo in shared)


def content_path(root: Path, sri: str) -> Path | None:
    """Where cacache keeps the bytes for one SRI hash.

    `content-v2/<algo>/<hex[0:2]>/<hex[2:4]>/<hex[4:]>`, where the hex is the
    base64 digest decoded. Confirmed against 777 real entries: every blob was
    present and every one hashed to the SRI its index claimed.
    """
    algo, _, b64 = str(sri or "").split()[0].partition("-") if sri.strip() else ("", "", "")
    if not algo or not b64:
        return None
    try:
        hexed = base64.b64decode(b64, validate=True).hex()
    except (ValueError, binascii.Error):
        return None
    if len(hexed) < 5 or algo not in hashlib.algorithms_available:
        return None
    return root / "content-v2" / algo / hexed[0:2] / hexed[2:4] / hexed[4:]


def _content_holds(root: Path, sri: str) -> bool | None:
    """Do the cached bytes actually hash to `sri`? None if they are not there.

    Without this the check compares the index's *claim* about the content,
    and the cache is writable by whoever owns the rest of the machine. An
    index entry can be edited to name the approved hash while the blob beside
    it is something else; npm would fail that on read, but this module would
    have said "verified" first, and a verdict that can be wrong is not a pin.
    """
    blob = content_path(root, sri)
    if blob is None:
        return None
    algo = sri.split()[0].partition("-")[0]
    try:
        if not blob.is_file() or blob.stat().st_size > MAX_BODY:
            return None
        digest = hashlib.new(algo)
        with blob.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, ValueError):
        return None
    return base64.b64encode(digest.digest()).decode() == sri.split()[0].partition("-")[2]


def _check_npm(key: str, approved: str, name: str, version: str,
               url: str | None) -> CacheCheck:
    target = url or npm_tarball_url(name, version)
    for root in _npm_roots():
        if not root.is_dir():
            continue
        found = _read_index(_index_path(root, target))
        if not found:
            continue
        verdict = _sri_matches(approved, found)
        if verdict is None:
            return CacheCheck(key, "absent",
                              "the cached entry uses a different hash algorithm, "
                              "so it cannot be compared")
        if not verdict:
            return CacheCheck(
                key, "changed",
                f"npm cache holds {found[:24]} for this version; "
                f"{approved[:24]} was approved")
        # The index agrees with the approval. Now read the bytes it points at,
        # so the answer is about content rather than about a claim.
        holds = _content_holds(root, found)
        if holds is None:
            return CacheCheck(
                key, "absent",
                "the npm cache names these bytes but does not hold them; the "
                "next launch fetches them")
        if not holds:
            return CacheCheck(
                key, "changed",
                "the npm cache holds bytes that do not hash to the entry "
                f"beside them ({found[:24]}), so they are not the approved ones")
        return CacheCheck(key, "verified",
                          f"npm cache holds these bytes ({found[:24]})")
    return CacheCheck(key, "absent",
                      "no npm cache entry for this tarball; the next launch "
                      "fetches it")


def _body_digest(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_BODY:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _check_pypi(key: str, approved: str, url: str | None) -> CacheCheck:
    algo, _, want = approved.partition("-")
    if algo.lower() != "sha256" or not want:
        return CacheCheck(key, "absent",
                          "the approved digest is not a sha256, so a cached "
                          "body cannot be compared to it")
    if not url:
        # The published URL carries a hash path that cannot be derived from
        # the package name, so without it there is nothing to look up. Locks
        # written before URLs were recorded land here, and say so.
        return CacheCheck(key, "absent",
                          "no artifact URL was recorded at approval, so the "
                          "local wheel cannot be located; re-run approve")
    digest = hashlib.sha224(url.encode("utf-8")).hexdigest()
    parts = list(digest[:5]) + [digest]
    for root in _pip_roots():
        for flavour in ("http-v2", "http"):
            body = root.joinpath(flavour, *parts).with_suffix(".body")
            found = _body_digest(body)
            if found is None:
                continue
            if found == want:
                return CacheCheck(key, "verified",
                                  f"pip cache holds these bytes (sha256-{found[:16]})")
            return CacheCheck(
                key, "changed",
                f"pip cache holds sha256-{found[:16]} for this version; "
                f"sha256-{want[:16]} was approved")
    return CacheCheck(key, "absent",
                      "no pip cache entry for this artifact; the next launch "
                      "fetches it")


def check(recorded: dict[str, str] | None,
          urls: dict[str, str] | None = None) -> list[CacheCheck]:
    """Compare every recorded registry hash against the local package cache.

    Pure and offline: reads files under the user's own cache directories and
    opens no socket. A key this module does not understand is `unsupported`,
    never `verified`.
    """
    out: list[CacheCheck] = []
    if not isinstance(recorded, dict):
        return out
    known = urls if isinstance(urls, dict) else {}
    # Sorted by the string form, not by the key itself. The lockfile is
    # hand-edited by design, and a mixed-type mapping makes a bare `sorted`
    # raise -- on the launch path, where an exception is an agent that never
    # starts rather than a finding somebody reads.
    for key, approved in sorted(recorded.items(), key=lambda kv: str(kv[0])):
        if not isinstance(key, str) or not isinstance(approved, str):
            continue
        url = known.get(key)
        url = url if isinstance(url, str) and url[:8] in ("https://", "http://") else None
        ecosystem, _, token = key.partition(":")
        try:
            if ecosystem == "npm":
                name, _, version = token.rpartition("@")
                out.append(_check_npm(key, approved, name, version, url))
            elif ecosystem == "pypi":
                out.append(_check_pypi(key, approved, url))
            else:
                out.append(CacheCheck(key, "unsupported",
                                      f"no local cache is read for {ecosystem!r}"))
        except (OSError, ValueError):
            # This runs immediately before a spawn. A surprise here must not
            # take the server down, and must not read as a pass either.
            out.append(CacheCheck(key, "absent",
                                  "the local cache could not be read"))
    return out


def refusal(recorded: dict[str, str] | None,
            urls: dict[str, str] | None = None, *,
            require: bool = False) -> str | None:
    """Why this server must not be started, or None.

    A `changed` artifact always refuses: the machine is holding bytes that
    are not the ones approved, and starting the child would run them. An
    `absent` one refuses only under `require`, because refusing every launch
    on a machine with a cold cache would make the pin unusable and get it
    turned off -- which is the failure mode this project has already paid
    for once.
    """
    checks = check(recorded, urls)
    for item in checks:
        if item.state == "changed":
            return f"approved artifact {item.key} has changed: {item.detail}"
    if not require:
        return None
    unverified = [c for c in checks if c.state != "verified"]
    if unverified:
        first = unverified[0]
        return (f"--require-integrity was given and {first.key} could not be "
                f"verified: {first.detail}")
    return None


# A dependency spec that names one version and no range. npm writes `1.2.3`;
# PEP 508 writes `==1.2.3`. Everything else -- `^1.2`, `~1.2`, `>=1`, `*`, a
# git url, a tag -- resolves to whatever is newest when the tree is installed.
_EXACT_NPM = re.compile(r"^\s*=?\d+\.\d+\.\d+[\w.+-]*\s*$")
_EXACT_PEP508 = re.compile(r"==\s*\d+\.\d+")


@dataclass(frozen=True)
class Reach:
    """How far the pin on one artifact actually extends.

    MCPA036 pins the tarball. The tree that tarball installs beneath itself is
    not pinned and cannot be from here: resolving it needs the package manager
    and the network, and the answer would be a different tree tomorrow. What
    *is* answerable offline, from the bytes already in the cache, is how much
    of that tree floats -- which is the honest size of what the pin does not
    cover.

    Measured on 60 real cached packages: 115 floating specs against 17 exact.
    That ratio is why this is a fact reported beside the pin and not a rule.
    A finding that fires on seven specs out of eight, everywhere, forever, is
    a finding people switch off -- and MCPA003 already taught this project that
    lesson at 69%.
    """

    total: int = 0
    floating: int = 0
    examples: tuple[str, ...] = ()
    read: bool = False

    @property
    def pinned(self) -> int:
        return max(self.total - self.floating, 0)

    def describe(self) -> str:
        if not self.read:
            return ""
        if not self.total:
            return "declares no dependencies, so the pin covers everything it runs"
        if not self.floating:
            return f"all {self.total} declared dependencies are pinned exactly"
        return (f"{self.floating} of {self.total} declared dependencies float, "
                f"so the pin covers this artifact and not them")


def _npm_manifest(blob: Path) -> dict[str, Any] | None:
    """`package.json` out of a cached tarball, without unpacking it to disk."""
    try:
        with gzip.open(blob, "rb") as gz:
            raw = gz.read(MAX_BODY)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            member = next((m for m in archive.getmembers()
                           if m.isfile() and m.name.count("/") == 1
                           and m.name.endswith("package.json")), None)
            if member is None:
                return None
            handle = archive.extractfile(member)
            if handle is None:
                return None
            parsed = json.loads(handle.read().decode("utf-8", errors="replace"))
    except (OSError, ValueError, tarfile.TarError, EOFError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _wheel_requires(blob: Path) -> list[str] | None:
    """`Requires-Dist` lines out of a cached wheel."""
    try:
        with zipfile.ZipFile(blob) as archive:
            name = next((n for n in archive.namelist()
                         if n.endswith(".dist-info/METADATA")), None)
            if name is None:
                return None
            text = archive.read(name).decode("utf-8", errors="replace")
    except (OSError, ValueError, zipfile.BadZipFile):
        return None
    return [line.split(":", 1)[1].strip() for line in text.splitlines()
            if line.lower().startswith("requires-dist:")]


def dependency_reach(recorded: dict[str, str] | None,
                     urls: dict[str, str] | None = None) -> Reach:
    """Read the cached artifact's own manifest and count what floats.

    Offline and read-only, like the rest of this module. Returns a `Reach` with
    `read=False` when there is nothing on disk to look at, which is a different
    answer from "no dependencies" and is kept distinct for the same reason
    `absent` is kept apart from `verified`.
    """
    if not isinstance(recorded, dict):
        return Reach()
    known = urls if isinstance(urls, dict) else {}
    for key in sorted(recorded, key=str):
        if not isinstance(key, str):
            continue
        ecosystem, _, token = key.partition(":")
        approved = recorded.get(key)
        if not isinstance(approved, str):
            continue
        try:
            if ecosystem == "npm":
                blob = _npm_blob(approved)
                manifest = _npm_manifest(blob) if blob else None
                if manifest is None:
                    continue
                deps = manifest.get("dependencies")
                if not isinstance(deps, dict):
                    deps = {}
                specs = [(str(n), str(v)) for n, v in deps.items()]
                floating = [f"{n}@{v}" for n, v in specs
                            if not _EXACT_NPM.match(v)]
                return Reach(len(specs), len(floating),
                             tuple(floating[:3]), read=True)
            if ecosystem == "pypi":
                url = known.get(key)
                blob = _pypi_blob(url) if isinstance(url, str) else None
                requires = _wheel_requires(blob) if blob else None
                if requires is None:
                    continue
                # An extra is not installed unless it is asked for, so a
                # conditional requirement is not part of what this runs.
                plain = [r for r in requires if "extra ==" not in r]
                floating = [r for r in plain if not _EXACT_PEP508.search(r)]
                return Reach(len(plain), len(floating),
                             tuple(f.split(";")[0].strip() for f in floating[:3]),
                             read=True)
        except (OSError, ValueError):
            continue
    return Reach()


def _npm_blob(integrity: str) -> Path | None:
    for root in _npm_roots():
        if not root.is_dir():
            continue
        candidate = content_path(root, integrity)
        if candidate is not None and candidate.is_file():
            return candidate
    return None


def _pypi_blob(url: str) -> Path | None:
    digest = hashlib.sha224(url.encode("utf-8")).hexdigest()
    parts = list(digest[:5]) + [digest]
    for root in _pip_roots():
        for flavour in ("http-v2", "http"):
            body = root.joinpath(flavour, *parts).with_suffix(".body")
            if body.is_file():
                return body
    return None
