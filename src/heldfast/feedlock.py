"""Pin a server from the drift feed instead of launching it here.

`approve --probe` has one real cost: it runs the servers it records, so the
honest workflow asks for a container or a machine you can throw away first.
Most people skip that step, which is the step that mattered.

The drift feed (research/feed in this repository, data in rufat325/heldfast-feed) has already
launched the popular servers, in a container with no capabilities and no
credentials, and kept every catalogue it read. For a server whose config pins
an exact npm version the feed has measured, `approve --from-feed` records that
catalogue instead of launching anything.

What this trusts, said plainly: the feed's measurement stands in for your
probe. What it does not change: `wrap` and `gateway` still compare the live
server with the lock, so a catalogue that does not match what the server
really says is refused at the call site -- the failure mode of a wrong feed
is a refusal, not a pass. And it is only ever the exact version: an unpinned
or floating launch runs whatever was published last, which no measurement
taken earlier can stand for.

The feed is read at one commit, resolved when the approval starts and
recorded in the lock, so the approval says which data it came from and a
later reader can fetch the same bytes.

Opens sockets (GitHub, for the feed). `--safe` refuses it.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

from .fetch import USER_AGENT, urlopen
from .model import ServerSpec, ToolSpec
from .rules.execution import (_FLOATING, _PYTHON_RUNNERS, extract_package,
                              split_package)
from .enforcement import unwrap_launcher

TIMEOUT = 15.0
# The feed gzips its catalogues. Inflating one is refused past this size:
# the text inside came from a server, and a server can build a catalogue to
# be one of those files that is small until it is opened.
MAX_INFLATED = 50 * 1024 * 1024
# The whole lookup record (lookup/all.json) has its own bound, shared with the
# writer (research/feed/watch.py): it is allowed to grow past MAX_INFLATED,
# and a reader holding the smaller limit would refuse a record the feed wrote.
MAX_LOOKUP = 90 * 1024 * 1024
# The feed lives in its own repository, so cloning the tool does not download
# the log. Until 0.2.1 it was the `feed` branch of rufat325/heldfast, which is
# no longer updated; `--feed URL` still reads any copy.
REPO = "rufat325/heldfast-feed"
BRANCH = "main"
# How the branch head is found: git's own ref advertisement, the request
# `git ls-remote` makes. The REST API allows sixty unauthenticated requests
# an hour per address, which a shared office, CI or cloud address spends
# before anyone here asks; this endpoint is not the REST API.
ADVERT_URL = f"https://github.com/{REPO}.git/info/refs?service=git-upload-pack"
MAX_ADVERT = 1 << 20
HEAD_URL = f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"
API_HOST = "api.github.com"
RAW_URL = "https://raw.githubusercontent.com/" + REPO + "/{ref}"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9@._\-]+$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]*$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class FeedError(Exception):
    """The feed itself could not be reached or read."""


@dataclass(frozen=True)
class Feed:
    base: str       # URL the catalogues are read under
    source: str     # what the lock records as provenance
    commit: str = ""  # the feed commit, when known; what never changes is cached by it


@dataclass(frozen=True)
class FeedEntry:
    package: str
    version: str
    measured_at: str
    protocol: str
    args: list[str]
    tools: list[ToolSpec] = field(default_factory=list)


def _limit(url: str) -> int:
    """The lookup record's own bound for lookup/all.json(.gz); MAX_INFLATED else."""
    return MAX_LOOKUP if url.rsplit("/", 2)[-2:] in (["lookup", "all.json"],
                                                     ["lookup", "all.json.gz"]) else MAX_INFLATED


def get_json(url: str) -> Any:
    """GET and parse JSON. None on 404; FeedError otherwise. Tests replace this.

    Bounded either way: a body, or what a gzip inflates to, past its limit is
    refused rather than read."""
    limit = _limit(url)
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(limit + 1)
        if url.endswith(".gz"):
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
                raw = fh.read(limit + 1)
            if len(raw) > limit:
                raise FeedError(f"{url}: inflates past {limit} bytes")
        elif len(raw) > limit:
            raise FeedError(f"{url}: larger than {limit} bytes")
        return json.loads(raw.decode("utf-8"))
    except URLError as exc:
        if getattr(exc, "code", None) == 404:
            return None
        raise FeedError(f"{url}: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise FeedError(f"{url}: {exc}") from exc


def parse_advertisement(data: bytes, branch: str = BRANCH) -> str:
    """The commit `refs/heads/<branch>` points at, from a smart-HTTP ref
    advertisement: pkt-lines, each prefixed by its length in four hex digits
    (the four included), `0000` a flush. Anything malformed is a FeedError."""
    want = f" refs/heads/{branch}".encode()
    i = 0
    while i < len(data):
        if i + 4 > len(data):
            raise FeedError("ref advertisement ends inside a length")
        try:
            size = int(data[i:i + 4].decode("ascii"), 16)
        except (UnicodeDecodeError, ValueError):
            raise FeedError("ref advertisement has a length that is not hex") from None
        if size == 0:
            i += 4
            continue
        if size < 4 or i + size > len(data):
            raise FeedError("ref advertisement has a malformed line")
        line = data[i + 4:i + size].split(b"\0", 1)[0].rstrip(b"\n")
        i += size
        if line.endswith(want) and len(line) == 40 + len(want):
            sha = line[:40].decode("ascii", "replace")
            if not _SHA.match(sha):
                raise FeedError(f"ref advertisement names {branch} with a non-commit {sha!r}")
            return sha
    raise FeedError(f"the feed repository does not advertise a {branch!r} branch")


def branch_head() -> str:
    """The feed's current commit, the way `git ls-remote` reads it. Tests replace this."""
    req = Request(ADVERT_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            data = resp.read(MAX_ADVERT + 1)
    except (URLError, OSError, ValueError) as exc:
        raise FeedError(f"{ADVERT_URL}: {exc}") from exc
    if len(data) > MAX_ADVERT:
        raise FeedError(f"{ADVERT_URL}: larger than {MAX_ADVERT} bytes")
    return parse_advertisement(data)


def _token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def _rate_limited(exc: HTTPError) -> str:
    """Why the API refused, said as a rate limit with its remedies, or ""."""
    headers = exc.headers or {}
    if exc.code not in (403, 429) or (exc.code == 403 and headers.get("X-RateLimit-Remaining") != "0"):
        return ""
    reset = str(headers.get("X-RateLimit-Reset") or "")
    when = ""
    if reset.isdigit():
        when = " until " + datetime.fromtimestamp(int(reset), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (f"GitHub's API rate limit for this address is spent{when}. Pass --feed URL, set "
            f"GITHUB_TOKEN (sent to {API_HOST} only), or try again later")


def rest_head() -> str:
    """The feed's current commit from the REST API: the fallback, authenticated
    with GITHUB_TOKEN or GH_TOKEN when one is set. The token goes to
    api.github.com and nowhere else -- never to raw.githubusercontent.com, and
    never to a --feed base someone else chose; a redirect off that host drops
    it (fetch.py, T-REDIRECT)."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = _token()
    if token and urlsplit(HEAD_URL).hostname == API_HOST:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(HEAD_URL, headers=headers), timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_ADVERT + 1)
        head = json.loads(raw.decode("utf-8")) if len(raw) <= MAX_ADVERT else None
    except HTTPError as exc:
        raise FeedError(_rate_limited(exc) or f"{HEAD_URL}: {exc}") from exc
    except (URLError, OSError, ValueError) as exc:
        raise FeedError(f"{HEAD_URL}: {exc}") from exc
    sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(sha, str) or not _SHA.match(sha):
        raise FeedError("could not resolve the feed to a commit")
    return sha


def resolve(base: str | None = None) -> Feed:
    """The feed at one commit. A moving branch is not something to approve from.

    In order: a --feed base as given; the branch head from git's ref
    advertisement; the REST API, with a token if one is set; then a
    FeedError that says what to do."""
    if base:
        return Feed(base.rstrip("/"), base.rstrip("/"))
    try:
        sha = branch_head()
    except FeedError as first:
        try:
            sha = rest_head()
        except FeedError as second:
            raise FeedError(f"{second} (reading the branch from git also failed: {first})") from second
    if not isinstance(sha, str) or not _SHA.match(sha):
        raise FeedError("could not resolve the feed to a commit")
    return Feed(RAW_URL.format(ref=sha), f"{REPO}@{sha}", sha)


def package_args(spec: ServerSpec) -> list[str]:
    """The arguments after the package, which the feed measured with its own."""
    found = extract_package(spec)
    if not found:
        return []
    _, args = unwrap_launcher(spec.command, spec.args)
    token = found[1]
    return list(args[args.index(token) + 1:]) if token in args else []


def pinned(spec: ServerSpec) -> tuple[str, str] | str:
    """(npm name, exact version), or why this launch cannot be pinned from the feed."""
    found = extract_package(spec)
    if not found:
        return "the launch command does not fetch a registry package"
    runner, token = found
    if runner in _PYTHON_RUNNERS:
        return "the feed measures npm packages; this one comes from PyPI"
    name, version = split_package(token, runner)
    if not version or _FLOATING.match(version):
        return (f"{name} has no exact version pinned, so it runs whatever was "
                f"published last and no earlier measurement can stand for it; "
                f"pin it as {name}@<version>")
    version = version.lstrip("=@ ")
    if not _SAFE_VERSION.match(version) or not _SAFE_NAME.match(name.replace("/", "__")):
        return f"{name}@{version} is not a name the feed stores"
    return name, version


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def catalogue(feed: Feed, name: str, version: str) -> tuple[dict | None, str]:
    """(the catalogue with its tool definitions resolved, its URL), or (None, URL).

    The current layout lists each tool by digest and stores the definition
    once under tools/, named by that digest: every definition fetched is
    hashed here and refused if it does not match its name, so a catalogue
    cannot be served with definitions it did not list. The first layout, a
    gzipped catalogue with the definitions inline, is read where it is all
    the feed has.
    """
    from .digest import tool_digest

    base = f"{feed.base}/catalogues/{name.replace('/', '__')}/{version}"
    body = get_json(base + ".json")
    if body is None:
        return get_json(base + ".json.gz"), base + ".json.gz"
    entries = body.get("tools") if isinstance(body, dict) else None
    if not isinstance(entries, list):
        raise FeedError(f"{base}.json: not a catalogue")
    tools = []
    for entry in entries:
        digest = entry.get("digest") if isinstance(entry, dict) else None
        if not isinstance(digest, str) or not _DIGEST.match(digest):
            raise FeedError(f"{base}.json: an entry without a tool digest")
        raw = get_json(f"{feed.base}/tools/{digest[:2]}/{digest}.json")
        if not isinstance(raw, dict):
            raise FeedError(f"{base}.json: tool {digest[:12]} is missing from the feed")
        try:
            actual = tool_digest(raw)
        except ValueError as exc:
            raise FeedError(f"tool {digest[:12]}: {exc}") from exc
        if actual != digest:
            raise FeedError(f"tool {digest[:12]} does not hash to its name; refused")
        tools.append(raw)
    return dict(body, tools=tools), base + ".json"


def lookup(spec: ServerSpec, feed: Feed) -> FeedEntry | str:
    """The feed's catalogue for this server's exact pinned version, or why not."""
    from .probe import _parse_tools  # the parser --probe uses, so digests agree

    want = pinned(spec)
    if isinstance(want, str):
        return want
    name, version = want
    body, url = catalogue(feed, name, version)
    if body is None:
        return (f"the feed has not measured {name}@{version}; it watches the npm "
                f"servers in the MCP registry and measures each new release, the "
                f"popular ones daily and the rest weekly")
    if (not isinstance(body, dict) or body.get("package") != name
            or body.get("version") != version or not isinstance(body.get("tools"), list)):
        raise FeedError(f"{url}: not a catalogue for {name}@{version}")
    tools = _parse_tools(spec.identity(), {"result": {"tools": body["tools"]}})
    return FeedEntry(package=name, version=version,
                     measured_at=str(body.get("measured_at") or ""),
                     protocol=str(body.get("protocol") or ""),
                     args=[str(a) for a in body.get("args") or []], tools=tools)
