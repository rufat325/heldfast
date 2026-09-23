"""Pin a server from the drift feed instead of launching it here.

`approve --probe` has one real cost: it runs the servers it records, so the
honest workflow asks for a container or a machine you can throw away first.
Most people skip that step, which is the step that mattered.

The drift feed (research/feed on main, data on the `feed` branch) has already
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

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.error import URLError
from urllib.request import Request

from .fetch import USER_AGENT, urlopen
from .model import ServerSpec, ToolSpec
from .rules.execution import (_FLOATING, _PYTHON_RUNNERS, extract_package,
                              split_package)
from .enforcement import unwrap_launcher

TIMEOUT = 15.0
REPO = "rufat325/mcp-pin"
BRANCH = "feed"
HEAD_URL = f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"
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


@dataclass(frozen=True)
class FeedEntry:
    package: str
    version: str
    measured_at: str
    protocol: str
    args: list[str]
    tools: list[ToolSpec] = field(default_factory=list)


def get_json(url: str) -> Any:
    """GET and parse JSON. None on 404; FeedError otherwise. Tests replace this."""
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as exc:
        if getattr(exc, "code", None) == 404:
            return None
        raise FeedError(f"{url}: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise FeedError(f"{url}: {exc}") from exc


def resolve(base: str | None = None) -> Feed:
    """The feed at one commit. A moving branch is not something to approve from."""
    if base:
        return Feed(base.rstrip("/"), base.rstrip("/"))
    head = get_json(HEAD_URL)
    sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(sha, str) or not _SHA.match(sha):
        raise FeedError("could not resolve the feed branch to a commit")
    return Feed(RAW_URL.format(ref=sha), f"{REPO}@{sha}")


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


def lookup(spec: ServerSpec, feed: Feed) -> FeedEntry | str:
    """The feed's catalogue for this server's exact pinned version, or why not."""
    from .probe import _parse_tools  # the parser --probe uses, so digests agree

    want = pinned(spec)
    if isinstance(want, str):
        return want
    name, version = want
    url = f"{feed.base}/catalogues/{name.replace('/', '__')}/{version}.json"
    body = get_json(url)
    if body is None:
        return (f"the feed has not measured {name}@{version}; it watches the "
                f"most-downloaded registry servers and the releases they publish")
    if (not isinstance(body, dict) or body.get("package") != name
            or body.get("version") != version or not isinstance(body.get("tools"), list)):
        raise FeedError(f"{url}: not a catalogue for {name}@{version}")
    tools = _parse_tools(spec.identity(), {"result": {"tools": body["tools"]}})
    return FeedEntry(package=name, version=version,
                     measured_at=str(body.get("measured_at") or ""),
                     protocol=str(body.get("protocol") or ""),
                     args=[str(a) for a in body.get("args") or []], tools=tools)
