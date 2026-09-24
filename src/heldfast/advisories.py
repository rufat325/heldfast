"""What the ecosystem already knows about an npm release, before you take it.

The drift feed compares what a server's tools say. The attacks that have
actually reached MCP servers never changed a word of that. postmark-mcp
1.0.16 copied every email it sent to its author. The Shai-Hulud worms put an
install hook into releases of Postman's, Browserbase's and AntV's servers.
A scanner that promised "your code never leaves the machine" uploaded it,
`.env` files included. Five malicious releases in eight months, and every one
would have compared equal to the release before it.

A pin keeps you on the version you approved, so none of that reaches you
until you move. This is for the moment you move. It reads three facts per
release from two public sources:

- advisories, from OSV (api.osv.dev), which carries the OpenSSF
  malicious-packages reports (`MAL-`) and GitHub's advisories (`GHSA-`);
- when the release was published, and
- which install scripts it runs, from the npm registry's own record.

Every one of those five was reported within nine days of its release, and
the worm releases within a day. A release is not proposed until it is old
enough for that to have happened, a reported one is never proposed, and one
that adds an install script is never quiet. It sends the package name and
the versions asked about, nothing else.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request

from .fetch import USER_AGENT, urlopen

OSV_URL = "https://api.osv.dev/v1/querybatch"
NPM_URL = "https://registry.npmjs.org/"
TIMEOUT = 20.0
# A packument lists every release a package ever had; a busy one runs to a
# few megabytes. Past this it is not read.
MAX_BYTES = 64 * 1024 * 1024
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
# Every malicious MCP release so far was reported within nine days.
DEFAULT_MIN_AGE = 14


class AdvisoryError(Exception):
    """OSV or the npm registry could not be asked."""


def _read(req: Request) -> Any:
    with urlopen(req, timeout=TIMEOUT) as resp:
        raw = resp.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise AdvisoryError(f"{req.full_url}: answer larger than {MAX_BYTES} bytes")
    return json.loads(raw.decode("utf-8"))


def get_json(url: str) -> Any:
    """GET JSON; None on 404, AdvisoryError otherwise. Tests replace this."""
    try:
        return _read(Request(url, headers={"User-Agent": USER_AGENT,
                                           "Accept": "application/json"}))
    except URLError as exc:
        if getattr(exc, "code", None) == 404:
            return None
        raise AdvisoryError(f"{url}: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise AdvisoryError(f"{url}: {exc}") from exc


def post_json(url: str, body: Any) -> Any:
    """POST JSON and parse the answer; AdvisoryError on failure. Tests replace this."""
    req = Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                  headers={"User-Agent": USER_AGENT, "Content-Type": "application/json",
                           "Accept": "application/json"})
    try:
        return _read(req)
    except (URLError, OSError, ValueError) as exc:
        raise AdvisoryError(f"{url}: {exc}") from exc


def known(package: str, versions: list[str]) -> dict[str, list[str]]:
    """OSV advisory ids for each version of an npm package."""
    if not versions:
        return {}
    body = post_json(OSV_URL, {"queries": [
        {"package": {"name": package, "ecosystem": "npm"}, "version": v} for v in versions]})
    results = body.get("results") if isinstance(body, dict) else None
    if not isinstance(results, list) or len(results) != len(versions):
        raise AdvisoryError(f"{OSV_URL}: not an answer to {len(versions)} queries")
    out: dict[str, list[str]] = {}
    for version, result in zip(versions, results):
        vulns = result.get("vulns") if isinstance(result, dict) else None
        out[version] = sorted(str(v["id"]) for v in vulns or []
                              if isinstance(v, dict) and v.get("id"))
    return out


def malware(ids: list[str]) -> list[str]:
    return [i for i in ids if i.startswith("MAL-")]


@dataclass(frozen=True)
class Release:
    present: bool                      # still downloadable from npm
    published: datetime | None
    hooks: dict[str, str] = field(default_factory=dict)


def releases(package: str) -> dict[str, Release]:
    """Every release npm has a record of: publish time, and install scripts
    for the ones still published. A release that was pulled keeps its time."""
    doc = get_json(NPM_URL + quote(package, safe="@"))
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise AdvisoryError(f"registry.npmjs.org: no record for {package}")
    times = doc.get("time") if isinstance(doc.get("time"), dict) else {}
    manifests = doc.get("versions") if isinstance(doc.get("versions"), dict) else {}
    out: dict[str, Release] = {}
    for version in set(times) | set(manifests):
        if version in ("created", "modified"):
            continue
        man = manifests.get(version)
        scripts = man.get("scripts") if isinstance(man, dict) else None
        hooks = {k: str(scripts[k]) for k in INSTALL_HOOKS
                 if isinstance(scripts, dict) and k in scripts}
        out[version] = Release(present=isinstance(man, dict),
                               published=_when(times.get(version)), hooks=hooks)
    return out


def _when(text: Any) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


@dataclass
class Screen:
    """What the ecosystem says about the pinned release and the newer ones."""

    alarm: str = ""                    # the pinned release itself is reported as malware
    target: str = ""                   # the newest release it is safe to propose
    passed_over: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)   # why the target is not quiet
    waiting: bool = False              # a newer release is only too young, not refused
    error: str = ""


def screen(package: str, current: str, newer: list[str], min_age: int = DEFAULT_MIN_AGE,
           now: datetime | None = None) -> Screen:
    """Screen the pinned release, and pick the newest newer one worth proposing.

    Newest first: a release reported as malware, pulled from npm, or younger
    than `min_age` days is passed over, with the reason, and the next older
    one is considered. The one chosen is not quiet if an advisory names it or
    it runs an install script the pinned release did not.
    """
    now = now or datetime.now(timezone.utc)
    out = Screen()
    try:
        ids = known(package, [current, *newer])
        rel = releases(package) if newer else {}
    except AdvisoryError as exc:
        out.error = str(exc)
        return out
    bad = malware(ids.get(current, []))
    if bad:
        out.alarm = (f"{package}@{current}, which this config runs, is reported as "
                     f"malware ({', '.join(bad)}). Remove it, and rotate every "
                     f"credential the machine running it could reach.")
    for version in reversed(newer):
        why = _refusal(version, ids.get(version, []), rel.get(version), min_age, now)
        if why is None:
            out.target = version
            break
        out.passed_over.append(f"{version}: {why}")
        out.waiting = out.waiting or why.startswith("published ")
    if out.target:
        out.concerns = _concerns(out.target, ids.get(out.target, []), rel.get(current),
                                 rel[out.target])
    return out


def _refusal(version: str, ids: list[str], rel: Release | None, min_age: int,
             now: datetime) -> str | None:
    bad = malware(ids)
    if bad:
        return f"reported as malware ({', '.join(bad)})"
    if rel is None or not rel.present:
        return "no longer on npm; a release pulled after publication is usually pulled for a reason"
    if rel.published is None:
        return "npm gives no publish time, so its age cannot be checked"
    age = (now - rel.published).total_seconds() / 86400
    if age < min_age:
        return (f"published {int(age)} day(s) ago; proposed once it is {min_age} days old, "
                f"after the time malicious releases have taken to be reported")
    return None


def _concerns(target: str, ids: list[str], before: Release | None, after: Release) -> list[str]:
    out = []
    if ids:
        out.append(f"{target} has advisories: {', '.join(ids)}")
    old = before.hooks if before is not None and before.present else {}
    for hook, command in sorted(after.hooks.items()):
        if old.get(hook) != command:
            verb = "changes" if hook in old else "adds"
            out.append(f"{target} {verb} an install script, which runs on install before "
                       f"any tool is listed: {hook}: {command[:120]}")
    return out
