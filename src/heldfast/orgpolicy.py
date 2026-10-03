"""Which MCP servers an organisation allows, and what it requires of them.

The lockfile is one repository's answer to "what did we approve". A security
team has a different question, asked of every machine and every repository at
once: which servers may anyone here run at all, and what must be true of each
one that does? This is that answer, written once and checked everywhere --
`heldfast inventory --policy` on one machine, `heldfast fleet --policy` across
all of them.

    {
      "policy": "heldfast.org-policy/1",
      "name": "Acme engineering",
      "allow": [{"package": "npm:@modelcontextprotocol/*"},
                {"url": "https://mcp.linear.app/*"}],
      "deny":  [{"package": "npm:postmark-mcp", "versions": ["1.0.16"],
                 "reason": "copied every email it sent to its author"}],
      "unlisted": "warn",
      "require": {"approved": true, "pinned": true, "exact_versions": true,
                  "enforced": false, "no_drift": true, "fail_on": "high"}
    }

It is read the way `Policy.check` reads argument limits: a key this version
does not know is an error, not something skipped. A policy that silently
ignored `"requre"` would report every machine compliant with a requirement
nobody is checking, which is the failure this project keeps naming.

What a selector matches:

- `package` -- `<ecosystem>:<name glob>`, ecosystem `npm`, `pypi` or `*`. PyPI
  names are compared in their normalised form (PEP 503), npm names as written.
- `versions` -- globs over the exact version. A server that pins no exact
  version can run any of them, so it matches a deny rule naming versions and
  never matches an allow rule naming versions.
- `url` -- `<scheme>://<host glob>[:port][/<path glob>]`. Host and path are
  matched separately, so `https://*.acme.com/*` cannot be met by
  `https://evil.example/.acme.com/`. The host is compared without case, as DNS
  does; the path with case, as RFC 3986 does. With no port in the pattern any
  port matches; with no path, any path.
- `command` -- a glob over the launched program's name (`node`, `docker`,
  `npx`), without directory or `.exe`.
- `kind` -- `hosted`, `package` or `local`.

Every selector given must match. A rule with none would match everything,
which is never what was meant, so it is refused.

At launch (`wrap`, `guard`, `gateway`) the same file is a refusal, not a
report: a denied server, an unlisted one when unlisted servers are denied, and
one that misses `approved`, `pinned` or `exact_versions` is not started. The
policy an administrator put at the machine's managed path (MANAGED_PATHS) is
always in force there; one named by `--org-policy` or `HELDFAST_ORG_POLICY`
is checked as well, so a local policy can tighten the managed one and never
loosen it. A managed file that exists and cannot be read refuses every
launch: a policy the administrator wrote and this cannot read is not one to
guess past.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "heldfast.org-policy/1"

_TOP_KEYS = {"policy", "name", "allow", "deny", "unlisted", "require", "description"}
_RULE_KEYS = {"package", "versions", "url", "command", "kind", "reason"}
_REQUIRE_KEYS = {"approved", "pinned", "exact_versions", "enforced", "no_drift", "fail_on"}
_KINDS = {"hosted", "package", "local"}
_UNLISTED = {"allow", "warn", "deny"}
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_ECOSYSTEMS = {"npm", "pypi", "*"}

# MCPA014 is "no lockfile approves this server", which `approved` asks
# directly. Counting it under `fail_on` as well would make `fail_on: high`
# require approval by the back door, and a policy that did not ask for
# approval would fail every unapproved server anyway.
_COVERED_ELSEWHERE = {"MCPA014"}

# Server states (status.py) that mean the server is not running here.
_NOT_RUNNING = {"GONE"}

# Where an administrator puts the policy every launch on the machine obeys --
# the same idea as a client's managed settings: written by whoever manages the
# machine, in a directory its user cannot write.
MANAGED_PATHS = {
    "linux": "/etc/heldfast/org-policy.json",
    "darwin": "/Library/Application Support/heldfast/org-policy.json",
    "win32": "%ProgramData%\\heldfast\\org-policy.json",
}
ENV_VAR = "HELDFAST_ORG_POLICY"

# What a lock entry records about what a server says. Approved with none of
# them is approved with nothing pinned (status.py's UNPINNED).
_PINNED_KEYS = ("tools", "prompts", "resources", "instructions")


@dataclass(frozen=True)
class Rule:
    package: str = ""
    versions: tuple[str, ...] = ()
    url: str = ""
    command: str = ""
    kind: str = ""
    reason: str = ""

    def describe(self) -> str:
        parts = [f"{key} {value}" for key, value in (
            ("package", self.package), ("url", self.url),
            ("command", self.command), ("kind", self.kind)) if value]
        if self.versions:
            parts.append("versions " + ", ".join(self.versions))
        return "; ".join(parts)


@dataclass
class OrgPolicy:
    name: str = ""
    allow: list[Rule] = field(default_factory=list)
    deny: list[Rule] = field(default_factory=list)
    unlisted: str = "warn"
    require: dict[str, Any] = field(default_factory=dict)
    # sha256 of the bytes the policy was read from: two reports that name the
    # same digest were checked against the same rules.
    digest: str = ""


@dataclass(frozen=True)
class Violation:
    server: str
    level: str          # "deny" fails the check; "warn" is reported only
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"server": self.server, "level": self.level, "code": self.code,
                "message": self.message}


# ---------------------------------------------------------------------------
# Reading


def load(path: Path) -> OrgPolicy:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{path}: cannot read policy ({exc})") from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: not JSON ({exc})") from None
    try:
        return parse(data, hashlib.sha256(raw).hexdigest())
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from None


def parse(data: Any, digest: str = "") -> OrgPolicy:
    if not isinstance(data, dict):
        raise ValueError("a policy is a JSON object")
    unknown = sorted(set(data) - _TOP_KEYS)
    if unknown:
        raise ValueError(f"unknown key(s) {', '.join(unknown)}; refusing a policy "
                         f"this version would only partly enforce")
    if data.get("policy") != SCHEMA:
        raise ValueError(f'"policy" must be "{SCHEMA}"')
    unlisted = data.get("unlisted", "warn")
    if unlisted not in _UNLISTED:
        raise ValueError(f'"unlisted" must be one of {", ".join(sorted(_UNLISTED))}')
    return OrgPolicy(
        name=_text(data.get("name", ""), "name"),
        allow=_rules(data.get("allow", []), "allow"),
        deny=_rules(data.get("deny", []), "deny"),
        unlisted=unlisted,
        require=_require(data.get("require", {})),
        digest=digest,
    )


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected a string")
    return value


def _rules(value: Any, where: str) -> list[Rule]:
    if not isinstance(value, list):
        raise ValueError(f'"{where}" must be a list of rules')
    return [_rule(item, f"{where}[{i}]") for i, item in enumerate(value)]


def _rule(item: Any, where: str) -> Rule:
    if not isinstance(item, dict):
        raise ValueError(f"{where}: a rule is an object")
    unknown = sorted(set(item) - _RULE_KEYS)
    if unknown:
        raise ValueError(f"{where}: unknown key(s) {', '.join(unknown)}")
    versions = item.get("versions", [])
    if not isinstance(versions, list) or not all(isinstance(v, str) and v for v in versions):
        raise ValueError(f"{where}: versions must be a list of version globs")
    rule = Rule(
        package=_text(item.get("package", ""), f"{where}.package"),
        versions=tuple(versions),
        url=_text(item.get("url", ""), f"{where}.url"),
        command=_text(item.get("command", ""), f"{where}.command"),
        kind=_text(item.get("kind", ""), f"{where}.kind"),
        reason=_text(item.get("reason", ""), f"{where}.reason"),
    )
    if not (rule.package or rule.url or rule.command or rule.kind):
        raise ValueError(f"{where}: a rule needs a package, url, command or kind; "
                         f"one with none would match every server")
    if rule.versions and not rule.package:
        raise ValueError(f"{where}: versions only mean something beside a package")
    if rule.package:
        eco, sep, name = rule.package.partition(":")
        if not sep or eco.lower() not in _ECOSYSTEMS or not name:
            raise ValueError(f"{where}: package is <npm|pypi|*>:<name glob>, "
                             f"not {rule.package!r}")
    if rule.url and _url_parts(rule.url) is None:
        raise ValueError(f"{where}: url is <scheme>://<host glob>[/<path glob>], "
                         f"not {rule.url!r}")
    if rule.kind and rule.kind not in _KINDS:
        raise ValueError(f"{where}: kind is one of {', '.join(sorted(_KINDS))}")
    return rule


def _require(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError('"require" must be an object')
    unknown = sorted(set(value) - _REQUIRE_KEYS)
    if unknown:
        raise ValueError(f"require: unknown key(s) {', '.join(unknown)}")
    for key, flag in value.items():
        if key == "fail_on":
            if flag not in _SEVERITIES:
                raise ValueError(f"require.fail_on is one of {', '.join(_SEVERITIES)}")
        elif not isinstance(flag, bool):
            raise ValueError(f"require.{key} must be true or false")
    return dict(value)


# ---------------------------------------------------------------------------
# Matching


_URL = re.compile(r"^(?P<scheme>[A-Za-z*][A-Za-z0-9+.*-]*)://(?P<host>[^/?#]+)(?P<path>/[^?#]*)?$")


def _url_parts(text: str) -> tuple[str, str, str | None, str | None] | None:
    """(scheme, host, port or None, path or None) of a URL or URL pattern."""
    m = _URL.match(text.strip())
    if not m:
        return None
    host = m.group("host").lower()
    if "@" in host:
        return None  # user info is never part of a pattern or an endpoint
    port: str | None = None
    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            return None
        rest = host[end + 1:]
        host = host[:end + 1]
        if rest:
            if not rest.startswith(":"):
                return None
            port = rest[1:]
    elif host.count(":") == 1:
        host, port = host.split(":", 1)
    return m.group("scheme").lower(), host, port, m.group("path")


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _package_matches(rule: Rule, package: dict[str, Any] | None) -> bool:
    if not package:
        return False
    eco, _, glob = rule.package.partition(":")
    eco = eco.lower()
    if eco != "*" and eco != package.get("ecosystem"):
        return False
    name = str(package.get("name") or "")
    if package.get("ecosystem") == "pypi":
        return fnmatch.fnmatchcase(_pep503(name), _pep503(glob))
    return fnmatch.fnmatchcase(name, glob)


def _versions_match(rule: Rule, package: dict[str, Any], deny: bool) -> bool:
    if not rule.versions:
        return True
    if not package.get("exact"):
        # It runs whatever was published last, which may be the named one.
        return deny
    version = str(package.get("version") or "")
    return any(fnmatch.fnmatchcase(version, glob) for glob in rule.versions)


def _url_matches(rule: Rule, endpoint: str | None) -> bool:
    if not endpoint:
        return False
    want, got = _url_parts(rule.url), _url_parts(endpoint)
    if want is None or got is None:
        return False
    scheme, host, port, path = want
    if not fnmatch.fnmatchcase(got[0], scheme) or not fnmatch.fnmatchcase(got[1], host):
        return False
    if port is not None and not fnmatch.fnmatchcase(got[2] or "", port):
        return False
    return path is None or fnmatch.fnmatchcase(got[3] or "/", path)


def matches(rule: Rule, row: dict[str, Any], *, deny: bool = False) -> bool:
    """Whether every selector in `rule` matches this inventory row."""
    if rule.kind and rule.kind != row.get("kind"):
        return False
    if rule.command and not fnmatch.fnmatchcase(str(row.get("command") or ""),
                                                rule.command.lower()):
        return False
    if rule.url and not _url_matches(rule, row.get("endpoint")):
        return False
    if rule.package:
        package = row.get("package")
        if not _package_matches(rule, package):
            return False
        if not _versions_match(rule, package or {}, deny):
            return False
    return True


# ---------------------------------------------------------------------------
# Evaluation


def _what(row: dict[str, Any]) -> str:
    package = row.get("package")
    if package:
        version = package.get("version") or ""
        return f"{package['name']}@{version}" if version else str(package["name"])
    return str(row.get("endpoint") or row.get("command") or row.get("identity"))


def _denied(policy: OrgPolicy, row: dict[str, Any]) -> Violation | None:
    for rule in policy.deny:
        if matches(rule, row, deny=True):
            why = rule.reason or f"matches deny rule ({rule.describe()})"
            package = row.get("package") or {}
            if rule.versions and package and not package.get("exact"):
                why += "; no exact version is pinned, so it may run a denied release"
            return Violation(row["identity"], "deny", "denied",
                             f"{_what(row)} is denied: {why}")
    return None


def _unlisted(policy: OrgPolicy, row: dict[str, Any]) -> Violation | None:
    if not policy.allow or policy.unlisted == "allow":
        return None
    if any(matches(rule, row) for rule in policy.allow):
        return None
    return Violation(row["identity"], policy.unlisted, "unlisted",
                     f"{_what(row)} is not on the allow list")


def _required(policy: OrgPolicy, row: dict[str, Any]) -> list[Violation]:
    need = policy.require
    ident = row["identity"]
    state = row.get("state")
    out: list[Violation] = []
    if need.get("approved") and state == "UNAPPROVED":
        out.append(Violation(ident, "deny", "unapproved",
                             "no lockfile approves this server"))
    if need.get("pinned") and state == "UNPINNED":
        out.append(Violation(ident, "deny", "unpinned",
                             "approved without its tool definitions, so nothing it "
                             "says is pinned"))
    package = row.get("package")
    if need.get("exact_versions") and package and not package.get("exact"):
        out.append(Violation(ident, "deny", "floating_version",
                             f"{package['name']} runs whatever was published last; "
                             f"pin an exact version"))
    if need.get("enforced") and row.get("enforced") in (None, "", "none"):
        out.append(Violation(ident, "deny", "unenforced",
                             "nothing checks the lockfile when this server is called"))
    if need.get("no_drift") and state == "DRIFTED":
        out.append(Violation(ident, "deny", "drifted",
                             "it no longer matches what was approved"))
    threshold = need.get("fail_on")
    if threshold:
        worst = _worst_finding(row, threshold)
        if worst:
            out.append(Violation(ident, "deny", "finding", worst))
    return out


def _worst_finding(row: dict[str, Any], threshold: str) -> str:
    """The first finding at or above `threshold`, as text, or ""."""
    limit = _SEVERITIES.index(threshold)
    for finding in row.get("top_findings") or []:
        if finding.get("rule_id") in _COVERED_ELSEWHERE:
            continue
        severity = finding.get("severity")
        if severity in _SEVERITIES and _SEVERITIES.index(severity) <= limit:
            return f"{finding['rule_id']} ({severity}): {finding.get('title', '')}"
    return ""


def evaluate(policy: OrgPolicy, rows: list[dict[str, Any]]) -> list[Violation]:
    """Every way these inventory rows fall short of the policy.

    A disabled server and one the lockfile names but nothing configures are
    not running, so they are not judged. A denied server is reported as
    denied and nothing else: what else is wrong with it does not matter
    until it is gone.
    """
    out: list[Violation] = []
    for row in rows:
        if row.get("disabled") or row.get("state") in _NOT_RUNNING:
            continue
        denied = _denied(policy, row)
        if denied is not None:
            out.append(denied)
            continue
        unlisted = _unlisted(policy, row)
        if unlisted is not None:
            out.append(unlisted)
        out.extend(_required(policy, row))
    return out


def failed(violations: list[Violation]) -> bool:
    return any(v.level == "deny" for v in violations)


# ---------------------------------------------------------------------------
# At launch


def managed_path(platform: str | None = None) -> Path | None:
    """The managed policy's path on this platform, or None where there is none."""
    name = platform or sys.platform
    key = "linux" if name.startswith(("linux", "freebsd", "openbsd", "netbsd")) else name
    raw = MANAGED_PATHS.get(key)
    return Path(os.path.expandvars(raw)) if raw else None


def for_launch(explicit: str | None = None,
               env: Mapping[str, str] | None = None) -> list[tuple[OrgPolicy, str]]:
    """(policy, where it was read) for every policy a launch must meet.

    Raises ValueError when one that is there cannot be read. The caller is on
    the launch path and refuses to start rather than guessing which rules
    would have applied.
    """
    env = os.environ if env is None else env
    found: list[tuple[OrgPolicy, str]] = []
    managed = managed_path()
    if managed is not None:
        try:
            present = managed.exists()
        except OSError as exc:
            raise ValueError(f"{managed}: the managed policy cannot be checked ({exc})") from None
        if present:
            found.append((load(managed), str(managed)))
    named = explicit or env.get(ENV_VAR)
    if named:
        found.append((load(Path(named)), named))
    return found


def for_report(explicit: str | None = None,
               env: Mapping[str, str] | None = None) -> tuple[OrgPolicy, str] | None:
    """The one policy an inventory is checked against: the one named, else the
    machine's managed one, else the one in HELDFAST_ORG_POLICY."""
    if explicit:
        return load(Path(explicit)), explicit
    env = os.environ if env is None else env
    managed = managed_path()
    if managed is not None and managed.is_file():
        return load(managed), str(managed)
    named = env.get(ENV_VAR)
    return (load(Path(named)), named) if named else None


def launch_refusal(policy: OrgPolicy, row: dict[str, Any],
                   entry: Mapping[str, Any] | None) -> str | None:
    """Why `policy` forbids starting this server, or None.

    `row` describes the launch (inventory.describe, plus an identity) and
    `entry` is its lock entry, None when it has none. Only what is knowable
    before the process exists is asked: the deny and allow lists, and the
    requirements a lock entry or a launch command can settle. `enforced` holds
    by being asked here, and findings are a scan's to judge.
    """
    head = (f"organisation policy {policy.name or '(unnamed)'} "
            f"(sha256:{policy.digest[:12]}) refuses this server: ")
    denied = _denied(policy, row)
    if denied is not None:
        return head + denied.message
    unlisted = _unlisted(policy, row)
    if unlisted is not None and unlisted.level == "deny":
        return head + unlisted.message
    need = policy.require
    if need.get("approved") and entry is None:
        return head + ("it requires every server to be approved in a lockfile, "
                       "and --allow-unapproved cannot waive that")
    if need.get("pinned") and entry is not None and not any(entry.get(k) for k in _PINNED_KEYS):
        return head + "it requires tool definitions to be pinned, and this approval pins none"
    package = row.get("package")
    if need.get("exact_versions") and package and not package.get("exact"):
        return head + (f"{package['name']} runs whatever was published last, and it "
                       f"requires an exact version")
    return None
