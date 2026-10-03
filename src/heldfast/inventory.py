"""What MCP servers one machine or repository runs, as a file a fleet can join.

`status` answers "where do things stand" for one person at one terminal. An
organisation asks the same question of two hundred laptops and forty
repositories, and nobody can open a terminal on all of them. This is the same
page as data: written to a file on each machine -- by MDM, a login script, a CI
job -- collected anywhere, and joined by `heldfast fleet`.

It is made to be sent somewhere, so it carries less than `status` does:

- no environment values, headers or arguments, which is where credentials
  live in an MCP config;
- a hosted server's address without its query, fragment or user info, and
  with any path segment that looks like a token replaced by `{redacted}`;
- config paths with the home directory written as `~`.

It runs nothing and opens no socket. The collection is `scan --safe`'s, so it
can be pushed to every machine without that push launching anyone's server.
The price of that is the same as `status` without `--probe`: tool definitions
are not read here, so a tool rewritten under an approved name is not seen
(`probed` is false in every inventory, and the fleet report says so).
"""

from __future__ import annotations

import hashlib
import platform
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from . import __version__
from .enforcement import (behind_gateway, fronting_clients, is_gateway, unwrap_launcher,
                          wraps)
from .findings import Finding
from .lockfile import Lock
from .model import ServerSpec
from .rules.execution import (_FLOATING, _PYTHON_RUNNERS, _basename, extract_package,
                              split_package)
from .secrets import redact, safe_name

SCHEMA = "heldfast.inventory/1"

# Runner -> the registry its package token names. `yarn dlx`, `pnpm dlx` and
# `bun x` fetch from npm; deno is handled on its own (an `npm:` specifier).
_ECOSYSTEM = {"npx": "npm", "pnpx": "npm", "bunx": "npm", "yarn": "npm",
              "pnpm": "npm", "bun": "npm", "uvx": "pypi", "pipx": "pypi"}

# A full version, not a range: npm reads `pkg@1.2` as 1.2.x and `pkg@1` as
# 1.x.x, so only three numbers (and a pre-release or build tag) name one
# release.
_EXACT_NPM = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_EXACT_PYPI = re.compile(r"^===?\s*[0-9A-Za-z][0-9A-Za-z.!+_-]*$")

# A path segment that is probably a credential or an account id rather than a
# route: long, and mixing letters with digits. Zapier and several gateways put
# the API key in the path, where neither a query strip nor `redact` sees it.
_OPAQUE = re.compile(r"^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_\-.~%=]{20,}$")
REDACTED = "{redacted}"

# Server states (status.py) worth counting as findings in a summary line.
_SEVERITIES = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# Describing one server without its secrets


def endpoint(url: str | None) -> str | None:
    """A hosted server's address, fit to leave the machine.

    Rebuilt from the parsed parts rather than edited, so user info never
    survives (`https://good.example@evil.example/` is evil.example) and the
    host is the host a client would connect to.
    """
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    segments = []
    for segment in parts.path.split("/"):
        if segment and (_OPAQUE.match(segment) or redact(segment) != segment):
            segment = REDACTED
        segments.append(segment)
    path = "/".join(segments)
    if not path.startswith("/"):
        path = "/" + path
    return f"{parts.scheme.lower()}://{netloc}{path}"


def inner(spec: ServerSpec) -> ServerSpec:
    """The server a `heldfast guard|wrap ... -- <server>` entry runs, or `spec`.

    An inventory that described a wrapped server as "heldfast" would list the
    enforcement instead of what it enforces, and the fleet would count one
    package used everywhere and none of the servers it wraps.
    """
    if not wraps(spec):
        return spec
    command, args = unwrap_launcher(spec.command or "", spec.args)
    argv = [command, *[str(a) for a in args]]
    if "--" not in argv:
        return spec
    rest = argv[argv.index("--") + 1:]
    if not rest:
        return spec
    return ServerSpec(name=spec.name, source=spec.source, client=spec.client,
                      scope=spec.scope, line=spec.line, transport=spec.transport,
                      command=rest[0], args=rest[1:], env=spec.env,
                      disabled=spec.disabled)


def exact(version: str | None, ecosystem: str) -> bool:
    if not version or _FLOATING.match(version):
        return False
    if ecosystem == "pypi":
        return bool(_EXACT_PYPI.match(version)) and "*" not in version
    return bool(_EXACT_NPM.match(version.lstrip("=v")))


def package_of(spec: ServerSpec) -> dict[str, Any] | None:
    """{ecosystem, name, version, exact} for a registry launch, else None."""
    found = extract_package(spec)
    if not found:
        return None
    runner, token = found
    if runner == "deno":
        if not token.startswith("npm:"):
            return None
        runner, token = "npx", token[4:]
    if token.startswith((".", "/", "~")) or re.match(r"^[a-zA-Z]:[\\/]", token):
        return None
    ecosystem = _ECOSYSTEM.get(runner)
    if ecosystem is None:
        return None
    name, spec_version = split_package(token, runner)
    if not name:
        return None
    pinned = exact(spec_version, ecosystem)
    version = (spec_version or "").strip()
    if pinned:
        version = version.lstrip("=").strip() if runner in _PYTHON_RUNNERS \
            else version.lstrip("=v")
    return {"ecosystem": ecosystem, "name": safe_name(name),
            "version": safe_name(version), "exact": pinned}


def kind_of(spec: ServerSpec) -> str:
    if spec.is_remote:
        return "hosted"
    return "package" if package_of(spec) else "local"


def _enforced(spec: ServerSpec | None, key: str, entry: Any, fronting: set,
              plugin: bool) -> str:
    """How a call to this server is checked against the lock, if at all.

    `wrap` and `gateway` see every definition; `plugin` is the Claude Code hook,
    which sees only the server and tool names (plugin/heldfast/README.md).
    """
    if spec is not None and wraps(spec):
        return "wrap"
    if spec is None and behind_gateway(key, entry, fronting):
        return "gateway"
    client = spec.client if spec is not None else key.split(":", 1)[0]
    if plugin and client in ("claude-code", "claude-code-plugin"):
        return "plugin"
    return "none"


def _home(path: str) -> str:
    home = str(Path.home())
    if home and home not in ("/", "") and (path == home or path.startswith(home + "/")
                                           or path.startswith(home + "\\")):
        return "~" + path[len(home):]
    return path


def _spec_from_lock(key: str, entry: dict[str, Any]) -> ServerSpec:
    """A lock entry read back as a launch, for a server only the lock names.

    The gateway's servers live only in the lockfile in the recommended setup;
    without this they would be listed with nothing to say what they run.
    """
    import shlex
    try:
        argv = shlex.split(str(entry.get("command_line") or ""))
    except ValueError:
        argv = []
    return ServerSpec(name=str(entry.get("name") or key), source=str(entry.get("source") or ""),
                      client=str(entry.get("client") or key.split(":", 1)[0]),
                      transport=str(entry.get("transport") or "unknown"),
                      command=argv[0] if argv else None, args=argv[1:],
                      url=entry.get("url") if isinstance(entry.get("url"), str) else None)


def describe(spec: ServerSpec) -> dict[str, Any]:
    """What a server is, with nothing secret: the facts a policy matches on."""
    run = inner(spec)
    command = None
    if not run.is_remote and run.command:
        command, _ = unwrap_launcher(run.command, run.args)
        command = safe_name(_basename(command))
    return {
        "kind": kind_of(run),
        "transport": safe_name(spec.transport),
        "package": package_of(run),
        "endpoint": safe_name(endpoint(run.url)) if run.url else None,
        "command": command,
    }


# ---------------------------------------------------------------------------
# One machine


def _counts(findings: list[Finding]) -> dict[str, int]:
    out = {label: 0 for label in _SEVERITIES}
    for finding in findings:
        out[finding.severity.label] = out.get(finding.severity.label, 0) + 1
    return out


def _findings_by_server(findings: list[Finding], servers: list[ServerSpec],
                        lock: Lock) -> dict[str, list[Finding]]:
    from .status import _findings_for, _name_owners
    by_name: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.server:
            by_name.setdefault(finding.server, []).append(finding)
    owners = _name_owners(servers, lock)
    keys = set(lock.servers) | {s.identity() for s in servers}
    out = {}
    for key in keys:
        entry = lock.servers.get(key)
        name = str(entry.get("name") or key) if isinstance(entry, dict) else key.split(":", 1)[-1]
        spec = next((s for s in servers if s.identity() == key), None)
        if spec is not None:
            name = spec.name
        out[key] = _findings_for(by_name, key, name, owners)
    return out


def _row(key: str, status_row: dict[str, Any], spec: ServerSpec | None,
         entry: Any, found: list[Finding], fronting: set, plugin: bool) -> dict[str, Any]:
    source = spec if spec is not None else _spec_from_lock(key, entry) \
        if isinstance(entry, dict) else None
    facts = describe(source) if source is not None else {
        "kind": "local", "transport": "unknown", "package": None,
        "endpoint": None, "command": None}
    ranked = sorted(found, key=lambda f: -f.severity.value)
    return {
        "identity": safe_name(key),
        "client": safe_name(source.client if source else key.split(":", 1)[0]),
        "name": status_row["name"],
        **facts,
        "config": safe_name(_home(spec.source)) if spec is not None else "",
        "configured": status_row["configured"],
        "disabled": bool(spec.disabled) if spec is not None else False,
        "state": status_row["state"],
        "approved_at": status_row["approved_at"],
        "tools": status_row["tools"],
        "integrity": status_row["integrity"],
        "enforced": _enforced(spec, key, entry, fronting, plugin),
        "findings": _counts(found),
        "top_findings": [{"rule_id": safe_name(f.rule_id), "severity": f.severity.label,
                          "title": safe_name(f.title)} for f in ranked[:5]],
    }


def build(lock: Lock, servers: list[ServerSpec], findings: list[Finding], *,
          label: str, scope: dict[str, Any], plugin: bool = False,
          skills: int = 0, unreadable: list | None = None,
          generated: str = "") -> dict[str, Any]:
    """The inventory document. Pure: everything it reports is passed in."""
    from . import status as status_mod
    from .lockfile import _now

    payload = status_mod.build(lock, servers, findings, None, probed=False)
    configured = {s.identity(): s for s in servers if not is_gateway(s)}
    fronting = fronting_clients(servers)
    by_server = _findings_by_server(findings, servers, lock)
    # status.build names rows by safe_name(identity); the raw key is needed to
    # find the spec and the lock entry again.
    raw_keys = {safe_name(k): k for k in set(lock.servers) | set(configured)}
    rows = []
    for status_row in payload["servers"]:
        key = raw_keys.get(status_row["identity"], status_row["identity"])
        rows.append(_row(key, status_row, configured.get(key), lock.servers.get(key),
                         by_server.get(key, []), fronting, plugin))
    return {
        "schema": SCHEMA,
        "generated": generated or _now(),
        "heldfast": __version__,
        "label": safe_name(label),
        "platform": platform.system().lower(),
        "scope": scope,
        "probed": False,
        "lockfile": {
            "path": safe_name(_home(str(lock.path.resolve()))) if lock.path else "",
            "exists": not lock.is_empty,
            "servers": len(lock.servers),
        },
        "clients": sorted({safe_name(s.client) for s in servers}),
        "gateways": sum(1 for s in servers if is_gateway(s) and not s.disabled),
        "plugin": plugin,
        "skills": skills,
        "unreadable": [safe_name(f"{_home(str(path))}: {why}")
                       for path, why in unreadable or []],
        "servers": rows,
    }


def host_label() -> str:
    """This machine's name, read without a socket."""
    return platform.node() or "unnamed"


# ---------------------------------------------------------------------------
# Rendering


def _summary(row: dict[str, Any]) -> str:
    package = row.get("package")
    if package:
        version = package.get("version") or "(no version)"
        mark = "" if package.get("exact") else "  floating"
        return f"{package['ecosystem']}:{package['name']}@{version}{mark}"
    return str(row.get("endpoint") or row.get("command") or "")


_STATE_COLOR = {"ok": "\033[32m", "DRIFTED": "\033[31m", "UNAPPROVED": "\033[33m",
                "UNPINNED": "\033[33m", "FINDINGS": "\033[33m", "FAILED": "\033[33m",
                "GONE": "\033[90m", "gateway": "\033[32m"}


def render(data: dict[str, Any], color: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color and code else text

    lines = ["", f"  {data['label']}   {len(data['servers'])} server(s) in "
                 f"{len(data['clients'])} client(s), {data['skills']} skill(s)   "
                 f"heldfast {data['heldfast']}"]
    lock = data["lockfile"]
    lines.append("  lockfile: " + (lock["path"] if lock["exists"] else "none"))
    lines.append("  Claude Code plugin: " + ("on" if data["plugin"] else "not installed"))
    lines.append("")
    width = max((len(r["identity"]) for r in data["servers"]), default=10)
    for row in data["servers"]:
        counts = row["findings"]
        worst = next((f"{counts[s]} {s}" for s in _SEVERITIES[:3] if counts.get(s)), "")
        lines.append("  %s  %-*s  %-7s %-8s %s%s" % (
            paint("%-10s" % row["state"], _STATE_COLOR.get(row["state"], "")),
            width, row["identity"], row["kind"], row["enforced"], _summary(row),
            f"  ({worst})" if worst else ""))
    for text in data["unreadable"]:
        lines.append("  " + paint("could not read " + text, "\033[33m"))
    policy = data.get("policy")
    if policy:
        lines += ["", f"  policy {policy['name'] or '(unnamed)'}  sha256:{policy['sha256'][:12]}"]
        if not policy["violations"]:
            lines.append("  " + paint("every server meets it", "\033[32m"))
        for v in policy["violations"]:
            mark = paint("DENY", "\033[31m") if v["level"] == "deny" else paint("warn", "\033[33m")
            lines.append(f"  {mark}  {v['server']}: {v['message']}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CycloneDX


def _purl(package: dict[str, Any]) -> str:
    name = str(package["name"])
    if package["ecosystem"] == "pypi":
        base = "pkg:pypi/" + quote(re.sub(r"[-_.]+", "-", name).lower(), safe="")
    elif name.startswith("@") and "/" in name:
        scope, _, rest = name.partition("/")
        base = f"pkg:npm/{quote(scope, safe='')}/{quote(rest, safe='')}"
    else:
        base = "pkg:npm/" + quote(name, safe="")
    if package.get("exact") and package.get("version"):
        return f"{base}@{quote(str(package['version']), safe='')}"
    return base


def _properties(row: dict[str, Any]) -> list[dict[str, str]]:
    props = {
        "heldfast:identity": row["identity"], "heldfast:client": row["client"],
        "heldfast:kind": row["kind"], "heldfast:state": row["state"],
        "heldfast:enforced": row["enforced"], "heldfast:tools": str(row["tools"]),
        "heldfast:config": row["config"],
    }
    for severity, count in row["findings"].items():
        if count:
            props[f"heldfast:findings:{severity}"] = str(count)
    package = row.get("package")
    if package and not package.get("exact"):
        props["heldfast:version-spec"] = package.get("version") or "(none)"
    return [{"name": k, "value": v} for k, v in props.items() if v != ""]


def cyclonedx(data: dict[str, Any]) -> dict[str, Any]:
    """The inventory as a CycloneDX 1.6 BOM, for tools that already ingest one.

    A registry package is a component with a purl; a hosted server is a
    service with its endpoint; anything else is a component named after the
    program it runs. heldfast's own verdicts ride along as `heldfast:*`
    properties, so a BOM consumer that knows nothing about MCP still sees
    which entries nobody approved.
    """
    components, services = [], []
    for row in data["servers"]:
        if row.get("disabled"):
            continue
        ref = "heldfast:" + row["identity"]
        if row["kind"] == "hosted":
            services.append({"bom-ref": ref, "name": row["name"],
                             "endpoints": [row["endpoint"]] if row.get("endpoint") else [],
                             "properties": _properties(row)})
            continue
        package = row.get("package")
        component: dict[str, Any] = {"type": "application", "bom-ref": ref}
        if package:
            component["name"] = package["name"]
            if package.get("exact"):
                component["version"] = package["version"]
            component["purl"] = _purl(package)
        else:
            component["name"] = row.get("command") or row["name"]
        component["properties"] = _properties(row)
        components.append(component)
    digest = hashlib.sha256(repr((data["label"], data["generated"], components,
                                  services)).encode("utf-8")).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.UUID(digest[:32])),
        "version": 1,
        "metadata": {
            "timestamp": data["generated"],
            "tools": {"components": [{"type": "application", "name": "heldfast",
                                      "version": data["heldfast"]}]},
            "component": {"type": "application", "bom-ref": "heldfast:host",
                          "name": data["label"]},
            "properties": [{"name": "heldfast:probed", "value": "false"},
                           {"name": "heldfast:plugin",
                            "value": "true" if data["plugin"] else "false"}],
        },
        "components": components,
        "services": services,
    }
