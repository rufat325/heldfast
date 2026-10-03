"""Many inventories, one answer for the organisation.

Each machine's `heldfast inventory` says what it runs. Nobody reads two
hundred of them. This joins them and answers what a security team is asked:

- which MCP servers run here at all, on how many machines, at which versions;
- how many of those installs a lockfile approves, pins, and checks at call
  time -- as counts, "41 of 60", never a score: the gaps are not equal and a
  percentage invites raising the number rather than closing the gap
  (coverage.py makes the same choice);
- which machines break the organisation's policy, and how;
- with `--advisories`, which machines run a release OSV reports as malware.

What it cannot do, said where it is used: an inventory is what a machine says
about itself, written by whatever ran there, so anyone who can write to the
place inventories are collected can write one. Inventories are read as data
from an untrusted source -- every field is checked and re-escaped here, and a
file that is not one is set aside with a note, not trusted and not fatal.
And no inventory reads tool definitions (`probed` is false), so a tool
rewritten under an approved name is invisible from here; that is what `wrap`,
`gateway` and the public log are for.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .inventory import SCHEMA as INVENTORY_SCHEMA
from .orgpolicy import OrgPolicy, evaluate
from .secrets import safe_name

SCHEMA = "heldfast.fleet/1"

# An inventory is a few kilobytes per server. One past this is not one.
MAX_BYTES = 16 * 1024 * 1024
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_STATES = {"ok", "UNAPPROVED", "UNPINNED", "DRIFTED", "FINDINGS", "FAILED", "GONE", "gateway"}
_KINDS = {"hosted", "package", "local"}
_ENFORCED = {"wrap", "gateway", "plugin", "none"}


# ---------------------------------------------------------------------------
# Reading inventories, which are untrusted


def _files(paths: list[Path], notes: list[str]) -> list[Path]:
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            out.extend(sorted(p for p in path.rglob("*.json") if p.is_file()))
        elif path.is_file():
            out.append(path)
        else:
            notes.append(f"{path}: no such file or directory")
    return out


def _text(value: Any, limit: int = 300) -> str:
    return safe_name(value, limit) if isinstance(value, (str, int, float)) else ""


def _choice(value: Any, allowed: set[str] | tuple[str, ...], default: str) -> str:
    """`value` when it is one of `allowed`, else `default`. Checked as a string
    first: a list or object is unhashable, and asking whether one is in a set
    raised, so one crafted inventory took the whole report down."""
    return value if isinstance(value, str) and value in allowed else default


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _seq(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _count(value: Any) -> int:
    """A non-negative count. `True` is an int to Python and -1 is a truthy
    one; neither is a number of findings."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return min(value, 10**6)


def _package(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or _choice(value.get("ecosystem"), ("npm", "pypi"), ""
                                              ) == "":
        return None
    name = _text(value.get("name"))
    if not name:
        return None
    return {"ecosystem": value["ecosystem"], "name": name,
            "version": _text(value.get("version"), 100),
            "exact": value.get("exact") is True}


def _row(value: Any) -> dict[str, Any] | None:
    """One server row, every field checked; None when it is not one."""
    if not isinstance(value, dict) or not _text(value.get("identity")):
        return None
    counts = _obj(value.get("findings"))
    top = _seq(value.get("top_findings"))
    state = _choice(value.get("state"), _STATES, "UNAPPROVED")
    return {
        "identity": _text(value["identity"]), "client": _text(value.get("client")),
        "name": _text(value.get("name")),
        "kind": _choice(value.get("kind"), _KINDS, "local"),
        "package": _package(value.get("package")),
        "endpoint": _text(value.get("endpoint"), 2000) or None,
        "command": _text(value.get("command"), 100) or None,
        "disabled": value.get("disabled") is True,
        "state": state,
        "enforced": _choice(value.get("enforced"), _ENFORCED, "none"),
        "tools": _count(value.get("tools")),
        "findings": {s: _count(counts.get(s)) for s in _SEVERITIES},
        "top_findings": [
            {"rule_id": _text(f.get("rule_id"), 20), "title": _text(f.get("title")),
             "severity": _choice(f.get("severity"), _SEVERITIES, "info")}
            for f in top[:5] if isinstance(f, dict)],
    }


def _inventory(data: Any, where: str, notes: list[str]) -> dict[str, Any] | None:
    if not isinstance(data, dict) or data.get("schema") != INVENTORY_SCHEMA:
        notes.append(f"{where}: not a {INVENTORY_SCHEMA} document; set aside")
        return None
    label = _text(data.get("label"))
    generated = _text(data.get("generated"), 40)
    servers = data.get("servers")
    if not label or not isinstance(servers, list):
        notes.append(f"{where}: an inventory without a label or a server list; set aside")
        return None
    rows = [_row(item) for item in servers]
    if any(row is None for row in rows):
        notes.append(f"{where}: {sum(r is None for r in rows)} server row(s) unreadable; "
                     f"the rest were read")
    lock = _obj(data.get("lockfile"))
    policy = _obj(data.get("policy"))
    reported = _seq(policy.get("violations"))
    return {
        "label": label, "generated": generated, "source": where,
        "platform": _text(data.get("platform"), 40),
        "heldfast": _text(data.get("heldfast"), 40),
        "plugin": data.get("plugin") is True,
        "lockfile": lock.get("exists") is True,
        "unreadable": len(_seq(data.get("unreadable"))),
        "servers": [row for row in rows if row is not None],
        # What the machine was checked against when it wrote this, kept only
        # for when no policy is given here.
        "reported_policy": _text(policy.get("sha256"), 64),
        "reported": [{k: _text(v.get(k), 500) for k in ("server", "level", "code", "message")}
                     for v in reported if isinstance(v, dict)
                     and _choice(v.get("level"), ("deny", "warn"), "")],
    }


def load(paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    """(inventories, notes). One inventory per label: the newest.

    Two files with one label are a machine reporting twice, or one machine
    claiming to be another. Either way only one can be shown, and the note
    says so rather than letting the second quietly replace the first.
    """
    notes: list[str] = []
    by_label: dict[str, dict[str, Any]] = {}
    for path in _files(paths, notes):
        try:
            if path.stat().st_size > MAX_BYTES:
                notes.append(f"{path}: larger than {MAX_BYTES} bytes; set aside")
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            # RecursionError is json's answer to `[[[[...` nested deeper than
            # the interpreter's stack, and it is not a ValueError.
            notes.append(f"{path}: unreadable ({type(exc).__name__}); set aside")
            continue
        inv = _inventory(data, str(path), notes)
        if inv is None:
            continue
        kept = by_label.get(inv["label"])
        if kept is not None:
            newer, older = (inv, kept) if inv["generated"] > kept["generated"] else (kept, inv)
            notes.append(f"two inventories call themselves {inv['label']!r}: kept "
                         f"{newer['source']} ({newer['generated']}), set aside "
                         f"{older['source']} ({older['generated']})")
            inv = newer
        by_label[inv["label"]] = inv
    return [by_label[k] for k in sorted(by_label)], notes


# ---------------------------------------------------------------------------
# Advisories


def _releases(inventories: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    out = set()
    for inv in inventories:
        for row in _running(inv):
            package = row.get("package")
            if package and package["exact"] and package["version"]:
                out.add((package["ecosystem"], package["name"], package["version"]))
    return sorted(out)


def ask_osv(inventories: list[dict[str, Any]]) -> tuple[dict[str, list[str]], str]:
    """({"eco:name@version": [advisory ids]}, error). Opens a socket."""
    from .advisories import AdvisoryError, batch
    try:
        found = batch(_releases(inventories))
    except AdvisoryError as exc:
        return {}, str(exc)
    return {f"{eco}:{name}@{version}": ids for (eco, name, version), ids in found.items()}, ""


# ---------------------------------------------------------------------------
# Joining


def _running(inv: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for r in inv["servers"] if not r["disabled"] and r["state"] != "GONE"]


def server_key(row: dict[str, Any]) -> str:
    """What makes two machines' rows the same server."""
    package = row.get("package")
    if package:
        return f"{package['ecosystem']}:{package['name']}"
    if row.get("endpoint"):
        return str(row["endpoint"])
    return f"local:{row.get('name') or row.get('command') or row['identity']}"


def _parse_time(text: str) -> datetime | None:
    try:
        when = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return when.replace(tzinfo=timezone.utc)


def _approved(row: dict[str, Any]) -> bool:
    return row["state"] != "UNAPPROVED"


def _pinned(row: dict[str, Any]) -> bool:
    return row["state"] not in ("UNAPPROVED", "UNPINNED")


def _worst(counts: dict[str, int]) -> str:
    return next((s for s in _SEVERITIES[:4] if counts.get(s)), "")


def _violations(inv: dict[str, Any], policy: OrgPolicy | None) -> list[dict[str, str]]:
    if policy is not None:
        return [v.to_dict() for v in evaluate(policy, inv["servers"])]
    return list(inv["reported"])


def _server_entry(key: str, row: dict[str, Any]) -> dict[str, Any]:
    return {"key": key, "kind": row["kind"], "machines": [], "installs": 0,
            "versions": {}, "floating": 0, "approved": 0, "pinned": 0,
            "enforced": 0, "drifted": 0, "deny": 0, "warn": 0, "policy": "",
            "findings": {s: 0 for s in _SEVERITIES}, "advisories": [], "malware": []}


def _add_row(entry: dict[str, Any], label: str, row: dict[str, Any]) -> None:
    if label not in entry["machines"]:
        entry["machines"].append(label)
    entry["installs"] += 1
    package = row.get("package")
    if package:
        version = package["version"] if package["exact"] else "(floating)"
        entry["versions"][version] = entry["versions"].get(version, 0) + 1
        entry["floating"] += 0 if package["exact"] else 1
    entry["approved"] += _approved(row)
    entry["pinned"] += _pinned(row)
    entry["enforced"] += row["enforced"] != "none"
    entry["drifted"] += row["state"] == "DRIFTED"
    for severity, count in row["findings"].items():
        entry["findings"][severity] += count


_RANK = {"": 0, "allowed": 1, "unlisted": 2, "denied": 3}


def _policy_word(codes: set[str], have_policy: bool) -> str:
    if not have_policy:
        return ""
    if "denied" in codes:
        return "denied"
    if "unlisted" in codes:
        return "unlisted"
    return "allowed"


def _host(inv: dict[str, Any], rows: list[dict[str, Any]], violations: list[dict[str, str]],
          now: datetime, max_age: int) -> dict[str, Any]:
    when = _parse_time(inv["generated"])
    counts = {s: sum(r["findings"][s] for r in rows) for s in _SEVERITIES}
    return {
        "label": inv["label"], "generated": inv["generated"],
        "stale": when is None or (now - when).days > max_age,
        "platform": inv["platform"], "heldfast": inv["heldfast"],
        "plugin": inv["plugin"], "lockfile": inv["lockfile"],
        "servers": len(rows),
        "unapproved": sum(not _approved(r) for r in rows),
        "unenforced": sum(r["enforced"] == "none" for r in rows),
        "drifted": sum(r["state"] == "DRIFTED" for r in rows),
        "deny": sum(v["level"] == "deny" for v in violations),
        "warn": sum(v["level"] == "warn" for v in violations),
        "unreadable": inv["unreadable"], "worst": _worst(counts),
    }


def _alarms(servers: dict[str, dict[str, Any]], hits: dict[str, list[tuple[str, str]]],
            advisories: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Releases reported as malware, with every machine that runs them."""
    out = []
    for release, machines in sorted(hits.items()):
        ids = advisories.get(release) or []
        bad = [i for i in ids if i.startswith("MAL-")]
        key, _, version = release.rpartition("@")
        entry = servers.get(key)
        if entry is not None:
            entry["advisories"] = sorted(set(entry["advisories"]) | set(ids))
            if bad:
                entry["malware"] = sorted(set(entry["malware"]) | {version})
        if bad:
            out.append({"release": release, "ids": bad,
                        "machines": sorted({label for label, _ in machines})})
    return out


def build(inventories: list[dict[str, Any]], *, policy: OrgPolicy | None = None,
          advisories: dict[str, list[str]] | None = None, advisory_error: str = "",
          max_age: int = 14, notes: list[str] | None = None,
          now: datetime | None = None) -> dict[str, Any]:
    """The organisation report. `advisories` is None when OSV was not asked or
    could not answer (`advisory_error` says which); only a dict is an answer."""
    now = now or datetime.now(timezone.utc)
    servers: dict[str, dict[str, Any]] = {}
    hosts, violations = [], []
    hits: dict[str, list[tuple[str, str]]] = {}
    for inv in inventories:
        rows = _running(inv)
        found = _violations(inv, policy)
        codes_by_identity: dict[str, set[str]] = {}
        for v in found:
            violations.append(dict(v, machine=inv["label"]))
            codes_by_identity.setdefault(v["server"], set()).add(v["code"])
        for row in rows:
            key = server_key(row)
            entry = servers.setdefault(key, _server_entry(key, row))
            _add_row(entry, inv["label"], row)
            codes = codes_by_identity.get(row["identity"], set())
            levels = [v["level"] for v in found if v["server"] == row["identity"]]
            entry["deny"] += "deny" in levels
            entry["warn"] += "warn" in levels and "deny" not in levels
            # The worst verdict any machine got for it: allow rules can name
            # versions, so one machine's release can be allowed and another's not.
            word = _policy_word(codes, policy is not None or bool(inv["reported_policy"]))
            if _RANK[word] > _RANK[entry["policy"]]:
                entry["policy"] = word
            package = row.get("package")
            if package and package["exact"]:
                release = f"{key}@{package['version']}"
                hits.setdefault(release, []).append((inv["label"], row["identity"]))
        hosts.append(_host(inv, rows, found, now, max_age))

    alarms = _alarms(servers, hits, advisories) if advisories is not None else []
    asked = "failed" if advisory_error else "asked" if advisories is not None else "not asked"
    return _report(hosts, servers, violations, alarms, policy, asked, notes or [], now,
                   inventories)


def _report(hosts: list[dict[str, Any]], servers: dict[str, dict[str, Any]],
            violations: list[dict[str, str]], alarms: list[dict[str, Any]],
            policy: OrgPolicy | None, advisories: str,
            notes: list[str], now: datetime,
            inventories: list[dict[str, Any]]) -> dict[str, Any]:
    entries = sorted(servers.values(), key=lambda e: (-len(e["machines"]), e["key"]))
    for entry in entries:
        entry["machines"] = sorted(entry["machines"])
    rows = [r for inv in inventories for r in _running(inv)]
    packages = [r for r in rows if r.get("package")]
    digests = sorted({inv["reported_policy"] for inv in inventories if inv["reported_policy"]})
    if policy is None and len(digests) > 1:
        notes.append(f"machines were checked against {len(digests)} different policies; "
                     f"pass --policy to judge them all by one")
    return {
        "schema": SCHEMA,
        "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy": ({"name": policy.name, "sha256": policy.digest} if policy is not None
                   else {"name": "", "sha256": digests[0]} if len(digests) == 1 else None),
        # "asked", "not asked" or "failed". Only "asked" makes a zero mean
        # that nothing is known to be wrong.
        "advisories": advisories,
        "totals": {
            "machines": len(hosts), "stale": sum(h["stale"] for h in hosts),
            "installs": len(rows), "servers": len(entries),
            "approved": sum(_approved(r) for r in rows),
            "pinned": sum(_pinned(r) for r in rows),
            "enforced": sum(r["enforced"] != "none" for r in rows),
            "drifted": sum(r["state"] == "DRIFTED" for r in rows),
            "packages": len(packages),
            "exact": sum(1 for r in packages if r["package"]["exact"]),
            "kinds": {k: sum(r["kind"] == k for r in rows) for k in sorted(_KINDS)},
            "deny": sum(v["level"] == "deny" for v in violations),
            "warn": sum(v["level"] == "warn" for v in violations),
            "machines_failing": sum(h["deny"] > 0 for h in hosts),
            "unreadable": sum(h["unreadable"] for h in hosts),
            "findings": {s: sum(r["findings"][s] for r in rows) for s in _SEVERITIES},
            "malware": len({m for a in alarms for m in a["machines"]}),
        },
        "alarms": alarms,
        "machines": sorted(hosts, key=lambda h: (-h["deny"], -h["unapproved"], h["label"])),
        "servers": entries,
        "violations": violations,
        "notes": [safe_name(n, 1000) for n in notes],
    }


def failed(report: dict[str, Any]) -> bool:
    """Exit 1: a policy violation at deny, or a machine running malware."""
    return bool(report["totals"]["deny"] or report["alarms"])


# ---------------------------------------------------------------------------
# Terminal


def _of(part: int, whole: int) -> str:
    return f"{part} of {whole}"


def _versions(entry: dict[str, Any]) -> str:
    items = sorted(entry["versions"].items(), key=lambda kv: (-kv[1], kv[0]))
    text = ", ".join(f"{v} x{n}" if n > 1 else v for v, n in items[:4])
    return text + (f", +{len(items) - 4} more" if len(items) > 4 else "")


def render(report: dict[str, Any], color: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color and code else text

    t = report["totals"]
    policy = report.get("policy")
    lines = ["", f"  {t['machines']} machine(s), {t['servers']} distinct server(s), "
                 f"{t['installs']} install(s)"
             + (f"   {t['stale']} stale" if t["stale"] else "")]
    if policy:
        lines.append(f"  policy {policy['name'] or '(unnamed)'}  sha256:{policy['sha256'][:12]}")
    lines += [
        f"  approved in a lockfile   {_of(t['approved'], t['installs'])}",
        f"  tool definitions pinned  {_of(t['pinned'], t['installs'])}",
        f"  checked at call time     {_of(t['enforced'], t['installs'])}",
        f"  exact package versions   {_of(t['exact'], t['packages'])}",
        "  tool definitions were not read on any machine (inventories never probe)",
    ]
    if report["advisories"] == "asked" and not report["alarms"]:
        lines.append("  OSV reports no release in use as malware")
    elif report["advisories"] == "failed":
        lines.append("  " + paint("OSV could not be asked, so nothing is known about "
                                  "advisories (see the note below)", "\033[33m"))
    for alarm in report["alarms"]:
        lines += ["", "  " + paint(f"MALWARE {alarm['release']} ({', '.join(alarm['ids'])}) "
                                   f"runs on: {', '.join(alarm['machines'])}", "\033[31m")]
    lines += ["", "  servers, by how many machines run them"]
    for entry in report["servers"][:25]:
        flags = [w for w in (entry["policy"] if entry["policy"] != "allowed" else "",
                             f"{entry['floating']} floating" if entry["floating"] else "",
                             f"{entry['installs'] - entry['approved']} unapproved"
                             if entry["installs"] > entry["approved"] else "") if w]
        lines.append("  %4d  %-7s %s%s" % (len(entry["machines"]), entry["kind"], entry["key"],
                                            "  " + paint(", ".join(flags), "\033[33m")
                                            if flags else ""))
        if len(entry["versions"]) > 1:
            lines.append("              versions: " + _versions(entry))
    if len(report["servers"]) > 25:
        lines.append(f"        ... and {len(report['servers']) - 25} more (-f json or --html)")
    failing = [h for h in report["machines"] if h["deny"]]
    if failing:
        lines += ["", f"  {len(failing)} machine(s) break the policy"]
        for host in failing[:20]:
            lines.append(f"    {paint(host['label'], chr(27) + '[31m')}  {host['deny']} "
                         f"violation(s), {host['unapproved']} unapproved")
    for note in report["notes"]:
        lines.append("  note: " + note)
    lines.append("")
    return "\n".join(lines)
