"""Where the guarantees stop.

Every layer in this tool is optional in practice. A server can be approved
without being probed, pinned by command without being pinned by digest,
policed at the fingerprint without any limit on its arguments. Each of those
is a reasonable state to be in. What is not reasonable is not knowing which
one you are in.

`status` shows two flags and an absent flag reads the same either way: no
`pinned-code` next to a server means either that pinning failed or that there
was never anything on this machine to pin. Those are opposite situations and
the operator cannot tell them apart, which is the failure mode this whole
project keeps running into -- a scanner that finds nothing looks exactly like
one that looked at nothing.

So this reports, per server and per layer: covered or not, *why* not, and the
command that would change it. The reason matters more than the verdict. "Run
from a registry, so there is no local file to hash" is a fact about the
ecosystem and the answer is to pin the version instead; "approved without
--probe" is an omission and the answer is thirty seconds of work. Printing
"no" for both and leaving the operator to work out which is theirs is how a
coverage report becomes a nag.

Nothing here computes a new judgement or a score. A percentage would invite
people to raise the number rather than close the gap, and the gaps are not
equal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import _candidates, named_scripts
from .enforcement import behind_gateway, fronting_clients, is_gateway, subcommand
from .identity import all_identities
from .lockfile import Lock
from .secrets import safe_name
from .rules.execution import _FLOATING, extract_package, split_package

# Runners that fetch from a registry at launch. Nothing of theirs is on disk
# in a form worth hashing -- and if it is, it is a cache entry that the next
# launch may not use.
REGISTRY_RUNNERS = {"npx", "pnpx", "bunx", "uvx", "pipx"}


@dataclass
class Layer:
    """One guarantee, and whether it is actually in force for one server."""

    name: str
    state: str          # "yes" | "no" | "n/a"
    detail: str = ""
    remedy: str = ""

    @property
    def covered(self) -> bool:
        return self.state == "yes"

    @property
    def gap(self) -> bool:
        """A layer that could apply and does not. 'n/a' is not a gap."""
        return self.state == "no"


def _approval(entry: dict | None) -> Layer:
    if not entry:
        return Layer("approved", "no",
                     "configured, never approved",
                     "mcp-pin approve --probe")
    when = str(entry.get("approved_at") or "")
    return Layer("approved", "yes", when)


def _tools(entry: dict | None) -> Layer:
    """Whether tool definitions are pinned, and which of two reasons they are not.

    An entry with no tools means one of two opposite things. Nobody probed, and
    thirty seconds fixes it. Or the server was launched at approve time and
    never answered -- in which case `approve --probe` is the command that
    already failed, and the report would be sending the operator in a circle.
    The lockfile records which, because this was guessing and guessed wrong.
    """
    if not entry:
        return Layer("tools pinned", "no", "nothing approved to pin",
                     "mcp-pin approve --probe")
    count = len(entry.get("tools") or {})
    if count:
        return Layer("tools pinned", "yes", f"{count} tool(s) fingerprinted")

    probe = str(entry.get("probe") or "")
    if probe.startswith("no response"):
        return Layer(
            "tools pinned", "no",
            f"probed at approve time and did not answer -- {probe[13:].strip()}",
            "the approval covers a server that does not start; fix or remove it")
    return Layer(
        "tools pinned", "no",
        "approved without --probe, so no tool definition was recorded",
        "mcp-pin approve --probe")


def _code(entry: dict | None, spec: Any) -> Layer:
    """The digest layer, and an honest account of when it cannot apply.

    This is the one that most needs its reason printed. Roughly every server
    in the ecosystem is `npx -y some-package`, for which there is genuinely
    nothing local to hash, and reporting that as a failure to pin would put a
    permanent red mark on correct configuration.
    """
    pinned = (entry or {}).get("artifacts") or {}
    if pinned:
        return Layer("code pinned", "yes", f"{len(pinned)} file(s) hashed")

    if spec is None:
        return Layer("code pinned", "n/a",
                     "not configured directly; nothing here to hash")

    if spec.is_remote:
        return Layer("code pinned", "n/a",
                     "remote transport; nothing is launched on this machine")

    found = extract_package(spec)
    if found and found[0] in REGISTRY_RUNNERS:
        runner, token = found
        name, version = split_package(token, runner)
        if version and not _FLOATING.match(version):
            # `==0.6.2` is how PEP 508 spells it and not how anyone reads it.
            shown = version.lstrip("=@ ")
            return Layer(
                "code pinned", "n/a",
                f"fetched from a registry at {shown}; local hashing does not apply")
        return Layer(
            "code pinned", "no",
            "fetched from a registry at launch, so there is no local file to hash",
            f"pin the version -- {name}==1.2.3" if runner in ("uvx", "pipx")
            else f"pin the version -- {name}@1.2.3")

    named = named_scripts(spec)
    if named:
        if _candidates(spec):
            return Layer(
                "code pinned", "no",
                "a local script is named but no digest was recorded",
                "mcp-pin approve")
        return Layer(
            "code pinned", "no",
            f"names {named[0]!r}, which is not a file on this machine",
            "the launch command cannot start; fix the path or remove the server")

    return Layer("code pinned", "n/a",
                 "the launch command names no script")


def _registry(entry: dict | None, spec: Any, offline: bool = False) -> Layer:
    """The tarball hash, when the launch is a registry fetch.

    A recorded hash and a verified one are different claims, and this used to
    print "yes" for both. Recording happens once, at approval; verifying is
    something a particular run either did or could not do. Reporting them as
    one guarantee means an operator on a machine that cannot reach the
    registry -- or whose package cache has never held the artifact -- reads
    the same green row as one where the bytes were just checked.
    """
    recorded = (entry or {}).get("integrity") or {}
    if recorded:
        from .pkgcache import check as cache_check
        urls = (entry or {}).get("artifact_urls")
        checks = cache_check(recorded, urls if isinstance(urls, dict) else None)
        key = next(iter(recorded))
        bad = next((c for c in checks if c.state == "changed"), None)
        if bad is not None:
            return Layer("registry pin", "no", f"{bad.key}: {bad.detail}",
                         "the bytes on this machine are not the approved ones; "
                         "do not start this server until you know why")
        good = [c for c in checks if c.state == "verified"]
        if good and len(good) == len(checks):
            return Layer("registry pin", "yes",
                         f"{key} verified against the local package cache")
        why = next((c.detail for c in checks if c.state != "verified"), "")
        if offline:
            why = f"{why}; --safe was given, so no registry was contacted"
        # This page reads the local package cache and nothing else, so the
        # remedy has to name the thing that does ask the registry rather than
        # implying this command would have.
        return Layer("registry pin", "?",
                     f"{key} recorded at approval, not verified here -- {why}",
                     "mcp-pin scan compares it against the registry; a launch "
                     "compares it against the package cache. --require-integrity "
                     "makes 'could not verify' a failure in both")

    if spec is None or spec.is_remote:
        return Layer("registry pin", "n/a", "not fetched from a registry")

    found = extract_package(spec)
    if not found or found[0] not in REGISTRY_RUNNERS:
        return Layer("registry pin", "n/a", "not fetched from a registry")
    runner, token = found
    name, version = split_package(token, runner)
    if version and not _FLOATING.match(version):
        shown = version.lstrip("=@ ")
        return Layer(
            "registry pin", "no",
            f"version {shown} is a name lookup, not a content pin",
            "mcp-pin approve --probe records the tarball hash")
    return Layer(
        "registry pin", "no",
        "fetched from a registry at launch with no version pin",
        f"pin the version -- {name}==1.2.3" if runner in ("uvx", "pipx")
        else f"pin the version -- {name}@1.2.3")


def _policy(entry: dict | None) -> Layer:
    limits = (entry or {}).get("policy") or {}
    if not isinstance(limits, dict) or not limits:
        return Layer(
            "argument policy", "no",
            "any argument reaches the server once the tool itself is approved",
            "mcp-pin policy --probe")
    return Layer("argument policy", "yes", f"{len(limits)} tool(s) constrained")


def _reachable_by(lock: Lock, name: str) -> Layer:
    """Which declared identities can reach this server.

    'n/a' when none are declared: a single unrestricted principal is the
    default and calling it a gap would demand access control from every
    single-agent setup that does not need it.
    """
    identities = all_identities(lock)
    if not identities:
        return Layer("identity", "n/a",
                     "none declared; the gateway serves one unrestricted principal")
    who = sorted(n for n, ident in identities.items() if ident.may_use_server(name))
    if not who:
        # Not a gap and not a guarantee either: no identity grants it, but a
        # gateway started without --as is not acting as any identity and still
        # reaches it. Saying "yes" here would claim a restriction that the
        # launch command, not the lockfile, decides.
        return Layer("identity", "n/a",
                     "granted to no identity; still reachable without --as")
    return Layer("identity", "yes", "reachable by " + ", ".join(who))


def _in_path(key: str, entry: dict | None, spec: Any, fronting: set) -> Layer:
    """Whether anything is between the client and this server at runtime.

    The layer that makes the others mean something. An approved, digest-pinned,
    policed server whose client talks straight to it has none of that in force
    -- the lockfile is then a committed artifact describing a boundary that is
    not in the path, which is worse than having no boundary because it reads
    like one.
    """
    if spec is not None and subcommand(spec) == "guard":
        return Layer("enforced", "yes", "wrapped by `mcp-pin guard`")
    if behind_gateway(key, entry, fronting):
        return Layer("enforced", "yes", "reached through the gateway")
    if spec is not None and spec.client in fronting:
        # A gateway exists for this client and the server is *also* configured
        # directly, so the agent has both paths. MCPA032 reports it as a
        # finding; here it is the reason the layer is not in force.
        return Layer(
            "enforced", "no",
            "a gateway is configured and this server is reachable around it (MCPA032)",
            "remove the direct entry; the gateway already exposes its tools")
    return Layer(
        "enforced", "no",
        "the client talks to this server directly; nothing checks the lockfile at runtime",
        "point the client at `mcp-pin gateway`, or wrap it with `mcp-pin guard`")


def for_server(lock: Lock, key: str, spec: Any,
               fronting: set | None = None, offline: bool = False) -> list[Layer]:
    entry = lock.servers.get(key)
    if not isinstance(entry, dict):
        entry = None
    name = str((entry or {}).get("name") or (spec.name if spec else key))
    return [
        _approval(entry),
        _tools(entry),
        _code(entry, spec),
        _registry(entry, spec, offline),
        _policy(entry),
        _in_path(key, entry, spec, fronting or set()),
        _reachable_by(lock, name),
    ]


def build(lock: Lock, servers: list, offline: bool = False) -> dict[str, Any]:
    # The gateway's own entry is not a server to report on: it is the thing
    # doing the reporting's work, and it has no approval by design.
    configured = {s.identity(): s for s in servers if not is_gateway(s)}
    fronting = fronting_clients(servers)
    keys = sorted(set(lock.servers) | set(configured))

    rows = []
    for key in keys:
        entry = lock.servers.get(key)
        if key in lock.servers and not isinstance(entry, dict):
            continue
        layers = for_server(lock, key, configured.get(key), fronting, offline)
        rows.append({
            "identity": safe_name(key),
            "configured": key in configured,
            # Reachable covers both paths. A fronted server is absent from the
            # config on purpose and calling it "no longer configured" told the
            # operator the recommended setup had lost their servers.
            "reachable": key in configured or behind_gateway(key, entry, fronting),
            "gaps": sum(1 for layer in layers if layer.gap),
            "unverified": sum(1 for layer in layers if layer.state == "?"),
            "layers": [
                {"name": l.name, "state": l.state,
                 "detail": safe_name(l.detail), "remedy": safe_name(l.remedy)}
                for l in layers
            ],
        })

    return {
        "servers": rows,
        # A layer nothing checked cannot count towards "covered". That is
        # the whole lesson of this module applied to itself.
        "fully_covered": sum(1 for r in rows
                             if r["gaps"] == 0 and r["unverified"] == 0),
        "unverified": sum(r["unverified"] for r in rows),
        "total": len(rows),
    }


_STATE_COLOR = {"yes": "\033[32m", "no": "\033[33m", "n/a": "\033[90m",
                "?": "\033[36m"}


def render(data: dict[str, Any], color: bool = True, verbose: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color and code else text

    if not data["servers"]:
        return "\n  Nothing configured and nothing approved.\n"

    lines = [""]
    for row in data["servers"]:
        suffix = "" if row.get("reachable", row["configured"]) \
            else "   (no longer configured)"
        lines.append(f"  {row['identity']}{suffix}")
        for layer in row["layers"]:
            if layer["state"] == "n/a" and not verbose:
                # The reason still matters when it is the only thing standing
                # in for a layer, so code pinning always explains itself.
                if layer["name"] != "code pinned":
                    continue
            lines.append("    %s  %-16s %s" % (
                paint("%-3s" % layer["state"], _STATE_COLOR.get(layer["state"], "")),
                layer["name"], layer["detail"]))
            if layer["remedy"]:
                lines.append("         %-16s -> %s" % ("", layer["remedy"]))
        lines.append("")

    covered, total = data["fully_covered"], data["total"]
    lines.append(f"  {covered}/{total} server(s) with no open gap")
    if covered < total and not verbose:
        lines.append("  -v also shows the layers that cannot apply")
    lines.append("")
    return "\n".join(lines)
