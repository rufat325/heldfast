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
from .identity import all_identities
from .lockfile import Lock
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
                     "mcp-audit approve --probe")
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
                     "mcp-audit approve --probe")
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
        "mcp-audit approve --probe")


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
        return Layer("code pinned", "n/a", "server is no longer configured")

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
                f"fetched from a registry at {shown}; the version is the pin")
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
                "mcp-audit approve")
        return Layer(
            "code pinned", "no",
            f"names {named[0]!r}, which is not a file on this machine",
            "the launch command cannot start; fix the path or remove the server")

    return Layer("code pinned", "n/a",
                 "the launch command names no script")


def _policy(entry: dict | None) -> Layer:
    limits = (entry or {}).get("policy") or {}
    if not isinstance(limits, dict) or not limits:
        return Layer(
            "argument policy", "no",
            "any argument reaches the server once the tool itself is approved",
            "mcp-audit policy --probe")
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


def for_server(lock: Lock, key: str, spec: Any) -> list[Layer]:
    entry = lock.servers.get(key)
    if not isinstance(entry, dict):
        entry = None
    name = str((entry or {}).get("name") or (spec.name if spec else key))
    return [
        _approval(entry),
        _tools(entry),
        _code(entry, spec),
        _policy(entry),
        _reachable_by(lock, name),
    ]


def build(lock: Lock, servers: list) -> dict[str, Any]:
    configured = {s.identity(): s for s in servers}
    keys = sorted(set(lock.servers) | set(configured))

    rows = []
    for key in keys:
        entry = lock.servers.get(key)
        if key in lock.servers and not isinstance(entry, dict):
            continue
        layers = for_server(lock, key, configured.get(key))
        rows.append({
            "identity": key,
            "configured": key in configured,
            "gaps": sum(1 for layer in layers if layer.gap),
            "layers": [
                {"name": l.name, "state": l.state,
                 "detail": l.detail, "remedy": l.remedy}
                for l in layers
            ],
        })

    return {
        "servers": rows,
        "fully_covered": sum(1 for r in rows if r["gaps"] == 0),
        "total": len(rows),
    }


_STATE_COLOR = {"yes": "\033[32m", "no": "\033[33m", "n/a": "\033[90m"}


def render(data: dict[str, Any], color: bool = True, verbose: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color and code else text

    if not data["servers"]:
        return "\n  Nothing configured and nothing approved.\n"

    lines = [""]
    for row in data["servers"]:
        suffix = "" if row["configured"] else "   (no longer configured)"
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
