"""Whether this tool is actually in the path.

The lockfile is a committed artifact describing a boundary. Nothing in it is
in force unless the client talks to `heldfast gateway` or `heldfast guard`,
and the configuration is where that is decided.

Two questions are asked from three places -- the MCPA032 rule, the status page
and the coverage report -- so the answering lives here rather than inside any
of them. It depends on nothing but the launch command, which is why it can.

The second question below was found by running the first. A client configured
the way the README recommends has exactly one entry, the gateway, and the
servers it fronts appear only in the lockfile. `status` read that as three
alarms: two approved servers GONE and an UNAPPROVED one called `everything`.
The tool was reporting the correct setup as the broken one, which is a good
deal worse than missing the broken one.
"""

from __future__ import annotations

from typing import Any

# What heldfast is called once installed, however it was installed.
_SELF = {"heldfast", "heldfast.exe", "heldfast"}

# Subcommands that put this tool between the client and a server. `scan` and
# the rest are not enforcement and must not be mistaken for it.
ENFORCING = {"gateway", "guard"}


def unwrap_launcher(command: str, args: list) -> tuple[str, list]:
    """See through `cmd /c <runner> ...` to the runner underneath.

    Windows users are told to write `cmd /c npx -y <pkg>`, because a package
    runner is a batch file there and CreateProcess cannot execute one. Every
    rule that reasons about the runner was reading `cmd` and giving up, so the
    same unpinned package that is reported on macOS was silently fine on
    Windows. Found by writing a test that asserted MCPA003 still fires after
    MCPA001 stopped.
    """
    base = (command or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base in ("cmd", "cmd.exe") and args:
        rest = [str(a) for a in args]
        if rest[0].lower() in ("/c", "/k") and len(rest) > 1:
            return rest[1], rest[2:]
    return command, list(args)


def subcommand(server: Any) -> str:
    """The heldfast subcommand this entry launches, or "".

    Recognises the shapes people actually write: the installed console script,
    an absolute path to it, `python -m heldfast`, a uvx invocation, and any of
    them behind the `cmd /c` wrapper Windows requires. Matching is on the whole
    path leaf and never on a substring -- `npx -y heldfast-helper` is somebody
    else's package, and a rule that can be switched off by choosing a package
    name is not a rule.
    """
    command, args = unwrap_launcher(
        getattr(server, "command", "") or "", getattr(server, "args", None) or [])
    seen_self = False
    for token in [command] + [str(a) for a in args]:
        text = str(token or "").strip().strip('"').strip("'")
        if not text:
            continue
        if text.replace("\\", "/").rsplit("/", 1)[-1] in _SELF:
            seen_self = True
            continue
        if seen_self and not text.startswith("-"):
            return text
    return ""


def fronting_clients(servers: list) -> set[str]:
    """Clients that configure a gateway, and therefore front their approved set."""
    return {s.client for s in servers
            if not s.disabled and subcommand(s) == "gateway"}


def is_gateway(server: Any) -> bool:
    """True for an aggregating endpoint that is not itself a server.

    Only the gateway. It has no approval by design -- approving the thing that
    enforces approvals is circular -- so judging it as a server would flag the
    one entry doing the work.

    A `guard` entry is *not* this. It names exactly one server and wraps it,
    so it is that server and must be reported as one; treating both the same
    way made every guarded server vanish from the coverage report, which is
    the opposite of what adopting the guard should do.
    """
    return subcommand(server) == "gateway"


def behind_gateway(key: str, lock_entry: Any, fronting: set) -> bool:
    """Whether an approved server absent from the config is still reachable.

    In the recommended setup it is: the client points at the gateway and the
    servers it fronts are named only in the lockfile. Without this the correct
    configuration reports as a pile of missing servers.
    """
    client = str((lock_entry or {}).get("client") or "") if isinstance(lock_entry, dict) \
        else ""
    if not client:
        client = key.split(":", 1)[0] if ":" in key else ""
    return client in fronting
