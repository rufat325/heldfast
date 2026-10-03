"""`inventory` and `fleet`: the organisation's view, one machine at a time.

Kept off `cli.py` for the reason `cli_parser.py` is: these are two commands,
not a reason to grow the file that runs every other one.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .fsutil import atomic_write
from .lockfile import Lock

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _write(args: argparse.Namespace, text: str) -> int | None:
    if not args.output:
        sys.stdout.write(text)
        return None
    try:
        # Written into whatever directory collects inventories, which other
        # machines write to as well: a link planted at the name is replaced,
        # not written through (fsutil).
        atomic_write(Path(args.output), text.encode("utf-8"))
    except OSError as exc:
        print(f"heldfast: cannot write {args.output}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return None


def _color(args: argparse.Namespace) -> bool:
    return not args.no_color and not args.output and sys.stdout.isatty()


def _org_policy(path: str | None) -> Any:
    """The policy at `path`, None when none was named; raises ValueError."""
    if not path:
        return None
    from .orgpolicy import load
    return load(Path(path))


def _report_policy(path: str | None) -> Any:
    """The policy an inventory is checked against: the one named, else the
    machine's managed one, else HELDFAST_ORG_POLICY. Raises ValueError."""
    from .orgpolicy import for_report
    found = for_report(path)
    return found[0] if found else None


def _scope(args: argparse.Namespace) -> dict[str, Any]:
    from .inventory import _home
    paths = [str(Path(p).resolve()) for p in (args.paths or ["."])]
    return {"paths": [_home(p) for p in paths], "user_configs": not args.no_user_configs}


def inventory(args: argparse.Namespace) -> int:
    from . import inventory as inv
    from .cli import _resolve_lock_path, collect, status_findings
    from .orgpolicy import evaluate, failed

    try:
        policy = _report_policy(args.policy)
        lock = Lock.load(_resolve_lock_path(args))
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    plugin = False
    if not args.no_user_configs:
        from .claudeplugins import enabled
        plugin = enabled("heldfast")
    payload = inv.build(lock, data.servers, status_findings(args, data, lock),
                        label=args.label or inv.host_label(), scope=_scope(args),
                        plugin=plugin, skills=len(data.skills),
                        unreadable=data.unreadable)
    violations = []
    if policy is not None:
        violations = evaluate(policy, payload["servers"])
        payload["policy"] = {"name": policy.name, "sha256": policy.digest,
                             "violations": [v.to_dict() for v in violations]}

    if args.format == "json":
        text = json.dumps(payload, indent=2) + "\n"
    elif args.format == "cyclonedx":
        text = json.dumps(inv.cyclonedx(payload), indent=2) + "\n"
    else:
        text = inv.render(payload, color=_color(args))
    written = _write(args, text)
    if written is not None:
        return written
    return EXIT_FINDINGS if failed(violations) else EXIT_OK


def fleet(args: argparse.Namespace) -> int:
    from . import fleet as fleet_mod

    if args.html:
        if args.output and args.output != args.html:
            print("heldfast: --html names the output file; drop -o", file=sys.stderr)
            return EXIT_ERROR
        args.format, args.output = "html", args.html

    try:
        policy = _org_policy(args.policy)
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
        return EXIT_ERROR
    inventories, notes = fleet_mod.load([Path(p) for p in args.paths])
    if not inventories:
        for note in notes:
            print(f"heldfast: {note}", file=sys.stderr)
        print("heldfast: no inventories to report on; write them with "
              "`heldfast inventory -f json -o <file>`", file=sys.stderr)
        return EXIT_ERROR

    advisories, error = None, ""
    if args.advisories:
        advisories, error = fleet_mod.ask_osv(inventories)
        if error:
            # Not an empty answer: "asked and nothing found" is the all-clear
            # this must never print when nothing was asked successfully.
            advisories = None
            notes.append(f"advisories could not be read, so none are reported: {error}")
    report = fleet_mod.build(inventories, policy=policy, advisories=advisories,
                             advisory_error=error, max_age=args.max_age, notes=notes)

    if args.format == "json":
        text = json.dumps(report, indent=2) + "\n"
    elif args.format == "html":
        from .fleet_html import render_html
        text = render_html(report)
    else:
        text = fleet_mod.render(report, color=_color(args))
    written = _write(args, text)
    if written is not None:
        return written
    return EXIT_FINDINGS if fleet_mod.failed(report) else EXIT_OK
