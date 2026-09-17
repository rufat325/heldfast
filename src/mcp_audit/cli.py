"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .discovery import discover_config_files
from .findings import Finding, Severity
from .lockfile import DEFAULT_LOCK_NAME, Lock
from .model import ServerSpec, SkillSpec, ToolSpec
from .parsers import discover_skills, parse_config
from .probe import probe
from .report import render_json, render_sarif, render_terminal
from .rules import AuditContext, all_rules, classifier_targets, run_rules
from . import llm as llm_mod
from . import suppressions as supp

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _add_scan_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="*", default=None,
                   help="files or directories to scan (default: current directory)")
    p.add_argument("--no-user-configs", action="store_true",
                   help="skip well-known per-user config locations; scan only the given paths")
    p.add_argument("--no-skills", action="store_true", help="skip SKILL.md discovery")
    p.add_argument("--probe", action="store_true",
                   help="connect to each server and read its tool definitions. "
                        "WARNING: this launches local STDIO servers")
    p.add_argument("--no-stdio-probe", action="store_true",
                   help="with --probe, contact remote servers only; never launch local ones")
    p.add_argument("--probe-timeout", type=float, default=20.0, metavar="SECONDS")
    p.add_argument("--lock", metavar="PATH", default=None,
                   help=f"approval lockfile (default: ./{DEFAULT_LOCK_NAME})")
    p.add_argument("--depth", type=int, default=6, metavar="N",
                   help="maximum directory depth when walking paths (default: 6)")
    p.add_argument("-v", "--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Security scanner for MCP server configurations and agent skills.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  no findings at or above the --fail-on threshold\n"
            "  1  findings at or above the threshold\n"
            "  2  the scan itself could not complete\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan for findings (default command)")
    _add_scan_arguments(scan)
    scan.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    scan.add_argument("--fail-on", default="high",
                      choices=[s.label for s in Severity] + ["never"],
                      help="minimum severity that sets exit code 1 (default: high)")
    scan.add_argument("--min-severity", default="info", choices=[s.label for s in Severity],
                      help="hide findings below this severity (default: info)")
    scan.add_argument("--only", action="append", metavar="RULE", default=[],
                      help="run only these rule ids (repeatable)")
    scan.add_argument("--disable", action="append", metavar="RULE", default=[],
                      help="skip these rule ids (repeatable)")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--ignore-file", metavar="PATH", default=None,
                      help=f"suppression file (default: ./{supp.DEFAULT_IGNORE_NAME} if present)")
    scan.add_argument("--no-ignore", action="store_true",
                      help="ignore the suppression file and report everything")
    llm_group = scan.add_argument_group(
        "semantic classifier (optional)",
        "Sends tool descriptions and skill text to the Anthropic API for judgement. "
        "Needs: pip install 'mcp-audit[llm]' and ANTHROPIC_API_KEY.",
    )
    llm_group.add_argument("--llm", action="store_true",
                           help="enable MCPA018. NOTE: this transmits agent-facing text "
                                "off this machine (credentials are redacted first)")
    llm_group.add_argument("--llm-model", default=llm_mod.DEFAULT_MODEL, metavar="MODEL")
    llm_group.add_argument("--llm-effort", default=llm_mod.DEFAULT_EFFORT,
                           choices=("low", "medium", "high", "xhigh", "max"))
    llm_group.add_argument("--llm-max-items", type=int, default=50, metavar="N",
                           help="maximum classifications per run (default: 50)")
    llm_group.add_argument("--llm-cache", metavar="PATH", default=None,
                           help=f"verdict cache (default: ./{llm_mod.CACHE_NAME}; "
                                "unchanged text is never re-sent)")
    llm_group.add_argument("--no-llm-cache", action="store_true",
                           help="do not read or write the verdict cache")

    approve = sub.add_parser(
        "approve",
        help="record the current state as approved in the lockfile",
        description="Write the lockfile that later scans compare against.",
    )
    _add_scan_arguments(approve)

    sub.add_parser("rules", help="list the built-in rules")
    return parser


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

class Collected:
    def __init__(self) -> None:
        self.servers: list[ServerSpec] = []
        self.skills: list[SkillSpec] = []
        self.tools: list[ToolSpec] = []
        self.errors: list[str] = []
        self.config_count = 0
        self.probed = False


def collect(args: argparse.Namespace) -> Collected:
    out = Collected()
    roots = [Path(p) for p in (args.paths or ["."])]
    for r in roots:
        if not r.exists():
            out.errors.append(f"{r}: no such file or directory")

    config_files = discover_config_files(
        [r for r in roots if r.exists()],
        scan_user=not args.no_user_configs,
        max_depth=args.depth,
    )
    out.config_count = len(config_files)
    for path, client in config_files:
        servers, errors = parse_config(path, client)
        out.servers.extend(servers)
        out.errors.extend(errors)

    if not args.no_skills:
        out.skills = discover_skills(
            [r for r in roots if r.exists()],
            max_depth=args.depth + 2,
            scan_user=not args.no_user_configs,
        )

    if args.probe:
        results = probe(
            out.servers,
            timeout=args.probe_timeout,
            allow_stdio=not args.no_stdio_probe,
            verbose=args.verbose,
        )
        out.probed = True
        for res in results:
            out.tools.extend(res.tools)
            if res.error:
                out.errors.append(f"probe {res.server}: {res.error}")
    return out


def _resolve_lock_path(args: argparse.Namespace) -> Path:
    if args.lock:
        return Path(args.lock)
    return Path.cwd() / DEFAULT_LOCK_NAME


def _validate_rule_ids(ids: list[str]) -> list[str]:
    known = {r.id for r in all_rules()}
    unknown = [i for i in ids if i.upper() not in known]
    if unknown:
        raise SystemExit(
            f"mcp-audit: unknown rule id(s): {', '.join(unknown)}\n"
            f"           run `mcp-audit rules` to list them"
        )
    return [i.upper() for i in ids]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    only = set(_validate_rule_ids(args.only)) or None
    disabled = set(_validate_rule_ids(args.disable))

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-audit: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    ctx = AuditContext(
        servers=data.servers,
        skills=data.skills,
        tools=data.tools,
        config_errors=data.errors,
        lock={"servers": lock.servers, "skills": lock.skills},
        options={"probed": data.probed},
    )
    if getattr(args, "llm", False):
        targets = classifier_targets(ctx)
        if targets:
            cache_path = None
            if not args.no_llm_cache:
                cache_path = Path(args.llm_cache) if args.llm_cache else Path.cwd() / llm_mod.CACHE_NAME
            print(
                f"mcp-audit: --llm will send up to {min(len(targets), args.llm_max_items)} "
                f"text(s) to the Anthropic API ({args.llm_model}).\n"
                "           Credentials are redacted first; cached verdicts are not re-sent.",
                file=sys.stderr,
            )
            try:
                llm_result = llm_mod.classify(
                    targets, model=args.llm_model, effort=args.llm_effort,
                    cache_path=cache_path, max_items=args.llm_max_items,
                    verbose=args.verbose,
                )
            except llm_mod.LLMUnavailable as exc:
                print(f"mcp-audit: {exc}", file=sys.stderr)
                return EXIT_ERROR
            ctx.llm_verdicts = llm_result.verdicts
            data.errors.extend(llm_result.errors)

    findings: list[Finding] = run_rules(ctx, enabled=only, disabled=disabled)

    floor = Severity.parse(args.min_severity)
    findings = [f for f in findings if f.severity >= floor]

    suppressed: list = []
    ignore_path = None
    if not args.no_ignore:
        rules_list, ignore_errors, ignore_path = supp.load(
            args.ignore_file, [Path(p) for p in (args.paths or ["."])]
        )
        data.errors.extend(ignore_errors)
        findings, suppressed = supp.apply(findings, rules_list)

    if args.format == "json":
        report = render_json(
            findings,
            scanned_configs=data.config_count, scanned_servers=len(data.servers),
            scanned_tools=len(data.tools), scanned_skills=len(data.skills),
            errors=data.errors, lock_present=not lock.is_empty, probed=data.probed,
            version=__version__, suppressed=suppressed,
        )
    elif args.format == "sarif":
        report = render_sarif(findings, base=Path.cwd(), version=__version__)
    else:
        report = render_terminal(
            findings,
            scanned_configs=data.config_count, scanned_servers=len(data.servers),
            scanned_tools=len(data.tools), scanned_skills=len(data.skills),
            errors=data.errors, lock_present=not lock.is_empty, probed=data.probed,
            color=False if args.no_color else None, verbose=args.verbose,
            suppressed=suppressed, ignore_path=str(ignore_path) if ignore_path else None,
        )

    if args.output:
        try:
            Path(args.output).write_text(report, encoding="utf-8")
        except OSError as exc:
            print(f"mcp-audit: cannot write {args.output}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if args.format != "text":
            print(f"mcp-audit: wrote {len(findings)} finding(s) to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.fail_on == "never":
        return EXIT_OK
    threshold = Severity.parse(args.fail_on)
    return EXIT_FINDINGS if any(f.severity >= threshold for f in findings) else EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    lock_path = _resolve_lock_path(args)
    try:
        previous = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-audit: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    if data.errors and args.verbose:
        for err in data.errors:
            print(f"  warning: {err}", file=sys.stderr)

    if not args.probe:
        print(
            "mcp-audit: approving without --probe records configuration only.\n"
            "           Tool descriptions are the thing a rug pull changes, so an\n"
            "           approval without --probe cannot detect one. Re-run with --probe\n"
            "           once you are ready to launch the servers.",
            file=sys.stderr,
        )

    lock = Lock(path=lock_path)
    lock.record(data.servers, data.tools, data.skills)
    lock.merge_unprobed(previous)
    written = lock.save()

    tool_total = sum(len(e.get("tools") or {}) for e in lock.servers.values())
    print(
        f"mcp-audit: approved {len(lock.servers)} server(s), {tool_total} tool(s), "
        f"{len(lock.skills)} skill(s) -> {written}"
    )
    return EXIT_OK


def cmd_rules(_args: argparse.Namespace) -> int:
    rules = all_rules()
    width = max((len(r.id) for r in rules), default=8)
    print(f"\n  {len(rules)} rules\n")
    for r in rules:
        print(f"  {r.id:<{width}}  {r.default_severity.label:<8}  {r.name}")
        if r.description and r.description != r.name:
            print(f"  {'':<{width}}  {'':<8}  {r.description}")
    print()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # Make `scan` the default command so bare `mcp-audit` and `mcp-audit .` work.
    known = {"scan", "approve", "rules"}
    if not argv or (argv[0] not in known and not argv[0].startswith("-")):
        argv = ["scan", *argv]
    elif argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv = ["scan", *argv]

    args = parser.parse_args(argv)
    try:
        if args.command == "approve":
            return cmd_approve(args)
        if args.command == "rules":
            return cmd_rules(args)
        return cmd_scan(args)
    except KeyboardInterrupt:
        print("\nmcp-audit: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
