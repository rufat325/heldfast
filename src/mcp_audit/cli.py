"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .discovery import discover_config_files
from .findings import Finding, Severity
from .lockfile import DEFAULT_LOCK_NAME, Lock
from .model import ServerSpec, SkillSpec, ToolSpec
from .parsers import discover_skills, parse_config
from .probe import probe
from .sourcescan import scan_source_tree
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
    p.add_argument("--no-source", action="store_true",
                   help="skip reading MCP server source for shell-injection flows")
    p.add_argument("--safe", action="store_true",
                   help="never execute anything and never open a connection, "
                        "whatever else is asked for")
    p.add_argument("--probe-gate", default="high",
                   choices=("critical", "high", "medium", "low", "off"),
                   help="refuse to launch a server already carrying a static "
                        "finding this severe (default: high)")
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

    inspect_p = sub.add_parser(
        "inspect",
        help="show what is configured, without judging it",
        description=(
            "List the MCP servers and skills this machine has configured, grouped by "
            "client. Reports no findings and makes no judgements. Environment values "
            "are classified as reference/placeholder/literal and never printed."
        ),
    )
    _add_scan_arguments(inspect_p)
    inspect_p.add_argument("-f", "--format", choices=("text", "json"), default="text")
    inspect_p.add_argument("-o", "--output", metavar="FILE")
    inspect_p.add_argument("--no-color", action="store_true")

    rules_p = sub.add_parser("rules", help="list the built-in rules")
    rules_p.add_argument("--markdown", action="store_true",
                         help="emit the full rule catalog as Markdown")
    rules_p.add_argument("-o", "--output", metavar="FILE",
                         help="write to FILE as UTF-8 instead of stdout")

    explain_p = sub.add_parser(
        "explain",
        help="describe one rule in full",
        description="What a check looks for, why it matters, how to fix it, and when it is wrong.",
    )
    explain_p.add_argument("rule_id", metavar="RULE", help="a rule id, e.g. MCPA015")

    policy_p = sub.add_parser(
        "policy",
        help="propose argument limits for the tools a server exposes",
        description=(
            "Reads the tools a server actually exposes and proposes a starter "
            "policy: path limits for tools that take a path, destination limits "
            "for tools that take a URL, operation limits for tools that take a "
            "query, and an outright deny for tools named after something "
            "destructive. Every value is a placeholder you have to edit -- a "
            "generated policy that quietly permitted your home directory would "
            "read like a boundary and be a rubber stamp."
        ),
    )
    policy_p.add_argument("paths", nargs="*", help="files or directories to scan")
    policy_p.add_argument("--probe", action="store_true",
                          help="connect to servers to read their live tool schemas "
                               "(this LAUNCHES local stdio servers)")
    policy_p.add_argument("--probe-timeout", type=float, default=10.0, metavar="SECONDS")
    policy_p.add_argument("--no-stdio-probe", action="store_true")
    policy_p.add_argument("--no-user-configs", action="store_true")
    policy_p.add_argument("--no-skills", action="store_true", default=True,
                          help=argparse.SUPPRESS)
    policy_p.add_argument("--no-source", action="store_true", default=True,
                          help=argparse.SUPPRESS)
    policy_p.add_argument("--depth", type=int, default=6, metavar="N")
    policy_p.add_argument("--lock", metavar="PATH", default=None)
    policy_p.add_argument("--write", action="store_true",
                          help="merge the proposal into the lockfile, leaving any "
                               "rule already there untouched")
    policy_p.add_argument("-v", "--verbose", action="store_true")

    status_p = sub.add_parser(
        "status",
        help="where things stand: approved, drifted, enforced, recorded",
        description=(
            "One page joining the lockfile, the current configuration and the "
            "audit trail. Computes nothing the other commands do not; it "
            "answers 'where do things stand' without reading three files."
        ),
    )
    _add_scan_arguments(status_p)
    status_p.add_argument("-f", "--format", choices=("text", "json"), default="text")
    status_p.add_argument("--log", metavar="PATH", default=None,
                          help="audit trail to summarise alongside it")
    status_p.add_argument("--no-color", action="store_true")

    coverage_p = sub.add_parser(
        "coverage",
        help="which guarantees are actually in force, and why not",
        description=(
            "Per server and per layer: covered or not, the reason, and the "
            "command that would change it. An absent guarantee and one that "
            "cannot apply are different situations, and this is the only "
            "place that distinguishes them."
        ),
    )
    _add_scan_arguments(coverage_p)
    # -v comes from the shared scan arguments; here it means "also show the
    # layers that cannot apply".
    coverage_p.add_argument("-f", "--format", choices=("text", "json"), default="text")
    coverage_p.add_argument("--no-color", action="store_true")

    gateway_p = sub.add_parser(
        "gateway",
        help="one MCP endpoint in front of every approved server",
        description=(
            "Starts every approved server from the lockfile and serves them as a "
            "single MCP server, applying the same approval checks, argument "
            "policy and result screening that `guard` applies to one. Tool names "
            "are namespaced server__tool, so two servers offering the same name "
            "cannot collide. Point your client at this instead of at the servers."
        ),
    )
    gateway_p.add_argument("paths", nargs="*", help="where to look for configs")
    gateway_p.add_argument("--no-user-configs", action="store_true")
    gateway_p.add_argument("--no-skills", action="store_true", default=True,
                           help=argparse.SUPPRESS)
    gateway_p.add_argument("--no-source", action="store_true", default=True,
                           help=argparse.SUPPRESS)
    gateway_p.add_argument("--probe", action="store_true", default=False,
                           help=argparse.SUPPRESS)
    gateway_p.add_argument("--safe", action="store_true", default=False,
                           help=argparse.SUPPRESS)
    gateway_p.add_argument("--depth", type=int, default=6, metavar="N")
    gateway_p.add_argument("--lock", metavar="PATH", default=None)
    gateway_p.add_argument("--policy", choices=("block", "strip", "warn"),
                           default="block")
    gateway_p.add_argument("--allow-unapproved", action="store_true",
                           help="start servers that are not in the lockfile "
                                "(they are refused by default)")
    gateway_p.add_argument("--dry-run", action="store_true",
                           help="report what the argument policy would refuse, "
                                "and forward the call anyway")
    gateway_p.add_argument("--as", dest="act_as", metavar="IDENTITY", default=None,
                           help="serve as this identity from the lockfile, which "
                                "narrows which servers and tools are reachable")
    gateway_p.add_argument("--max-calls", type=int, default=0, metavar="N",
                           help="refuse a tool after N calls in one session "
                                "(0 = no budget)")
    gateway_p.add_argument("--timeout", type=float, default=30.0, metavar="SECONDS")
    gateway_p.add_argument("--log", metavar="PATH", default=None,
                           help="append a hash-chained record of the session")
    # The same two the guard has taken since it learned about them. The
    # gateway screened neither until the halves were compared.
    gateway_p.add_argument("--deny-sampling", action="store_true",
                           help="refuse sampling/createMessage requests, which ask your "
                                "model to generate on a server's behalf")
    gateway_p.add_argument("--deny-elicitation", action="store_true",
                           help="refuse elicitation/create requests, which ask you for "
                                "input through the client's own dialog")
    gateway_p.add_argument("--quiet", action="store_true")
    gateway_p.add_argument("-v", "--verbose", action="store_true")

    verify_p = sub.add_parser(
        "verify-log",
        help="check that a guard audit log has not been altered",
        description=(
            "Walks the hash chain written by `guard --log` and reports the first "
            "entry that does not follow the one before it. Proves the file has not "
            "been edited since it was written; it does not prove who wrote it."
        ),
    )
    verify_p.add_argument("path", metavar="PATH", help="the log file to check")

    report_p = sub.add_parser(
        "report",
        help="what the agent did: sessions, calls, refusals",
        description=(
            "Reads back an audit trail written by `guard --log` or "
            "`gateway --log`: which sessions ran, as which identity, what they "
            "called and what was refused. Verifies the chain first and reports "
            "only the entries it could verify -- a summary of a file that was "
            "edited would launder a tampered log into a clean-looking report."
        ),
    )
    report_p.add_argument("path", metavar="PATH", help="the trail to read")
    report_p.add_argument("-f", "--format", choices=("text", "json"), default="text")
    report_p.add_argument("-v", "--verbose", action="store_true",
                          help="list every tool rather than the busiest few")
    report_p.add_argument("--no-color", action="store_true")

    guard_p = sub.add_parser(
        "guard",
        help="proxy a server and enforce the approval lockfile at runtime",
        description=(
            "Sit between the client and an MCP server, and refuse to pass through tools "
            "that are unapproved or whose definition changed since approval. Reads the "
            "same .mcp-audit.lock the CI gate reads, so one artifact governs both. "
            "Usage: mcp-audit guard -- <server command...>"
        ),
    )
    guard_p.add_argument("--lock", metavar="PATH", default=None,
                         help=f"approval lockfile (default: ./{DEFAULT_LOCK_NAME})")
    guard_p.add_argument("--name", metavar="NAME", default=None,
                         help="server name as it appears in the lockfile "
                              "(default: inferred from the command)")
    guard_p.add_argument("--policy", choices=("block", "strip", "warn"), default="block",
                         help="what to do with a rejected tool: replace it with a blocked "
                              "stub (default), remove it, or allow it and log")
    guard_p.add_argument("--block-severity", default="critical",
                         choices=[s.label for s in Severity],
                         help="minimum content-rule severity that rejects a tool "
                              "(default: critical)")
    guard_p.add_argument("--strict", action="store_true",
                         help="fail closed on internal errors too, not just on drift")
    guard_p.add_argument("--quiet", action="store_true", help="suppress stderr diagnostics")
    guard_p.add_argument("--dry-run", action="store_true",
                         help="report what the argument policy would block, and "
                              "forward the call anyway")
    guard_p.add_argument("--allow-unapproved", action="store_true",
                         help="forward a server that is not in the lockfile instead of "
                              "withholding its tools (the pre-0.2 behaviour)")
    guard_p.add_argument("--log", metavar="PATH", default=None,
                         help="append a hash-chained record of the session to PATH "
                              "(tool names and decisions; never arguments)")
    guard_p.add_argument("--deny-sampling", action="store_true",
                         help="refuse sampling/createMessage requests, which ask your "
                              "model to generate on the server's behalf")
    guard_p.add_argument("--deny-elicitation", action="store_true",
                         help="refuse elicitation/create requests, which ask you for "
                              "input through the client's own dialog")
    guard_p.add_argument("server_command", nargs=argparse.REMAINDER, metavar="-- COMMAND")
    guard_p.add_argument("--deny-roots", action="store_true",
                         help="refuse roots/list requests, which ask which "
                              "filesystem roots you expose")
    guard_p.add_argument("--result-policy", default="annotate",
                         choices=("annotate", "block", "off"),
                         help="what to do when a tool RESULT contains injection "
                              "signals: fence it as untrusted data (default), "
                              "withhold it, or only log")

    sub.add_parser(
        "serve",
        help="run mcp-audit as an MCP server over stdio",
        description=(
            "Expose the scanner's analysis over MCP so an agent can check a server "
            "configuration before a human installs it. Read-only: no probing, and "
            "path scanning only when MCP_AUDIT_ALLOW_PATH_SCAN is set."
        ),
    )
    # The command names come from the parser rather than a second list.
    # A hardcoded set is how `verify-log` was silently treated as a path
    # to scan for its first few minutes of existence.
    parser.mcp_commands = set(sub.choices)
    return parser


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

class Collected:
    def __init__(self) -> None:
        self.servers: list[ServerSpec] = []
        self.skills: list[SkillSpec] = []
        self.tools: list[ToolSpec] = []
        self.prompts: list = []
        self.resources: list = []
        self.instructions: dict[str, str] = {}
        self.eras: dict[str, str] = {}
        self.errors: list[str] = []
        self.config_count = 0
        self.probed = False
        self.source_flows: list = []
        # (identity, reason) for servers deliberately not launched.
        self.probe_skipped: list = []
        # server name -> "answered" or a short reason it did not. Absent means
        # no probe was attempted, which is a different thing from a failed one.
        self.probe_status: dict = {}


_GATE_NAMES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "off": None,
}


def _severity_named(name: str):
    return _GATE_NAMES.get(str(name).lower(), Severity.HIGH)


def _gate_servers(out: "Collected", gate) -> tuple[list, list]:
    """(servers safe to launch, [(identity, why not)]).

    Runs everything that needs no probe data -- the config rules, the skill
    rules, the source scanner -- and holds back any server already carrying a
    finding at or above the gate. Launching a server the scanner is about to
    call dangerous is the one thing a security tool should not do.
    """
    if gate is None:
        return list(out.servers), []

    try:
        findings = run_rules(AuditContext(
            servers=out.servers, skills=out.skills,
            source_flows=out.source_flows, config_errors=out.errors))
    except Exception as exc:                      # a rule bug must not gate
        return list(out.servers), [("<rules>", f"static pre-pass failed: {exc}")]

    worst: dict[str, Finding] = {}
    for finding in findings:
        if finding.server is None or finding.severity < gate:
            continue
        current = worst.get(finding.server)
        if current is None or finding.severity > current.severity:
            worst[finding.server] = finding

    launchable, skipped = [], []
    for server in out.servers:
        blocker = worst.get(server.name)
        if blocker is None:
            launchable.append(server)
            continue
        skipped.append((server.identity(),
                        f"{blocker.rule_id} ({blocker.severity.label}) -- "
                        f"{blocker.title}. Re-run with --probe-gate off to "
                        f"launch it anyway."))
    return launchable, skipped


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

    # Reading the servers' own source only makes sense for a path the user
    # named. The user-config sweep finds servers installed from packages, and
    # their source is not in the tree being scanned.
    if not getattr(args, "no_source", False):
        out.source_flows = scan_source_tree(
            [r for r in roots if r.exists()], max_depth=args.depth + 2)

    if args.probe and getattr(args, "safe", False):
        out.errors.append(
            "--safe was given, so nothing was launched or connected to; "
            "--probe was ignored")

    if args.probe and not getattr(args, "safe", False):
        # Static verdict FIRST. Probing a STDIO server means executing it, and
        # until this ran, `scan --probe` launched every configured server
        # before a single rule had looked at the config -- so a config that
        # the scanner was about to call dangerous had already had its say.
        #
        # This does not make probing safe. Reading a server's live tools means
        # running it, and no amount of static analysis makes that free. What
        # it does is stop the tool from executing something it was itself
        # about to report, and give a name to the servers it declined.
        gate = _severity_named(getattr(args, "probe_gate", "high"))
        launchable, out.probe_skipped = _gate_servers(out, gate)

        if launchable and not getattr(args, "quiet", False):
            local = [s for s in launchable if s.transport == "stdio"]
            if local and not args.no_stdio_probe:
                print("mcp-audit: --probe launches these servers as local "
                      "processes: " + ", ".join(sorted(s.identity() for s in local)),
                      file=sys.stderr)

        for identity, reason in out.probe_skipped:
            out.errors.append(f"not probed: {identity} -- {reason}")

        results = probe(
            launchable,
            timeout=args.probe_timeout,
            allow_stdio=not args.no_stdio_probe,
            verbose=args.verbose,
        )
        out.probed = True
        for res in results:
            out.tools.extend(res.tools)
            out.prompts.extend(res.prompts)
            out.resources.extend(res.resources)
            if res.instructions:
                out.instructions[res.server] = res.instructions
            out.eras[res.server] = res.protocol_era
            out.probe_status[res.server] = (
                f"no response: {res.error}" if res.error else "answered")
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
        prompts=data.prompts,
        resources=data.resources,
        instructions=data.instructions,
        config_errors=data.errors,
        lock={"servers": lock.servers, "skills": lock.skills},
        source_flows=data.source_flows,
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
    lock.record(data.servers, data.tools, data.skills,
                prompts=data.prompts, resources=data.resources,
                instructions=data.instructions, previous=previous,
                probe_status=data.probe_status)
    lock.merge_unprobed(previous)
    written = lock.save()

    tool_total = sum(len(e.get("tools") or {}) for e in lock.servers.values())
    prompt_total = sum(len(e.get("prompts") or {}) for e in lock.servers.values())
    res_total = sum(len(e.get("resources") or {}) for e in lock.servers.values())
    instr_total = sum(1 for e in lock.servers.values() if e.get("instructions"))
    parts = [f"{len(lock.servers)} server(s)", f"{tool_total} tool(s)"]
    if instr_total:
        parts.append(f"{instr_total} instruction block(s)")
    if prompt_total:
        parts.append(f"{prompt_total} prompt(s)")
    if res_total:
        parts.append(f"{res_total} resource(s)")
    parts.append(f"{len(lock.skills)} skill(s)")
    print(f"mcp-audit: approved " + ", ".join(parts) + f" -> {written}")
    return EXIT_OK


def cmd_inspect(args: argparse.Namespace) -> int:
    from . import inspect as inspect_mod

    data = collect(args)
    report = inspect_mod.build(data.servers, data.skills, data.tools, data.errors,
                               eras=data.eras)

    if args.format == "json":
        import json as _json
        text = _json.dumps(report, indent=2) + "\n"
    else:
        from .report.terminal import use_color
        text = inspect_mod.render(
            report,
            color=False if args.no_color else use_color(),
            verbose=args.verbose,
        )

    if args.output:
        try:
            Path(args.output).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"mcp-audit: cannot write {args.output}: {exc}", file=sys.stderr)
            return EXIT_ERROR
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_guard(args: argparse.Namespace) -> int:
    from . import guard as guard_mod

    argv = list(args.server_command or [])
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("mcp-audit: guard needs a server command, for example\n"
              "           mcp-audit guard -- npx -y @scope/server@1.0.0",
              file=sys.stderr)
        return EXIT_ERROR

    lock_path = Path(args.lock) if args.lock else Path.cwd() / DEFAULT_LOCK_NAME
    return guard_mod.run(
        argv,
        lock_path=lock_path,
        policy=args.policy,
        server_name=args.name,
        strict=args.strict,
        block_severity=Severity.parse(args.block_severity),
        quiet=args.quiet,
        deny_sampling=args.deny_sampling,
        deny_elicitation=args.deny_elicitation,
        deny_roots=args.deny_roots,
        result_policy=args.result_policy,
        log_path=Path(args.log) if getattr(args, "log", None) else None,
        allow_unapproved=args.allow_unapproved,
        dry_run=args.dry_run,
    )


def cmd_policy(args: argparse.Namespace) -> int:
    from .policy import suggest
    from .rules.annotations import MUTATING_VERBS

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-audit: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    if not data.tools:
        print("mcp-audit: no tools to propose limits for. Argument limits are "
              "written against a tool's schema, so this needs --probe.",
              file=sys.stderr)
        return EXIT_OK

    by_server: dict[str, list] = {}
    for tool in data.tools:
        by_server.setdefault(tool.server, []).append(tool)

    identities = {s.name: s.identity() for s in data.servers}
    proposal: dict[str, dict] = {}
    for server_name, tools in sorted(by_server.items()):
        rules = suggest(tools, MUTATING_VERBS)
        if rules:
            proposal[identities.get(server_name, server_name)] = rules

    if not proposal:
        print("mcp-audit: no tool takes a path, a destination or a query. "
              "Nothing to limit.")
        return EXIT_OK

    if not args.write:
        print(json.dumps({"policy": proposal}, indent=2))
        print("\n  Placeholders above are deliberate: edit them, then re-run with",
              file=sys.stderr)
        print("  --write, or paste the rules under the matching server in the lockfile.",
              file=sys.stderr)
        return EXIT_OK

    added, kept = 0, 0
    for identity, rules in proposal.items():
        entry = lock.servers.get(identity)
        if not isinstance(entry, dict):
            continue
        existing = entry.setdefault("policy", {})
        for tool, rule in rules.items():
            if tool in existing:
                kept += 1      # never overwrite a decision somebody made
                continue
            existing[tool] = rule
            added += 1
    lock.save(lock_path)
    print(f"mcp-audit: added {added} rule(s) to {lock_path}, left {kept} untouched.")
    print("           Every added value is a placeholder and will refuse every call "
          "until you edit it.")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    from . import status as status_mod

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-audit: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    ctx = AuditContext(
        servers=data.servers, skills=data.skills, tools=data.tools,
        prompts=data.prompts, resources=data.resources,
        instructions=data.instructions, source_flows=data.source_flows,
        config_errors=data.errors,
        lock={"servers": lock.servers, "skills": lock.skills},
        options={"probed": data.probed},
    )
    findings = run_rules(ctx)

    log_path = Path(args.log) if args.log else None
    payload = status_mod.build(lock, data.servers, findings, log_path,
                               probed=data.probed)

    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(status_mod.render(payload, color=not args.no_color))
    return EXIT_OK


def cmd_coverage(args: argparse.Namespace) -> int:
    from . import coverage as coverage_mod

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-audit: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # No rules are run: this reports on the control plane, not on the servers.
    # It is also the reason it stays fast enough to put in a prompt.
    data = collect(args)
    payload = coverage_mod.build(lock, data.servers)

    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(coverage_mod.render(
            payload, color=not args.no_color, verbose=args.verbose))
    return EXIT_OK


def cmd_gateway(args: argparse.Namespace) -> int:
    from . import gateway as gateway_mod

    lock_path = _resolve_lock_path(args)
    data = collect(args)
    if not data.servers:
        print("mcp-audit gateway: no MCP servers found to serve.", file=sys.stderr)
        return EXIT_ERROR

    return gateway_mod.run(
        data.servers, lock_path,
        policy=args.policy,
        allow_unapproved=args.allow_unapproved,
        dry_run=args.dry_run,
        quiet=args.quiet,
        timeout=args.timeout,
        log_path=Path(args.log) if args.log else None,
        act_as=args.act_as,
        max_calls=args.max_calls,
        deny_sampling=args.deny_sampling,
        deny_elicitation=args.deny_elicitation,
    )


def cmd_verify_log(args: argparse.Namespace) -> int:
    from .auditlog import verify

    result = verify(args.path)
    print(f"mcp-audit: {result.summary()}")
    for problem in result.problems[1:]:
        print(f"           also line {problem.line}: {problem.reason}")
    return EXIT_OK if result.ok else EXIT_FINDINGS


def cmd_report(args: argparse.Namespace) -> int:
    from . import sessions as report_mod

    path = Path(args.path)
    if not path.exists():
        print(f"mcp-audit: {path}: no such file", file=sys.stderr)
        return EXIT_ERROR

    payload = report_mod.build(path)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(report_mod.render(
            payload, color=not args.no_color, verbose=args.verbose))
    # A broken chain exits non-zero for the same reason `verify-log` does: in
    # CI this is the only signal anyone reads.
    return EXIT_OK if payload["integrity"]["intact"] else EXIT_FINDINGS


def cmd_explain(args: argparse.Namespace) -> int:
    from . import rule_docs

    rule_id = args.rule_id.upper()
    rule = next((r for r in all_rules() if r.id == rule_id), None)
    if rule is None:
        print(f"mcp-audit: unknown rule id {args.rule_id!r}; run `mcp-audit rules`",
              file=sys.stderr)
        return EXIT_ERROR

    doc = rule_docs.get(rule_id)
    sys.stdout.write(rule_docs.render_terminal(rule, doc))
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    if getattr(args, "markdown", False):
        from . import rule_docs
        markdown = rule_docs.render_markdown(all_rules())
        target = getattr(args, "output", None)
        if target:
            # Explicit encoding: a shell redirect on Windows picks up the
            # console codepage and silently mangles any non-ASCII byte.
            Path(target).write_text(markdown, encoding="utf-8")
            return EXIT_OK
        sys.stdout.write(markdown)
        return EXIT_OK
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
    known = getattr(parser, "mcp_commands", set())
    if not argv or (argv[0] not in known and not argv[0].startswith("-")):
        argv = ["scan", *argv]
    elif argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv = ["scan", *argv]

    args = parser.parse_args(argv)
    try:
        if args.command == "approve":
            return cmd_approve(args)
        if args.command == "inspect":
            return cmd_inspect(args)
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "explain":
            return cmd_explain(args)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "coverage":
            return cmd_coverage(args)
        if args.command == "gateway":
            return cmd_gateway(args)
        if args.command == "policy":
            return cmd_policy(args)
        if args.command == "verify-log":
            return cmd_verify_log(args)
        if args.command == "report":
            return cmd_report(args)
        if args.command == "guard":
            return cmd_guard(args)
        if args.command == "serve":
            from .server import main as serve_main
            return serve_main()
        return cmd_scan(args)
    except KeyboardInterrupt:
        print("\nmcp-audit: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
