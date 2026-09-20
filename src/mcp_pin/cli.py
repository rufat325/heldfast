"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .discovery import discover_config_files
from .findings import Finding, Severity
from .lockfile import Lock, resolve_lock_path
from .model import ServerSpec, SkillSpec, ToolSpec
from .parsers import discover_skills, parse_config
from .probe import probe
from .sourcescan import scan_source_tree
from .report import render_json, render_sarif, render_terminal
from .rules import AuditContext, all_rules, classifier_targets, run_rules
from . import llm as llm_mod
from . import suppressions as supp
from .cli_parser import build_parser

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


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
    except Exception as err:                      # a rule bug must not launch
        why = f"static pre-pass failed: {err}"
        return [], [(s.identity(), why) for s in out.servers]

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


def _live_roots(roots: list[Path]) -> list[Path]:
    return [r for r in roots if r.exists()]


def _excludes(args: argparse.Namespace) -> list[Path]:
    return [Path(p) for p in (getattr(args, "exclude", None) or [])]


def _roots(args: argparse.Namespace, out: "Collected") -> list[Path]:
    roots = [Path(p) for p in (args.paths or ["."])]
    for r in roots:
        if not r.exists():
            out.errors.append(f"{r}: no such file or directory")
    return roots


def _collect_configs(out: "Collected", roots: list[Path], args: argparse.Namespace) -> None:
    config_files = discover_config_files(
        _live_roots(roots),
        scan_user=not args.no_user_configs,
        max_depth=args.depth,
        exclude=_excludes(args),
    )
    out.config_count = len(config_files)
    for path, client in config_files:
        servers, errors = parse_config(path, client)
        out.servers.extend(servers)
        out.errors.extend(errors)


def _collect_skills_and_source(out: "Collected", roots: list[Path],
                               args: argparse.Namespace) -> None:
    live = _live_roots(roots)
    if not args.no_skills:
        out.skills = discover_skills(
            live, max_depth=args.depth + 2, scan_user=not args.no_user_configs,
            exclude=_excludes(args))
    # Reading the servers' own source only makes sense for a path the user
    # named. The user-config sweep finds servers installed from packages, and
    # their source is not in the tree being scanned.
    if not getattr(args, "no_source", False):
        out.source_flows = scan_source_tree(
            live, max_depth=args.depth + 2, exclude=_excludes(args))


def _ingest_probe(out: "Collected", results: list) -> None:
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


def _collect_probe(out: "Collected", args: argparse.Namespace) -> None:
    if not args.probe:
        return
    if getattr(args, "safe", False):
        out.errors.append(
            "--safe was given, so nothing was launched or connected to; "
            "--probe was ignored")
        return
    # Static verdict FIRST. Probing a STDIO server means executing it, and
    # until this ran, `scan --probe` launched every configured server
    # before a single rule had looked at the config -- so a config that
    # the scanner was about to call dangerous had already had its say.
    gate = _severity_named(getattr(args, "probe_gate", "high"))
    launchable, out.probe_skipped = _gate_servers(out, gate)
    if launchable and not getattr(args, "quiet", False):
        local = [s for s in launchable if s.transport == "stdio"]
        if local and not args.no_stdio_probe:
            print("mcp-pin: --probe launches these servers as local "
                  "processes: " + ", ".join(sorted(s.identity() for s in local)),
                  file=sys.stderr)
    for identity, reason in out.probe_skipped:
        out.errors.append(f"not probed: {identity} -- {reason}")
    _ingest_probe(out, probe(
        launchable,
        timeout=args.probe_timeout,
        allow_stdio=not args.no_stdio_probe,
        verbose=args.verbose,
        share_env=set(getattr(args, "share_env", None) or []),
    ))


def collect(args: argparse.Namespace) -> Collected:
    out = Collected()
    roots = _roots(args, out)
    _collect_configs(out, roots, args)
    _collect_skills_and_source(out, roots, args)
    _collect_probe(out, args)
    return out

def _resolve_lock_path(args: argparse.Namespace) -> Path:
    raw = getattr(args, "paths", None) or ["."]
    return resolve_lock_path(getattr(args, "lock", None),
                             roots=[Path(p) for p in raw])


def _validate_rule_ids(ids: list[str]) -> list[str]:
    known = {r.id for r in all_rules()}
    unknown = [i for i in ids if i.upper() not in known]
    if unknown:
        raise SystemExit(
            f"mcp-pin: unknown rule id(s): {', '.join(unknown)}\n"
            f"           run `mcp-pin rules` to list them"
        )
    return [i.upper() for i in ids]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _scan_context(args: argparse.Namespace, data: Collected, lock: Lock) -> AuditContext:
    return AuditContext(
        servers=data.servers,
        skills=data.skills,
        tools=data.tools,
        prompts=data.prompts,
        resources=data.resources,
        instructions=data.instructions,
        config_errors=data.errors,
        lock={"servers": lock.servers, "skills": lock.skills},
        source_flows=data.source_flows,
        options=_rule_options(args, data),
    )


def _rule_options(args: argparse.Namespace, data: "Collected") -> dict:
    """What the rules need to know about how this run was invoked.

    `offline` is the `--safe` promise reaching the two rules that would
    otherwise open a socket. `require_integrity` decides whether "could not
    verify" is a note or a failure.
    """
    return {
        "probed": data.probed,
        "offline": bool(getattr(args, "safe", False)),
        "require_integrity": bool(getattr(args, "require_integrity", False)),
    }


def _apply_llm(args: argparse.Namespace, ctx: AuditContext, data: Collected) -> int | None:
    if not getattr(args, "llm", False):
        return None
    targets = classifier_targets(ctx)
    if not targets:
        return None
    cache_path = None
    if not args.no_llm_cache:
        cache_path = Path(args.llm_cache) if args.llm_cache else Path.cwd() / llm_mod.CACHE_NAME
    print(
        f"mcp-pin: --llm will send up to {min(len(targets), args.llm_max_items)} "
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
        print(f"mcp-pin: {exc}", file=sys.stderr)
        return EXIT_ERROR
    ctx.llm_verdicts = llm_result.verdicts
    data.errors.extend(llm_result.errors)
    return None


def _render_scan(args: argparse.Namespace, data: Collected, lock: Lock,
                 findings: list[Finding], suppressed: list, ignore_path) -> str:
    if args.format == "json":
        return render_json(
            findings,
            scanned_configs=data.config_count, scanned_servers=len(data.servers),
            scanned_tools=len(data.tools), scanned_skills=len(data.skills),
            errors=data.errors, lock_present=not lock.is_empty, probed=data.probed,
            version=__version__, suppressed=suppressed,
        )
    if args.format == "sarif":
        return render_sarif(findings, base=Path.cwd(), version=__version__)
    return render_terminal(
        findings,
        scanned_configs=data.config_count, scanned_servers=len(data.servers),
        scanned_tools=len(data.tools), scanned_skills=len(data.skills),
        errors=data.errors, lock_present=not lock.is_empty, probed=data.probed,
        color=False if args.no_color else None, verbose=args.verbose,
        suppressed=suppressed, ignore_path=str(ignore_path) if ignore_path else None,
    )


def _emit_report(args: argparse.Namespace, report: str, findings: list[Finding]) -> int | None:
    if not args.output:
        sys.stdout.write(report)
        return None
    try:
        Path(args.output).write_text(report, encoding="utf-8")
    except OSError as exc:
        print(f"mcp-pin: cannot write {args.output}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.format != "text":
        print(f"mcp-pin: wrote {len(findings)} finding(s) to {args.output}", file=sys.stderr)
    return None


def cmd_scan(args: argparse.Namespace) -> int:
    only = set(_validate_rule_ids(args.only)) or None
    disabled = set(_validate_rule_ids(args.disable))
    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-pin: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    ctx = _scan_context(args, data, lock)
    llm_fail = _apply_llm(args, ctx, data)
    if llm_fail is not None:
        return llm_fail

    findings: list[Finding] = run_rules(ctx, enabled=only, disabled=disabled)
    if lock.is_empty and (only is None or "MCPA014" in only) and "MCPA014" not in (disabled or set()):
        from .rules.drift import unpinned_findings
        findings.extend(unpinned_findings(data.servers))
    findings = [f for f in findings if f.severity >= Severity.parse(args.min_severity)]

    suppressed: list = []
    ignore_path = None
    if not args.no_ignore:
        rules_list, ignore_errors, ignore_path = supp.load(
            args.ignore_file, [Path(p) for p in (args.paths or ["."])]
        )
        data.errors.extend(ignore_errors)
        findings, suppressed = supp.apply(findings, rules_list)

    report = _render_scan(args, data, lock, findings, suppressed, ignore_path)
    emit_fail = _emit_report(args, report, findings)
    if emit_fail is not None:
        return emit_fail
    if args.fail_on == "never":
        return EXIT_OK
    return EXIT_FINDINGS if any(f.severity >= Severity.parse(args.fail_on) for f in findings) else EXIT_OK


def _approval_summary(lock: Lock) -> str:
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
    return ", ".join(parts)


def _pins_a_registry_package(spec) -> bool:
    """Would this launch have a tarball to record? Answered without a socket."""
    from .rules.execution import _FLOATING, extract_package, split_package
    found = extract_package(spec)
    if not found:
        return False
    name, version = split_package(found[1], found[0])
    return bool(name and version and not _FLOATING.match(version))


def _stamp_integrity(lock: Lock, servers: list, *, offline: bool = False) -> list[str]:
    """Record registry tarball hashes and where they came from.

    Returns the pinned registry launches whose hash could *not* be recorded,
    so the caller can say so rather than leaving an approval that looks
    complete. An approval that silently skipped this step produces a lockfile
    which cannot tell "no tarball to pin" from "the registry was down".
    """
    from .integrity import ANSWERED, published
    missed: list[str] = []
    for spec in servers:
        entry = lock.servers.get(spec.identity())
        if not isinstance(entry, dict):
            continue
        if offline:
            # `--safe` promises no connections, and a registry lookup is one.
            if _pins_a_registry_package(spec):
                missed.append(f"{spec.identity()}: --safe was given, so no "
                              f"registry was contacted")
            continue
        answer = published(spec)
        if answer.state != ANSWERED:
            if _pins_a_registry_package(spec):
                missed.append(f"{spec.identity()}: {answer.detail}")
            continue
        entry["integrity"] = answer.hashes
        if answer.urls:
            # pkgcache needs the published URL to find the same artifact in
            # the local package cache; a PyPI URL carries a hash path that
            # cannot be derived from the package name.
            entry["artifact_urls"] = answer.urls
    return missed


def _commit_lock(lock: Lock, previous: Lock, *, yes: bool,
                 yes_tools: list[str] | None = None) -> int:
    """Write the pin, or refuse if something moved and nobody said --yes."""
    from .review import acknowledged, changes, render
    moved = [] if previous.is_empty else changes(previous, lock)
    if moved:
        print(render(moved), end="", file=sys.stderr)
        if not acknowledged(moved, yes=yes, yes_tools=yes_tools):
            if any(item.grade == "critical" for item in moved):
                print("mcp-pin: lock not written. A critical change must be named "
                      "with --yes-tool NAME; --yes is not enough.",
                      file=sys.stderr)
            else:
                print("mcp-pin: lock not written. Pass --yes after you have read "
                      "the diff, or --yes-tool NAME for each drifted tool.",
                      file=sys.stderr)
            return EXIT_ERROR
    written = lock.save()
    print(f"mcp-pin: approved {_approval_summary(lock)} -> {written}")
    return EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    lock_path = _resolve_lock_path(args)
    try:
        previous = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-pin: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    if data.errors and args.verbose:
        for err in data.errors:
            print(f"  warning: {err}", file=sys.stderr)

    if not args.probe:
        print(
            "mcp-pin: approving without --probe records configuration only.\n"
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
    for miss in _stamp_integrity(lock, data.servers,
                                 offline=bool(getattr(args, "safe", False))):
        # An approval that could not record the tarball hash is a weaker
        # approval than one that did, and the operator has to be told at the
        # moment they are deciding, not left to find it in `coverage`.
        print(f"mcp-pin: no registry hash recorded for {miss}", file=sys.stderr)
    return _commit_lock(lock, previous, yes=bool(getattr(args, "yes", False)),
                        yes_tools=list(getattr(args, "yes_tool", None) or []))


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
            print(f"mcp-pin: cannot write {args.output}: {exc}", file=sys.stderr)
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
        print("mcp-pin: guard needs a server command, for example\n"
              "           mcp-pin guard -- npx -y @scope/server@1.0.0",
              file=sys.stderr)
        return EXIT_ERROR

    lock_path = _resolve_lock_path(args)
    return guard_mod.run(
        argv,
        lock_path=lock_path,
        policy=args.policy,
        server_name=args.name,
        strict=not args.fail_open,
        block_severity=Severity.parse(args.block_severity),
        quiet=args.quiet,
        deny_sampling=args.deny_sampling,
        deny_elicitation=args.deny_elicitation,
        deny_roots=args.deny_roots,
        result_policy=args.result_policy,
        log_path=Path(args.log) if getattr(args, "log", None) else None,
        allow_unapproved=args.allow_unapproved,
        dry_run=args.dry_run,
        require_integrity=bool(getattr(args, "require_integrity", False)),
        sign_command=getattr(args, "sign_command", None),
    )


def cmd_policy(args: argparse.Namespace) -> int:
    from .policy import suggest
    from .rules.annotations import MUTATING_VERBS

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-pin: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    if not data.tools:
        print("mcp-pin: no tools to propose limits for. Argument limits are "
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
        print("mcp-pin: no tool takes a path, a destination or a query. "
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
    print(f"mcp-pin: added {added} rule(s) to {lock_path}, left {kept} untouched.")
    print("           Every added value is a placeholder and will refuse every call "
          "until you edit it.")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    from . import status as status_mod

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-pin: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    ctx = AuditContext(
        servers=data.servers, skills=data.skills, tools=data.tools,
        prompts=data.prompts, resources=data.resources,
        instructions=data.instructions, source_flows=data.source_flows,
        config_errors=data.errors,
        lock={"servers": lock.servers, "skills": lock.skills},
        options=_rule_options(args, data),
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
        print(f"mcp-pin: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # No rules are run: this reports on the control plane, not on the servers.
    # It is also the reason it stays fast enough to put in a prompt.
    data = collect(args)
    payload = coverage_mod.build(lock, data.servers,
                                 offline=bool(getattr(args, "safe", False)))

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
        print("mcp-pin gateway: no MCP servers found to serve.", file=sys.stderr)
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
        isolate_env=not args.no_isolate_env,
        share_env=set(args.share_env or []),
        require_integrity=bool(getattr(args, "require_integrity", False)),
    )


def cmd_verify_log(args: argparse.Namespace) -> int:
    from .auditlog import KEY_VAR, verify

    result = verify(args.path,
                    expect_head=getattr(args, "expect_head", None),
                    expect_count=getattr(args, "expect_count", None),
                    verify_command=getattr(args, "verify_command", None))
    print(f"mcp-pin: {result.summary()}")
    for problem in result.problems[1:]:
        where = f" line {problem.line}" if problem.line else ""
        print(f"           also{where}: {problem.reason}")
    if result.ok and result.signatures_checked:
        # A verified segment is the one claim here that an attacker with write
        # access cannot manufacture, so it is worth saying separately from the
        # chain being internally consistent.
        print(f"           {result.signatures_checked} signed segment(s) verified; "
              f"the prefixes they cover cannot have been rewritten.")
    if result.ok and not result.keyed:
        # The command used to stop at "chain intact", which reads as a stronger
        # statement than an unkeyed chain can make: whoever can write the log
        # can recompute it.
        print(f"           unkeyed, so this is tamper-evidence and not proof. "
              f"Set {KEY_VAR} to chain with HMAC-SHA256.")
    return EXIT_OK if result.ok else EXIT_FINDINGS


def cmd_report(args: argparse.Namespace) -> int:
    from . import sessions as report_mod

    path = Path(args.path)
    if not path.exists():
        print(f"mcp-pin: {path}: no such file", file=sys.stderr)
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
        print(f"mcp-pin: unknown rule id {args.rule_id!r}; run `mcp-pin rules`",
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


def _with_default_command(parser: argparse.ArgumentParser, argv: list[str]) -> list[str]:
    # Make `scan` the default command so bare `mcp-pin` and `mcp-pin .` work.
    known = getattr(parser, "mcp_commands", set())
    if not argv or (argv[0] not in known and not argv[0].startswith("-")):
        return ["scan", *argv]
    if argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        return ["scan", *argv]
    return argv


def _serve() -> int:
    from .server import main as serve_main
    return serve_main()


_COMMANDS = {
    "approve": cmd_approve,
    "inspect": cmd_inspect,
    "rules": cmd_rules,
    "explain": cmd_explain,
    "status": cmd_status,
    "coverage": cmd_coverage,
    "gateway": cmd_gateway,
    "policy": cmd_policy,
    "verify-log": cmd_verify_log,
    "report": cmd_report,
    "guard": cmd_guard,
    "serve": lambda _args: _serve(),
    "scan": cmd_scan,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = _with_default_command(parser, list(sys.argv[1:] if argv is None else argv))
    args = parser.parse_args(argv)
    try:
        return _COMMANDS.get(args.command, cmd_scan)(args)
    except KeyboardInterrupt:
        print("\nmcp-pin: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
