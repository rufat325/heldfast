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
from .model import ServerSpec, SkillSpec, ToolSpec, observed_for
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
        # (path, reason) for config files that exist and did not parse.
        self.unreadable: list = []


_GATE_NAMES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "off": None,
}


def _severity_named(name: str):
    return _GATE_NAMES.get(str(name).lower(), Severity.HIGH)


def _gate_servers(out: "Collected", gate, lock: Lock | None = None) -> tuple[list, list]:
    """(servers safe to launch, [(identity, why not)]).

    Runs everything that needs no probe data -- the config rules, the skill
    rules, the source scanner -- and holds back any server already carrying a
    finding at or above the gate. Launching a server the scanner is about to
    call dangerous is the one thing a security tool should not do.

    `lock` is what makes that true of a *pin* as well as of a config. Without
    it the context carried no lockfile, so MCPA015, MCPA016, MCPA031 and
    MCPA036 -- every rule that compares against an approval -- were
    structurally unable to fire here. `scan --probe` therefore executed a
    server whose recorded script had been rewritten, and reported the drift
    afterwards. The rewrite is the rug pull; running it to find out is the
    one order these steps must not happen in.

    Deliberately absent when approving: `approve --probe` exists to re-record
    a server that changed, so gating it on having changed would make the
    review workflow impossible. The refusal to *write* a drifted lock without
    `--yes` is what covers that command, and it still does.
    """
    if gate is None:
        return list(out.servers), []

    recorded = ({"servers": lock.servers, "skills": lock.skills,
                 "stale_digests": lock.stale_digests} if lock is not None else {})
    try:
        findings = run_rules(AuditContext(
            servers=out.servers, skills=out.skills, lock=recorded,
            source_flows=out.source_flows, config_errors=out.errors,
            unreadable=out.unreadable))
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
        blocker = observed_for(worst, server, out.servers)
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
    from .clients import BY_ID
    for path, client in config_files:
        servers, errors = parse_config(path, client)
        out.servers.extend(servers)
        out.errors.extend(errors)
        if servers or not errors:
            continue
        # A file that exists, yielded nothing, and complained. Two reasons
        # that apart: a format this scanner never parses is a known and
        # documented gap (docs/CLIENTS.md), while a file that should have
        # parsed and did not is a blind spot opening right now. Only the
        # second is a finding, or the first would fire on every YAML client
        # forever -- and a finding that fires on everyone forever is one
        # people switch off.
        definition = BY_ID.get(client)
        if definition is not None and definition.unsupported_format:
            continue
        reason = errors[0].split(": ", 1)[-1] if errors else "could not be read"
        out.unreadable.append((str(path), reason))


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


def _gate_lock(args: argparse.Namespace) -> "Lock | None":
    """The lockfile the probe gate compares against, or None when approving.

    An unreadable lock returns None rather than raising: the gate is one of
    several checks and losing it must not take the scan down. `scan` reports
    the same file separately, so the problem is not swallowed.
    """
    if getattr(args, "command", "") == "approve":
        return None
    try:
        return Lock.load(_resolve_lock_path(args))
    except (ValueError, OSError):
        return None


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
    launchable, out.probe_skipped = _gate_servers(out, gate, _gate_lock(args))
    if launchable and not getattr(args, "quiet", False):
        local = [s for s in launchable if s.transport == "stdio"]
        if local and not args.no_stdio_probe:
            print("heldfast: --probe launches these servers as local "
                  "processes: " + ", ".join(sorted(s.identity() for s in local))
                  + " -- this is a pin, not a sandbox",
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
            f"heldfast: unknown rule id(s): {', '.join(unknown)}\n"
            f"           run `heldfast rules` to list them"
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
        unreadable=data.unreadable,
        lock={"servers": lock.servers, "skills": lock.skills,
              "stale_digests": lock.stale_digests},
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
        f"heldfast: --llm will send up to {min(len(targets), args.llm_max_items)} "
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
        print(f"heldfast: {exc}", file=sys.stderr)
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
        print(f"heldfast: cannot write {args.output}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.format != "text":
        print(f"heldfast: wrote {len(findings)} finding(s) to {args.output}", file=sys.stderr)
    return None


def cmd_scan(args: argparse.Namespace) -> int:
    only = set(_validate_rule_ids(args.only)) or None
    disabled = set(_validate_rule_ids(args.disable))
    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
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
                print("heldfast: lock not written. A critical change must be named "
                      "with --yes-tool NAME; --yes is not enough.",
                      file=sys.stderr)
            else:
                print("heldfast: lock not written. Pass --yes after you have read "
                      "the diff, or --yes-tool NAME for each drifted tool.",
                      file=sys.stderr)
            return EXIT_ERROR
    written = lock.save()
    print(f"heldfast: approved {_approval_summary(lock)} -> {written}")
    return EXIT_OK


def _collect_feed(out: Collected, base: str | None) -> bool:
    """Tools for each pinned npm server, from the feed's measurement of it.

    False when the feed itself cannot be read: an approval that silently
    recorded nothing would look like one that recorded everything. False too
    when a release is reported as malware, or that could not be asked.
    """
    from .advisories import AdvisoryError, known, malware
    from .feedlock import FeedError, lookup, package_args, pinned, resolve

    try:
        feed = resolve(base)
        found = 0
        for spec in out.servers:
            if spec.disabled:
                continue
            # Every pinned npm release, measured by the feed or not: an approval
            # of a config that runs known malware is not one to write.
            want = pinned(spec)
            bad = [] if isinstance(want, str) else malware(
                known(want[0], [want[1]]).get(want[1], []))
            if bad:
                print(f"heldfast: {spec.identity()}: {want[0]}@{want[1]} is reported as "
                      f"malware ({', '.join(bad)}); nothing approved. Remove it from the "
                      f"config and rotate what the machine running it could reach.",
                      file=sys.stderr)
                return False
            got = lookup(spec, feed)
            if isinstance(got, str):
                print(f"heldfast: {spec.identity()}: not recorded from the feed -- {got}",
                      file=sys.stderr)
                continue
            found += 1
            out.tools.extend(got.tools)
            out.probe_status[spec.identity()] = (
                f"from feed: {got.package}@{got.version}, measured "
                f"{got.measured_at[:10]} ({feed.source})")
            print(f"heldfast: {spec.identity()}: {len(got.tools)} tool(s) from the "
                  f"feed's measurement of {got.package}@{got.version}", file=sys.stderr)
            if package_args(spec) != got.args:
                print(f"         measured with arguments {got.args}, configured with "
                      f"{package_args(spec)}; if they change the tools, wrap will "
                      f"refuse the difference", file=sys.stderr)
    except FeedError as exc:
        print(f"heldfast: the feed could not be read: {exc}", file=sys.stderr)
        return False
    except AdvisoryError as exc:
        print(f"heldfast: advisories could not be checked ({exc}); nothing approved "
              f"from the feed without them", file=sys.stderr)
        return False
    out.probed = found > 0
    _warn_feed_content(out)
    return True


def _warn_feed_content(out: Collected) -> None:
    """The first version from the feed is the version you approve. Say what
    the content rules make of it before it is written, since nothing here
    launched it and the reviewer has not otherwise seen it."""
    ctx = AuditContext(servers=out.servers, tools=out.tools)
    for f in run_rules(ctx):
        if f.severity >= Severity.HIGH and f.rule_id in ("MCPA010", "MCPA011", "MCPA012"):
            print(f"heldfast: {f.severity.label} {f.rule_id} {f.evidence}", file=sys.stderr)


def cmd_updates(args: argparse.Namespace) -> int:
    from . import updates as up
    from .feedlock import FeedError, resolve

    if args.probe or getattr(args, "safe", False):
        print("heldfast: updates reads the feed, which --safe promises not to do, "
              "and launches nothing, so --probe has no meaning here",
              file=sys.stderr)
        return EXIT_ERROR
    lock_path = _resolve_lock_path(args)
    try:
        previous = Lock.load(lock_path)
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
        return EXIT_ERROR
    data = collect(args)
    try:
        feed = resolve(getattr(args, "feed", None))
        found = up.check(data.servers, previous, feed, min_age=args.min_age)
    except FeedError as exc:
        print(f"heldfast: the feed could not be read: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.format == "json":
        print(json.dumps({"feed": feed.source, "min_age_days": args.min_age,
                          "servers": [u.to_dict() for u in found]}, indent=2))
    else:
        sys.stdout.write(up.render(found, feed.source, args.min_age))
    # A pinned release reported as malware fails the command, --apply or not:
    # a scheduled job that exits 0 over it is a job nobody reads.
    alarmed = EXIT_FINDINGS if any(u.alarm for u in found) else EXIT_OK
    if not args.apply:
        return alarmed
    code = _apply_updates(args, previous, [u for u in found if u.grade == "quiet"], feed)
    return code if code != EXIT_OK else alarmed


def cmd_verify(args: argparse.Namespace) -> int:
    """Each hosted server's tools, as shown to you, against the public log."""
    from . import transparency as tr
    from .feedlock import FeedError, resolve
    from .updates import feed_index

    if getattr(args, "safe", False):
        print("heldfast: verify connects to your hosted servers and reads the public log, "
              "which --safe promises not to do", file=sys.stderr)
        return EXIT_ERROR
    # Hosted servers only: a local server has no public record to compare,
    # and verify must never launch one.
    args.probe, args.no_stdio_probe = True, True
    data = collect(args)
    hosted = [s for s in data.servers if s.is_remote and not s.disabled]
    errors = {k: v for k, v in data.probe_status.items() if v != "answered"}
    try:
        feed = resolve(getattr(args, "feed", None))
        wanted = any(tr.public(s.url or "") for s in hosted)
        found = tr.check(hosted, data.tools, feed_index(feed) if wanted else {}, feed, errors)
        records = _verify_record(args, feed)
    except FeedError as exc:
        print(f"heldfast: the public log could not be read: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.format == "json":
        print(json.dumps({"log": feed.source, "servers": [w.to_dict() for w in found],
                          "record": [r.to_dict() for r in records]}, indent=2))
    else:
        from .lookup import render as render_record
        sys.stdout.write(tr.render(found, feed.source)
                         + "".join(line + "\n" for line in render_record(records)))
    worst = ("differs", "unlogged") if args.strict else ("differs",)
    failed = any(w.status in worst for w in found) or (
        args.strict and any(r.unseen for r in records))
    return EXIT_FINDINGS if failed else EXIT_OK


def _verify_record(args: argparse.Namespace, feed: object) -> list:
    """Every tool the lock records, looked up in the public record by bucket.
    No lock, or one that cannot be read, is simply nothing to look up."""
    from .lookup import check as look_up

    try:
        lock = Lock.load(_resolve_lock_path(args))
    except (ValueError, OSError):
        return []
    return look_up(lock.servers, feed) if lock.servers else []


def _witness_approval(data: Collected, args: argparse.Namespace) -> bool:
    """First contact with a hosted server, checked against the public log.

    Trust on first use trusts whatever the server chose to show you first.
    For a hosted server, the public log is a second witness: a tool whose
    definition, as shown to you, the log has never recorded is not approved
    unless named with --yes-tool. When the log cannot be read, approval goes
    ahead without the witness and says so -- it is an extra check, and it is
    not one an unreachable GitHub should be able to turn into an outage.
    """
    from . import transparency as tr
    from .feedlock import FeedError, resolve
    from .updates import feed_index

    hosted = [s for s in data.servers if s.is_remote and not s.disabled and s.url
              and tr.public(s.url) and any(t.server == s.identity() for t in data.tools)]
    if not hosted:
        return True
    try:
        feed = resolve(getattr(args, "feed", None))
        found = tr.check(hosted, data.tools, feed_index(feed), feed)
    except FeedError as exc:
        print(f"heldfast: the public log could not be read ({exc}); hosted servers are "
              f"approved without a second witness", file=sys.stderr)
        return True
    named, refused = set(getattr(args, "yes_tool", None) or []), False
    for w in found:
        left = [n for n in w.differs if n not in named]
        if left:
            refused = True
            print(f"heldfast: {w.identity}: shows you a definition of {', '.join(left)} that "
                  f"the public log has never recorded; not approved. Read it, then pass "
                  f"--yes-tool NAME for each to accept it (`heldfast verify` has detail).",
                  file=sys.stderr)
        elif w.status in ("same", "differs"):
            print(f"heldfast: {w.identity}: matches the public log", file=sys.stderr)
        elif w.status == "unlogged":
            print(f"heldfast: {w.identity}: {len(w.unseen)} tool(s) the public log has never "
                  f"seen ({', '.join(w.unseen[:5])}); expected behind a login -- read them",
                  file=sys.stderr)
    return not refused


def _apply_updates(args: argparse.Namespace, previous: Lock, todo: list,
                   feed: object) -> int:
    """Bump the config for each quiet update, then re-approve just those.

    Every config edit is undone if the approval does not go through, in
    reverse order so two servers in one file come back as they were.
    """
    from .updates import rewrite_config

    if not todo:
        print("heldfast: no quiet update to apply", file=sys.stderr)
        return EXIT_OK
    specs, edits, applied = {}, [], []
    for spec in collect(args).servers:
        specs[spec.identity()] = spec
    for u in todo:
        path = Path(specs[u.identity].source)
        original = rewrite_config(path, f"{u.package}@{u.current}", f"{u.package}@{u.target}")
        if original is None:
            print(f"heldfast: {u.identity}: \"{u.package}@{u.current}\" does not occur "
                  f"exactly once in {path}; left for you to bump", file=sys.stderr)
            continue
        edits.append((path, original))
        applied.append(u.identity)
    code = EXIT_ERROR
    try:
        code = _reapprove(args, previous, set(applied), feed) if applied else EXIT_OK
    finally:
        if code != EXIT_OK:
            for path, original in reversed(edits):
                path.write_bytes(original.encode("utf-8"))
            if edits:
                print("heldfast: config restored; nothing was bumped", file=sys.stderr)
    return code


def _reapprove(args: argparse.Namespace, previous: Lock, applied: set, feed: object) -> int:
    """Record the bumped servers from the feed and nothing else."""
    from .feedlock import lookup
    from .review import changes

    data = collect(args)
    for spec in data.servers:
        if spec.identity() not in applied:
            continue
        got = lookup(spec, feed)
        if isinstance(got, str):
            print(f"heldfast: {spec.identity()}: {got}", file=sys.stderr)
            return EXIT_ERROR
        data.tools.extend(got.tools)
        data.probe_status[spec.identity()] = (
            f"from feed: {got.package}@{got.version}, measured "
            f"{got.measured_at[:10]} ({feed.source})")
    lock = Lock(path=_resolve_lock_path(args))
    lock.record(data.servers, data.tools, data.skills, prompts=data.prompts,
                resources=data.resources, instructions=data.instructions,
                previous=previous, probe_status=data.probe_status)
    lock.merge_unprobed(previous)
    for ident in applied:
        # The old version's tarball hash is not this version's. Stamped fresh
        # below, or reported missing -- never carried forward.
        for key in ("integrity", "artifact_urls"):
            lock.servers.get(ident, {}).pop(key, None)
    for miss in _stamp_integrity(lock, [s for s in data.servers if s.identity() in applied]):
        print(f"heldfast: no registry hash recorded for {miss}", file=sys.stderr)
    foreign = sorted({c.identity for c in changes(previous, lock)} - applied)
    if foreign:
        print("heldfast: the lock would also change for " + ", ".join(foreign) +
              ", which --apply was not asked to bump; run `heldfast approve` to review "
              "those first", file=sys.stderr)
        return EXIT_ERROR
    return _commit_lock(lock, previous, yes=True)


def cmd_approve(args: argparse.Namespace) -> int:
    lock_path = _resolve_lock_path(args)
    try:
        previous = Lock.load(lock_path)
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
        return EXIT_ERROR

    from_feed = bool(getattr(args, "from_feed", False))
    if from_feed and (args.probe or getattr(args, "safe", False)):
        print("heldfast: --from-feed replaces --probe, and it reads the feed over "
              "the network, which --safe promises not to do; pass it alone",
              file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    if data.errors and args.verbose:
        for err in data.errors:
            print(f"  warning: {err}", file=sys.stderr)

    if from_feed:
        if not _collect_feed(data, getattr(args, "feed", None)):
            return EXIT_ERROR
    elif args.probe:
        if not getattr(args, "safe", False) and not _witness_approval(data, args):
            return EXIT_ERROR
    else:
        print(
            "heldfast: approving without --probe records configuration only.\n"
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
        print(f"heldfast: no registry hash recorded for {miss}", file=sys.stderr)
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
            print(f"heldfast: cannot write {args.output}: {exc}", file=sys.stderr)
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
        print("heldfast: wrap needs a server command, for example\n"
              "           heldfast wrap -- npx -y @scope/server@1.0.0",
              file=sys.stderr)
        return EXIT_ERROR

    lock_path = _resolve_lock_path(args)
    return guard_mod.run(
        argv,
        lock_path=lock_path,
        lock_was_explicit=bool(getattr(args, "lock", None)),
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
        share_env=set(getattr(args, "share_env", None) or []),
        isolate_env=bool(getattr(args, "isolate_env", False)),
        drift=getattr(args, "drift", "block"),
    )


def cmd_grade_drift(_args: argparse.Namespace) -> int:
    """`guard --drift graded`'s test, for a caller that is not Python.

    The definition goes through the guard's own wire reader, so a field the
    guard grades is a field this grades; a second reader is where the two
    would start to disagree.
    """
    from .driftgrade import introduced, live_text
    from .guard import _tool_from_wire

    try:
        # Bytes, decoded as UTF-8 whatever the locale says. Text-mode stdin on
        # Windows is the ANSI codepage, which turned a zero-width space from
        # the hook into three ordinary letters: the hidden character this
        # grades for, graded clean. Bytes that are not UTF-8 are an error,
        # and an error is a refusal on the other side.
        raw = sys.stdin.buffer.read().decode("utf-8")
        payload = json.loads(raw or "{}")
        definition = payload.get("definition")
        if not isinstance(definition, dict):
            raise ValueError("no tool definition given")
        recorded = payload.get("recorded")
        tool = _tool_from_wire("hook", definition)
        found = introduced(recorded if isinstance(recorded, dict) else None, live_text(
            tool.description, tool.title, tool.annotations,
            tool.input_schema, tool.output_schema))
    except (ValueError, AttributeError, TypeError) as exc:
        print(f"heldfast grade-drift: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps({"introduced": [{"kind": s.kind, "match": s.match} for s in found]}))
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    from . import check as check_mod
    return check_mod.run(getattr(args, "lock", None))


def cmd_ci(args: argparse.Namespace) -> int:
    # The build-gate name cannot be talked into launching or lowering the bar.
    args.probe = False
    args.fail_on = "high"
    return cmd_scan(args)


def cmd_policy(args: argparse.Namespace) -> int:
    from .policy import suggest
    from .rules.annotations import MUTATING_VERBS

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    if not data.tools:
        print("heldfast: no tools to propose limits for. Argument limits are "
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
        print("heldfast: no tool takes a path, a destination or a query. "
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
    print(f"heldfast: added {added} rule(s) to {lock_path}, left {kept} untouched.")
    print("           Every added value is a placeholder and will refuse every call "
          "until you edit it.")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    from . import status as status_mod

    lock_path = _resolve_lock_path(args)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"heldfast: {exc}", file=sys.stderr)
        return EXIT_ERROR

    data = collect(args)
    ctx = AuditContext(
        servers=data.servers, skills=data.skills, tools=data.tools,
        prompts=data.prompts, resources=data.resources,
        instructions=data.instructions, source_flows=data.source_flows,
        config_errors=data.errors,
        unreadable=data.unreadable,
        lock={"servers": lock.servers, "skills": lock.skills,
              "stale_digests": lock.stale_digests},
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
        print(f"heldfast: {exc}", file=sys.stderr)
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
        print("heldfast gateway: no MCP servers found to serve.", file=sys.stderr)
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
        drift=getattr(args, "drift", "block"),
    )


def cmd_verify_log(args: argparse.Namespace) -> int:
    from .auditlog import KEY_VAR, verify

    result = verify(args.path,
                    expect_head=getattr(args, "expect_head", None),
                    expect_count=getattr(args, "expect_count", None),
                    verify_command=getattr(args, "verify_command", None))
    print(f"heldfast: {result.summary()}")
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
        print(f"heldfast: {path}: no such file", file=sys.stderr)
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
        print(f"heldfast: unknown rule id {args.rule_id!r}; run `heldfast rules`",
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
    # `heldfast -- <server>` is wrap. Bare `heldfast` and `heldfast .` are scan.
    known = getattr(parser, "mcp_commands", set())
    if argv and argv[0] == "--":
        return ["wrap", *argv]
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
    "updates": cmd_updates,
    "verify": cmd_verify,
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
    "wrap": cmd_guard,
    "check": cmd_check,
    "grade-drift": cmd_grade_drift,
    "ci": cmd_ci,
    "serve": lambda _args: _serve(),
    "scan": cmd_scan,
    "doctor": cmd_scan,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = _with_default_command(parser, list(sys.argv[1:] if argv is None else argv))
    args = parser.parse_args(argv)
    try:
        return _COMMANDS.get(args.command, cmd_scan)(args)
    except KeyboardInterrupt:
        print("\nheldfast: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
