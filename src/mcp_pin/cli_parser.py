"""Flag definitions for the command line.

Kept off `cli.py` so adding a command is one function here rather than
another hundred lines in the file that also runs the commands. The
behaviour is identical: `cli.build_parser` is this module's `build_parser`.
"""

from __future__ import annotations

import argparse

from . import __version__
from . import llm as llm_mod
from . import suppressions as supp
from .findings import Severity
from .lockfile import DEFAULT_LOCK_NAME


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
                   help="approval lockfile (default: .mcp-pin.lock in the scanned tree)")
    p.add_argument("--depth", type=int, default=6, metavar="N",
                   help="maximum directory depth when walking paths (default: 6)")
    p.add_argument("--exclude", metavar="PATH", action="append", default=[],
                   help="skip this path (repeatable); a tests/ directory of "
                        "attack corpora is not the product")
    p.add_argument("--share-env", metavar="NAME", action="append", default=[],
                   help="with --probe, also pass this environment variable to the "
                        "servers being launched (repeatable). By default a probed "
                        "server gets what its config declares plus the infrastructure "
                        "it needs, and none of your other credentials")
    p.add_argument("--require-integrity", action="store_true",
                   help="treat a registry artifact that could not be verified "
                        "as a failure rather than a note (MCPA037 becomes high). "
                        "For build runners that must not pass on 'could not see'")
    p.add_argument("-v", "--verbose", action="store_true")



def _register_scan(sub: argparse._SubParsersAction) -> None:
    scan = sub.add_parser(
        "scan",
        aliases=["doctor"],
        help="scan for findings (default command; `doctor` is the same job)",
    )
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
        "Needs: pip install 'mcp-pin[llm]' and ANTHROPIC_API_KEY.",
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


def _register_approve(sub: argparse._SubParsersAction) -> None:
    approve = sub.add_parser(
        "approve",
        help="record the current state as approved in the lockfile",
        description="Write the lockfile that later scans compare against.",
    )
    _add_scan_arguments(approve)
    approve.add_argument(
        "--yes", action="store_true",
        help="write the lock for cosmetic drift; a critical-graded change "
             "still needs --yes-tool; the diff is still printed",
    )
    approve.add_argument(
        "--yes-tool", metavar="NAME", action="append", default=[],
        help="acknowledge this drifted tool (repeatable); required for a "
             "critical-graded change, where --yes is not enough; a digest or "
             "command change still needs --yes",
    )
    approve.add_argument(
        "--from-feed", action="store_true",
        help="record each pinned npm server's tools from the drift feed's "
             "measurement of that exact version, instead of launching it here "
             "(--probe); servers the feed has not measured are left as they were",
    )
    approve.add_argument(
        "--feed", metavar="URL", default=None,
        help="read the feed from this base URL instead of the `feed` branch "
             "of rufat325/mcp-pin (a mirror, or a copy you host)",
    )


def _register_updates(sub: argparse._SubParsersAction) -> None:
    updates = sub.add_parser(
        "updates",
        help="newer releases the drift feed has measured for your pinned servers",
        description=(
            "For each server pinned to an exact npm version, report whether the "
            "drift feed has measured a newer release and what approving it would "
            "change: quiet (approve --yes would take it) or review (a critical "
            "change a person must name). --apply bumps the quiet ones in the "
            "config and re-approves them from the feed, and nothing else."
        ),
    )
    _add_scan_arguments(updates)
    updates.add_argument("--apply", action="store_true",
                         help="bump each quiet update in its config file and "
                              "re-approve it from the feed")
    updates.add_argument("--feed", metavar="URL", default=None,
                         help="read the feed from this base URL instead of the "
                              "`feed` branch of rufat325/mcp-pin")
    updates.add_argument("-f", "--format", choices=("text", "json"), default="text")


def _register_inspect(sub: argparse._SubParsersAction) -> None:
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


def _register_rules(sub: argparse._SubParsersAction) -> None:
    rules_p = sub.add_parser("rules", help="list the built-in rules")
    rules_p.add_argument("--markdown", action="store_true",
                         help="emit the full rule catalog as Markdown")
    rules_p.add_argument("-o", "--output", metavar="FILE",
                         help="write to FILE as UTF-8 instead of stdout")


def _register_explain(sub: argparse._SubParsersAction) -> None:
    explain_p = sub.add_parser(
        "explain",
        help="describe one rule in full",
        description="What a check looks for, why it matters, how to fix it, and when it is wrong.",
    )
    explain_p.add_argument("rule_id", metavar="RULE", help="a rule id, e.g. MCPA015")


def _register_policy(sub: argparse._SubParsersAction) -> None:
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


def _register_status(sub: argparse._SubParsersAction) -> None:
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


def _register_coverage(sub: argparse._SubParsersAction) -> None:
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


def _register_gateway(sub: argparse._SubParsersAction) -> None:
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
    gateway_p.add_argument("--drift", choices=("block", "graded"), default="block",
                           help="what to do with a tool whose definition changed since "
                                "approval: refuse it (default), or forward it when "
                                "the change introduced no attack signal -- a "
                                "heuristic, not a pin")
    gateway_p.add_argument("--require-integrity", action="store_true",
                           help="refuse to start a backend whose recorded registry "
                                "artifact cannot be verified locally")
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
    gateway_p.add_argument("--share-env", metavar="NAME", action="append", default=[],
                           help="also pass this environment variable through to every "
                                "backend (repeatable). By default a backend gets the "
                                "infrastructure it needs plus what its own config "
                                "declares, so one server's token does not reach the rest")
    gateway_p.add_argument("--no-isolate-env", action="store_true",
                           help="give every backend the gateway's whole environment, "
                                "as clients do. Restores the behaviour from before "
                                "isolation existed")
    gateway_p.add_argument("--quiet", action="store_true")
    gateway_p.add_argument("-v", "--verbose", action="store_true")


def _register_verify_log(sub: argparse._SubParsersAction) -> None:
    verify_p = sub.add_parser(
        "verify-log",
        help="check that a guard audit log has not been altered",
        description=(
            "Walks the hash chain written by `guard --log` and reports the first "
            "entry that does not follow the one before it. Then, *if it can*, "
            "checks that this is the whole chain rather than a prefix somebody "
            "left behind: against the .head file the writer keeps when that file "
            "is present, and against --expect-head / --expect-count when you "
            "supply them from somewhere the log's author could not reach. When "
            "neither is available the summary says so, because deleting the "
            "sidecar is cheaper than forging it and a silent pass would look "
            "identical to a complete log. Without MCP_PIN_LOG_KEY set this is "
            "tamper-evidence, not attestation: an attacker who can write the log "
            "can recompute an unkeyed chain. With it set the chain is "
            "HMAC-SHA256. It never proves who wrote the record."
        ),
    )
    verify_p.add_argument("path", metavar="PATH", help="the log file to check")
    verify_p.add_argument("--verify-command", metavar="CMD", default=None,
                          help="check signed segments with this command; {sig} is "
                               "replaced by a file holding the signature and the "
                               "payload arrives on stdin. Without it, segments are "
                               "reported as present and unchecked rather than "
                               "assumed good")
    verify_p.add_argument("--expect-head", metavar="HASH", default=None,
                          help="the hash the chain should end on, from a record "
                               "kept outside the log")
    verify_p.add_argument("--expect-count", type=int, metavar="N", default=None,
                          help="how many entries the chain should have; catches a "
                               "truncated tail even if the .head file went with it")


def _register_report(sub: argparse._SubParsersAction) -> None:
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


def _register_guard(sub: argparse._SubParsersAction) -> None:
    guard_p = sub.add_parser(
        "guard",
        aliases=["wrap"],
        help="proxy a server and enforce the approval lockfile at runtime",
        description=(
            "Sit between the client and an MCP server, and refuse to pass through tools "
            "that are unapproved or whose definition changed since approval. Reads the "
            "same .mcp-pin.lock the CI gate reads, so one artifact governs both. "
            "`wrap` is the same command. Usage: mcp-pin wrap -- <server command...>"
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
    guard_p.add_argument("--drift", choices=("block", "graded"), default="block",
                         help="what to do with a tool whose definition changed since "
                              "approval: refuse it (default), or forward it when "
                              "the change introduced no attack signal -- a "
                              "heuristic, not a pin")
    guard_p.add_argument("--block-severity", default="critical",
                         choices=[s.label for s in Severity],
                         help="minimum content-rule severity that rejects a tool "
                              "(default: critical)")
    guard_p.add_argument("--fail-open", action="store_true",
                         help="forward a call when an internal error happens instead of "
                              "refusing it (the default is to refuse)")
    guard_p.add_argument("--strict", action="store_true",
                         help="fail closed on internal errors (the default; "
                              "--fail-open inverts this)")
    guard_p.add_argument("--sign-command", metavar="CMD", default=None,
                         help="close the audit trail with a signature from this "
                              "command, which receives the payload on stdin. The "
                              "key stays wherever it already lives -- e.g. "
                              "\"ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n mcp-pin -q\". "
                              "A prefix that has been signed cannot be rewritten "
                              "afterwards, which an unkeyed chain cannot promise")
    guard_p.add_argument("--require-integrity", action="store_true",
                         help="refuse to start when a recorded registry artifact "
                              "cannot be verified against the local package cache")
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
    guard_p.add_argument("--isolate-env", action="store_true",
                         help="give the wrapped server only the environment it needs "
                              "to run, instead of everything this process has. Off by "
                              "default because wrap takes a command rather than a "
                              "config entry, so there is no declared 'env' block to "
                              "read a server's own token from -- turning it on may "
                              "need --share-env. mcp-pin's own variables are withheld "
                              "either way")
    guard_p.add_argument("--share-env", metavar="NAME", action="append", default=[],
                         help="with --isolate-env, also pass this variable through "
                              "(repeatable)")


def _register_check(sub: argparse._SubParsersAction) -> None:
    check_p = sub.add_parser(
        "check",
        help="verify .mcp-pin.lock is well-formed (no scan, no launch)",
        description=(
            "The lockfile check another language can run. Refuses a missing file "
            "(MCPA014) and a version this tool does not understand. Does not "
            "launch servers and does not contact a registry."
        ),
    )
    check_p.add_argument("--lock", metavar="PATH", default=None,
                         help=f"lockfile (default: ./{DEFAULT_LOCK_NAME})")


def _register_grade_drift(sub: argparse._SubParsersAction) -> None:
    sub.add_parser(
        "grade-drift",
        help="grade one changed tool definition, JSON in and out (for hooks)",
        description=(
            "Reads {\"recorded\": <lock entry for the tool>, \"definition\": "
            "<live tool>} on stdin and prints {\"introduced\": [...]}: the "
            "signals the live definition carries that the recorded text did "
            "not. The same test `guard --drift graded` applies, so a caller in "
            "another language -- the Claude Code hook -- does not keep a second "
            "copy of the patterns. Exit 2 on input it cannot read."
        ),
    )


def _register_ci(sub: argparse._SubParsersAction) -> None:
    ci = sub.add_parser(
        "ci",
        help="scan that fails the PR on MCPA014/015 (never launches)",
        description=(
            "The build-gate name. Equivalent to `scan --fail-on high` with "
            "`--probe` refused, so a runner cannot be talked into launching "
            "configured servers. MCPA014 (no lock) and MCPA015 (drift) fail "
            "the job under the default threshold."
        ),
    )
    _add_scan_arguments(ci)
    ci.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    ci.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    ci.add_argument("--fail-on", default="high",
                    choices=[s.label for s in Severity] + ["never"],
                    help="minimum severity that sets exit code 1 (ci forces high)")
    ci.add_argument("--min-severity", default="info", choices=[s.label for s in Severity])
    ci.add_argument("--only", action="append", metavar="RULE", default=[])
    ci.add_argument("--disable", action="append", metavar="RULE", default=[])
    ci.add_argument("--no-color", action="store_true")
    ci.add_argument("--ignore-file", metavar="PATH", default=None)
    ci.add_argument("--no-ignore", action="store_true")


def _register_serve(sub: argparse._SubParsersAction) -> None:
    sub.add_parser(
        "serve",
        help="run mcp-pin as an MCP server over stdio",
        description=(
            "Expose the scanner's analysis over MCP so an agent can check a server "
            "configuration before a human installs it. Read-only: no probing, and "
            "path scanning only when MCP_PIN_ALLOW_PATH_SCAN is set."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-pin",
        description="Pin the MCP servers you approved, and refuse the drift.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  no findings at or above the --fail-on threshold\n"
            "  1  findings at or above the threshold\n"
            "  2  the scan itself could not complete\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"mcp-pin {__version__}")
    sub = parser.add_subparsers(dest="command")

    _register_scan(sub)
    _register_approve(sub)
    _register_updates(sub)
    _register_inspect(sub)
    _register_rules(sub)
    _register_explain(sub)
    _register_policy(sub)
    _register_status(sub)
    _register_coverage(sub)
    _register_gateway(sub)
    _register_verify_log(sub)
    _register_report(sub)
    _register_guard(sub)
    _register_check(sub)
    _register_grade_drift(sub)
    _register_ci(sub)
    _register_serve(sub)
    # The command names come from the parser rather than a second list.
    # A hardcoded set is how `verify-log` was silently treated as a path
    # to scan for its first few minutes of existence.
    parser.mcp_commands = set(sub.choices)
    return parser
