# heldfast and AIUC-1's MCP controls

[AIUC-1](https://standard.aiuc-1.com) is the security and reliability standard AI agents are
certified and insured against. Its Q2 2026 update brought MCP servers into scope. This page
says which of those controls heldfast produces evidence for, which it covers only in part,
and which it does not touch. heldfast is not affiliated with AIUC, and using it is not a
certification.

Control text is quoted from standard.aiuc-1.com as read on 4 October 2026. The standard
changes quarterly; check the current wording before an audit.

## At a glance

| control | what it asks | heldfast | evidence it leaves |
|---|---|---|---|
| B006.1 | restrict agents to approved MCP servers | **yes** | `.mcp-pin.lock`, `--org-policy`, the gateway refusing unapproved servers |
| B006.2 | log and alert on boundary violations | partly | refusals in a hash-chained log; alerting is yours |
| B006.3 | runtime safeguards | three of the four examples | tool-definition pinning, pre-execution hooks, artifact scanning; **not a sandbox** |
| D003.1 | tool allowlists and parameter validation | **yes** | lock entries and argument `policy` |
| D003.2 | rate limits for tools | partly | `--max-calls` per tool per session; no transaction caps |
| D003.3 | tool call log | **yes, with one deliberate gap** | server, tool, decision, time; argument values are never logged |
| D003.4 | human approval for sensitive operations | no | your client's confirmation prompts |
| D003.5 | periodic review of tool use | supports it | `heldfast report`, `status` |
| E009.1 | log third-party interactions | partly | the gateway's log of every MCP server it fronts |
| E009.2 | alert on anomalous third-party access | partly | drift and budget refusals; routing alerts is yours |
| E006 | vendor due diligence | supports it | the approval record, `verify` against the public log |

## B006: Prevent unauthorized AI agent actions

**B006.1, agent service access restrictions** (mandatory). The standard asks for "restricting
agent access to approved backend services, APIs and MCP servers", and lists "MCP server
allowlists" as evidence.

The lockfile is that allowlist, committed and reviewed like code. `wrap` and `gateway` will not
start a server the lock does not name: "An unapproved server is never started", not started and
filtered. `--org-policy` adds the organisation's own denials on top, and the Claude Code plugin
refuses calls to servers the lock or the policy does not allow
([MANUAL.md](MANUAL.md#one-endpoint-in-front-of-everything-gateway),
[plugin](../plugin/heldfast/README.md)).

Evidence: `.mcp-pin.lock` in version control with its review history, the org policy file, and
a `guard` or `gateway` log showing an unapproved server refused.

**B006.2, agent security monitoring and alerting** (mandatory). Every refusal, whether an
unapproved server, a drifted tool, an argument outside policy or an exhausted budget, is a line
in the `--log` trail, and `heldfast report` reads it back. heldfast does not send alerts. Ship the
JSONL to whatever pages someone; the CI check exits non-zero, which is an alert of its own kind.

**B006.3, execution-level safeguards** (supplemental). The control lists four examples. heldfast
is three of them:

- "monitoring MCP tool definitions for unauthorized changes after initial approval": the
  lockfile records each tool's definition at approval, and `guard` and `gateway` withhold any
  tool that no longer matches it, at call time
  ([MANUAL.md](MANUAL.md#enforcing-it-at-runtime-guard)). A server announcing mid-session that
  its tools changed gets an alert on screen
  ([MANUAL.md](MANUAL.md#when-a-server-changes-its-mind-mid-session)).
- "pre-execution authorization hooks that verify runtime tool calls against defined policy":
  the Claude Code plugin's PreToolUse hook, against the same lockfile and org policy.
- "scanning agent configuration artifacts such as hooks, skills and rules": `heldfast scan`
  reads `SKILL.md` files in the tree ([rules.md](rules.md)).

The fourth, "sandboxed execution environments", is not heldfast. It is a pin, not a sandbox:
`--probe` and `guard` run the server, and you confine it with the OS, a container or a VM.

## D003: Restrict unsafe tool calls

**D003.1, tool authorization and validation** (mandatory). "Restricting tool calls to approved
functions and MCP servers, validating parameters before execution." Approved tools are the lock
entries. Parameters are checked against a lock entry's argument `policy`: allowed paths, SQL
verbs, domains, or a tool denied outright, before the call leaves
([MANUAL.md](MANUAL.md#constraining-what-a-tool-may-be-asked-to-do)).

**D003.2, rate limits for tools** (mandatory). `--max-calls N` caps calls per tool per session,
and `--dry-run` finds the right number before enforcing it
([MANUAL.md](MANUAL.md#a-ceiling-on-calls---max-calls)). There are no time-windowed limits or
money caps; those belong to the payment layer.

**D003.3, tool call log** (mandatory). The evidence the standard describes "may include log
entries capturing the originating MCP server, tool name, tool version, input parameters, and
timestamps". The `--log` trail records the server, the tool, the decision, the time and the
size of the arguments, in a hash chain that `verify-log` checks: an edited, deleted, reordered
or forged line breaks it ([MANUAL.md](MANUAL.md#proving-what-the-guard-did)). The approved
tool version is in the lockfile beside it.

It does not record argument values, on purpose. Arguments are where credentials and customer
records live, and a security tool that copies them to disk has built the problem it was
installed to find. If your auditor requires values, log them in a system built to hold that
data, and tell them why this one does not.

**D003.4, human-approval workflows** (supplemental). heldfast requires a human to approve a
server and, for critical drift, to name each changed tool with `--yes-tool`. That is approval of
the tool, not of each call. Per-call confirmation is your client's job.

**D003.5, tool call log reviews** (supplemental). `heldfast report trail.jsonl` summarises
sessions, calls and refusals per tool; `heldfast status` puts the lock, the drift and the trail
on one page. The review itself, and its record, is yours.

## E009 and E006: third parties

**E009.1, third-party access monitoring** (mandatory). An MCP server is a third party your agent
talks to. Run everything through `gateway --log` and one trail covers every server it fronts
([MANUAL.md](MANUAL.md#one-endpoint-in-front-of-everything-gateway)). It does not capture IP
addresses or user sessions; the standard's examples are written for human access too.

**E009.2, anomalous third-party access alerting** (supplemental). The anomalies heldfast detects
are a server changing its tools, a call outside argument policy, and a tool exceeding its
budget. Each is refused and logged. Routing them to an owner is yours.

**E006, vendor due diligence** (mandatory, every 12 months). Written for upstream model vendors,
it asks for documented assessments and retained evidence. For MCP servers the approval in the
lockfile is a dated, reviewed record of what was accepted, and `heldfast verify` checks a hosted
server against the public log, a record nobody holding this repository's credentials can
rewrite ([TRANSPARENCY.md](TRANSPARENCY.md)). That supports an assessment; it is not one.

## What to hand an auditor

- `.mcp-pin.lock` and its commit history: what was approved, when, by whom.
- The org policy file, if you use one.
- The `--log` trail and `heldfast verify-log` output showing the chain intact.
- `heldfast report` for the review period.
- CI runs of `heldfast ci` or the GitHub Action failing on drift.

Preparing for an AIUC-1 audit and want help fitting this to your setup? Email
ewawes4@gmail.com.
