# Working on mcp-audit

Context for anyone (or any session) picking this up cold. The code explains
what it does; this explains what is not in the code — where the work stopped,
which decisions were made and why, and the ones that were wrong first.

A security scanner for MCP server configurations and agent skills, plus a
runtime proxy that enforces what you approved. Zero runtime dependencies,
stdlib only, Python 3.9+. Public at https://github.com/rufat325/mcp-audit.

---

## Where this stopped

**Nothing is half-finished.** Working tree clean, CI green, the last commit
is a complete unit. 26 commits, 284 tests, 26 rules, CI across
Linux/macOS/Windows on Python 3.9/3.12/3.13 plus a wire-shape job, a job that
exercises `action.yml` itself, and a release workflow that publishes on a
version tag.

The last stretch ran as a loop: the owner said "keep researching and
building" repeatedly, and each cycle picked one source, found a gap, built
it, tested it and committed. Reading the **specification** turned out to be a
far better source than reading competitors — most cycles found a defect in
this tool rather than a missing feature.

The cycles, most recent last:

1. `cb339a4` — a server controls four channels into the model, not one. Added
   `instructions` (the spec permits a client to put it in the system prompt),
   prompts and resources to probing, fingerprinting and scanning.
2. `d916356` — tool annotations (`readOnlyHint`) are a self-declared claim
   clients use to skip approval prompts; added MCPA021/022 and put
   annotations in the fingerprint.
3. `eda37e4` — the spec's security document yielded MCPA023/024/025:
   dangerous URL schemes, cloud metadata addresses, over-broad OAuth scopes.
4. `64c630e` — the probe was negotiating a protocol two revisions old. Now
   dual-era: `server/discover` and the legacy handshake, resolved on
   whichever answers.
5. `6d916ff` — MRTR means elicitation and sampling arrive differently on
   current servers; the guard screened only the legacy shape.
6. `41e18d5` — `title` is the display name the user actually reads and was
   unscanned; added MCPA026 and resource templates.
7. `0d475a5`, `ccdf630` — screen what servers *return*, not just what they
   declare. The second commit fixed the first: it screened `content` but not
   `contents` or `messages`.
8. `03d8dc3` — probed 15 real public endpoints, got 56 real tools, and found
   the rules were 27% false-positive. Narrowed MCPA021 to destructive verbs
   in the tool name only and deleted a signal that fired on the canonical
   good tool description.
9. `6b7fbe1` — `hostile_server.py`, eleven deliberate protocol failure modes.
   Found that killing the guard orphaned the wrapped server; `lifetime.py`
   fixes it with a Windows Job Object / Linux PDEATHSIG.
10. `6b7393c` — the source changed from the spec to **the tool as a user
    meets it**: build the wheel, install it clean, run it from outside the
    source tree. `mcp-audit` with no arguments scans the current directory,
    so running it in a home directory walks AppData: 30 seconds in it had
    covered 5,599 directories and was not finished. Now about a second.
    Pruned the cache trees, answered client paths from the directory listing
    instead of 12 stats per directory, and stopped following junctions twice.
11. `903f6a2` — the README opened with `uvx mcp-audit`, which fails because
    the package is not on PyPI. Every install line now names the repository
    and all four were run before being written down. Added `release.yml`:
    trusted publishing on a version tag, no stored token, and it refuses to
    publish a wheel that pulled in a dependency.

### If the loop resumes, change source

**The spec is near exhausted.** The remaining unscreened methods
(`completion/complete`, `notifications/message`, `subscriptions/listen`)
carry little model-facing text. Better sources now:

- more real-world corpora — only 4 of 15 endpoints were reachable, and the
  harvested config corpus was 98 blocks from 250 repos out of 4,129 available
- running the LLM tier against the live API once; it is stub-verified only
  and has never made a real call
- the owner's items below, which are worth more than another rule

### Outstanding, and needing the owner rather than an agent

- **PyPI.** `release.yml` does the publishing; it needs a pending publisher
  created once at pypi.org -> Publishing (project `mcp-audit`, owner
  `rufat325`, workflow `release.yml`, environment `pypi`), then
  `git tag v0.1.0 && git push --tags`. Afterwards the README's install lines
  shorten to `uvx mcp-audit` and `pipx install mcp-audit`.
- **GitHub profile.** Bio, location and "available for hire" are empty; a
  profile README is drafted on the Desktop in `rufat325-profile/`.
- **Global git email** is still `rufatm726@email.com`, so every other repo on
  the machine commits under an address GitHub cannot link.
- **Marketplace** listing for the action — the action is tested and ready.
- **History rewrite**: three old commit messages still discuss competitors by
  name. Removing them needs a force push, which was blocked as a destructive
  action and needs an explicit decision.

Never exercised against the live Anthropic API: the `--llm` request shape
is verified against `anthropic` 1.6.0 through a stub server only.

An unpublished tool attached to an empty profile earns nothing, so these are
worth more than the next rule.

---

## What this is for

This is a **credential**. It exists to make its author demonstrably competent
at MCP and agent security — the market for that is contract work building MCP
servers ($50–150/hr, $3–8k for a simple server). It is not trying to win a
product category. Judge changes against "does this make the repo more
convincing and more correct", not "does this add a feature".

## Standing rules for changes

**Zero runtime dependencies.** The JSONC parser, frontmatter parser and MCP
client are all hand-written. A supply-chain scanner that drags in a
dependency tree asks you to trust what it audits. The `anthropic` SDK is an
optional extra, lazily imported, for `--llm` only.

**False positives are the expensive failure.** A scanner that fires on
correct configuration gets uninstalled, and then it catches nothing. The most
load-bearing test is a clean fixture that must produce exactly zero findings.
Prefer low recall and high precision — that tradeoff has been made explicitly
more than once and should keep being made.

**Secrets never reach the report.** `Finding.__post_init__` scrubs every
evidence and snippet string. It is a chokepoint rather than a convention so a
new rule cannot reintroduce a leak.

**Docs are generated from code.** Add a rule, add a `RuleDoc`, regenerate
with `mcp-audit rules --markdown -o docs/rules.md`. Tests fail if a rule is
undocumented or the checked-in file is stale.

**Tests pin decisions, not just behaviour.** Where a test looks oddly
specific it is usually recording a bug that shipped. Read the docstring
before changing one.

**Do not add a "Prior art" section to the README.** It was there, it went
stale between commits because the field moves faster than this repo, and the
owner removed it deliberately. Revisit only if asked.

## How the owner works

- **Ignore suggested timelines.** Phased plans read as padding; build the
  whole thing in the session.
- **Do not spend their money.** API integrations are verified by pointing the
  real SDK at a local stub server (`tests/test_wire_shape.py`).
- **Do not break their machine.** Third-party MCP servers are not installed
  or launched. Protocol robustness is covered by `hostile_server.py`, which
  misbehaves deliberately but touches no files, network or subprocesses.

## Architecture

    clients.py      declarative registry of 17 MCP clients and their config paths
    discovery.py    finds config files; tolerant JSONC parser
    parsers.py      config + SKILL.md -> normalized specs
    model.py        ServerSpec / ToolSpec / PromptSpec / ResourceSpec + fingerprints
    probe.py        MCP client. Dual-era: server/discover (2026-07-28) and the
                    legacy initialize handshake
    lockfile.py     .mcp-audit.lock — what you approved
    guard.py        stdio proxy that enforces the lockfile at runtime
    lifetime.py     ties the wrapped server's lifetime to the guard's
    server.py       mcp-audit *as* an MCP server (`serve`)
    inspect.py      what is configured, with no judgements
    llm.py          optional semantic classifier (extra: mcp-audit[llm])
    rules/          26 rules, MCPA001–MCPA026
    rule_docs.py    long-form docs; docs/rules.md is generated from this

Commands: `scan`, `inspect`, `approve`, `explain`, `rules`, `guard`, `serve`.

## Lessons that cost something

- **Verify competitors by reading their source.** Two wrong claims were made
  from search summaries — once saying the drift wedge was gone, once saying
  it was intact. Clone the repo.
- **Validate against real data, not your own fixtures.** Rules tuned on
  hand-written fixtures fired on 27% of 56 real tools, essentially all false
  positives: "charges" in billing prose, "runs" in a verification tool, and a
  docs search tool whose description says *nothing runs on the user's
  computer*. The corpora live in the eval workflow, not the repo.
- **Enumerate from the schema.** Two gaps were found by extracting every
  text-bearing interface and every RPC method from the spec and diffing
  against coverage — including `content` vs `contents`, one letter apart and
  different types, which left `resources/read` unscreened.
- **A structural match must not be vetoed by a fuzzy one.** Matching
  placeholder words anywhere made the scanner miss a real AWS key, because
  AWS's own example key contains "EXAMPLE".
- **TLS verification failures are often local.** Seven of fifteen real
  endpoints reported expired certificates; every chain was in date and the
  local CA bundle was stale. Do not blame the server.
- **Check that a new test fails without the fix.** Two tests written for the
  walk's symlink handling passed with the fix removed, twice over: `os.walk`
  never follows symlinks, and the findings dict is keyed on the resolved
  path, so a tree walked twice collapses to the same result. The defect was
  real — junctions *are* followed, `os.path.islink()` returns False for one —
  but the tests had to count directories entered, not configs found.
- **Run the thing the way a stranger will.** Installing the wheel and running
  it from an unrelated directory found a walk that appears to hang, in the
  exact command the README opens with. Nothing in 275 passing tests could
  have caught it; they all ran from the source tree against fixtures.

## Environment traps on this machine

- **Bash heredocs mangle escapes, including quoted ones.** `\\` collapses to
  `\` and `\n` becomes a real newline, which has broken source files
  repeatedly. `<<'EOF'` does *not* save you: a `\\` written inside a
  single-quoted heredoc still arrived as one `\`, and because it sat at the
  end of a line, Python then read `\` + newline as a line continuation and
  silently joined the two lines. The string matched nothing and the patch
  failed. Use the Write tool for anything containing a backslash.
- **Windows path length.** The project lives at a short path deliberately;
  deep nesting under Temp hits the 248-character directory limit.
- **CRLF.** `.gitattributes` normalizes to LF; the warnings on commit are
  expected.
- `wmic` is very slow to start and has hung a command for minutes.
- Unauthenticated GitHub API polling gets rate-limited quickly.
- `.venv/` is gitignored and holds the `anthropic` extra so the wire-shape
  tests can run. `python -m unittest discover -s tests` works without it;
  11 tests skip.

## The competitive position, for reference

Bigger tools exist: Tencent's AI-Infra-Guard (6.4k stars), Snyk's agent-scan
(3.1k, analysis runs server-side at api.snyk.io), Cisco's mcp-scanner, Trail
of Bits' mcp-context-protector (runtime pinning, blocks at the call site).
Verified by cloning and reading them, not from their READMEs.

What actually differs here: analysis runs entirely locally, there are no
runtime dependencies, findings map to MITRE ATLAS (none of the others do),
and the approval lockfile is a **committed artifact**, so one file governs
code review, CI and runtime enforcement.
