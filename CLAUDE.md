# Working on mcp-audit

Context for anyone (or any session) picking this up cold. The code explains
what it does; this explains what is not in the code — where the work stopped,
which decisions were made and why, and the ones that were wrong first.

A security scanner for MCP server configurations and agent skills, plus a
runtime proxy that enforces what you approved. Zero runtime dependencies,
stdlib only, Python 3.9+. Public at https://github.com/rufat325/mcp-audit.

---

## Where this stopped

**Nothing is half-finished.** Working tree clean, the last commit is a
complete unit. 43 commits, 382 tests, 30 rules, CI across Linux/macOS/Windows
on Python 3.9/3.12/3.13 plus a wire-shape job, a job that exercises
`action.yml` itself, and a release workflow that publishes on a version tag.

**CI is green, and that was checked rather than assumed.** It had been red on
all three Windows jobs from `6b7fbe1` through `903f6a2` while this file
claimed otherwise. Confirm it against the API before repeating it:
`https://api.github.com/repos/rufat325/mcp-audit/actions/runs?per_page=1`.
Reading job *logs* needs a signed-in session; the run and job status do not.

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

12. `9a6115a` — CI had been red on Windows since cycle 9 and nobody looked.
    The orphan test shelled out to `wmic`, which current Windows runner
    images no longer ship, so it raised FileNotFoundError; it passed locally
    only because this machine is old enough to still have wmic. The fixture
    now reports its own pid and liveness is an OpenProcess check. Whole suite
    went from 28 seconds to 15.
13. `cdf6fb2` — `serve` answered only the legacy handshake while `probe`
    spoke both eras, so mcp-audit's own server was two revisions behind the
    thing that checks for exactly that. It now answers `server/discover`, and
    the end-to-end test asserts which era the two halves settle on.

14. `15b62db`, `ef498f6` — corrected the CI claim in this file, added the
    badge, and made the README's test count a thing a test checks. It said
    275 while the suite had 286.

15. `4115c8b` — read the source of fourteen other MCP and AI security tools.
    Added MCPA027 (tool shadowing), MCPA028 (exfiltration reach across a pair
    of servers) and MCPA029 (a command allowlist naming binaries that run
    anything). The theme is findings that exist only in the *combination* of
    servers, which per-server scanners cannot see and this one is unusually
    placed to compute.

16. `a648135` — MCPA030 and `sourcescan.py`: read the server's own Python
    and find a tool parameter reaching a shell. AST taint, not regex, because
    the argv form and `shlex.quote` are the *fixes* and a scanner that reports
    the fix gets ignored. Follows one hop into a local helper, because every
    real server uses the dispatcher shape and stopping at the handler finds
    only tutorials. Validated on 41 handlers across 14 repos before shipping.

17. `d6284f1` — `auditlog.py`: the guard can now leave a hash-chained record
    (`guard --log`, `verify-log`). Idea from mcp-firewall, minus the Ed25519
    signing, because a key needs somewhere to live. Arguments are never
    written -- that is the design, not an omission. Also fixed a hardcoded
    command list in `main()` that silently parsed `verify-log` as a path.

18. `482073a` — an outside review read the code and found two real holes in
    the guard, both confirmed before changing anything. An unknown server was
    forwarded untouched (now withheld; `--allow-unapproved` restores it), and
    the lock entry was resolved by bare name while entries are keyed
    `client:name`, so two clients with a server called `github` got each
    other's approvals. **A reviewer who reads the code is the best source
    tried so far** — better than the spec, better than competitors.

19. `56c1f4a` — `policy.py`: argument-level limits in the lockfile (paths,
    domains, sql, deny), enforced by the guard before a call reaches the
    server, plus `--dry-run`. The lockfile answered "is this the tool I
    approved"; this answers "may it be asked to do *that*". Most of the tests
    are evasions -- traversal, `/workspace-evil`, `api.github.com.evil.io`,
    stacked SQL, a path hidden in a nested argument.

20. `8578c12` — `mcp-audit policy --probe` proposes a starter policy from
    observed tool schemas, because one nobody writes protects nothing. Every
    generated value is a placeholder that *refuses* until edited: a generated
    policy that quietly permitted the home directory would read like a
    boundary and be a rubber stamp.

### If the loop resumes, change source

**The spec is near exhausted.** The remaining unscreened methods
(`completion/complete`, `notifications/message`, `subscriptions/listen`)
carry little model-facing text. Better sources now:

- **other tools' source, read properly.** Cycle 15 cloned fourteen of them and
  the pattern that worked was: take the *idea*, reject the *implementation*.
  Their best ideas were real (cross-server attack paths, tool shadowing,
  allowlist bypass) and their detection was description-substring matching,
  which this project already proved fires on everything. Do not read their
  READMEs and stop there — the READMEs claim precision the code does not have.
  Clones are in a scratch dir, not the repo.
- more real-world corpora — only 4 of 15 endpoints were reachable, and the
  harvested config corpus was 98 blocks from 250 repos out of 4,129 available.
  Grepping the cloned repos for real env-var names was cheap and caught a
  false positive before it shipped; do that for any new config-shape rule.
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
- **GitHub repo metadata** is empty: no description, no topics, no homepage,
  no release. Confirmed via the API. Two minutes of work on the repo settings
  page, and it is the first thing anyone sees.
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
    auditlog.py     hash-chained record of a guarded session
    policy.py       argument limits for an approved tool; deterministic
    sourcescan.py   AST taint: tool parameter -> shell, in the server's own code
    lifetime.py     ties the wrapped server's lifetime to the guard's
    server.py       mcp-audit *as* an MCP server (`serve`)
    inspect.py      what is configured, with no judgements
    llm.py          optional semantic classifier (extra: mcp-audit[llm])
    rules/          30 rules, MCPA001–MCPA030
    rule_docs.py    long-form docs; docs/rules.md is generated from this

Commands: `scan`, `inspect`, `approve`, `explain`, `rules`, `guard`,
`policy`, `verify-log`, `serve`.

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
- **A green local suite is not a green CI.** Windows CI was red for six
  commits while this file said otherwise, because a test called a utility
  this machine still has and the runners no longer do. Local success says the
  code works *here*.
- **Competitors are a source of ideas, not of methods** — but be exact about
  which part is weak. Fourteen were read in one cycle. MCPhound's cross-server
  attack graph is the best idea in the field and its capability inference is
  bare substrings (`"run"`, `"api"`, `"read"`) over tool descriptions, which
  this project measured at 27% false positives on live tools. mcprobe is not
  guilty of that: its injection patterns are phrase regexes much like MCPA010,
  and its shadow check is real — it just needs baseline files you collected by
  hand and has no idea which client configures which server, so it cannot tell
  a genuine collision from two servers that never meet. Take the idea, check
  the implementation, and say precisely what was wrong with it.
- **Ask someone to read the code, not the README.** One outside review found
  two genuine security-model holes in `guard` that eighteen cycles of
  self-directed work had walked past, because both were *defaults* rather than
  bugs and everything passed. Defaults are invisible from the inside.
- **A scanner that reports the remediation is worse than none.** The whole
  value of parsing over grepping in `sourcescan.py` is that
  `subprocess.run([...])` and `shlex.quote(x)` stay silent. Both are what the
  finding tells you to do. Check any new rule against its own remediation.
- **The two halves of the repo can drift apart.** `probe.py` was taught the
  current protocol revision; `server.py` was not, and nothing compared them
  for four cycles. When one side of a client/server pair learns something,
  check the other.

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
