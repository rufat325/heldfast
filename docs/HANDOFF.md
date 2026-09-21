# Handoff

For whoever continues this — including Claude Code.

`CLAUDE.md` is gitignored on purpose (local notes, not the public record).
Read this file and `docs/GUARANTEES.md` instead.

## Where it is

- Feature freeze. No new clients. A new lockfile theorem is allowed when
  it has a test that would fail if the implementation were deleted.
  PyPI is live; a new version is a tag.
- GitHub repo, command, wheel and lockfile are `mcp-pin`. Rule ids stay
  `MCPA*`: a detection namespace is not a product name.
- An existing `.mcp-audit.lock` is still loaded if `.mcp-pin.lock` is
  absent, so renaming the file is not a silent loss of enforcement.
- Last public commit on `main` before this freeze work:
  `d54123c Stop a name in a config from rewriting the report about it`
- `pkgcache.py` is on the launch path and is in the `mypy --strict` job for
  that reason. It opens no socket; if it ever needs to, that is a design
  change, not an implementation detail.

## Conventions (do not "modernize")

- Python 3.9+, stdlib only at runtime. The wheel job fails if a dependency
  appears.
- Tests are `unittest`, nothing to pip-install. Fixtures are generated:
  `python tests/fixtures/make_fixtures.py`
- Commit subject describes the harm avoided, present tense, no ticket IDs.
  Look at `git log --oneline` and match that voice.
- Do not add Typer, Rich, Pydantic, Hypothesis, or a second lockfile format.
- Do not rewrite `guard.py` / `cli.py` in the same change as a kernel fix.

## What landed in the freeze

- `docs/GUARANTEES.md` — theorems / best-effort / out of scope
- `Policy.check` refuses unknown constraint keys (fail-closed)
- `tests/test_kernel_properties.py` — purity, determinism, fingerprint, JSONC
- `tests/test_golden_findings.py` — pinned rule IDs on the known-bad tree
- `tests/test_guarantees.py` — this document and the guarantees file stay coupled
- `tests/mutants.py` + `tests/test_mutation.py` — catalogued fail-open edits must die
- `tests/golden/traces/` — pinned JSON-RPC conversations for guard and gateway
- `cli_parser.py` — argparse off `cli.py`; `guard.run` split into small pumps
- `mypy --strict` on the four kernels, CI job `types`

## Next, in order

1. ~~Mutation-score the kernels.~~ Done: 16 fail-open mutants, score 1.0.
2. ~~Golden JSON-RPC traces.~~ Done: `tests/golden/traces/`.
3. ~~Split `cli.py` and `guard.py`.~~ Done. Functions in those two files
   must fit on one page (`tests/test_function_size.py`).
4. ~~`mypy --strict` on `policy.py`, `lockfile.py`, `model.py`, `findings.py`.~~
   Done, CI job `types`. Not a runtime dependency.
5. ~~A name that can win search.~~ Done: repo, command, wheel and lockfile
   are `mcp-pin`. Rule ids stay `MCPA*`. Then: PyPI, more clients.
6. ~~Guard fails closed on kernel exceptions.~~ Done: `--fail-open` is the
   opt-out. A withheld catalogue cannot still be called.
7. ~~Mutants for lockfile load and the guard pump.~~ Done.
8. ~~Golden traces for sampling / elicitation / roots / a screened result.~~
   Done.
9. ~~README first screen is the pin.~~ Done. GIF is a live filesystem
   wrap plus the rug pull. Long form is `docs/MANUAL.md`.
   [PyPI `mcp-pin` 0.1.0](https://pypi.org/project/mcp-pin/).
10. ~~JSON-RPC batches skip the pump.~~ Done: `_screen_outbound` / `_client_to_server`.
11. ~~`.mcp-pin-ignore` could hide MCPA015.~~ Done: `PINNED` lockfile theorems.
12. ~~`NODE_OPTIONS` / `PYTHONPATH` inherited.~~ Done: declare them or they stay out.
13. ~~Gateway mux by bare name.~~ Done: second `github` is refused, not overwritten.
14. ~~`--probe` children unbound.~~ Done: `posix_preexec` + `bind_child`.
15. ~~Unpinned tree greens CI.~~ Done: MCPA014 HIGH without a lock.
16. ~~Gateway `list_changed` not re-fingerprinted.~~ Done: next list/call re-fetches.
17. ~~Probe gate launches on a rule exception.~~ Done: launches nothing.
18. ~~Drift first-match on bare name.~~ Done: `_entry_for` refuses to guess.
19. ~~Public-repo hygiene.~~ Done: noreply authors, SHA-pinned actions,
    `SECURITY.md`. [PyPI `mcp-pin` 0.1.0](https://pypi.org/project/mcp-pin/).
20. ~~Scan looked for the lock in cwd, not the tree.~~ Done: a lock beside
    the scanned directory is the lock; the Action job on the clean fixture
    no longer files MCPA014 because the runner's cwd is the repo root.
21. ~~Self-scan uploaded the attack corpus to GitHub code scanning.~~ Done:
    `--exclude tests`. The 33 Security-tab alerts were fixture findings.
22. ~~Guard did not enforce recorded script digests at spawn.~~ Done:
    T-ARTIFACT. Scan-time MCPA031 is no longer the only place the hash is
    checked.
23. ~~Guard did not bind the launch command at spawn.~~ Done: T-LAUNCH.
24. ~~Re-approval rubber-stamped drift.~~ Done: T-REVIEW. Word-level diff,
    `--yes` / `--yes-tool` to write.
25. ~~Prompts and resources pinned but not filtered at runtime.~~ Done:
    T-SURFACE.
26. ~~`--yes` rubber-stamped a critical-graded change.~~ Done: T-YES-CRITICAL.
27. ~~Registry pin was a version string.~~ Done: T-INTEGRITY / MCPA036.
28. ~~MCPA036 was a scanner finding wearing the vocabulary of a pin.~~ Done:
    T-CACHE / T-UNVERIFIED / T-SAFE-OFFLINE. An outside review made three
    points and all three held.
    - *Fail-open reporting.* "A failed fetch is not a finding" was right about
      severity and wrong about reporting. Anyone who could break the lookup
      bought silence, and an offline runner bought the same silence by
      accident. Now MCPA037, `status` and `coverage` separate "verified" from
      "could not verify", and `--require-integrity` makes unverifiable fail.
    - *Scan time is not launch time.* `npx -y pkg@1.2.3` resolves and fetches
      for itself at spawn, so registry metadata is adjacent to the bytes that
      run, not identical to them. `pkgcache.py` reads the artifact the package
      manager already holds -- npm's `_cacache` index, pip's `http-v2` body --
      and `guard` / `gateway` refuse to spawn on a mismatch. Offline by
      design: a registry lookup on the launch path is a DNS timeout between
      the user and their agent starting.
    - *Threat model.* npm will not let a name and version be reused and PyPI
      refuses filename reuse, so on the public registries the swap largely
      cannot happen. The rule's real scope -- private registries, mirrors and
      caching proxies, `--registry` overrides, intercepting proxies -- is now
      stated in the rule doc, so a knowledgeable reader does not dismiss it.
      The transitive limit is stated too: the top-level artifact is pinned and
      the dependency tree beneath it is not.
    - Also: `--safe` contacts no registry (it never did promise to, and it
      was), a scan's outbound lookups are disclosed, and `docs/MANUAL.md`
      stopped carrying a third hand-copied rule table. A test now fails if
      either document grows one again.

    Both cache layouts were derived from the real caches on the dev machine,
    not from documentation: all 777 npm tarball entries verified, all 777
    caught when the digest was tampered with, three pip wheels matched the
    sha256 PyPI publishes. 1,554 lookups took 1.2s, which is what makes the
    check affordable on the launch path -- the index shard is derived from
    the URL, so nothing is searched. Validated against live metadata for a real MCP server package
    too. The first version of `check` read the approved digest out of the dict
    *key* instead of its value and reported `absent` for all 777 -- which is
    why that validation exists and runs before the feature is believed.

29. ~~The npm half trusted the cache's index instead of hashing its bytes.~~
    Done: T-CACHE now reads `content-v2`. Second review round, and the point
    was one I should have written myself: the index entry is a *claim about*
    the content, and the cache is writable by the same user who owns the
    server's files, so an entry naming the approved SRI beside a different
    blob read as verified. npm fails that on read, so it was never silent
    execution -- but a verdict that can be wrong is not a pin. The blob path
    is derivable (`content-v2/<algo>/<hex[0:2]>/<hex[2:4]>/<hex[4:]>`, the
    base64 digest decoded), and hashing it costs 2.7ms. All 777 real entries
    verified down to their content.

    Two answers that were inferable and are now stated: `--require-integrity`
    changes the launch path, not just a severity, on `guard` and `gateway` as
    well as `scan` -- gating CI while developer machines launch unverified
    servers leaves the loop open at the end that matters -- and an empty cache
    is the commonest route to "could not verify", which is why it is a flag
    rather than the default.

    Still not claimed, and written down in three places: this proves the cache
    agrees with the approval at the moment of the check, not that the bytes
    finally executed are those bytes.

    Two documentation bugs in the same pass, both the same shape as the
    duplicated rule table. Five links in `MANUAL.md` were written as if from
    the repo root while the file lives in `docs/` -- and a test I had added
    asserted one of the broken paths, which is how a test holds a bug in
    place. `MANUAL.md` said 902 tests while `README.md` said 988, because the
    count was asserted in one file and typed into the other. Every relative
    link now resolves against the filesystem and every stated count is
    checked, in every document, with no file excluded from either test.

30. ~~A reviewer cloned it, ran the suite, and found three real things.~~ Done.
    Best source so far, again: reading the code beats reading the README, and
    running it beats both.
    - *The audit log claimed more than it did.* Truncating the tail and
      re-chaining the file both verified clean. Any prefix of a valid chain is
      a valid chain, so the fix cannot live inside the file -- there is a
      `.head` sidecar now, plus `--expect-head`/`--expect-count`, and
      `MCP_PIN_LOG_KEY` for HMAC. Direction is what makes truncation
      reportable without false alarms: the head is written after the entry it
      describes, so a crash leaves it behind the log and never ahead.
      T-LOG-WHOLE, T-LOG-KEYED.
    - *`--policy warn` did half of what the manual said.* It forwarded the
      drifted description and then refused the call, leaving the agent a tool
      it could see and never use. Now observe mode at both layers, and
      explicitly *not* extended to the argument policy. T-POLICY-CONSISTENT.
    - *MCPA010 missed an injection that was still English.* A Cyrillic o in
      "Ignore all previous instructions" defeated every pattern. Text is now
      folded to an ASCII skeleton before matching, and MCPA038 reports the
      substitution. The precision argument is a property, not a measurement:
      the fold is the identity on ASCII, so it cannot change any ASCII
      corpus. MCPA038 also covers the one case MCPA027 structurally cannot --
      a tool *name* that looks like an approved one collides with nothing.
    - Two acknowledged limits are now named in the best-effort bucket instead
      of being left to be discovered: the phrases are English, and encoded
      payloads are not decoded.

    Writing the hosted-MCP position down found a bug of its own. The README
    claimed `coverage` states the limitation per server; it did not, and worse,
    it told a remote server's operator to run `guard` or `gateway`, both of
    which are stdio only. A remedy that cannot be carried out reads as "you
    forgot something" when the answer is "this tool does not do that yet".
    Check a claim before writing it down, then make it true rather than
    softening it.

    Still not done and worth saying out loud: `guard` and `gateway` are stdio
    only, and hosted MCP is where the ecosystem is going. The gateway already
    decides per call for a fleet; it needs an HTTP/SSE backend transport beside
    the stdio one. That is the next real feature, not a second tool.

    Account-side, and untouched here because it needs a signed-in human: the
    GitHub repo has no description and no topics, there is no releases page,
    and there is no writeup of the Invariant Labs attack reproduced end to end.
    See NOTES.local.md.

31. ~~The three open problems: hosted MCP, attribution, transitive pinning.~~
    Done, with one of them only partly closable and said so.

    **Hosted MCP is enforced.** `gateway` has an `HttpBackend` speaking
    Streamable HTTP; `guard` still cannot wrap a `url` and never will, because
    there is no child. The refactor that mattered was making `start()` final
    and each transport implement `_start()`: the pre-spawn pin gate lives once
    and a future transport cannot forget it. The mutant catalogue caught the
    first version, where the gate was copied -- the snippet occurred twice, so
    no single edit could be attributed, which is the catalogue doing exactly
    its job. T-HOSTED, T-HOSTED-TLS.

    Building it found a bug in code that predates it: `probe_http` discarded
    the `Mcp-Session-Id` from the initialize response, so `scan --probe` worked
    against hosted servers that do not enforce sessions and failed on every
    server that does. That is very likely part of why only 4 of 15 real
    endpoints were ever reachable. The stub in `tests/fixtures/http_server.py`
    enforces the rule a real server does, which is why it surfaced at all.

    **Attribution is delegated, not invented.** The blocker was never the
    algorithm -- there is no asymmetric signing in the standard library -- it
    was "a key needs somewhere to live". It should not live in this process at
    all. `--sign-command` hands a short payload to whatever already holds keys
    (`ssh-keygen -Y sign -U` keeps the private key in the agent) and records
    what comes back, inside the hashed body so it cannot be swapped. There is
    deliberately no `--signing-key`. T-LOG-SEALED.

    What that buys, precisely: a signed prefix cannot be rewritten afterwards,
    which is the gap an unkeyed chain cannot close at all. What it does not
    buy: protection from a live same-user attacker, who can ask the same agent
    to sign a story of their own. Nothing on the same host closes that, and the
    out-of-scope list now says so rather than implying signing solved it.

    **Transitive pinning is not possible from here, so it is measured
    instead.** Resolving the tree needs the package manager and the network and
    the answer differs tomorrow. What is answerable offline, from the cached
    artifact's own manifest, is how much of it floats -- `coverage` reports
    that beside the pin. It is deliberately not a rule: measured across 60 real
    cached packages, 115 dependency specs float against 17 exact, so a finding
    would fire on seven specs in eight, everywhere, forever. MCPA003 taught
    that at 69%.

    Also corrected in the same pass: the `coverage` row for a hosted server
    said "no fix available today", which was true when it was written that
    morning and false by the afternoon. A remedy line is a claim like any
    other.

32. ~~The same reviewer re-ran every attack and found one new bug plus two
    stale claims.~~ Done. All three were confirmed by reproducing them before
    anything changed.
    - *A `SyntaxWarning` shipped.* `split_command`'s docstring carried
      `C:\Python\python.exe` in a non-raw string -- a heredoc had eaten one
      backslash, which is the trap this file already warns about, hit again.
      Cached bytecode hides it, so the only people who would ever have seen it
      are the ones installing for the first time, and it becomes a hard
      `SyntaxError` in Python 3.15. Fixed with `r"""`, and closed as a class:
      `compileall` under `-W error::SyntaxWarning`, both as a CI step and as a
      test, because the matrix ran three Pythons and turned no warning into a
      failure. T-COMPILES-CLEAN.
    - *The out-of-scope list contradicted T-HOSTED.* It still read "Proxying
      remote HTTP/SSE MCP (scan only; `guard` is stdio)" a day after the gateway
      learned HTTP. That list is headed "Do not claim these. Do not imply them
      in output", which makes a stale line there worse than elsewhere. This is
      the "a remedy line is a claim with a shelf life" lesson from the section
      below, written the same day and then not applied to this file -- the
      coverage surface was grepped and this one was not.
    - *`verify` was silent when the sidecar was absent.* Deleting the `.head`
      file is cheaper than forging it, and the result read exactly like a
      complete log. The summary now says when completeness could not be checked
      at all, which is the treatment `keyed`/`unkeyed` already gets in the same
      sentence. `--help` also claimed the head check always happens; it says
      "if it can" now. T-LOG-COMPLETE.

    Worth recording that the reviewer verified the previous round by re-running
    the attacks rather than reading the diff, and that is how the stale
    out-of-scope line was found -- a passing suite cannot catch a sentence that
    contradicts a theorem two sections above it.

33. ~~Surfaces other people occupy.~~ Done, without growing MCPA rules.
    The file you commit is the same check that runs in CI and on the wire.
    - README leads with wrap, names the collision with GautamTalksDev/mcp-pin
      in one sentence (`npx mcp-pin` is theirs).
    - `wrap` is `guard`. `mcp-pin -- <server>` is wrap. `doctor` is scan.
      `ci` refuses `--probe` and keeps `--fail-on high`. `check` verifies
      the lockfile and launches nothing.
    - `js/mcp-pin-check` is a zero-dep verifier of `.mcp-pin.lock` (T-DIGEST).
      `js/mcp-pin-wrap` is `npx @rufat325/mcp-pin`, which execs the Python
      wheel and does not download one.
    - Claude Code plugin: SessionStart audit, PreToolUse deny on miss/drift.
      No hash rewrite, no pin file in `~/.claude`, no Sonnet judge.
    - Lock spec + twelve golden tool objects. Pre-commit hooks. Badge.
      Comparison page. Client table frozen 2026-09-21.
    - Three result-screen theorems (RS-ANSI / RS-SECRET / RS-EXFIL-HOST)
      withhold even under annotate (T-RESULT-BLOCK).
    - `release.yml` attaches SHA256SUMS to the GitHub release. The v0.1.3
      tag predated that job.

34. ~~Same-named servers from two clients shared one probe observation.~~
    Done. Probe stored tools, instructions and probe status under `s.name`,
    and `Lock.record` looked them up the same way while writing entries under
    `s.identity()`. `cursor:github` and `claude-code:github` therefore merged
    before they were pinned -- a poisoned definition from one namesake could
    become the other's baseline. T-DRIFT-ID already refused to *compare*
    against the first match; it did not cover `approve --probe`. Probe now
    keys by identity. `record` accepts a bare name only when it is unique
    among the servers being written. T-PROBE-ID.

35. ~~Subject IDs leaked back to the bare name after the pin was written.~~
    Done. Findings, the probe gate and the status page still keyed on
    `s.name`, so a HIGH finding on `cursor:github` could skip (or decorate)
    `claude-code:github` too. They now use `identity()`, with the same
    unique-name fallback as `record`. The types job on #3 was red because
    `observed_for` had no return annotation; that is typed.

    The architecture note that followed -- ATR rules, Aguara analyzers,
    mcpsnoop observe, Node9 shields, agent-bom evidence graphs, SkillHawk
    benchmarks, offsec-ai active testing -- is not a backlog. The lock is
    the product. Those projects already occupy those surfaces. Gluing them
    on is seven tools. Composition toxic-flow (MCPA028), argument policy,
    `--safe` vs `--probe`, the audit log and the mutation catalog already
    cover the pieces of that note that belong here.

## Lessons that cost something

Kept in the tracked file rather than in local notes, because every one of them
was paid for by a red build or a wrong claim and the next person should not buy
them again. The oldest ones live in the numbered list above; these came out of
the stretch that closed items 29 to 31, where three of the defects were
self-inflicted and two turned CI red.

- **CI has to be diagnosable without a login.** Reading a job's log needs a
  signed-in session with rights on the repository. Annotations do not -- they
  are in the public API. When macOS went red and Linux and Windows stayed
  green, two rounds were spent guessing before the test step was taught to emit
  each failing test name as an annotation, and it named the cause on its first
  run. This file already recorded that logs need a session; nobody had drawn
  the conclusion from it.

- **Verify portability by relocating the tree, not by running it in place.**
  Two mutant probes shipped with a developer's home directory baked into them:
  the local suite was green and all nine CI test jobs were red. `git archive`
  into a temporary directory and run the suite from there -- that is what a
  runner does, and running in the source tree cannot see the difference. A
  green local suite is a claim about one machine; say which machine when
  reporting it.

- **An exemption list must not contain the name from the bug it was written
  for.** The test written to catch that hardcoded path exempted the account
  `administrator`, and the path that shipped was under `Administrator`. `root`
  was in there too, and is equally real. The self-test now asserts that the
  exact account from the shipped bug is still caught, so the list cannot
  quietly grow back over it.

- **A test that has to exempt its own file has a hole shaped like itself.** The
  first version of that same guard flagged its own docstring, and the first fix
  was an exemption for its own path. The shapes are described in prose now and
  assembled from pieces inside the assertions, so the file stays clean under
  its own rule.

- **A mutant probe is in-process logic, not a program.** One probe stood up an
  HTTP server to observe a fail-open. It was the only one of 51 doing any I/O,
  and it exceeded the harness's 20-second budget on the slowest runners and
  nowhere else. It never needed the server: `Gateway.__init__` chooses a
  transport and starts nothing, so the hole was observable by asking which
  class it picked. Every probe now finishes in under two seconds, measured.

- **A harness that hides its own failure mode costs more than the bug in it.**
  That timeout escaped as a bare `TimeoutExpired`, so the subtest errored
  without naming the probe or the fact that time was the problem. An empty
  stdout raised `IndexError` from `splitlines()[-1]`; a non-JSON last line
  raised `JSONDecodeError`. This is the "a report that guesses a cause" lesson
  pointed at the test infrastructure, and it is worth the same care: the
  timeout message now names the assumption that was violated.

- **The duplication a mutant catches is real duplication.** Copying the
  pre-spawn pin gate into the second transport made the mutant's snippet occur
  twice, so no single edit could be attributed to it and the catalogue check
  failed. The fix was not a more specific mutant; it was removing the
  duplication. `start()` is final and each transport implements `_start()`, so
  a future transport cannot forget the gate -- which is the same failure the
  gateway already had once, when it was missing three screens the guard had.

- **A remedy line is a claim with a shelf life, and so is an out-of-scope
  line.** `coverage` told a hosted server's operator there was "no fix
  available today". That was true when it was written and false a few hours
  later, when the gateway learned HTTP. The lesson was written down that same
  day -- and `docs/GUARANTEES.md` still said "Proxying remote HTTP/SSE MCP
  (scan only)" until a reviewer found it, because only the coverage surface got
  grepped. Whenever a capability lands, grep *every* place that said it was
  impossible: the remedy strings, the out-of-scope list, the README and the
  manual. A list headed "do not imply these in output" is the worst one to
  leave stale.

- **Implementing a protocol a second time audits the first.** Giving the
  gateway an HTTP transport found that `probe_http` had been taking the
  `Mcp-Session-Id` from the initialize response and discarding it for as long
  as it had existed -- so `scan --probe` worked against hosted servers that do
  not enforce sessions and failed on every server that does, reporting it as
  the endpoint's fault. That is very likely part of why only 4 of 15 real
  endpoints were ever reachable. The stub that found it enforces the rule a
  real server does.

- **Name the limit rather than the feature.** Two of the three roadmap items
  closed here cannot be closed completely: signing does not stop a live
  same-user attacker who can reach the same agent, and a dependency tree cannot
  be pinned from here at all. Both are shipped with the boundary written into
  the module, the manual and the out-of-scope list. A capability described
  without its edge is a capability someone will lean on where it does not hold.

## How to run

```bash
python tests/fixtures/make_fixtures.py
python -m unittest discover -s tests -v
```

A theorem that cannot be falsified by deleting its implementation is not a
theorem. Do not add marketing sentences to the README during the freeze.
