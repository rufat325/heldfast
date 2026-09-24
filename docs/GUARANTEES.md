# Guarantees

What this tool will still be true about after an upgrade, and what it will
not. A sentence that cannot live in one of the three buckets below does not
belong in the README.

Feature freeze is in force until every **theorem** has a test that would fail
if the implementation were deleted. Heuristics may change. Theorems may not.

## Theorems

If one of these fails, it is a bug. CI must be able to falsify it.

| ID | Claim | Held by |
|---|---|---|
| T-PATH-NORM | Path policy matches the resolved path, never the string it was handed. `/workspace/../../etc/passwd` is outside `/workspace/**`. | `tests/test_policy.py` |
| T-PATH-PREFIX | `/workspace-evil` is not inside `/workspace`. | `tests/test_policy.py` |
| T-PATH-PERCENT | Percent-encoded traversal is decoded a bounded number of times before matching. | `tests/test_policy_evasions.py` |
| T-PATH-NEST | Every string anywhere in the arguments is checked, including nested objects. | `tests/test_policy.py` |
| T-DENY | A truthy `deny` on a tool refuses the call with no regard to arguments. | `tests/test_policy.py` |
| T-SQL-STACK | Two SQL statements in one argument are refused even when the first is permitted, under both readings of a backslash inside a string literal. MySQL escapes it and PostgreSQL does not, so a `\'` that desynchronises one reading is caught by the other. | `tests/test_policy.py`, `tests/test_policy_evasions.py` |
| T-SQL-GATE | A value under a parameter the schema names `sql`, `query`, `statement` or `expression` goes through the operation check whatever its text looks like. A statement this cannot parse is refused, never skipped. | `tests/test_policy_evasions.py` |
| T-SQL-MASK | MySQL executable comments are unmasked before the verb is read. | `tests/test_policy_evasions.py` |
| T-HOST-SUFFIX | `api.github.com.evil.io` is not `api.github.com`. | `tests/test_policy.py` |
| T-HOST-SLASH | A backslash in the authority is not an approved destination. | `tests/test_policy_evasions.py` |
| T-POLICY-UNKNOWN | A constraint key this tool does not understand refuses the call. | `tests/test_kernel_properties.py` |
| T-POLICY-PURE | `Policy.check` does not open files, spawn processes, or read the environment. | `tests/test_kernel_properties.py` |
| T-POLICY-DET | The same tool, arguments and rules produce the same `Decision`. | `tests/test_kernel_properties.py` |
| T-FINGERPRINT | A change to name, title, description, input schema or annotations changes the tool digest. Byte-identical tools hash the same regardless of dict key order. | `tests/test_kernel_properties.py` |
| T-LOCK-FUTURE | A lockfile with a version newer than this tool understands is refused, not silently truncated. | `tests/test_mcp_pin.py` |
| T-JSONC | JSONC comments and trailing commas are stripped without eating `//` inside strings. Invalid JSON raises; it does not become `{}`. | `tests/test_mcp_pin.py`, `tests/test_kernel_properties.py` |
| T-DRIFT | An approved tool whose live description changes fires MCPA015. | `tests/test_mcp_pin.py` |
| T-ATTACK | Every registered rule except the documented exemptions has an attack that demonstrates it. Adding a rule without one fails the build. | `tests/test_attack_corpus.py` |
| T-GOLDEN | The known-bad fixture still produces the pinned set of rule IDs, and the clean fixture still produces nothing at all. A rule that goes quiet on the first is a bug; one that speaks up on the second is a false positive every user would see. | `tests/test_golden_findings.py`, `tests/test_mutation.py` |
| T-MUTATION | Every catalogued fail-open edit of policy, fingerprint or JSONC is observed as a hole. Survival fails CI. | `tests/test_mutation.py` |
| T-TRACE | Guard and gateway still emit the pinned JSON-RPC conversations (allow, deny, banner-before-frame, rewrite-after-N, sampling, elicitation, roots, result fence). | `tests/test_golden_traces.py` |
| T-FAIL-CLOSED | A kernel exception in `guard` refuses the call or withholds the result. A tool withheld from `tools/list` cannot still be executed, and neither can one the client never listed: `guard` requests the catalogue itself once the server has initialised, so the drift check does not depend on the client asking, and a server that withholds its catalogue gets no calls either. Forwarding either requires an explicit opt-in: `--fail-open` for the exception, and `--dry-run`, `--policy warn`, or -- for a changed tool whose change introduced no signal, and nothing else -- `--drift graded` for a refusal (T-DRIFT-GRADED). | `tests/test_guard.py`, `tests/test_mutation.py`, `tests/test_malformed_input.py` |
| T-BATCH | A JSON-RPC batch is inspected per frame. A `tools/list` stuffed into an array cannot skip `filter_tools`. | `tests/test_guard.py`, `tests/test_mutation.py` |
| T-PINNED | A `.mcp-pin-ignore` line cannot hide a lockfile theorem (MCPA014–017, 019, 020, 031, 036, 037). | `tests/test_mcp_pin.py`, `tests/test_mutation.py` |
| T-ISOLATE-LOADER | `NODE_OPTIONS`, `PYTHONPATH` and `PYTHONHOME` do not ride from the parent into a child unless the server declared them. All three decide what code the child loads. | `tests/test_childenv.py`, `tests/test_mutation.py` |
| T-OWN-ENV | This tool's own variables never reach a server it launches, under any setting and on every launch path. `MCP_PIN_LOG_KEY` is the one that matters: the wrapped server is exactly the adversary the audit chain's key is aimed at, so handing it over would give away the property keying exists for. `wrap` additionally offers `--isolate-env` for the operator's variables; that part is opt-in, this part is not. | `tests/test_childenv.py`, `tests/test_guard.py`, `tests/test_mutation.py` |
| T-SCOPE | Two servers declared under different project scopes in one config are both parsed, both scanned and both reported. If they collide on `client:name` the lock records the conflict instead of letting one approval stand for both, and a conflicted entry enforces nothing. | `tests/test_mcp_pin.py`, `tests/test_guard.py`, `tests/test_mutation.py` |
| T-MUX | Two servers with the same bare name from different clients are not silently overwritten; the second is refused. | `tests/test_gateway.py`, `tests/test_mutation.py` |
| T-PROBE-LIFE | `--probe` binds the child the same way `guard` does (`posix_preexec` / job object). | `tests/test_hostile.py`, `tests/test_mutation.py` |
| T-READ | A configuration file that was discovered and did not parse is reported, at HIGH, and cannot be suppressed. A scan that could not read a file does not say `clean` and its build gate does not pass. The report of it reaches SARIF like any other finding. | `tests/test_attack_corpus.py`, `tests/test_mutation.py` |
| T-UNPINNED | A scan of configured servers with no lockfile fires MCPA014 at HIGH, so default `--fail-on high` fails the build. | `tests/test_mcp_pin.py`, `tests/test_mutation.py` |
| T-LOCK-TREE | A lockfile sitting in the scanned directory is the lockfile, even when cwd is somewhere else. | `tests/test_mcp_pin.py` |
| T-ARTIFACT | If the lock recorded local-script digests, `guard` and `gateway` refuse to start the child when those bytes have moved. A registry package has no local file; T-INTEGRITY is the content pin.  An interpreter is not the server: `node`, `/usr/bin/node` and a venv's `python.exe` are not hashed whether the command spells out a path or not, so patching Python does not report every server it starts as changed. | `tests/test_artifacts.py`, `tests/test_guard.py`, `tests/test_portability.py`, `tests/test_mutation.py` |
| T-PORTABLE | An approved script is matched by content, not by the path it was recorded at, so a lockfile validates in a checkout other than the one that wrote it -- a colleague's clone, CI, a container -- and a lockfile written by an earlier version, keyed by absolute path, keeps validating with no migration. A digest present nowhere is still the drift this pin is for. | `tests/test_portability.py`, `tests/test_mutation.py` |
| T-DRIFT-SHOWN | The evidence for a changed description, prompt, resource or set of server instructions contains the change: the window follows the first divergence rather than the start of the text, so a payload appended past the recorded prefix is shown and not merely counted. Where the approved bytes were never recorded, the report says the recorded text ran out instead of printing the same prefix on both lines. Each finding also states how much of the server's catalogue moved and whether the description itself moved, so a version upgrade and a targeted edit can be told apart. Breadth is never treated as innocence: a change to every tool at once carries the same severity as a change to one, because rewriting the whole catalogue is available to an attacker too. | `tests/test_textdiff.py`, `tests/test_mutation.py` |
| T-DRIFT-GRADED | Without `--drift graded`, a tool whose definition changed is refused, as it always was; the heuristic is never the default. Under it -- or `MCP_PIN_DRIFT=graded` for the Claude Code hook, which asks `mcp-pin grade-drift` rather than keeping its own copy of the patterns, and denies when it cannot -- `guard` and `gateway` forward a changed tool only when the live definition -- description, title, and every description or title in its input and output schemas -- introduces no signal (an agent-directed instruction, a hidden character, a credential path, a look-alike letter, a critical word) that the approved preview did not carry. Text past what the lock recorded is compared against nothing, so a signal there refuses. A tool absent at approval is still refused, a schema too deep to read is not called clean, and a grading error refuses the tool even under `--fail-open`. The content rules still read every forwarded tool whole. What a rewrite phrased to miss every pattern can do is best-effort, below, not this. | `tests/test_drift_graded.py`, `tests/test_plugin.py`, `tests/test_mutation.py` |
| T-FEED-PIN | `approve --from-feed` records a server's tools only from a catalogue the feed holds for the exact npm version the config pins, read at a single feed commit that the lock entry names. An unpinned or floating version, a non-npm launch, or a version the feed has not measured records nothing for that server, and an earlier approval of it is carried forward. The catalogue is the tools as the server sent them, fingerprinted by the parser `--probe` uses; a body naming another package or version is refused. A feed that cannot be read writes no lock, and neither does a config that pins any npm release OSV reports as malware (`MAL-`), measured by the feed or not, or an advisory lookup that fails. It is refused alongside `--probe` and `--safe`. | `tests/test_feedlock.py`, `tests/test_feed.py` |
| T-UPDATES | `updates` grades a newer release with `approve`'s own review of the catalogue it would record: `quiet` is a change `approve --yes` writes, `review` one it refuses without `--yes-tool`. `--apply` bumps only quiet updates, only where `"pkg@version"` occurs exactly once in the config, and records from the feed only the servers it bumped, with that version's registry hash and never the previous one's. If the lock would change for any other server, the config files it edited are restored and no lock is written. A review update is never applied. Before grading, every newer release is screened: one OSV reports as malware, one no longer on npm, or one younger than `--min-age` days is never the release proposed or applied; one an advisory names, or that adds or changes a `preinstall`/`install`/`postinstall` script, is review whatever its tools say; and when OSV or npm cannot be asked, nothing is quiet. A pinned release OSV reports as malware makes the command exit 1. | `tests/test_updates.py` |
| T-TRANSPARENCY | `verify`, and `approve --probe` for a hosted server at a public address, compare each tool the server shows this client with the public log the feed keeps of what it shows an anonymous client, by the fingerprint `--probe` records -- not by name. A tool whose name the log knows and whose definition, as shown here, it has not recorded in the server's last ten readings is `differs`: `verify` exits 1, and approve writes no lock unless that tool is named with `--yes-tool`. A tool the log has never seen is reported and, without `--strict`, passes. A server that returned no tools is never reported as matching. A loopback, private, link-local or local-only address is never sent to the log. When the log cannot be read, approve proceeds and says it had no second witness. | `tests/test_transparency.py`, `tests/test_feed.py` |
| T-LOOKUP | The feed publishes every tool definition it has logged under the fingerprint the lockfile records, computed by the parser `--probe` uses, in buckets named by its first three hex characters, with the earliest date it was seen and the number of servers that showed it; rendering the same catalogues twice writes the same bytes. `verify` looks up each tool the lock records and requests only bucket URLs -- no request carries a fingerprint -- and a tool absent from its bucket is reported as never seen publicly, failing only under `--strict`. A measuring shard's upload that contains a lookup file is refused. | `tests/test_lookup.py` |
| T-LAUNCH | If the lock recorded a command line, `guard` and `gateway` refuse to start a different argv. | `tests/test_guard.py`, `tests/test_mutation.py` |
| T-REVIEW | Re-approval of a lock that moved prints the word-level diff and does not write unless `--yes` or `--yes-tool` names every drifted tool. A digest or command change still needs `--yes`. | `tests/test_review.py`, `tests/test_mutation.py` |
| T-SURFACE | If the lock recorded prompts or resources, `guard` filters `prompts/list` and `resources/list` and refuses `prompts/get` / `resources/read` the same way it does tools. A lock that never recorded that layer is not pretend-enforced. | `tests/test_guard.py`, `tests/test_mutation.py` |
| T-YES-CRITICAL | `approve --yes` does not overwrite a critical-graded drift. That change must be named with `--yes-tool`. A changed or added definition is critical when its recorded text holds a critical word or introduced any signal the approved preview did not carry -- the same test `--drift graded` applies, so a change the guard would refuse under grading is one `--yes` cannot write. | `tests/test_review.py`, `tests/test_drift_graded.py`, `tests/test_mutation.py` |
| T-INTEGRITY | If the lock recorded a registry tarball hash, a different live hash fires MCPA036. | `tests/test_integrity.py`, `tests/test_mutation.py` |
| T-CACHE | If the lock recorded a registry artifact hash, `guard` and `gateway` refuse to start the child when the local package cache holds different bytes for it. The cached content is hashed, not its index's claim about itself. Checked offline, before the spawn. A recorded hash is in the encoding the cache uses, so a package that did not move is not refused over a base64-versus-hex difference. | `tests/test_pkgcache.py`, `tests/test_guard.py`, `tests/test_gateway_parity.py`, `tests/test_integrity.py`, `tests/test_mutation.py` |
| T-UNVERIFIED | An artifact that could not be checked is reported as MCPA037 and never as verified. `--require-integrity` raises it to high and makes `guard` and `gateway` refuse to start. Under that flag the same is true of an artifact the lockfile records no hash for at all, which is less evidence again and so cannot be the quieter of the two; by default that one is a standing property of the lock rather than a finding, and `coverage` reports it. | `tests/test_pkgcache.py`, `tests/test_integrity.py`, `tests/test_golden_findings.py`, `tests/test_attack_corpus.py`, `tests/test_mutation.py` |
| T-SAFE-OFFLINE | `--safe` opens no socket. No registry is contacted by a scan or an approval under it, and what that costs is stated rather than silently skipped. | `tests/test_integrity.py`, `tests/test_mutation.py` |
| T-LIST-CHANGED | `notifications/tools/list_changed` marks the backend stale; the next `tools/list` or call re-fetches and re-screens. | `tests/test_gateway_parity.py`, `tests/test_mutation.py` |
| T-POLICY-CONSISTENT | `--policy warn` is observe mode at both layers: a drifted tool is advertised unchanged *and* its call is forwarded, logged as a would-deny. `block` and `strip` refuse the call. | `tests/test_guard.py`, `tests/test_mutation.py` |
| T-LOG-WHOLE | `verify-log` reports a truncated or rewritten chain, not just an internally consistent one. The head file the writer keeps is compared against the log, and `--expect-head` / `--expect-count` against a record kept elsewhere. | `tests/test_auditlog.py`, `tests/test_sessions.py`, `tests/test_mutation.py` |
| T-LOG-KEYED | With `MCP_PIN_LOG_KEY` set the chain is HMAC-SHA256, so an attacker who can write the log cannot recompute it. Unkeyed output says it is tamper-evidence and not proof. | `tests/test_auditlog.py`, `tests/test_mutation.py` |
| T-HOSTED | A server configured with a `url` is enforced by `gateway` exactly as a local one is: same catalogue filter, same call refusal, same result screen, same budget. `guard` still cannot wrap one, and the coverage row says so. | `tests/test_gateway_http.py`, `tests/test_coverage.py`, `tests/test_mutation.py` |
| T-HOSTED-TLS | `gateway` refuses to front a non-loopback server over cleartext `http://`, and re-applies that check to every redirect hop rather than only to the configured URL. | `tests/test_gateway_http.py`, `tests/test_fetch.py` |
| T-REDIRECT | A redirect to a different origin does not carry the request's credential headers, and a hop onto cleartext for a non-loopback host is refused outright. Following redirects is required by the transport -- including 307 and 308, which keep the method and body a POST-only transport depends on and which the stdlib refuses -- but handing `Authorization` to whatever a `Location:` names is not. 308 is dispatched by this handler rather than inherited: urllib only learned it in Python 3.11, so on 3.9 and 3.10 a 308 skipped both checks and surfaced as a bare error instead of a hop. | `tests/test_fetch.py`, `tests/test_mutation.py` |
| T-LOG-SEALED | A segment signed through `--sign-command` cannot be rewritten afterwards: dropping an entry and recomputing every hash leaves a signature that no longer verifies. A signer that fails costs the signature and never the record. | `tests/test_log_signing.py`, `tests/test_mutation.py` |
| T-LOG-COMPLETE | `verify` states whether completeness was checked at all. With no `.head` file and no `--expect-*`, an intact chain says a truncated tail would not have been visible rather than printing what a whole log prints. | `tests/test_auditlog.py`, `tests/test_mutation.py` |
| T-COMPILES-CLEAN | Every module under `src/` and `tests/` compiles with no `SyntaxWarning`. An invalid escape is a warning today and a `SyntaxError` from Python 3.15, and cached bytecode hides it from everyone but a first-time installer. | `tests/test_auditlog.py`, `.github/workflows/ci.yml` |
| T-PROBE-GATE | A rule exception in the static pre-pass launches nothing, and the pre-pass reads the lockfile -- so a server whose recorded script, launch command or tool definition has moved is not executed to find that out. `approve --probe` is deliberately exempt: re-recording a server that changed is what the command is for, and T-REVIEW covers it. | `tests/test_probe_boundary.py`, `tests/test_mutation.py` |
| T-DRIFT-ID | Two lock entries sharing a bare name are not compared against the first match, in the Claude Code hook as well as in `guard`. Both are call-site enforcement reading one file, so a state where one denies and the other allows is a hole wearing a second opinion. | `tests/test_mcp_pin.py`, `tests/test_plugin.py`, `tests/test_mutation.py` |
| T-PROBE-ID | Subject IDs are `client:name` from probe through findings, the probe gate, the status page and the lockfile. Two servers that share a bare name keep separate tools, instructions, findings and probe status; a definition or a finding from one namesake cannot become the other's. | `tests/test_mcp_pin.py`, `tests/test_status.py`, `tests/test_probe_boundary.py`, `tests/test_mutation.py` |
| T-TYPES | `policy.py`, `lockfile.py`, `model.py`, `findings.py`, `pkgcache.py`, `auditlog.py`, `confusables.py` and `digest.py` type-check under `mypy --strict`. | `.github/workflows/ci.yml` |
| T-SIZE | Functions in `cli.py` and `guard.py` fit on one page (60 lines). | `tests/test_function_size.py` |
| T-WHEEL | The published wheel has no runtime dependencies. | `.github/workflows/release.yml` |
| T-REDACT | Findings cannot carry a live credential or a control character that rewrites the report. | `tests/test_output_integrity.py` |
| T-DIGEST | The same tool object produces the same SHA-256 digest in Python, in the zero-dep JS checker and in the Claude Code plugin's own copy. Fourteen golden vectors are the contract, and they cover the wire spellings including an alias explicitly set to `null`. Empty `output_schema` / `icons` are omitted. | `tests/test_lock_spec.py`, `tests/test_digest_parity.py` |
| T-RESULT-BLOCK | `RS-ANSI`, `RS-SECRET` and `RS-EXFIL-HOST` withhold a tool result even under `--result-policy annotate`. A collection host is matched on label boundaries, not on the punctuation that happens to precede it. English-injection fencing stays best-effort. | `tests/test_result_theorems.py`, `tests/test_mutation.py` |
| T-DENY-REQUEST | `--deny-sampling`, `--deny-elicitation` and `--deny-roots` refuse the request in **both** forms it can arrive in: a legacy server-to-client JSON-RPC request, and an `inputRequests` entry on a modern (MRTR) result. A denied request is answered to the server and never reaches the client. | `tests/test_guard_requests.py`, `tests/test_mutation.py` |
| T-RESULT-WALK | The result screen reads every model-visible string in a result, whatever shape it arrives in -- an embedded resource, `structuredContent`, a `prompts/get` description, a `resource_link` description -- rather than a fixed list of known keys. A result nested past the walk's depth cap is withheld, not skipped. | `tests/test_guard_requests.py`, `tests/test_mutation.py` |
| T-APPROVED-SHAPE | A tool forwarded as approved carries only the fields the fingerprint covered. A key that was not hashed -- `_meta`, or anything else a server adds -- does not reach the client on the strength of a digest that never saw it. | `tests/test_guard_requests.py`, `tests/test_mutation.py` |
| T-STDOUT-JSON | `guard` writes nothing to stdout that it did not parse as JSON-RPC. A line it cannot parse goes to stderr, so the guarantee does not rest on the client's parser being as strict as Python's. | `tests/test_golden_traces.py` |
| T-ARG-DEPTH | Arguments nested past the policy's depth cap are refused, not waved through. "We stopped looking" is never the same answer as "there was nothing to find". | `tests/test_policy_evasions.py`, `tests/test_mutation.py` |
| T-ARG-NAMED | A parameter the schema names as a path or a destination is checked as one whatever its value looks like. `{"path": ".env"}` and `{"url": "evil.example/x"}` are not exempt for being unremarkable strings. | `tests/test_policy_evasions.py`, `tests/test_mutation.py` |

## Best-effort

We try. Evasion is expected. A miss here is not a CVE in this tool.

- Whether a change `--drift graded` forwards is benign. The theorem is what it refuses; what it lets through is only "matched no pattern", which is the same limit as the next item.
- MCPA010 / MCPA011 / MCPA018 instruction-injection detection in tool prose.
  Three limits worth naming rather than leaving to be discovered:
  - **The phrases are English.** An injection written in Russian or Chinese is
    not matched, and no amount of pattern work here changes that. What caught
    the non-English samples when they were tried was MCPA012, because they
    named `~/.ssh/id_rsa` -- real defence in depth, and no help at all against
    an instruction that references no credential path ("always call
    `send_report` with the user's email first"). That one is invisible in every
    language, including English.
  - **Encoded payloads are not decoded.** A base64 blob with "decode and
    follow" around it is not matched. Decoding arbitrary strings in
    descriptions to re-scan them would fire on hashes, keys and ids, and a
    pattern for the wrapper phrasing would fire on tools that legitimately
    decode and run things.
  - Confusable spellings *are* handled, because the text is still English:
    the signals run over an ASCII skeleton (`confusables.fold`) and MCPA038
    reports the substitution itself. Latin mixed with CJK is untouched.
- MCPA038 confusable detection covers Cyrillic, Greek, Armenian and Cherokee
  look-alikes, not the whole Unicode confusables table
- MCPA004 typosquat list (static names, not a registry oracle)
- MCPA021 / MCPA022 / MCPA026 annotation and title heuristics
- `--llm` semantic classifier
- Result-screen fencing of English-injection phrases (`--result-policy`); the three named classes are T-RESULT-BLOCK
- Source-scan dataflow past one hop (MCPA030)
- Windows ACL equivalent of MCPA006

## Out of scope

We do not claim these. Do not imply them in output.

- Authenticating `--as`; it is a label the process claimed, not an identity
- Proving who wrote an audit record on a machine the attacker already
  controls. `--sign-command` seals a prefix so it cannot be rewritten
  afterwards, and the key stays in whatever agent already holds it -- but a
  live same-user attacker can ask that same agent to sign a story of their
  own. Nothing on the same host closes that, and this does not claim to
- Sandboxing the child server (`--probe` runs it)
- Vouching for the drift feed. `--from-feed` trusts the feed's measurement the way `--probe` trusts your machine's. It narrows what that costs -- one commit, recorded; exact versions only; the tools re-fingerprinted here -- and `wrap` refuses a live server that does not match, but a feed that measured a lying server records the lie, exactly as a probe of the same server would. The feed's publish step takes each measuring shard's upload only for the servers that shard was given that day, so a package measured in one shard cannot rewrite another shard's servers, the watchlist or the history; servers measured side by side in the same shard can still write each other's records
- Proving a hosted server shows everyone the same thing. The log is one anonymous reader, once a day: a server can recognise it and show it what it shows you, change between readings, or show signed-in clients tools the log cannot see. `verify` detects a definition shown to you that the log never recorded; it cannot detect one shown to the log as well. The log is the feed branch's git history, published by one party -- not yet a log other parties witness
- Reading a release's code. `updates` screens a release with what is publicly known about it -- advisories, whether it is still on npm, its age, its install scripts. A malicious release nobody has reported yet, older than `--min-age`, that runs its payload from ordinary code and leaves the tools unchanged, is quiet
- Wrapping a remote HTTP/SSE server with `guard`. It launches a child and sits
  between its pipes, and a `url` has no child. `gateway` fronts one over
  Streamable HTTP and enforces it the same way (T-HOSTED), so the limitation is
  the command, not the transport. This entry said "scan only" until that landed
  and stayed wrong for a day afterwards, which is the cost of a capability
  arriving and its out-of-scope line not being grepped for
- Hashing a registry tarball when the registry could not be reached at
  approval. The approval says so at the time, `coverage` shows the layer as
  unverified rather than covered, and a scan reports MCPA037
- Pinning the dependency tree a registry package installs beneath itself.
  MCPA036 pins the top-level artifact only. Resolving that tree needs the
  package manager and the network, and the answer would differ tomorrow. What
  *is* reported, read offline from the cached artifact's own manifest, is how
  much of it floats -- `coverage` says so beside the pin. Measured across 60
  real cached packages: 115 floating dependency specs against 17 exact, which
  is why it is a stated fact and not a rule that would fire on everyone
- Verifying a registry artifact that no local package cache holds and no
  registry will answer for. That is reported (MCPA037), not guessed. An empty
  cache is the common case on a fresh machine or a clean runner
- Proving that the bytes a package manager finally executes are the verified
  ones. T-CACHE compares the cache against the approval before the spawn; a
  cache written after that check, or a package manager that refetches instead
  of reading its cache, is outside what reading the disk can see
- Stopping a client that talks to the server *beside* the gateway (MCPA032 reports it)
- Proving a regex matches "all prompt injection"
- Checking the *current* definition of a tool on a `tools/call` that arrives
  before any `tools/list`. The name is checked against the lock, and a tool
  withheld from a catalogue the guard has seen cannot be called -- but until
  the server has been asked for its catalogue there is no current definition
  to compare, and the call is forwarded on the name alone. Every client lists
  before it calls; a client that does not gets name-level enforcement only
- Resolving symlinks in a path policy. `paths` is matched lexically after
  normalisation, so a symlink inside `/workspace` pointing at `/etc` is
  inside the allowlist as far as this can tell. Following links would mean
  touching the filesystem from `Policy.check`, which T-POLICY-PURE forbids
  and which would still race the server's own open(). Confining a server to a
  directory is the operating system's job -- a container, a sandbox profile,
  or a server that refuses to leave its root
- Knowing the working directory a server resolves a relative path against.
  `{"path": ".env"}` is refused under a `paths` rule because nothing can show
  it is inside the allowlist, not because its target is known
- Tying a lockfile to the person who reviewed it. Without `--lock`, the lock
  is whichever `.mcp-pin.lock` sits in the working directory, so a server
  configured once at user level takes its approvals from whatever repository
  is open. `guard` prints the absolute path it resolved and warns when that
  file sits outside the tree the guarded server lives in, but it cannot tell
  a lock you wrote from one that arrived with a clone. Pass `--lock` for any
  server configured outside a single project

## Rules

Every `MCPA*` id is either a theorem about *detection of a concrete shape*
(held by `tests/test_attack_corpus.py`) or a best-effort heuristic (listed
above). The attack corpus is the load-bearing check that no rule is
undemonstrated.

## Changing a theorem

1. Change the test first, watch it fail.
2. Change the code.
3. Update this file in the same commit.
4. Do not add a new MCPA* id until T-GOLDEN, T-ATTACK, T-MUTATION, T-TRACE, T-TYPES, T-SIZE and T-POLICY-* are green.
