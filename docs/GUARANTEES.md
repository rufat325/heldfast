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
| T-SQL-STACK | Two SQL statements in one argument are refused even when the first is permitted. | `tests/test_policy.py` |
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
| T-GOLDEN | The known-bad fixture still produces the pinned set of rule IDs. A rule that goes quiet is a bug. | `tests/test_golden_findings.py` |
| T-MUTATION | Every catalogued fail-open edit of policy, fingerprint or JSONC is observed as a hole. Survival fails CI. | `tests/test_mutation.py` |
| T-TRACE | Guard and gateway still emit the pinned JSON-RPC conversations (allow, deny, banner-before-frame, rewrite-after-N, sampling, elicitation, roots, result fence). | `tests/test_golden_traces.py` |
| T-FAIL-CLOSED | A kernel exception in `guard` refuses the call or withholds the result. A tool withheld from `tools/list` cannot still be executed. Forwarding either requires `--fail-open`. | `tests/test_guard.py`, `tests/test_mutation.py`, `tests/test_malformed_input.py` |
| T-BATCH | A JSON-RPC batch is inspected per frame. A `tools/list` stuffed into an array cannot skip `filter_tools`. | `tests/test_guard.py`, `tests/test_mutation.py` |
| T-PINNED | A `.mcp-pin-ignore` line cannot hide a lockfile theorem (MCPA014–017, 019, 020, 031, 036, 037). | `tests/test_mcp_pin.py`, `tests/test_mutation.py` |
| T-ISOLATE-LOADER | `NODE_OPTIONS` and `PYTHONPATH` do not ride from the parent into a child unless the server declared them. | `tests/test_childenv.py`, `tests/test_mutation.py` |
| T-MUX | Two servers with the same bare name from different clients are not silently overwritten; the second is refused. | `tests/test_gateway.py`, `tests/test_mutation.py` |
| T-PROBE-LIFE | `--probe` binds the child the same way `guard` does (`posix_preexec` / job object). | `tests/test_hostile.py`, `tests/test_mutation.py` |
| T-UNPINNED | A scan of configured servers with no lockfile fires MCPA014 at HIGH, so default `--fail-on high` fails the build. | `tests/test_mcp_pin.py`, `tests/test_mutation.py` |
| T-LOCK-TREE | A lockfile sitting in the scanned directory is the lockfile, even when cwd is somewhere else. | `tests/test_mcp_pin.py` |
| T-ARTIFACT | If the lock recorded local-script digests, `guard` and `gateway` refuse to start the child when those bytes have moved. A registry package has no local file; T-INTEGRITY is the content pin. | `tests/test_artifacts.py`, `tests/test_guard.py`, `tests/test_mutation.py` |
| T-LAUNCH | If the lock recorded a command line, `guard` and `gateway` refuse to start a different argv. | `tests/test_guard.py`, `tests/test_mutation.py` |
| T-REVIEW | Re-approval of a lock that moved prints the word-level diff and does not write unless `--yes` or `--yes-tool` names every drifted tool. A digest or command change still needs `--yes`. | `tests/test_review.py`, `tests/test_mutation.py` |
| T-SURFACE | If the lock recorded prompts or resources, `guard` filters `prompts/list` and `resources/list` and refuses `prompts/get` / `resources/read` the same way it does tools. A lock that never recorded that layer is not pretend-enforced. | `tests/test_guard.py`, `tests/test_mutation.py` |
| T-YES-CRITICAL | `approve --yes` does not overwrite a critical-graded drift. That change must be named with `--yes-tool`. | `tests/test_review.py`, `tests/test_mutation.py` |
| T-INTEGRITY | If the lock recorded a registry tarball hash, a different live hash fires MCPA036. | `tests/test_integrity.py`, `tests/test_mutation.py` |
| T-CACHE | If the lock recorded a registry artifact hash, `guard` and `gateway` refuse to start the child when the local package cache holds different bytes for it. Checked offline, before the spawn. | `tests/test_pkgcache.py`, `tests/test_guard.py`, `tests/test_gateway_parity.py`, `tests/test_mutation.py` |
| T-UNVERIFIED | An artifact that could not be checked is reported as MCPA037 and never as verified. `--require-integrity` makes it high, and makes `guard` and `gateway` refuse to start. | `tests/test_pkgcache.py`, `tests/test_attack_corpus.py`, `tests/test_mutation.py` |
| T-SAFE-OFFLINE | `--safe` opens no socket. No registry is contacted by a scan or an approval under it, and what that costs is stated rather than silently skipped. | `tests/test_integrity.py`, `tests/test_mutation.py` |
| T-LIST-CHANGED | `notifications/tools/list_changed` marks the backend stale; the next `tools/list` or call re-fetches and re-screens. | `tests/test_gateway_parity.py`, `tests/test_mutation.py` |
| T-PROBE-GATE | A rule exception in the static pre-pass launches nothing. | `tests/test_probe_boundary.py`, `tests/test_mutation.py` |
| T-DRIFT-ID | Two lock entries sharing a bare name are not compared against the first match. | `tests/test_mcp_pin.py`, `tests/test_mutation.py` |
| T-TYPES | `policy.py`, `lockfile.py`, `model.py`, `findings.py` and `pkgcache.py` type-check under `mypy --strict`. | `.github/workflows/ci.yml` |
| T-SIZE | Functions in `cli.py` and `guard.py` fit on one page (60 lines). | `tests/test_function_size.py` |
| T-WHEEL | The published wheel has no runtime dependencies. | `.github/workflows/release.yml` |
| T-REDACT | Findings cannot carry a live credential or a control character that rewrites the report. | `tests/test_output_integrity.py` |

## Best-effort

We try. Evasion is expected. A miss here is not a CVE in this tool.

- MCPA010 / MCPA011 / MCPA018 instruction-injection detection in tool prose
- MCPA004 typosquat list (static names, not a registry oracle)
- MCPA021 / MCPA022 / MCPA026 annotation and title heuristics
- `--llm` semantic classifier
- Result-screen fencing (`--result-policy`)
- Source-scan dataflow past one hop (MCPA030)
- Windows ACL equivalent of MCPA006

## Out of scope

We do not claim these. Do not imply them in output.

- Authenticating `--as`; it is a label the process claimed, not an identity
- Sandboxing the child server (`--probe` runs it)
- Proxying remote HTTP/SSE MCP (scan only; `guard` is stdio)
- Hashing a registry tarball when the registry could not be reached at
  approval. The approval says so at the time, `coverage` shows the layer as
  unverified rather than covered, and a scan reports MCPA037
- Pinning the dependency tree a registry package installs beneath itself.
  MCPA036 pins the top-level artifact only
- Verifying a registry artifact that no local package cache holds and no
  registry will answer for. That is reported (MCPA037), not guessed
- Stopping a client that talks to the server *beside* the gateway (MCPA032 reports it)
- Proving a regex matches "all prompt injection"

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
