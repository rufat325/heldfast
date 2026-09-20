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
    not from documentation: 777 npm tarball entries all verified, 25/25
    tampered digests caught, three pip wheels matched the sha256 PyPI
    publishes. Validated against live metadata for a real MCP server package
    too. The first version of `check` read the approved digest out of the dict
    *key* instead of its value and reported `absent` for all 777 -- which is
    why that validation exists and runs before the feature is believed.

## How to run

```bash
python tests/fixtures/make_fixtures.py
python -m unittest discover -s tests -v
```

A theorem that cannot be falsified by deleting its implementation is not a
theorem. Do not add marketing sentences to the README during the freeze.
