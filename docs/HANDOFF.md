# Handoff

For whoever continues this — including Claude Code.

`CLAUDE.md` is gitignored on purpose (local notes, not the public record).
Read this file and `docs/GUARANTEES.md` instead.

## Where it is

- Feature freeze. No new clients, no new rules, no PyPI until
  the theorems in `docs/GUARANTEES.md` hold under the tests named there.
- GitHub repo, command, wheel and lockfile are `mcp-pin`. Rule ids stay
  `MCPA*`: a detection namespace is not a product name.
- An existing `.mcp-audit.lock` is still loaded if `.mcp-pin.lock` is
  absent, so renaming the file is not a silent loss of enforcement.
- Last public commit on `main` before this freeze work:
  `d54123c Stop a name in a config from rewriting the report about it`

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

## How to run

```bash
python tests/fixtures/make_fixtures.py
python -m unittest discover -s tests -v
```

A theorem that cannot be falsified by deleting its implementation is not a
theorem. Do not add marketing sentences to the README during the freeze.
