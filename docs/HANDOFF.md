# Handoff

For whoever continues this — including Claude Code.

`CLAUDE.md` is gitignored on purpose (local notes, not the public record).
Read this file and `docs/GUARANTEES.md` instead.

## Where it is

- Feature freeze. No new clients, no new rules, no rename, no PyPI until
  the theorems in `docs/GUARANTEES.md` hold under the tests named there.
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

## Next, in order

1. ~~Mutation-score the kernels (`policy.py`, `model.ToolSpec.fingerprint`,
   `discovery._strip_jsonc`). Fail CI under a threshold you pick.~~ Done:
   16 fail-open mutants, score must be 1.0. Not mutmut; equivalent mutants
   are excluded on purpose.
2. ~~Golden JSON-RPC traces for `guard` / `gateway` (allow, deny, hostile
   stdout-before-frame, rewrite-after-N-calls).~~ Done: `tests/golden/traces/`.
3. Split `cli.py` and `guard.py` only after (1) and (2). Small functions,
   same behaviour, same tests.
4. `mypy --strict` on `policy.py`, `lockfile.py`, `model.py`, `findings.py`
   as a non-runtime extra. Do not block the rest of the tree on day one.
5. Only then: PyPI, a name that can win search, more clients.

## How to run

```bash
python tests/fixtures/make_fixtures.py
python -m unittest discover -s tests -v
```

A theorem that cannot be falsified by deleting its implementation is not a
theorem. Do not add marketing sentences to the README during the freeze.
