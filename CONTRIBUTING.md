# Contributing

## Running the tests

```bash
git clone https://github.com/rufat325/heldfast && cd heldfast
python tests/fixtures/make_fixtures.py
python -m unittest discover -s tests
```

**The fixture step is not optional.** Part of the suite scans a deliberately
bad configuration tree that is generated rather than committed, because a
repository carrying a file with `ghp_…` in it is a repository that trips every
secret scanner pointed at it. Skip the step and a handful of tests fail for a
reason that looks nothing like the cause. Nothing to pip-install otherwise;
`unittest` is the whole harness.

Eleven tests skip unless the optional `anthropic` extra is installed. That is
expected — they check the shape of the `--llm` request against the real SDK
pointed at a local stub, and they never call the live API.

## What a change needs

Python 3.9+, standard library only at runtime. The wheel job fails if a
dependency appears. The `anthropic` SDK is an optional extra, imported lazily,
for `--llm` alone.

`docs/GUARANTEES.md` is the specification. Claims live in one of three buckets
— theorem (falsifiable, test-backed), best-effort (evasion expected), or out of
scope — and a sentence that fits none of them does not belong in the README.

**Adding a rule takes four things, all enforced by tests:**

1. the rule itself
2. a `RuleDoc` entry in `src/heldfast/rule_docs.py`, then
   `heldfast rules --markdown -o docs/rules.md` to regenerate the catalogue
3. an attack in `tests/test_attack_corpus.py` that demonstrates it
4. evidence it stays quiet on real data

Miss any one and the build fails. That is deliberate: an undemonstrated rule is
one nobody has shown to work, and an undocumented one is one nobody can act on.

**Detection needs three corpora, not two.** Clean (does it stay quiet), attacks
(does it fire), and evasions (does it fire on the *other* spelling of the same
attack). The third has found more real gaps here than the first two together,
including a CRITICAL SSRF rule that knew one spelling of one IP address.

**Changing a theorem** means changing its test first and watching it fail, then
the code, then `docs/GUARANTEES.md` in the same commit.

## Things that will be sent back

- A rule with no evidence about false positives. "It might be noisy" is a
  measurable question, and so is "it might be quiet".
- A runtime dependency.
- A test whose failure message guesses at a cause. If a reason is worth
  printing it is worth recording where it is known.
- Reformatting unrelated code in the same commit as a behaviour change.

## Tests pin decisions, not just behaviour

Where a test looks oddly specific it is usually recording a bug that shipped.
Read the docstring before changing one — several of them exist because the
obvious behaviour was wrong for a reason that is not obvious.

## Commit messages

Describe the harm avoided, present tense, no ticket IDs. `git log --oneline`
is the house style; match it.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a
security problem in the enforcement path.
