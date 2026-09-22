# How often do MCP servers change their tool definitions?

Tool poisoning is a documented attack: a server rewrites a tool's description
after you approved it, and the agent reads the new text. Invariant Labs
demonstrated it in April 2025, and has since reported that 5.5% of public MCP
servers carry tool-poisoning payloads.

Pinning tool definitions only works as a *defence* if legitimate servers do
not change them constantly. If they do, every upgrade is an alert, alerts
become noise, and the control gets muted -- which is worse than not having it,
because a muted control still looks like coverage.

Nobody appears to have measured that. This is a first attempt, on a small
sample, with the method and the raw data in the repository so anyone can
disagree with it precisely.

## Method

`research/churn/measure.py` takes each package, lists its published versions,
and for the last six: launches the server with `npx`, completes the MCP
handshake, asks for `tools/list`, and digests every tool the way
`.mcp-pin.lock` does (RFC 8785 canonicalization, SHA-256). It records the
description and input schema separately so the kind of change can be told
apart from the fact of one.

`research/churn/analyse.py` compares consecutive releases. Every number below
comes out of that script; run it against the data and it should reproduce.

A server that will not answer `tools/list` is recorded as unmeasured, never
counted as unchanged -- "we could not look" and "nothing moved" must not share
a bucket.

## Sample

Four servers, `@modelcontextprotocol/server-{filesystem,memory,everything,sequential-thinking}`,
six releases each, 20 consecutive release pairs, 172 tool-versions carried
across a release boundary.

**This is a small and unrepresentative sample.** All four are maintained by
the protocol's own authors, which is close to a best case for discipline. A
wider run across third-party servers was started and not finished; the script
is here to do it.

## Results

| | count | of carried |
|---|---|---|
| tool-versions carried across a release | 172 | |
| digest moved | 51 | 29.7% |
| — description text changed | 4 | 2.3% |
| — input schema changed | 19 | 11.0% |
| — only other fields (annotations, title, outputSchema) | 28 | 16.3% |
| tools added | 12 | |
| tools removed | 10 | |

**30% churn sounds fatal for pinning. It isn't, because of how it clusters.**

| | releases | tool-versions |
|---|---|---|
| moved **every** tool at once | 4 | 45 |
| moved **some** tools | 6 | 6 |

45 of the 51 moves came from four releases that changed every tool in the
catalogue simultaneously. Those are protocol-era upgrades, not tool edits:

```
server-memory   2026.1.26 -> 2026.7.4   9/9   every tool gained `annotations`
server-memory   2025.9.25 -> 2025.11.25 9/9   every input schema restated
server-filesystem 2026.7.4 -> 2026.7.10 14/14
server-everything 2026.1.26 -> 2026.7.4 13/13
```

`server-memory` gained `annotations` on all nine tools in a single release
without touching a word of any description.

## What this suggests

**Prose is the stable part.** Only 4 of 172 carried tool-versions changed
their description at all. The overwhelming majority of digest movement is
structural -- schemas restated, spec fields adopted -- and a pin that reports
"the description changed" is reporting something genuinely rare.

**Breadth is the signal to sort on.** A release where every tool moves looks
like an upgrade. A release where one tool moves while its siblings hold still
looks like an edit. Both deserve the same severity, because an attacker can
rewrite a whole catalogue as easily as one tool, but a reader needs to be told
which shape they are looking at. mcp-pin reports that ratio on every
`MCPA015`.

**Pinning descriptions is viable; pinning whole definitions is noisy.** Anyone
building this should expect an upgrade to move most digests, and should say so
in the report rather than emitting one critical finding per tool with no
context.

## Limitations, in order of how much they matter

1. **Four servers, all first-party.** Third-party servers may churn very
   differently. Do not read 2.3% as an ecosystem figure.
2. **Single-tool servers distort the split.** `server-sequential-thinking` has
   one tool, so it can never be classified as "moved every tool" under a rule
   that requires more than one. Four of the six "isolated" moves come from
   catalogues where only one tool carried across. Excluding those, exactly one
   clean case remains: `server-filesystem` 2026.1.14 → 2026.7.4, where 1 of 14
   tools moved. **One case is an anecdote, not a rate.**
3. **Six releases per package**, the most recent, so this is recent behaviour
   rather than project history.
4. **Only servers that enumerate tools without credentials.** Several
   third-party servers refuse `tools/list` until authenticated, and any
   correlation between "needs auth" and "churns differently" is invisible
   here.
5. **Releases, not wall-clock time.** A server that ships weekly and one that
   ships twice a year are weighted identically.

## Reproducing

```bash
python research/churn/measure.py     # writes wide.json
python research/churn/analyse.py     # prints every number above
```

`measure.py` downloads and runs published npm packages. Run it somewhere you
are willing to do that.

The raw catalogues behind the table are in
`research/churn/official-servers.json`.
