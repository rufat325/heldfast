# How often do MCP servers change their tool definitions?

Tool poisoning is a documented attack: a server rewrites a tool's description
after you approved it, and the agent reads the new text. Invariant Labs
demonstrated it in April 2025, and has since reported that 5.5% of public MCP
servers carry tool-poisoning payloads.

Pinning tool definitions only works as a *defence* if legitimate servers do
not change them constantly. If they do, every upgrade is an alert, alerts
become noise, and the control gets muted -- which is worse than not having it,
because a muted control still looks like coverage.

This measures that, across the most-used MCP servers in the official
registry, with the method, the sample rule and the data in the repository so
anyone can disagree with it precisely.

**Short version.** Across 109 third-party servers and 522 upgrades, a pin
stops on 45% of upgrades and a description is reworded in 29% of them. Almost
none of that is a whole-catalogue protocol bump; it is one or two tools edited
at a time, which is exactly the shape a targeted rug pull has. None of the 616
description edits introduced an attack signal a human reading them would
keep. A pin that treats every change the same will be muted. A pin that says
*what* changed, and grades it, would have interrupted 3 upgrades in 522.

## Method

`research/churn/sample.py` builds the sample by a rule, not by hand:

1. every server whose latest entry in `registry.modelcontextprotocol.io`
   ships an npm package over stdio (9,318 packages on 2026-09-22),
2. ranked by npm downloads over the last month,
3. the top 150 with at least two stable releases.

It keeps the registry's launch arguments, because several of the most-used
entries are general CLIs whose server is a subcommand (`snyk mcp -t stdio`,
`firebase-tools mcp`). The four `@modelcontextprotocol` servers from the
first version of this study are measured alongside, for comparison.

`research/churn/measure.py` takes the last six stable releases of each, in
publish order, and for each one: launches it with `npx`, completes the MCP
handshake, asks for `tools/list`, and digests every tool the way
`.mcp-pin.lock` does (RFC 8785 canonicalization, SHA-256). It runs in
`research/churn/Dockerfile` -- a container with no capabilities and one
writable host path -- and gives each server a fixed environment with nothing
inherited. A variable the registry marks as required gets a placeholder.

`research/churn/analyse.py` compares consecutive releases.
`research/churn/suspicious.py` reads every tool whose agent-facing text
changed -- description, title, and every description inside the input schema
-- and reports what a release *introduced*: mcp-pin's poisoning signals,
hidden characters, credential paths, and new domains. A signal the previous
release already carried is not counted again. Every number below comes out of
one of those two scripts; run them against the data and they should
reproduce.

A server that will not answer `tools/list` is recorded as unmeasured, with the
reason, never counted as unchanged -- "we could not look" and "nothing moved"
must not share a bucket.

## Sample

154 packages; **113 measured** (109 third-party, 4 official), 542 release
pairs, 23,266 tool-versions carried across a release boundary. The measured
servers account for 94% of the sample's monthly downloads. The 41 that could
not be measured are under [Limitations](#limitations-in-order-of-how-much-they-matter).

The four official servers reproduce the first version of this study exactly:
51 of 172 tool-versions moved, 4 descriptions. The pipeline changed; the
answer for the same servers did not.

## Results

| | third-party | official |
|---|---|---|
| packages | 109 | 4 |
| release pairs | 522 | 20 |
| tool-versions carried | 23,094 | 172 |
| digest moved | 1,583 (6.9%) | 51 (29.7%) |
| — description text changed | 616 (2.7%) | 4 (2.3%) |
| — input schema changed | 669 (2.9%) | 19 (11.0%) |
| — only other fields | 298 (1.3%) | 28 (16.3%) |
| tools added / removed | 472 / 146 | 12 / 10 |

Per tool, third-party servers move *less* than the official four. Per
upgrade, which is what a user meets, they stop a pin about as often:

| | third-party | official |
|---|---|---|
| releases a pin stops on | **235 of 522 (45%)**, in 90 of 109 packages | 11 of 20 (55%) |
| releases that reword a description | **150 of 522 (29%)**, in 74 packages | 4 of 20 (20%) |

## The first version of this study was wrong about third-party servers

It said two things. Both held for the official four and neither holds here.

**"Prose is the stable part."** For the official servers, 4 of 51 moves were
description text. For third-party servers it is 616 of 1,583 -- the single
largest category after schemas, and 29% of all upgrades reword at least one
tool. Descriptions are where maintainers put usage guidance for the model, and
they tune it the way they tune code.

**"Breadth is the signal to sort on."** The official moves were dominated by
releases that changed every tool at once -- protocol-era upgrades. Third-party
moves are the opposite:

| | releases | tool-versions |
|---|---|---|
| moved **every** tool at once | 24 | 394 |
| moved **some** tools | 195 | 1,189 |

510 description edits landed in releases where the tool's siblings held
still. That is the shape a targeted rewrite has. "One tool moved and the rest
did not" is not rare enough to be a signal; it is the normal case.

## What the changes actually said

`suspicious.py` found 25 changes, across 542 release pairs, that introduced
anything at all. 21 were a new domain in documentation (`docs.atlassian.com`,
`swagger.io`, `github.com`, ...). Four carried a signal at confidence 0.5 or
above, in three releases. All four read as benign in context:

| release | tool | signal | in context |
|---|---|---|---|
| `@smartbear/mcp` 0.37.0 | `qmetry_fetch_udf_layout` (new) | concealment | "use that value automatically without asking the user" -- about pre-filled form defaults |
| `@smartbear/mcp` 0.37.0 | `qmetry_create_test_case` | exfiltration | "Send the re-formatted string to the API" -- a date format |
| `@sap-ux/fiori-mcp-server` 1.12.9 | `generate_fiori_app_cap` | mandated side effect | "MUST NOT already exist before calling this tool" -- a precondition |
| `@trusty-squire/mcp` 1.1.13 | `fetch_credential` (new) | credential path | names `.env` files; the tool manages credentials behind a passkey approval |

**No change in this sample looked like tool poisoning.** That is a statement
about these signals over these 150 servers, not a proof: a rewrite phrased to
miss every pattern would be missed here too.

## What this suggests

**A pin that stops on every change will be muted.** Nearly half of real
upgrades move something, and 90 of the 109 servers moved at least once in six
releases. mcp-pin as it stands refuses every one of those until someone
re-approves, and the re-approval prompt for a benign doc edit looks the same
as the one for an attack. Asked that often, people stop reading it.

**The grade has to carry the weight breadth could not.** 616 description
edits and 472 new tools; 4 changes that tripped a signal (two edits, two new
tools); 0 that were hostile. The information a user
needs at an upgrade is not "this changed" -- it changes all the time -- but
"this changed, here are the words, and here is whether any of them are
addressed to the agent in a way the old text was not." A benign edit shown as
a one-line diff and a signal-bearing edit that refuses the call are two
different products; only the second survives contact with a real upgrade
cadence.

**Schemas matter as much as prose.** 669 input-schema changes -- new optional
parameters, restated types. A description the model reads also lives in every
property of the schema, which is why `suspicious.py` reads those too and why a
pin that hashed only the top-level description would miss where a careful
attacker would write.

## Limitations, in order of how much they matter

1. **Only the popular head, and only npm over stdio.** 150 of 9,318 registry
   packages, ranked by downloads. Hostile servers are more likely in the long
   tail, which this does not reach. Hosted (remote) servers are not measured
   at all -- and for them a definition can change without any release, which
   is where a pin matters most and where "per release" is not even the right
   unit.
2. **41 of 154 could not be measured**, by reading each error: about 15
   validate credentials or configuration at startup and refuse placeholders
   (Perplexity, Dynatrace, WordPress, Google Sheets, an OAuth sign-in); about
   9 are for another platform (macOS- or Windows-only, Bun, Node 24, a glibc
   mismatch); about 7 have registry entries that do not launch as written
   ("could not determine executable to run", a help screen); about 10 exited
   or hung for reasons the log does not show. Any correlation between "checks
   credentials at startup" and "churns differently" is invisible here. The
   reason for each is in its result file.
3. **The signals are regular expressions.** "Nothing hostile" means nothing
   matched and the four that did were read by a person. It is a floor on
   what was there, not a ceiling.
4. **Six releases per package, the most recent.** Fast shippers contribute
   six recent weeks; slow ones, two years. Releases are weighted equally
   regardless of time.
5. **One run, 2026-09-22**, from one Linux container on Node 22.

## Reproducing

```bash
python research/churn/sample.py            # writes sample.json (the frame and the rule)
docker build -f research/churn/Dockerfile -t mcp-pin-churn .
docker run --rm --cap-drop ALL --security-opt no-new-privileges \
  --memory 4g --cpus 2 \
  -v "$PWD/research/churn/sample.json:/work/research/churn/sample.json:ro" \
  -v "$PWD/research/churn/results:/work/research/churn/results" \
  mcp-pin-churn --jobs 2
python research/churn/measure.py merge     # results/ -> wide.json.gz
python research/churn/analyse.py           # every count above
python research/churn/suspicious.py        # the four, and suspicious.json
```

`measure.py` downloads and runs published npm packages. Run it in the
container, or somewhere you are willing to lose. It resumes: a package whose
result file exists is not measured again. A first attempt at six servers in
parallel ended when the host crashed (a driver watchdog, under that load);
two in parallel ran to the end.

The sample is `research/churn/sample.json`; the catalogues behind every table
are `research/churn/wide.json.gz` (schemas as hashes, descriptions in full).
The first version's data is `research/churn/official-servers.json`, and
`python research/churn/analyse.py official-servers.json` still reproduces it.
