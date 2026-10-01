# What MCP servers told their agents: the first week of a public log

*Data: heldfast-feed at the 2026-09-29 checkpoint [D1]. Code: heldfast at
commit `b9f7ec8` [C1]. Written 2026-10-01. Each number below was computed by
`research/report/numbers.py` and carries the claim ID that defines it; the
register is the appendix.*

## Summary

- The log watched 29,458 MCP servers from the official registry: 9,712 npm
  packages and 19,746 hosted endpoints, so 67.0% of the watchlist was hosted
  (watchlist of 2026-09-28).
- Between 2026-09-23 and 2026-09-29 it observed 12,775 changes to tool
  definitions. With 246 events carried in from an earlier study, the record
  held 13,021.
- Three operators accounted for 9,788 of the 12,642 hosted events (77.4%;
  75.2% of all 13,021).
- 66 events were graded `review`. 58 of them introduced a price, on 41
  servers; 8 introduced something else and are listed for a person to read.
- Of 19,764 hosted servers with a state file, 13,255 (67.1%) had been read and
  were current. 4,165 (21.1%) had never been read because they asked for a
  login or payment.
<!-- C01 C03 C05 C06 C02 -->

## Why hosted servers matter

An MCP client learns what a server's tools do by sending `tools/list`; each
definition carries a name, a description and an input schema, and the model
reads the description [4]. Tool poisoning puts instructions there [1], and a
server can change its tools after a client has trusted them [2]. A study of
open-source MCP servers has measured how often such patterns occur [3].

A package scanner, or an advisory database such as OSV [9], starts from a
name and a version. A hosted server has no release to download: it is a URL, and what it returns can change between two
requests. At the start of this week 19,746 of the 29,458 servers the log
watched were hosted. What the log records is the tool list each one returned
to an anonymous client, each time it read one. The idea is Certificate
Transparency's [5]: after certificates for sites like google.com were issued
to people who were not Google [6], certificates had to be logged in public.
<!-- C01 -->

## Data and method

**Snapshot.** The figures come from one commit of rufat325/heldfast-feed,
`08a6e310855f6facb9d3bf6e4203db59733bd1ca`, the commit the 2026-09-29
checkpoint names [D1]. Its manifest digest is
`c16aa7cc35e5e04fd65fe2a86d664cb22f102704e0529b0a4a17c3e5e4693e00`, over
171,308 files. We rebuilt the manifest from the commit and the digest matched.
The OpenTimestamps proof [7] was parsed and commits to the checkpoint file, but
was not checked against a Bitcoin node; the Sigstore signature [8] was not
checked.
<!-- D1 -->

**What is read, and how often.** Each hosted server is read daily as an
anonymous client, and at four-hour intervals while it has changed in the last three
days; npm servers are started in a container with no network, the
most-downloaded daily and the rest weekly (docs/TRANSPARENCY.md, "What it
cannot do"; the watchlist's `rule`).

**What counts as a change.** An event is recorded when a server's tool list
differs from the last one held: a tool added, removed, or changed in any field
the lock digest covers. The collector sorts each event into one of three kinds
(research/feed/operators.py): 149 were reorder-only (equal once lists are
sorted), 3,150 numbers-only (equal once digits are masked) and 9,722
substantive. Recomputing the kinds from both catalogues of each event gave the
same counts as the published `stats.json`.
<!-- C04 -->

**How grades are decided.** An event is `review` when a changed tool
introduced a signal that the earlier text did not carry: an instruction to
conceal, override or exfiltrate, a credential path, a hidden character, a
look-alike letter, or a price (`heldfast.driftgrade`). Otherwise it is `quiet`.
The first review event for a price was observed on 2026-09-27.
<!-- C06 -->

**What is sealed.** Checkpoints began on 27 September 2026. The snapshot's
tree holds the checkpoints of 2026-09-27 and 2026-09-28; its own checkpoint
was written after it. Records before the first checkpoint were collected the
same way but are not anchored.
<!-- C09 -->

## Results

**Volume.** The log observed 12,775 changes between 2026-09-23T04:23Z and
2026-09-29T07:38Z: 12,642 on hosted servers and 133 on npm servers. Hosted
changes per UTC day were 1,267, 6,028, 257, 2,041, 2,214, 468 and 367 (the
last day partial). Without the three largest operators, all observed changes
per day were 182, 521, 262, 562, 599, 491 and 370.
<!-- C03 -->

**Three operators.** The record groups hosted servers by registrable domain,
which is approximate: it can merge customers of one host and split an operator
with several domains. Across 1,260 operators, three stood out. `pipeworx.io`
had 7,023 hosted events on 1,522 servers (55.6% of hosted events): 2,975 were
numbers-only and 4,048 substantive, and 7,022 of them changed a description.
`nolimit-observatory.workers.dev` had 2,341 events on 2,341 servers, each one a
whole-catalogue change of `inputSchema` alone. `a2awire.com` had 424 events on
106 servers; `outputSchema` changed in 424, `inputSchema` in 106 and a
description in 47.
<!-- C05 -->

A catalogue counter that ticks, or a schema regenerated in bulk, is a change
the log has to record. It is not misbehaviour, and nothing here says these
operators did anything wrong. Corrections are welcome as issues on
[rufat325/heldfast](https://github.com/rufat325/heldfast/issues).

**Outside those three.** 2,854 hosted events came from 1,288 servers. Across
all 5,257 hosted servers with a change, the median was 1 change, and 3,107
servers changed exactly once.
<!-- C05 -->

**Grades.** 12,955 events were `quiet` and 66 `review`. 58 review events
introduced a price, on 41 servers. Of the rest, by kind of signal (an event
can carry several): exfiltration 2, credential path 2, mandated side effect 2,
critical word 2, concealment 1, override 1. Those 8 events are listed in
`research/report/review-events.md`. A signal is a lead for a reader, not a
finding of intent.
<!-- C06 -->

**Prices.** Stated prices are read with driftgrade's price patterns, and a
stated amount can be an example rather than a charge. On 16 servers a tool's
single stated price became a different single price. Prices fell on 10 of
them, rose on 3, and moved both ways on 3. One server carried 285 of the 414
before-and-after pairs (68.8%), so these are reported per server. 4 servers
at least tripled a price. The most servers with such a change within four
days was 15, from 2026-09-24. An earlier draft's claim of 23 servers in four
days does not hold under this definition, and is withdrawn.
<!-- C07 -->

**Coverage.** Of 19,764 hosted state files, 13,255 (67.1%) were read and
current, and 369 (1.9%) had a catalogue but a failed latest attempt, 151 of
them with HTTP 429. 6,140 (31.1%) had never been read: 4,165 (21.1%) asked
for a login or payment (HTTP 401, 402, 403), 586 (3.0%) answered 404, 773
(3.9%) failed at the network, 262 (1.3%) returned a 5xx, 248 (1.3%) another
4xx, and 98 (0.5%) failed the protocol.
<!-- C02 -->

**Lookup.** The log's lookup file held 230,763 distinct tool definitions, of
which 217,985 had been seen on exactly one server.
<!-- C08 -->

**Earlier studies.** The churn study's figures (docs/CHURN.md) reproduced from
its committed data: across 109 third-party servers and 522 upgrades, a pin
stopped on 235 (45%) and a description was reworded in 150 (29%). The scan
study (docs/SCAN.md) read 240,464 tools from 13,170 servers on 2026-09-23; it
is quoted as dated and was not rerun. Its finding was that the rules matched
nothing a person reading the hits judged to be a poisoning payload. Its
caveats stand: pattern rules and one reader, the semantic tier not run, and
five of sixteen reworded attacks caught.
<!-- C10 C11 -->

## Limitations

- **One reader, a few times a day.** A version a server shows for a few hours
  between two readings can be missed (docs/TRANSPARENCY.md, "What it cannot
  do").
- **Signed-in clients see more.** The log reads what an anonymous client is
  shown (same section).
- **A server that recognises the reader** and shows it the same poisoned tool
  it shows a target is not caught by the log, though that tool is then on the
  public record (same section).
- **One publisher.** The log is published by one party, not by several
  independent logs that watch each other (same section).
- **The seal bounds dates from above.** It says nothing about whether the data
  is accurate, or that the log left nothing out (docs/TRANSPARENCY.md, "What it
  does not prove").
- **Records before 27 September 2026 are not sealed**, and cannot be
  (docs/TRANSPARENCY.md, "From which date").
- **A baseline, not a trend.** The observed window ran from 2026-09-23 to
  2026-09-29.
- **Coverage.** 6,140 of 19,764 hosted servers (31.1%) had never been read,
  with the reasons above.
<!-- C03 C02 -->

## Reproducing

```bash
git clone https://github.com/rufat325/heldfast-feed feed
git -C feed -c core.autocrlf=false archive 08a6e310855f6facb9d3bf6e4203db59733bd1ca \
  | tar -x -C feed-snapshot          # a case-sensitive directory on Windows or macOS
git clone https://github.com/rufat325/heldfast && cd heldfast
git checkout b9f7ec8c10367e74abb5044ac02aee86405236a0
python research/report/numbers.py --feed ../feed-snapshot --out research/report/numbers.json
python research/report/numbers.py --feed ../feed-snapshot --verify
python research/report/check_numbers.py docs/FIRST-WEEK.md
```

Checking the checkpoint itself is described in docs/TRANSPARENCY.md, "How to
verify one". Some paths in the feed differ in nothing but case, so on Windows or
macOS extract into a case-sensitive directory.

## References

- [D1] rufat325/heldfast-feed, commit `08a6e310855f6facb9d3bf6e4203db59733bd1ca`;
  checkpoint `checkpoints/2026-09-29.json`; manifest SHA-256
  `c16aa7cc35e5e04fd65fe2a86d664cb22f102704e0529b0a4a17c3e5e4693e00`.
  https://github.com/rufat325/heldfast-feed
- [C1] rufat325/heldfast, commit `b9f7ec8c10367e74abb5044ac02aee86405236a0`.
  https://github.com/rufat325/heldfast
- [1] Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks",
  1 April 2025. https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
  (accessed 2026-10-01)
- [2] Invariant Labs, "WhatsApp MCP Exploited", 7 April 2025.
  https://invariantlabs.ai/blog/whatsapp-mcp-exploited (accessed 2026-10-01)
- [3] M. M. Hasan, H. Li, E. Fallahzadeh, G. K. Rajbahadur, B. Adams, A. E.
  Hassan, "Model Context Protocol (MCP) at First Glance: Studying the Security
  and Maintainability of MCP Servers", arXiv:2506.13538, June 2025.
  https://arxiv.org/abs/2506.13538 (accessed 2026-10-01)
- [4] Model Context Protocol specification, 2025-06-18, "Tools".
  https://modelcontextprotocol.io/specification/2025-06-18/server/tools
  (accessed 2026-10-01)
- [5] B. Laurie, A. Langley, E. Kasper, "Certificate Transparency", RFC 6962,
  June 2013. https://www.rfc-editor.org/rfc/rfc6962 (accessed 2026-10-01)
- [6] Google Online Security Blog, "An update on attempted man-in-the-middle
  attacks", 29 August 2011.
  https://security.googleblog.com/2011/08/update-on-attempted-man-in-middle.html
  (accessed 2026-10-01)
- [7] OpenTimestamps. https://opentimestamps.org (accessed 2026-10-01)
- [8] Sigstore, "Overview". https://docs.sigstore.dev/about/overview/
  (accessed 2026-10-01)
- [9] OSV, "Data sources". https://google.github.io/osv.dev/data/
  (accessed 2026-10-01)

## Appendix: claims register

Generated by research/report/numbers.py from numbers.json. Do not edit by hand.

### C01

| figure | value | denominator | definition |
|---|---|---|---|
| npm watched | 9712 |  | npm packages on the watchlist. |
| hosted watched | 19746 |  | Hosted endpoints on the watchlist. |
| total watched | 29458 |  | Every entry on the watchlist. |
| hosted watched pct | 67.0 | entries on the watchlist (29458) | Hosted endpoints' share of the watchlist. As a percentage, one decimal. |
| watchlist synced | "2026-09-28" |  | The date the watchlist was last rebuilt from the registry. |

### C02

| figure | value | denominator | definition |
|---|---|---|---|
| hosted state files | 19764 |  | Hosted servers the feed holds a state file for, including ones since dropped from the watchlist. |
| read and current | 13255 |  | Hosted state files with a catalogue and no failed attempt since. |
| read and current pct | 67.1 | hosted state files (19764) | Read and current, of all hosted state files. As a percentage, one decimal. |
| catalogue but latest failed | 369 |  | Hosted state files with a catalogue whose latest reading attempt failed. |
| catalogue but latest failed pct | 1.9 | hosted state files (19764) | The same, of all hosted state files. As a percentage, one decimal. |
| catalogue but latest failed by reason | {"HTTP 429": 151, "HTTP 400": 35, "URLError": 30, "HTTP 404": 28, "TimeoutError": 28, "HTTP 401": 21, "HTTP 530": 15, "HTTP 503": 15, "HTTP 403": 9, "HTTP 402": 8, "HTTP 502": 8, "no tools/list answer": 7, "HTTP 410": 5, "HTTP 500": 4, "HTTP 405": 2, "HTTP 522": 2, "HTTP 409": 1} |  | Those, by the recorded reason (attempted.why). |
| never read | 6140 |  | Hosted state files with no catalogue: never read. |
| never read pct | 31.1 | hosted state files (19764) | Never read, of all hosted state files. As a percentage, one decimal. |
| never read by reason | {"HTTP 401": 4057, "URLError": 757, "HTTP 404": 586, "HTTP 400": 110, "HTTP 503": 84, "no tools/list answer": 72, "HTTP 402": 69, "HTTP 502": 57, "HTTP 405": 56, "HTTP 500": 47, "HTTP 530": 45, "HTTP 403": 39, "HTTP 429": 39, "HTTP 410": 36, "initialize failed": 26, "HTTP 522": 17, "TimeoutError": 16, "HTTP 307": 8, "HTTP 521": 4, "HTTP 421": 4, "HTTP 526": 3, "HTTP 451": 2, "HTTP 525": 2, "HTTP 501": 2, "HTTP 422": 1, "HTTP 523": 1} |  | Never read, by the recorded reason (attempted.why). |
| never read: login or payment | 4165 |  | Never read, reason grouped as login or payment. |
| never read: login or payment pct | 21.1 | hosted state files (19764) | Never read for login or payment, of all hosted state files. As a percentage, one decimal. |
| never read: not found | 586 |  | Never read, reason grouped as not found. |
| never read: not found pct | 3.0 | hosted state files (19764) | Never read for not found, of all hosted state files. As a percentage, one decimal. |
| never read: other 4xx | 248 |  | Never read, reason grouped as other 4xx. |
| never read: other 4xx pct | 1.3 | hosted state files (19764) | Never read for other 4xx, of all hosted state files. As a percentage, one decimal. |
| never read: 5xx | 262 |  | Never read, reason grouped as 5xx. |
| never read: 5xx pct | 1.3 | hosted state files (19764) | Never read for 5xx, of all hosted state files. As a percentage, one decimal. |
| never read: network error | 773 |  | Never read, reason grouped as network error. |
| never read: network error pct | 3.9 | hosted state files (19764) | Never read for network error, of all hosted state files. As a percentage, one decimal. |
| never read: protocol | 98 |  | Never read, reason grouped as protocol. |
| never read: protocol pct | 0.5 | hosted state files (19764) | Never read for protocol, of all hosted state files. As a percentage, one decimal. |
| never read: other | 8 |  | Never read, reason grouped as other. |
| never read: other pct | 0.0 | hosted state files (19764) | Never read for other, of all hosted state files. As a percentage, one decimal. |

### C03

| figure | value | denominator | definition |
|---|---|---|---|
| events | 13021 |  | Every change event in the snapshot's events/*.jsonl. |
| hosted events | 12642 |  | Change events of hosted servers. |
| npm events | 379 |  | Change events of npm servers. |
| npm events seeded | 246 |  | npm events carried in from the churn study (`seeded`), not observed by the feed. |
| npm events live | 133 |  | npm events the feed observed. |
| live events | 12775 |  | Every event the feed observed (not seeded). |
| live window start | "2026-09-23T04:23:42+00:00" |  | The earliest observed_at among observed events. |
| live window end | "2026-09-29T07:38:43+00:00" |  | The latest observed_at among observed events. |
| live events per UTC day | {"2026-09-23": 1308, "2026-09-24": 6051, "2026-09-25": 266, "2026-09-26": 2056, "2026-09-27": 2227, "2026-09-28": 491, "2026-09-29": 376} |  | Observed events by the UTC date of observed_at. |
| live hosted events per UTC day | {"2026-09-23": 1267, "2026-09-24": 6028, "2026-09-25": 257, "2026-09-26": 2041, "2026-09-27": 2214, "2026-09-28": 468, "2026-09-29": 367} |  | Observed hosted events by the UTC date of observed_at. |
| live events per UTC day without top three | {"2026-09-23": 182, "2026-09-24": 521, "2026-09-25": 262, "2026-09-26": 562, "2026-09-27": 599, "2026-09-28": 491, "2026-09-29": 370} |  | The same, leaving out the three operators with the most hosted events. |
| busiest hosted day | "2026-09-24" |  | The UTC date with the most observed hosted events. |
| busiest hosted day events | 6028 |  | Observed hosted events on that date. |

### C04

| figure | value | denominator | definition |
|---|---|---|---|
| substantive | 9722 |  | Events of kind substantive (research/feed/operators.py: an event is substantive if a tool was added, removed or changed in substance). |
| numbers-only | 3150 |  | Events of kind numbers-only (research/feed/operators.py: an event is substantive if a tool was added, removed or changed in substance). |
| reorder-only | 149 |  | Events of kind reorder-only (research/feed/operators.py: an event is substantive if a tool was added, removed or changed in substance). |
| unclassified | 0 |  | Events of kind unclassified (research/feed/operators.py: an event is substantive if a tool was added, removed or changed in substance). |
| stats.json kinds | {"numbers-only": 3150, "reorder-only": 149, "substantive": 9722} |  | The kinds stats.json states. |
| recomputed kinds | {"numbers-only": 3150, "reorder-only": 149, "substantive": 9722} |  | The kinds recomputed from both catalogues of every event with research/feed/operators.py. |
| stats.json equals recomputed | true |  | Whether the two agree. |

### C05

| figure | value | denominator | definition |
|---|---|---|---|
| operators | 1260 |  | Distinct operators over every event: a hosted server's registrable domain, an npm package's name (approximate; see stats.json `grouping`). |
| top 1 operator | "pipeworx.io" |  | The operator with the 1. most hosted events. |
| top 1 events | 7023 |  | Hosted events of pipeworx.io. |
| top 1 events of hosted pct | 55.6 | hosted events (12642) | pipeworx.io's share of hosted events. As a percentage, one decimal. |
| top 1 events of all pct | 53.9 | all events (13021) | pipeworx.io's share of all events. As a percentage, one decimal. |
| top 1 kinds | {"numbers-only": 2975, "substantive": 4048} |  | pipeworx.io's events by kind. |
| top 1 events changing each field | {"description": 7022, "inputSchema": 2527, "outputSchema": 1} |  | pipeworx.io's events in which a changed tool's field moved, per field (one event counts once per field). |
| top 1 servers | 1522 |  | Distinct hosted servers of pipeworx.io with an event. |
| top 1 whole-catalogue events | 0 |  | pipeworx.io's events marked whole_catalogue (every tool changed at once). |
| top 1 whole-catalogue events pct | 0.0 | pipeworx.io's hosted events (7023) | The same, of the operator's hosted events. As a percentage, one decimal. |
| top 2 operator | "nolimit-observatory.workers.dev" |  | The operator with the 2. most hosted events. |
| top 2 events | 2341 |  | Hosted events of nolimit-observatory.workers.dev. |
| top 2 events of hosted pct | 18.5 | hosted events (12642) | nolimit-observatory.workers.dev's share of hosted events. As a percentage, one decimal. |
| top 2 events of all pct | 18.0 | all events (13021) | nolimit-observatory.workers.dev's share of all events. As a percentage, one decimal. |
| top 2 kinds | {"substantive": 2341} |  | nolimit-observatory.workers.dev's events by kind. |
| top 2 events changing each field | {"inputSchema": 2341} |  | nolimit-observatory.workers.dev's events in which a changed tool's field moved, per field (one event counts once per field). |
| top 2 servers | 2341 |  | Distinct hosted servers of nolimit-observatory.workers.dev with an event. |
| top 2 whole-catalogue events | 2341 |  | nolimit-observatory.workers.dev's events marked whole_catalogue (every tool changed at once). |
| top 2 whole-catalogue events pct | 100.0 | nolimit-observatory.workers.dev's hosted events (2341) | The same, of the operator's hosted events. As a percentage, one decimal. |
| top 3 operator | "a2awire.com" |  | The operator with the 3. most hosted events. |
| top 3 events | 424 |  | Hosted events of a2awire.com. |
| top 3 events of hosted pct | 3.4 | hosted events (12642) | a2awire.com's share of hosted events. As a percentage, one decimal. |
| top 3 events of all pct | 3.3 | all events (13021) | a2awire.com's share of all events. As a percentage, one decimal. |
| top 3 kinds | {"substantive": 424} |  | a2awire.com's events by kind. |
| top 3 events changing each field | {"outputSchema": 424, "inputSchema": 106, "description": 47} |  | a2awire.com's events in which a changed tool's field moved, per field (one event counts once per field). |
| top 3 servers | 106 |  | Distinct hosted servers of a2awire.com with an event. |
| top 3 whole-catalogue events | 0 |  | a2awire.com's events marked whole_catalogue (every tool changed at once). |
| top 3 whole-catalogue events pct | 0.0 | a2awire.com's hosted events (424) | The same, of the operator's hosted events. As a percentage, one decimal. |
| top three events | 9788 |  | Hosted events of the top three operators together. |
| top three of hosted pct | 77.4 | hosted events (12642) | The top three's share of hosted events. As a percentage, one decimal. |
| top three of all pct | 75.2 | all events (13021) | The top three's share of all events. As a percentage, one decimal. |
| hosted servers changed | 5257 |  | Distinct hosted servers with at least one event. |
| median changes per changed hosted server | 1 |  | The median number of events per hosted server with at least one. |
| hosted servers with exactly one change | 3107 |  | Hosted servers with exactly one event. |
| changes per changed hosted server | {"1": 3107, "2": 277, "3-5": 1789, "6-10": 61, "11-100": 23, "over 100": 0} |  | Hosted servers with at least one event, by how many they had. |
| hosted events outside top three | 2854 |  | Hosted events of every other operator. |
| hosted servers outside top three | 1288 |  | Distinct hosted servers with an event, outside the top three operators. |

### C06

| figure | value | denominator | definition |
|---|---|---|---|
| review | 66 |  | Events the collector graded review: a change introduced a signal (heldfast.driftgrade). |
| quiet | 12955 |  | Events graded quiet. |
| review by introduced kind | {"credential-path": 2, "critical-word": 2, "price": 58, "signal:concealment": 1, "signal:exfiltration": 2, "signal:mandated-side-effect": 2, "signal:override": 1} |  | Review events per kind of signal introduced; an event with several kinds counts once under each. |
| price review events | 58 |  | Review events that introduced a price. |
| price review servers | 41 |  | Distinct servers with such an event. |
| first price review | "2026-09-27T12:30:45+00:00" |  | The earliest observed_at of a review event that introduced a price. |
| review without price | 8 |  | Review events that introduced no price; each is listed in research/report/review-events.md. |

### C07

| figure | value | denominator | definition |
|---|---|---|---|
| servers with a stated price changed | 64 |  | Servers with an observed event in which a stated price was changed (amounts found by heldfast.driftgrade's price patterns, per unit, in the description, title and schema text of a changed or added tool). A stated amount can be an example rather than the server's charge. |
| servers with a stated price added to a tool | 45 |  | Servers with an observed event in which a stated price was added to a tool (amounts found by heldfast.driftgrade's price patterns, per unit, in the description, title and schema text of a changed or added tool). A stated amount can be an example rather than the server's charge. |
| servers with a stated price removed from a tool | 18 |  | Servers with an observed event in which a stated price was removed from a tool (amounts found by heldfast.driftgrade's price patterns, per unit, in the description, title and schema text of a changed or added tool). A stated amount can be an example rather than the server's charge. |
| servers with a stated price on a new tool | 82 |  | Servers with an observed event in which a stated price was on a new tool (amounts found by heldfast.driftgrade's price patterns, per unit, in the description, title and schema text of a changed or added tool). A stated amount can be an example rather than the server's charge. |
| servers with a readable price change | 16 |  | Servers with at least one tool whose single stated price in a unit became a different single price in that unit. |
| readable price pairs | 414 |  | Such before-and-after pairs, per tool and event, over every server. |
| servers by direction | {"both": 3, "down": 10, "up": 3} |  | Servers with a readable change, by whether every pair rose, every pair fell, or both. |
| server with most pairs | "remote/io.github.rccola990-cloud/x402-agent-store" |  | The server carrying the most readable pairs. |
| pairs on that server | 285 |  | Readable pairs on that server. |
| pairs on that server pct | 68.8 | readable price pairs (414) | That server's share of all readable pairs. As a percentage, one decimal. |
| most servers with a stated price changed in four days | 55 |  | The largest number of servers with a stated price changed (as above) within any 4 consecutive UTC days. |
| that four-day window starts | "2026-09-24" |  | The first day of that window. |
| most servers with a readable price change in four days | 15 |  | The same, counting only readable changes (one price became another). |
| that readable four-day window starts | "2026-09-24" |  | The first day of that window. |
| servers with a price at least tripled | 4 |  | Servers with a readable pair whose new price is three or more times the old. |
| claim of 23 servers in four days reproduced | false |  | Whether at least 23 servers had a readable price change within four days and at least one price at least tripled. Counting any change in stated amounts instead is the figure two above. |

### C08

| figure | value | denominator | definition |
|---|---|---|---|
| distinct definitions | 230763 |  | Entries in lookup/all.json: distinct tool definitions the log has recorded. |
| definitions on exactly one server | 217985 |  | Of those, the ones recorded on exactly one server. |

### C09

| figure | value | denominator | definition |
|---|---|---|---|
| checkpoints | {"2026-09-27": [".json", ".json.ots"], "2026-09-28": [".json", ".json.ots", ".json.sigstore.json"]} |  | Checkpoints in the snapshot tree, with the files each has (.json, .json.ots, .json.sigstore.json). The snapshot's own checkpoint is written after its commit, so it is not in its tree. |

### C10

| figure | value | denominator | definition |
|---|---|---|---|
| packages | 109 |  | Churn study, third-party servers: packages, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| release pairs | 522 |  | Churn study, third-party servers: release pairs, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| pin stops | 235 |  | Churn study, third-party servers: pin stops, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| pin stops pct | 45 |  | Churn study, third-party servers: pin stops pct, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| reword | 150 |  | Churn study, third-party servers: reword, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| reword pct | 29 |  | Churn study, third-party servers: reword pct, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| description edits | 616 |  | Churn study, third-party servers: description edits, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| introduced anything | 25 |  | Churn study, third-party servers: introduced anything, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| above 0.5 | 4 |  | Churn study, third-party servers: above 0.5, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| above 0.5 releases | 3 |  | Churn study, third-party servers: above 0.5 releases, from analyse.py rerun (or suspicious.json, which needs results/ that are not committed to rerun). |
| matches docs/CHURN.md | true |  | Whether every figure above equals the one docs/CHURN.md states. |

### C11

| figure | value | denominator | definition |
|---|---|---|---|
| scan tools | 240464 |  | Tools the scan study read, quoted from docs/SCAN.md (data of 2026-09-23), not recomputed. |
| scan servers | 13170 |  | Servers it read, quoted. |
| scan hosted | 12171 |  | Of them hosted, quoted. |
| scan npm | 999 |  | Of them npm, quoted. |
| scan feed commit | "87b7b05ace47" |  | The heldfast-feed commit docs/SCAN.md names as its data. |
