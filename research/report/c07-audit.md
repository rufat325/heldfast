# Audit of C07 (readable price pairs), 2 October 2026

Hand classification of every pair behind C07 on the report's snapshot (feed
commit 08a6e310, 13,021 events). It reproduces numbers.json exactly: 414 pairs,
16 servers, 4 with a price at least tripled. `audit_c07.py` lists the pairs;
`audit_c07.json` holds all 414 with the words around each amount.

  python research/report/audit_c07.py ../feed-snapshot research/report/audit_c07.json

How the pairs were classified: mechanically, by whether the words around the
amount are the same on both sides once numbers are ignored (400 of 414 are);
then by reading every pair whose words differ beyond a number (14), and a sample
of the rest. A pair is **L** (like-for-like: the same per-call or per-item charge
on both sides), **D** (a different kind of amount) or **U** (unclear).

## The 4 servers behind "at least tripled"

| server | pairs tripled / pairs | example (old → new, words around) | class |
|---|---|---|---|
| com.oliverkiss/agentic-endpoints | 5 / 12 | `Costs $0.001 in USDC on Base` → `Costs $0.005 in USDC on Base` (also 0.001→0.01, 0.003→0.01) | L |
| io.github.rccola990-cloud/x402-agent-store | 117 / 285 | `$0.02 via x402: live AI category ranking` → `$0.09 via x402: live AI category ranking` | L |
| online.x-402/mcp | 13 / 73 | `$0.001/call, paid per request via x402 (USDC)` → `$0.005000/call, paid per request via x402 (USDC)` | L |
| world.agentindex/x402 | 1 / 1 | `exactly one atomic unit of USDC ($0.000001)` → `settle $0.001 of USDC` (x402_echo) | L, with a caveat |

The caveat on world.agentindex: both amounts are what the one conformance call settles, so they are the same kind of amount, but the first is "exactly one atomic unit of USDC ($0.000001)" and the second a round "$0.001". The text does not show whether that is a change or a rewording. It is the only pair behind that server's place in the "tripled" count; the other three are per-call rises on many tools.

## The 16 readable-change servers

| server | pairs | what the words around the amounts show | class |
|---|---|---|---|
| rccola990-cloud/x402-agent-store | 285 (19 events) | `$X via x402: <same tool blurb>` both sides, 15 tools | L |
| online.x-402/mcp | 73 | `$X/call, paid per request via x402 (USDC)`; 72 identical slots, 1 (`search`) differs only by the words cut either side | L |
| com.oliverkiss/agentic-endpoints | 12 | `Costs $X in USDC on Base` | L |
| app.apiguru/amazon-data | 10 | `Price: $0.01 per call` → `Price: $0.003 per call`; `$0.015 per item (max 10)` → `$0.0045 per item` | L |
| xyz.apexfaucet/apex-x1 | 6 | 5 are `$1` → `$0.025` / `$0.009 per call` / `$0.14` / `$0.004` for the same endpoint. **`leads_verify_domains`: `$1 per call` → `$0.20 per 1,000 domains, from prepaid credits`** | 5 L, 1 **D** (basis changed: per call to per 1,000 domains) |
| moralito311-andr/andreax | 6 (5 events) | `[x402: 0.02 USDC on Base, pay-per-use]` → `0.03 USDC` etc.; the words differ only because the tool text was rewritten around it | L |
| foxxx009/x402-tools-mcp | 6 | `$0.02 per call — Domain due-diligence bundle` → `$0.005 per call — …`; `$3` → `$0.12` | L |
| org.californiabitcoin/agent-commerce | 5 | `PAID 0.50 USD via MPP` → `PAID 0.10 USD via MPP` | L |
| MikeyPetrillo/agent402 | 3 | `[wallet-required, $0.02/call]` → `$0.01/call` | L |
| erickmckee/klearflow-relay | 2 | `Execution costs $0.25 by default via x402` → `Launch execution costs $0.01 via x402` (wording around changed, same "execution" charge) | L |
| com.odilelabs/odile | 1 | `Video is a 1-2 credit range per output…` (2.0) → `…cost exactly 1 credit each; YouTube 16:9 costs 1 or…` (1.0) | **U** (an upper bound of a range against an exact figure) |
| com.davisvillelabs.filmrights/filmrightsproof | 1 | `$2 per completed authorized invocation` → `$0.50 per …` | L |
| com.filmrightsproof/filmrightsproof | 1 | same tool, same words (a second listing of it) | L |
| world.agentindex/x402 | 1 | see above | L, caveat |
| nanoodlecom/nanoodle-mcp | 1 | `$0.63 deposit per call, paid in Nano` → `$0.53 deposit per call` | L |
| statementtobudget/bank-statement-converter | 1 | `buy the full file for $4.99` → `$9.99` | L |

Totals over the 414 pairs: 412 L, 1 D (apex-x1 `leads_verify_domains`), 1 U (odile). I read all 14 pairs whose words around the amount differ beyond a number, and a sample of the rest.

Not among these pairs: the apex-arc case (`about 0.004 USDC of gas` → `costs $0.99`). It happened on 2026-10-01, after the report's snapshot (2026-09-29), so the published 414 pairs do not contain it. It is exactly the kind of pair the pairing rule would let through, so the same hole exists; it had not yet been hit in the report's window.

## What each published figure does if the two non-L pairs are excluded

| figure | published | without the D and U pairs |
|---|---|---|
| servers with a readable price change | 16 | 15 (odile has no other pair; apex-x1 keeps 5 L pairs) |
| readable pairs | 414 | 412 |
| rccola990 share | 285 = 68.8% | 285/412 = 69.2% |
| servers that fell / rose / both | 10 / 3 / 3 | 9 / 3 / 3 |
| most servers with a readable change in four days | 15 | 14 (odile is inside the window) |
| servers with a price at least tripled | 4 | 4 (neither pair is a rise) |

## Outcome

The two pairs that are not like-for-like are on servers whose price moved down,
so the count of servers that at least tripled a price is unaffected. The report
keeps every figure and says in its Prices paragraph what a pair is and which two
are not like-for-like (docs/FIRST-WEEK.md, "Corrections and clarifications",
2 October 2026). The second table above shows what the figures would be if the
two pairs were left out; none of them is published.

## Pairing rule: units tried apart, not adopted

`numbers.prices()` puts "$x" and "x USDC" in one unit, which lets a gas fee in
USDC pair with a price in dollars (the apex-arc `arc_passport_draft` case of
2026-10-01, after this snapshot). Counting them as separate units was tried on
the snapshot's events and did not leave the figures alone: 426 pairs (not 414),
22 servers with a readable change (not 16) and 5 with a price at least tripled
(not 4); the extra pairs were not examined one by one. It was therefore not
applied. It is for the next report, with its own snapshot and its own count.
