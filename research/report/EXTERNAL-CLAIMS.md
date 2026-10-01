# External claims in the README and docs

Every factual claim in `README.md` and `docs/*.md` that rests on someone
else's work, checked against a primary source. Line numbers are as of commit
`ff695b6`, before the corrections listed under each claim. Accessed 2026-10-01.

Verdicts: **supported**, **partly supported** (true in substance, wrong in a
detail, or broader than the source), **unsupported**. No claim is left unknown.

Claims about this project's own measurements (counts of servers, events,
coverage) are not here: they come from `research/report/numbers.json`.

## E01. Invariant Labs, tool poisoning

- **Text.** README.md:187 "[Invariant Labs, 6 April 2025](...) showed tool poisoning:
  hidden instructions in a tool description." TOOL-POISONING.md:3-5 says the same.
- **Source.** https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- **Verdict.** Partly supported. The post describes exactly this attack, but it is
  dated **1 April 2025**, not 6 April.
- **Action.** Date corrected in README.md.

## E02. Invariant Labs, WhatsApp

- **Text.** README.md:188-190 "A day later they showed a second, untrusted MCP
  server sitting beside a trusted WhatsApp MCP instance, shadowing its tools to
  exfiltrate chats." TOOL-POISONING.md:3 "two MCP attacks a day apart".
- **Source.** https://invariantlabs.ai/blog/whatsapp-mcp-exploited, dated 7 April 2025.
- **Verdict.** Partly supported. The attack is as described; the posts are six days
  apart, not one.
- **Action.** "A day later" and "a day apart" corrected to six days.

## E03. The 5.5% figure

- **Text.** CHURN.md:4-6 "Invariant Labs ... has since reported that 5.5% of public
  MCP servers carry tool-poisoning payloads." SCAN.md:169 "the widely cited figure
  that 5.5% of public MCP servers carry poisoning payloads".
- **Source.** Hasan, Li, Fallahzadeh, Rajbahadur, Adams, Hassan, *Model Context
  Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP
  Servers*, arXiv:2506.13538, 16 June 2025: of 1,899 open-source MCP servers,
  "5.5% exhibit MCP-specific tool poisoning". Neither Invariant Labs post contains it.
- **Verdict.** Unsupported as attributed. The number is real; the author is not
  Invariant Labs, and the population is 1,899 open-source servers, not "public MCP
  servers".
- **Action.** CHURN.md re-attributes it with the population. SCAN.md names and
  links the study.

## E04. postmark-mcp 1.0.16

- **Text.** MANUAL.md:1463 "postmark-mcp 1.0.16 copied every email it sent to its
  author". TRANSPARENCY.md:7 "the postmark-mcp backdoor".
- **Source.** OSV MAL-2025-47604 (published 2025-09-26): "turned malicious in v1.0.16
  and exfiltrates email data via BCC", citing
  https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft.
- **Verdict.** Supported.

## E05. Shai-Hulud releases of Postman's, Browserbase's and AntV's servers

- **Text.** MANUAL.md:1464-1465 "the Shai-Hulud npm worms put an install hook into
  releases of Postman's, Browserbase's and AntV's official servers". Also
  TRANSPARENCY.md:6, src/heldfast/advisories.py.
- **Source.** OSV MAL-2025-190909 (`@postman/postman-mcp-server` 2.4.10-2.4.12),
  MAL-2025-191196 (`@browserbasehq/mcp-server-browserbase` 2.4.2), MAL-2025-191195
  (`@browserbasehq/mcp` 2.1.1), all citing the Shai-Hulud 2.0 reports
  (https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack); MAL-2026-4069
  (`@antv/mcp-server-chart` 0.10.10, 0.11.10): "Mini Shai-Hulud ... injects a
  `preinstall` hook".
- **Verdict.** Supported. AntV's was the later "Mini Shai-Hulud" campaign; "the
  Shai-Hulud npm worms", plural, covers both.

## E06. The "local-only" scanner that uploaded code

- **Text.** MANUAL.md:1465-1466 "a scanner that promised your code never left the
  machine uploaded it". TRANSPARENCY.md:7.
- **Source.** OSV MAL-2026-4675 (`supership-scan` 1.0.0, published 2026-05-20):
  the README said "Runs locally. Your code never leaves the machine"; the code
  did not.
- **Verdict.** Supported.

## E07. Reporting delay

- **Text.** MANUAL.md:1472-1473 "every one of those five was reported within nine
  days, the worm releases within one".
- **Source.** npm publish time against OSV `published`:

  | release | on npm | in OSV | delay |
  |---|---|---|---|
  | postmark-mcp 1.0.16 | 2025-09-17 08:59Z | 2025-09-26 04:14Z | 8.8 days |
  | @postman/postman-mcp-server 2.4.10 | 2025-11-24 05:04Z | 2025-11-24 16:31Z | 11 h |
  | @browserbasehq/mcp-server-browserbase 2.4.2 | 2025-11-24 12:56Z | 2025-11-25 00:16Z | 11 h |
  | @antv/mcp-server-chart 0.10.10 | 2026-05-19 01:56Z | 2026-05-19 (date only) | same day |
  | supership-scan 1.0.0 | 2026-05-18 14:08Z | 2026-05-20 22:01Z | 2.3 days |

- **Verdict.** Supported.

## E08. "Every malicious MCP release so far changed code"

- **Text.** MANUAL.md:1462 "Every malicious MCP server release found so far changed
  code and left the tools alone". TRANSPARENCY.md:5 "That is how every malicious MCP
  release so far was caught". README first screen (before 99f63dd) "Every malicious
  MCP release so far changed code, not tool text".
- **Source.** E04 to E06 cover five releases. No source enumerates every malicious
  MCP release, so "every ... so far" cannot be checked.
- **Verdict.** Partly supported: true of the five named, unverifiable as a universal.
- **Action.** README already narrowed to "reported so far" (99f63dd). MANUAL.md and
  TRANSPARENCY.md narrowed to the releases named.

## E09. OSV's sources

- **Text.** MANUAL.md:1467-1468 OSV "carries the OpenSSF malicious-package reports
  and GitHub's advisories".
- **Source.** https://google.github.io/osv.dev/data/ lists both the GitHub Advisory
  Database and OpenSSF Malicious Packages as current data sources.
- **Verdict.** Supported.

## E10. Certificate Transparency history

- **Text.** TRANSPARENCY.md:26-31 "Around 2011, certificate authorities were issuing
  certificates for sites like google.com to people who were not Google, and nobody
  could see it happening: each fake was shown only to its victims. ... browsers
  refuse one the log has not seen."
- **Source.** Google, *An update on attempted man-in-the-middle attacks*, 29 August
  2011 (https://security.googleblog.com/2011/08/update-on-attempted-man-in-middle.html):
  a fraudulent DigiNotar certificate for google.com used against users mainly in
  Iran; Mozilla, *Fraudulent \*.google.com Certificate*
  (https://blog.mozilla.org/security/2011/08/29/fraudulent-google-com-certificate/);
  RFC 6962 (2013). https://certificate.transparency.dev/howctworks/ : "Both Safari
  and Chrome user agents require at least 2 SCTs".
- **Verdict.** Partly supported. The mis-issuance is documented. But Chrome caught
  the DigiNotar certificate through key pinning, so "nobody could see it" is too
  strong. And browsers require proof that a certificate was logged (SCTs), which is
  close to, but not exactly, checking the log.
- **Action.** TRANSPARENCY.md now says the fake came to light only because it was
  used against users and Chrome pinned Google's keys, and that browsers require
  proof of logging.

## Not external

These read like outside facts but are this project's measurements. They are
stale and are refreshed from `numbers.json` in Step 3, not here:
TRANSPARENCY.md:10-15 (27,985 watched, 18,576 hosted, about 5,400 changes in a
day); README.md:15 and :90 ("two in three").
