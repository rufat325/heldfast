# MCP server tool changes

Last change observed 2026-09-23T15:59:41+00:00. Built by `research/feed/watch.py` on the `main` branch. Watching 9409 npm servers from the official MCP registry (154 daily, the rest weekly) and 18576 hosted endpoints (daily).

273 releases that changed a tool definition (27 observed live, 246 from the [churn study](https://github.com/rufat325/mcp-pin/blob/main/docs/CHURN.md)); 3 where `mcp-pin wrap --drift graded` would refuse something.

Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, with the words that moved: [events/](events).

`quiet`: a graded pin forwards every changed tool (new tools still need approval). `review`: a change introduced an agent-directed instruction, hidden character, credential path or look-alike letter. Review means read it, not that it is hostile.

| published | server | release | tools | grade |
|---|---|---|---|---|
| 2026-09-23 | `@mobilenext/mobile-mcp` | 1.0.4 -> 1.0.5 | 32 changed (every tool) | quiet |
| 2026-09-23 | `@togglhq/mcp` | 1.11.39 -> 1.11.40 | 9 changed, 1 removed | quiet |
| 2026-09-23 | `firecrawl-mcp` | 3.25.3 -> 3.25.4 | 2 changed | quiet |
| 2026-09-23 | `@zereight/mcp-gitlab` | 2.1.65 -> 2.1.66 | 118 changed (every tool) | quiet |
| 2026-09-23 | `@togglhq/mcp` | 1.11.37 -> 1.11.39 | 1 changed, 1 added | quiet |
| 2026-09-23 | `hermoso` | 0.1.272 -> 0.1.273 | 1 changed | quiet |
| 2026-09-23 | `mongodb-mcp-server` | 3.0.4 -> 2.1.2 | 27 changed (every tool) | quiet |
| 2026-09-23 | `@shipstatic/mcp` | 2.0.0 -> 2.1.0 | 1 changed | quiet |
| 2026-09-23 | `gdharness` | 1.0.21 -> 1.0.22 | 1 changed | quiet |
| 2026-09-23 | `gdharness` | 1.0.17 -> 1.0.21 | 2 changed | quiet |
| 2026-09-23 | `githits` | 0.21.0 -> 0.22.0 | 1 changed | quiet |
| 2026-09-23 | `chrome-devtools-mcp` | 1.9.0 -> 1.10.1 | 29 changed, 1 added (every tool) | quiet |
| 2026-09-23 | `run402-mcp` | 4.98.0 -> 4.101.0 | 8 changed (every tool) | quiet |
| 2026-09-23 | `premiere-pro-mcp` | 1.17.0 -> 1.18.0 | 5 changed | quiet |
| 2026-09-23 | `memorix` | 1.9.5 -> 1.9.6 | 1 changed | quiet |
| 2026-09-23 | `@wdio/mcp` | 3.13.0 -> 3.14.0 | 3 changed, 1 added | quiet |
| 2026-09-23 | `@cyanheads/pubmed-mcp-server` | 2.10.16 -> 2.10.18 | 1 changed | quiet |
| 2026-09-23 | `@cyanheads/pubmed-mcp-server` | 2.10.14 -> 2.10.16 | 11 changed (every tool) | quiet |
| 2026-09-23 | `hermoso` | 0.1.270 -> 0.1.272 | 3 changed | quiet |
| 2026-09-23 | `run402-mcp` | 4.93.2 -> 4.98.0 | 3 changed, 4 added, 212 removed | quiet |
| 2026-09-23 | `gdharness` | 1.0.13 -> 1.0.17 | 3 changed | quiet |
| 2026-09-23 | `@oracle-agent/oracle` | 0.35.47 -> 0.35.48 | 2 added | quiet |
| 2026-09-23 | `obsidian-mcp-server` | 3.5.4 -> 3.5.5 | 6 changed | quiet |
| 2026-09-22 | `clinicaltrialsgov-mcp-server` | 2.9.8 -> 2.9.10 | 3 changed | quiet |
| 2026-09-22 | `@togglhq/mcp` | 1.11.30 -> 1.11.34 | 1 changed | quiet |
| 2026-09-22 | `firecrawl-mcp` | 3.25.2 -> 3.25.3 | 4 changed | quiet |
| 2026-09-22 | `trace-mcp` | 3.31.2 -> 3.31.3 | 7 changed | quiet |
| 2026-09-22 | `@togglhq/mcp` | 1.11.28 -> 1.11.29 | 8 changed | quiet |
| 2026-09-22 | `agent-device` | 0.21.11 -> 0.21.12 | 1 changed | quiet |
| 2026-09-22 | `gdharness` | 1.0.11 -> 1.0.12 | 6 changed | quiet |
| 2026-09-22 | `@togglhq/mcp` | 1.11.26 -> 1.11.27 | 8 changed | quiet |
| 2026-09-22 | `tokportal-mcp` | 1.17.0 -> 1.17.1 | 2 changed | quiet |
| 2026-09-22 | `tokportal-mcp` | 1.16.0 -> 1.17.0 | 5 changed, 1 added | quiet |
| 2026-09-22 | `@sap-ux/fiori-mcp-server` | 1.12.13 -> 1.13.0 | 2 changed | quiet |
| 2026-09-22 | `gdharness` | 1.0.10 -> 1.0.11 | 5 changed | quiet |
| 2026-09-22 | `ssh-mcp` | 2.10.0 -> 2.11.0 | 1 changed | quiet |
| 2026-09-22 | `gdharness` | 1.0.9 -> 1.0.10 | 1 changed | quiet |
| 2026-09-22 | `@alisaitteke/photoshop-mcp` | 1.7.19 -> 1.7.20 | 2 changed | quiet |
| 2026-09-22 | `agent-device` | 0.21.8 -> 0.21.9 | 3 changed | quiet |
| 2026-09-22 | `githits` | 0.20.0 -> 0.21.0 | 4 changed | quiet |
| 2026-09-22 | `premiere-pro-mcp` | 1.16.4 -> 1.17.0 | 9 changed, 3 added | quiet |
| 2026-09-22 | `ssh-mcp` | 2.9.1 -> 2.10.0 | 5 changed | quiet |
| 2026-09-22 | `firecrawl-mcp` | 3.25.1 -> 3.25.2 | 3 changed | quiet |
| 2026-09-22 | `hermoso` | 0.1.268 -> 0.1.269 | 6 changed | quiet |
| 2026-09-22 | `aiterm-mcp` | 0.37.10 -> 0.38.0 | 6 changed | quiet |
| 2026-09-22 | `firecrawl-mcp` | 3.25.0 -> 3.25.1 | 3 changed | quiet |
| 2026-09-22 | `firecrawl-mcp` | 3.24.0 -> 3.25.0 | 25 changed, 2 added (every tool) | quiet |
| 2026-09-22 | `hermoso` | 0.1.265 -> 0.1.267 | 1 changed | quiet |
| 2026-09-21 | `hermoso` | 0.1.264 -> 0.1.265 | 40 changed | quiet |
| 2026-09-21 | `@dbx-app/mcp-server` | 0.4.92 -> 0.4.93 | 2 changed | quiet |
| 2026-09-21 | `@getbourdon/mcp-server` | 0.7.0 -> 0.8.0 | 7 added | quiet |
| 2026-09-21 | `@postman/postman-mcp-server` | 2.12.3 -> 2.13.0 | 4 changed | quiet |
| 2026-09-21 | `@sap-ux/fiori-mcp-server` | 1.12.7 -> 1.12.9 | 2 changed | review |
| 2026-09-21 | `@alisaitteke/photoshop-mcp` | 1.7.17 -> 1.7.18 | 9 changed, 6 added | quiet |
| 2026-09-21 | `@cloudbase/cloudbase-mcp` | 2.34.5 -> 2.34.6 | 4 changed | quiet |
| 2026-09-21 | `agent-device` | 0.21.7 -> 0.21.8 | 1 changed, 1 added | quiet |
| 2026-09-21 | `@shipstatic/mcp` | 1.12.4 -> 2.0.0 | 4 changed | quiet |
| 2026-09-21 | `sbuilder-mcp` | 0.62.0 -> 0.63.0 | 2 changed, 1 added | quiet |
| 2026-09-21 | `@qase/mcp-server` | 2.5.1 -> 2.6.0 | 1 changed, 3 added | quiet |
| 2026-09-21 | `@cap-js/mcp-server` | 0.0.5 -> 0.0.6 | 1 changed | quiet |
