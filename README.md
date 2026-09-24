# MCP server tool changes

Last change observed 2026-09-24T20:28:48+00:00. Built by `research/feed/watch.py` on the `main` branch. Watching 9409 npm servers from the official MCP registry (154 daily, the rest weekly) and 18576 hosted endpoints (daily).

7497 releases that changed a tool definition (7251 observed live, 246 from the [churn study](https://github.com/rufat325/mcp-pin/blob/main/docs/CHURN.md)); 5 where `mcp-pin wrap --drift graded` would refuse something.

Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, with the words that moved: [events/](events).

`quiet`: a graded pin forwards every changed tool (new tools still need approval). `review`: a change introduced an agent-directed instruction, hidden character, credential path or look-alike letter. Review means read it, not that it is hostile.

| published | server | release | tools | grade |
|---|---|---|---|---|
| 2026-09-24 | `remote/com.xoomar/xoomar-mcp` | 2026-09-23T160900103187 -> 2026-09-24T202849325116 | 7 changed | quiet |
| 2026-09-24 | `remote/fit.ilook/face-analysis` | 2026-09-23T160843128425 -> 2026-09-24T202832584258 | 14 changed (every tool) | quiet |
| 2026-09-24 | `remote/io.github.JakubTrousil/agentsjunction` | 2026-09-23T160834292753 -> 2026-09-24T202822796575 | 1 changed, 2 added | quiet |
| 2026-09-24 | `remote/io.github.creator35lwb-web/verifimind-genesis` | 2026-09-23T160823452348 -> 2026-09-24T202810493236 | 13 changed (every tool) | quiet |
| 2026-09-24 | `remote/io.github.brawlaphant/vealth` | 2026-09-23T202413925478 -> 2026-09-24T202809115099 | 1 changed | quiet |
| 2026-09-24 | `remote/ru.zavod-stanki/cnc-catalog` | 2026-09-23T163002028077 -> 2026-09-24T202805671044 | 5 changed, 1 added | quiet |
| 2026-09-24 | `remote/io.github.aanari/loacare-healthcare-pricing` | 2026-09-23T162946133668 -> 2026-09-24T202756592350 | 7 changed | quiet |
| 2026-09-24 | `remote/cc.thecolony/mcp-server` | 2026-09-23T160809712524 -> 2026-09-24T202756874098 | 1 changed | quiet |
| 2026-09-24 | `remote/com.ikeytz/website` | 2026-09-24T120504419055 -> 2026-09-24T202755083788 | 8 changed | quiet |
| 2026-09-24 | `remote/fi.akkilahdot/travel-search` | 2026-09-24T120454072251 -> 2026-09-24T202749065228 | 1 changed | quiet |
| 2026-09-24 | `remote/org.websitestarter/website-starter` | 2026-09-23T162927936676 -> 2026-09-24T202744700775 | 2 changed | quiet |
| 2026-09-24 | `remote/social.walletlink/wallet-identity` | 2026-09-24T120447020696 -> 2026-09-24T202743896221 | 3 changed | quiet |
| 2026-09-24 | `remote/io.github.Embassy-of-the-Free-Mind/sourcelibrary` | 2026-09-23T160755455077 -> 2026-09-24T202743478937 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.thinksuitesolution-coder/visibilityai` | 2026-09-23T162926056451 -> 2026-09-24T202744395235 | 7 added | quiet |
| 2026-09-24 | `remote/io.github.Schoasch/backtesting-arena` | 2026-09-24T120435372162 -> 2026-09-24T202734239723 | 3 changed | quiet |
| 2026-09-24 | `remote/io.github.JustJuice55/telegram-catalog` | 2026-09-23T162909866204 -> 2026-09-24T202729164086 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.cyanheads/sanctions-screening-mcp-server` | 2026-09-23T160736869982 -> 2026-09-24T202727410041 | 2 changed | quiet |
| 2026-09-24 | `remote/io.github.IO31-WEB/synapse-lounge` | 2026-09-23T202425197606 -> 2026-09-24T202727155459 | 1 changed, 21 added | quiet |
| 2026-09-24 | `remote/io.github.socialloopai/socialloop-mcp.1` | 2026-09-24T120417616419 -> 2026-09-24T202716696002 | 1 changed | quiet |
| 2026-09-24 | `remote/com.quintadb/mcp` | 2026-09-23T160728854630 -> 2026-09-24T202718172165 | 1 changed | quiet |
| 2026-09-24 | `remote/com.seqbench/workbench` | 2026-09-24T120408578701 -> 2026-09-24T202709365254 | 1 changed, 2 added | quiet |
| 2026-09-24 | `remote/com.powmcp/epub-check` | 2026-09-23T160721994322 -> 2026-09-24T202710457750 | 2 changed (every tool) | quiet |
| 2026-09-24 | `remote/io.github.davidgringras/scrutica` | 2026-09-23T162842770332 -> 2026-09-24T202707272640 | 1 changed | quiet |
| 2026-09-24 | `remote/com.plainrouter/mcp` | 2026-09-23T160718454738 -> 2026-09-24T202708329227 | 1 changed, 1 added, 1 removed | quiet |
| 2026-09-24 | `remote/wine.spillthe.www/wineries` | 2026-09-23T161036563356 -> 2026-09-24T202705440963 | 1 changed | quiet |
| 2026-09-24 | `remote/se.sistaminuten/travel-search` | 2026-09-24T120340326838 -> 2026-09-24T202704248467 | 1 changed | quiet |
| 2026-09-24 | `remote/ai.snowsure/snow` | 2026-09-23T161035714227 -> 2026-09-24T202704400360 | 2 changed | quiet |
| 2026-09-24 | `remote/guide.peopleleader/guide-registry` | 2026-09-23T160715047639 -> 2026-09-24T202702987554 | 3 added, 1 removed | quiet |
| 2026-09-24 | `remote/com.remoshift/jobs` | 2026-09-24T120356912308 -> 2026-09-24T202659869345 | 1 changed | quiet |
| 2026-09-24 | `remote/com.pakistancaselaw/caselaw` | 2026-09-23T160710456516 -> 2026-09-24T202700014452 | 1 changed | quiet |
| 2026-09-24 | `remote/io.engineeringleaders/elc-partnership-builder` | 2026-09-23T161025381696 -> 2026-09-24T202655923639 | 1 changed | quiet |
| 2026-09-24 | `remote/com.contrie/contrie` | 2026-09-23T202527535474 -> 2026-09-24T202654031042 | 8 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.blitzreels/blitzreels` | 2026-09-23T161022985167 -> 2026-09-24T202654167636 | 5 changed | quiet |
| 2026-09-24 | `remote/net.pifini/pifini` | 2026-09-23T162817275347 -> 2026-09-24T202646503602 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.austin-starks/nexustrade-mcp` | 2026-09-24T120251084836 -> 2026-09-24T202646548026 | 3 changed | quiet |
| 2026-09-24 | `remote/bg.namerimidom/namerimidom` | 2026-09-23T160651105562 -> 2026-09-24T202644015011 | 1 changed | quiet |
| 2026-09-24 | `remote/org.texs/tapercraft` | 2026-09-23T161007319873 -> 2026-09-24T202640901738 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.cyanheads/osv-advisory-mcp-server` | 2026-09-23T162807807820 -> 2026-09-24T202638589003 | 4 changed (every tool) | quiet |
| 2026-09-24 | `remote/il.co.moroc/morocco-travel` | 2026-09-23T160646456308 -> 2026-09-24T202640190202 | 1 changed | quiet |
| 2026-09-24 | `remote/mu.micro/mu` | 2026-09-24T120240270489 -> 2026-09-24T202635396825 | 1 changed, 2 added | quiet |
| 2026-09-24 | `remote/com.odilelabs/odile` | 2026-09-24T120325289543 -> 2026-09-24T202633257157 | 6 changed | quiet |
| 2026-09-24 | `remote/io.github.newspacemarket-com/mrd` | 2026-09-23T202324487993 -> 2026-09-24T202628425748 | 2 changed, 1 added | quiet |
| 2026-09-24 | `remote/ai.undetectedgpt/humanizer` | 2026-09-23T163148614866 -> 2026-09-24T202627862029 | 1 changed | quiet |
| 2026-09-24 | `remote/com.tudetic/product-search` | 2026-09-23T163149176951 -> 2026-09-24T202628106563 | 3 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.multicinesortega/cartelera` | 2026-09-24T120317589738 -> 2026-09-24T202625767514 | 1 changed | quiet |
| 2026-09-24 | `remote/com.windowsforum/mcp-server` | 2026-09-23T160632569199 -> 2026-09-24T202623964141 | 8 changed | quiet |
| 2026-09-24 | `remote/no.restplass/travel-search` | 2026-09-24T120443356637 -> 2026-09-24T202622456606 | 1 changed | quiet |
| 2026-09-24 | `remote/com.victano/victano` | 2026-09-24T120225567450 -> 2026-09-24T202621415877 | 7 changed (every tool) | quiet |
| 2026-09-24 | `remote/io.github.cyanheads/medical-codes-mcp-server` | 2026-09-23T162747601972 -> 2026-09-24T202615585756 | 6 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.thepantrybutler/pantry` | 2026-09-23T160949426078 -> 2026-09-24T202614190907 | 6 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.sonarconnections/sonar-connections` | 2026-09-24T120307428407 -> 2026-09-24T202613969930 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.mzahir/tellandgo-mcp` | 2026-09-24T120216237582 -> 2026-09-24T202613012034 | 2 changed | quiet |
| 2026-09-24 | `remote/fyi.barcelona-rent/mcp` | 2026-09-23T163126126356 -> 2026-09-24T202612328167 | 1 added | quiet |
| 2026-09-24 | `remote/dk.afbudsrejser/travel-search` | 2026-09-24T120430820119 -> 2026-09-24T202609207416 | 1 changed | quiet |
| 2026-09-24 | `remote/ai.wem3/wem-price-compare` | 2026-09-23T163111996345 -> 2026-09-24T202605100289 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.sailorpepe/undesirables-mcp-server` | 2026-09-23T162733576511 -> 2026-09-24T202602567349 | 1 changed | quiet |
| 2026-09-24 | `remote/com.rekvira/rekvira` | 2026-09-23T160606770949 -> 2026-09-24T202559569168 | 17 changed (every tool) | quiet |
| 2026-09-24 | `remote/store.scvd/general-store` | 2026-09-23T160931032041 -> 2026-09-24T202554116740 | 7 changed | quiet |
| 2026-09-24 | `remote/com.senzing/mcp` | 2026-09-23T162727138070 -> 2026-09-24T202554790629 | 1 changed | quiet |
| 2026-09-24 | `remote/xyz.trusteed/mcp-gateway` | 2026-09-24T120414717688 -> 2026-09-24T202553594916 | 3 changed | quiet |
