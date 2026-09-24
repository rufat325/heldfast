# MCP server tool changes

Last change observed 2026-09-24T12:05:15+00:00. Built by `research/feed/watch.py` on the `main` branch. Watching 9409 npm servers from the official MCP registry (154 daily, the rest weekly) and 18576 hosted endpoints (daily).

5745 releases that changed a tool definition (5499 observed live, 246 from the [churn study](https://github.com/rufat325/mcp-pin/blob/main/docs/CHURN.md)); 5 where `mcp-pin wrap --drift graded` would refuse something.

Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, with the words that moved: [events/](events).

`quiet`: a graded pin forwards every changed tool (new tools still need approval). `review`: a change introduced an agent-directed instruction, hidden character, credential path or look-alike letter. Review means read it, not that it is hostile.

| published | server | release | tools | grade |
|---|---|---|---|---|
| 2026-09-24 | `remote/com.zinvyl/marketplace` | 2026-09-23T163002987641 -> 2026-09-24T120516307990 | 3 changed | quiet |
| 2026-09-24 | `remote/io.zerogex/gamma-levels` | 2026-09-23T163000899875 -> 2026-09-24T120515618964 | 2 changed (every tool) | quiet |
| 2026-09-24 | `remote/io.github.speeedy10/foxify-x402-agent-commerce-payment-preflight` | 2026-09-23T162959976571 -> 2026-09-24T120514856235 | 1 changed, 1 added | quiet |
| 2026-09-24 | `remote/ai.thebotique.www/sigil` | 2026-09-23T202509169699 -> 2026-09-24T120511200417 | 1 added | quiet |
| 2026-09-24 | `remote/com.ikeytz/website` | 2026-09-23T162944600996 -> 2026-09-24T120504419055 | 2 changed, 2 added | quiet |
| 2026-09-24 | `remote/com.hillsignal/hillsignalapp` | 2026-09-23T162943635038 -> 2026-09-24T120502779678 | 1 changed | quiet |
| 2026-09-24 | `remote/fi.akkilahdot/travel-search` | 2026-09-23T202452357859 -> 2026-09-24T120454072251 | 2 changed (every tool) | quiet |
| 2026-09-24 | `remote/world.swampai/swamp` | 2026-09-23T202555724031 -> 2026-09-24T120447538337 | 1 changed, 2 added | quiet |
| 2026-09-24 | `remote/social.walletlink/wallet-identity` | 2026-09-23T162926217379 -> 2026-09-24T120447020696 | 8 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.voyscout/price-history` | 2026-09-23T162926040673 -> 2026-09-24T120446608962 | 5 changed (every tool) | quiet |
| 2026-09-24 | `remote/ro.soundcreation/catalog` | 2026-09-23T163144888512 -> 2026-09-24T120446036935 | 1 changed, 1 added | quiet |
| 2026-09-24 | `remote/io.github.falsalama/proper-job` | 2026-09-23T160848874505 -> 2026-09-24T120445120646 | 1 changed | quiet |
| 2026-09-24 | `remote/com.rubrkit/rubrkit` | 2026-09-23T163141989923 -> 2026-09-24T120443992216 | 1 added, 3 removed | quiet |
| 2026-09-24 | `remote/no.restplass/travel-search` | 2026-09-23T202551860693 -> 2026-09-24T120443356637 | 2 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.instilus/gpsr` | 2026-09-23T163134759093 -> 2026-09-24T120439286818 | 1 removed | quiet |
| 2026-09-24 | `remote/io.github.Schoasch/backtesting-arena` | 2026-09-23T162915454359 -> 2026-09-24T120435372162 | 1 changed, 1 added, 43 removed | quiet |
| 2026-09-24 | `remote/ir.cbest/lighting` | 2026-09-23T163125419838 -> 2026-09-24T120433180705 | 1 changed | quiet |
| 2026-09-24 | `remote/dk.afbudsrejser/travel-search` | 2026-09-23T202536967880 -> 2026-09-24T120430820119 | 2 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.thecastlemap/castles` | 2026-09-23T162907776213 -> 2026-09-24T120428552814 | 1 changed | quiet |
| 2026-09-24 | `remote/insure.spot/insurance-research` | 2026-09-23T162856493314 -> 2026-09-24T120420212949 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.socialloopai/socialloop-mcp.1` | 2026-09-23T202416713047 -> 2026-09-24T120417616419 | 1 changed | quiet |
| 2026-09-24 | `remote/de.urlaub-smart/planner` | 2026-09-23T163100027542 -> 2026-09-24T120418091583 | 3 changed, 1 added | quiet |
| 2026-09-24 | `remote/io.github.SidneyBissoli/uis-mcp-server` | 2026-09-23T163054753257 -> 2026-09-24T120416365322 | 1 changed | quiet |
| 2026-09-24 | `remote/ai.trydock/dock` | 2026-09-23T163052907740 -> 2026-09-24T120414991775 | 1 changed | quiet |
| 2026-09-24 | `remote/xyz.trusteed/mcp-gateway` | 2026-09-23T163052944629 -> 2026-09-24T120414717688 | 12 changed | quiet |
| 2026-09-24 | `remote/kr.pe.trading/community` | 2026-09-23T160817217617 -> 2026-09-24T120412433166 | 1 changed | quiet |
| 2026-09-24 | `remote/com.seqbench/workbench` | 2026-09-23T162845080729 -> 2026-09-24T120408578701 | 4 changed, 12 added | quiet |
| 2026-09-24 | `remote/io.github.bnmbnmai/bnm-data-shop` | 2026-09-23T202519711546 -> 2026-09-24T120416213819 | 4 changed, 1 added | quiet |
| 2026-09-24 | `remote/com.tickerfacts/fundamentals` | 2026-09-23T163043785973 -> 2026-09-24T120404901199 | 3 changed | quiet |
| 2026-09-24 | `remote/com.roxyapi/docs` | 2026-09-23T162838194656 -> 2026-09-24T120401692734 | 1 changed | quiet |
| 2026-09-24 | `remote/com.googleapis.run/mcp` | 2026-09-23T162837496879 -> 2026-09-24T120400937222 | 4 changed | quiet |
| 2026-09-24 | `remote/com.remoshift/jobs` | 2026-09-23T202358486407 -> 2026-09-24T120356912308 | 1 changed | quiet |
| 2026-09-24 | `remote/com.suomiatlas/area-statistics` | 2026-09-23T160804821230 -> 2026-09-24T120357740009 | 1 added | quiet |
| 2026-09-24 | `remote/ai.raccha/raccha` | 2026-09-23T162828801963 -> 2026-09-24T120352891083 | 2 added | quiet |
| 2026-09-24 | `remote/com.luxurylodgingpm.stay/luxury-lodging` | 2026-09-23T202452904325 -> 2026-09-24T120352422925 | 4 changed | quiet |
| 2026-09-24 | `remote/app.sprkly/sprkly` | 2026-09-23T160758031096 -> 2026-09-24T120352629987 | 1 added | quiet |
| 2026-09-24 | `remote/com.solvscore/mcp` | 2026-09-23T163009785716 -> 2026-09-24T120349513432 | 1 added | quiet |
| 2026-09-24 | `remote/io.github.Abacore-net/acn-preflight` | 2026-09-23T162822978276 -> 2026-09-24T120347678034 | 2 changed | quiet |
| 2026-09-24 | `remote/io.github.maixmeduret/pillr` | 2026-09-23T162818009657 -> 2026-09-24T120343075509 | 2 changed | quiet |
| 2026-09-24 | `remote/ai.spendline/spendline` | 2026-09-23T161035769040 -> 2026-09-24T120340807783 | 1 changed | quiet |
| 2026-09-24 | `remote/se.sistaminuten/travel-search` | 2026-09-23T202538383247 -> 2026-09-24T120340326838 | 2 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.peopleanalyst/discovery` | 2026-09-23T162814179662 -> 2026-09-24T120337894129 | 1 changed | quiet |
| 2026-09-24 | `remote/com.aex402/rpc` | 2026-09-23T162947606525 -> 2026-09-24T120334933200 | 1 changed | quiet |
| 2026-09-24 | `remote/pl.klyo/games` | 2026-09-23T162811320416 -> 2026-09-24T120333816267 | 7 changed | quiet |
| 2026-09-24 | `remote/site.chatgpt.bootyplease.saas-bundlecheck/sideeye` | 2026-09-23T160738248327 -> 2026-09-24T120332593052 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.cyanheads/orcid-mcp-server` | 2026-09-23T162807588994 -> 2026-09-24T120330419954 | 9 changed (every tool) | quiet |
| 2026-09-24 | `remote/io.github.Andyxcg/agentshop-reports` | 2026-09-23T162942639582 -> 2026-09-24T120331353504 | 3 changed | quiet |
| 2026-09-24 | `remote/eu.nulegal/recht` | 2026-09-23T160729823536 -> 2026-09-24T120324863603 | 9 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.odilelabs/odile` | 2026-09-23T162802740492 -> 2026-09-24T120325289543 | 9 changed (every tool) | quiet |
| 2026-09-24 | `remote/io.github.aboul3ata/mudpie-public` | 2026-09-23T162754285497 -> 2026-09-24T120316006041 | 7 changed (every tool) | quiet |
| 2026-09-24 | `remote/com.multicinesortega/cartelera` | 2026-09-23T202321439506 -> 2026-09-24T120317589738 | 1 changed | quiet |
| 2026-09-24 | `remote/com.lucernanoetica/lucerna` | 2026-09-23T162917342185 -> 2026-09-24T120315234956 | 1 added | quiet |
| 2026-09-24 | `remote/io.github.Project-Gifted1/pg1-threat-intel` | 2026-09-23T162913858886 -> 2026-09-24T120312282143 | 7 changed | quiet |
| 2026-09-24 | `remote/es.cesaryague/paki-curator` | 2026-09-23T162910645990 -> 2026-09-24T120310265979 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.cloakmaster/pact0` | 2026-09-23T202405024458 -> 2026-09-24T120309441206 | 1 changed | quiet |
| 2026-09-24 | `remote/com.orbylon/readiness` | 2026-09-23T162907886910 -> 2026-09-24T120308698287 | 6 changed, 1 added (every tool) | quiet |
| 2026-09-24 | `remote/com.sonarconnections/sonar-connections` | 2026-09-23T162745891975 -> 2026-09-24T120307428407 | 1 added | quiet |
| 2026-09-24 | `remote/io.github.bartek-filipiuk/intent-hub` | 2026-09-23T162907796350 -> 2026-09-24T120309256943 | 3 changed | quiet |
| 2026-09-24 | `remote/io.github.SKalinin909/tradingcalc` | 2026-09-23T160957218322 -> 2026-09-24T120307855941 | 7 changed, 11 added | quiet |
| 2026-09-24 | `remote/com.topologyindex/topology-index` | 2026-09-23T202458837281 -> 2026-09-24T120305259296 | 1 changed | quiet |
