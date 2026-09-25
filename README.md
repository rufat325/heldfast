# MCP server tool changes

Last change observed 2026-09-25T12:06:49+00:00. Built by `research/feed/watch.py` on the `main` branch. Watching 9409 npm servers from the official MCP registry (154 daily, the rest weekly) and 18576 hosted endpoints (daily).

7871 releases that changed a tool definition (7625 observed live, 246 from the [churn study](https://github.com/rufat325/heldfast/blob/main/docs/CHURN.md)); 7 where `heldfast wrap --drift graded` would refuse something.

Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, with the words that moved: [events/](events).

`quiet`: a graded pin forwards every changed tool (new tools still need approval). `review`: a change introduced an agent-directed instruction, hidden character, credential path or look-alike letter. Review means read it, not that it is hostile.

| published | server | release | tools | grade |
|---|---|---|---|---|
| 2026-09-25 | `remote/world.agentindex/x402` | 2026-09-23T163151033484 -> 2026-09-25T120650732868 | 1 changed | quiet |
| 2026-09-25 | `remote/no.restplass/travel-search` | 2026-09-24T212219594251 -> 2026-09-25T120643363760 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.assa83/borsabovini` | 2026-09-23T163122559877 -> 2026-09-25T120632106772 | 1 changed, 5 added, 1 removed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/wsdot-mcp-server` | 2026-09-24T212208712750 -> 2026-09-25T120630036399 | 4 changed | quiet |
| 2026-09-25 | `remote/dk.afbudsrejser/travel-search` | 2026-09-24T212209300150 -> 2026-09-25T120630693327 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/usgs-water-mcp-server` | 2026-09-23T163058916496 -> 2026-09-25T120620161269 | 4 changed | quiet |
| 2026-09-25 | `remote/de.urlaub-smart/planner` | 2026-09-24T120418091583 -> 2026-09-25T120620831976 | 4 changed | quiet |
| 2026-09-25 | `remote/io.github.switchwize/switchwize-mcp` | 2026-09-23T162954464263 -> 2026-09-25T120618915601 | 1 added | quiet |
| 2026-09-25 | `remote/io.github.bnmbnmai/bnm-data-shop` | 2026-09-24T202602018043 -> 2026-09-25T120618188592 | 3 changed, 1 added | quiet |
| 2026-09-25 | `remote/com.tickerfacts/fundamentals` | 2026-09-24T202544068462 -> 2026-09-25T120606964026 | 1 changed, 1 added | quiet |
| 2026-09-25 | `remote/se.sistaminuten/travel-search` | 2026-09-24T212329956535 -> 2026-09-25T120606205764 | 1 changed | quiet |
| 2026-09-25 | `remote/com.pactlio/contracts` | 2026-09-23T161032069953 -> 2026-09-25T120603320140 | 1 removed | quiet |
| 2026-09-25 | `remote/fi.akkilahdot/travel-search` | 2026-09-24T212407089496 -> 2026-09-25T120601256596 | 1 changed | quiet |
| 2026-09-25 | `remote/io.kolmo.www/kolmo-mcp-server` | 2026-09-23T161028444699 -> 2026-09-25T120600399155 | 1 changed | quiet |
| 2026-09-25 | `remote/site.aeon-labs/stratify` | 2026-09-23T202456425365 -> 2026-09-25T120559081336 | 10 changed, 1 added (every tool) | quiet |
| 2026-09-25 | `remote/com.goedvps.app.wodan-posture/wodan-posture` | 2026-09-23T162931191641 -> 2026-09-25T120558536209 | 2 changed (every tool) | quiet |
| 2026-09-25 | `remote/io.github.rccola990-cloud/x402-agent-store` | 2026-09-24T202530254990 -> 2026-09-25T120557275641 | 15 changed | quiet |
| 2026-09-25 | `remote/dev.stepcode/stepcode` | 2026-09-23T163014813702 -> 2026-09-25T120556357737 | 1 removed | quiet |
| 2026-09-25 | `remote/com.contrie/contrie` | 2026-09-24T202654031042 -> 2026-09-25T120556092447 | 2 changed | quiet |
| 2026-09-25 | `remote/com.webmcp-tool/agent-readiness` | 2026-09-23T162928226362 -> 2026-09-25T120559281147 | 2 changed | quiet |
| 2026-09-25 | `remote/app.srift/srift` | 2026-09-23T163013876007 -> 2026-09-25T120556087283 | 1 added | quiet |
| 2026-09-25 | `remote/com.waitingforpower/energy-permitting-tracker` | 2026-09-23T162925836298 -> 2026-09-25T120553041841 | 4 added | quiet |
| 2026-09-25 | `remote/tech.viewprinter/viewprinter` | 2026-09-23T202443606956 -> 2026-09-25T120550795380 | 1 changed | quiet |
| 2026-09-25 | `remote/ru.vedarai/mcp` | 2026-09-23T162923169437 -> 2026-09-25T120549979449 | 1 changed, 1 added | quiet |
| 2026-09-25 | `remote/fyi.whatsnew/changelogs` | 2026-09-23T202520375330 -> 2026-09-25T120548810600 | 1 changed, 1 added | quiet |
| 2026-09-25 | `remote/com.useslop/mcp` | 2026-09-23T162921956908 -> 2026-09-25T120547720600 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/usaspending-mcp-server` | 2026-09-23T162920671261 -> 2026-09-25T120547163675 | 6 changed | quiet |
| 2026-09-25 | `remote/io.github.Schoasch/backtesting-arena` | 2026-09-24T202734239723 -> 2026-09-25T120542632331 | 3 changed | quiet |
| 2026-09-25 | `remote/com.aex402/rpc` | 2026-09-24T202503464998 -> 2026-09-25T120537360330 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.JustJuice55/telegram-catalog` | 2026-09-24T205737118865 -> 2026-09-25T120536759166 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.IO31-WEB/synapse-lounge` | 2026-09-24T202727155459 -> 2026-09-25T120533526844 | 1 added | quiet |
| 2026-09-25 | `remote/io.github.SKalinin909/tradingcalc` | 2026-09-24T120307855941 -> 2026-09-25T120530797726 | 8 added | quiet |
| 2026-09-25 | `remote/io.github.socialloopai/socialloop-mcp.1` | 2026-09-24T212311522504 -> 2026-09-25T120523710241 | 1 changed, 4 added | quiet |
| 2026-09-25 | `remote/com.tofubofu/ai-visibility` | 2026-09-23T160950972601 -> 2026-09-25T120523279459 | 1 changed | quiet |
| 2026-09-25 | `remote/com.thefomite/fomite` | 2026-09-24T120300269514 -> 2026-09-25T120522144807 | 1 changed | quiet |
| 2026-09-25 | `remote/com.thefamilyalmanac/discovery` | 2026-09-23T160950105740 -> 2026-09-25T120521724636 | 1 removed | quiet |
| 2026-09-25 | `remote/com.seqbench/workbench` | 2026-09-24T202709365254 -> 2026-09-25T120516095999 | 5 changed | quiet |
| 2026-09-25 | `remote/com.searchfragments/search-fragments` | 2026-09-23T162842868854 -> 2026-09-25T120514033230 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.Project-Gifted1/pg1-threat-intel` | 2026-09-24T202440121129 -> 2026-09-25T120511526116 | 7 changed | quiet |
| 2026-09-25 | `remote/com.pestpin/pestpin` | 2026-09-23T162914074259 -> 2026-09-25T120511908116 | 2 changed | quiet |
| 2026-09-25 | `remote/com.lazyweb/discovery` | 2026-09-23T160845403043 -> 2026-09-25T120507770802 | 1 changed | quiet |
| 2026-09-25 | `remote/cc.roboparts/roboparts` | 2026-09-23T162836367443 -> 2026-09-25T120508182707 | 1 added | quiet |
| 2026-09-25 | `remote/online.sellular/sellular` | 2026-09-23T160932571501 -> 2026-09-25T120505966968 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.SidneyBissoli/senado-br-mcp-cloudflare` | 2026-09-24T120245104618 -> 2026-09-25T120506423720 | 5 changed | quiet |
| 2026-09-25 | `remote/io.github.deviljin17/remode` | 2026-09-23T162833162842 -> 2026-09-25T120505053375 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/openlibrary-mcp-server` | 2026-09-23T162905312075 -> 2026-09-25T120504846529 | 9 changed | quiet |
| 2026-09-25 | `remote/fit.ilook/face-analysis` | 2026-09-24T202832584258 -> 2026-09-25T120505309525 | 14 changed (every tool) | quiet |
| 2026-09-25 | `remote/com.remoshift/jobs` | 2026-09-24T205707843491 -> 2026-09-25T120505279777 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/onebusaway-mcp-server` | 2026-09-23T162902244128 -> 2026-09-25T120501091439 | 5 changed, 1 added | quiet |
| 2026-09-25 | `remote/ai.satohub/onchain-agents` | 2026-09-23T160927728151 -> 2026-09-25T120500693337 | 6 changed, 1 added | quiet |
| 2026-09-25 | `remote/io.github.salemalem/npmscan` | 2026-09-24T120301625727 -> 2026-09-25T120458050682 | 1 changed | quiet |
| 2026-09-25 | `remote/co.civai.nova/telegram-agent` | 2026-09-23T162857738835 -> 2026-09-25T120457381646 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/worldbank-mcp-server` | 2026-09-23T160832826091 -> 2026-09-25T120451789648 | 2 changed | quiet |
| 2026-09-25 | `remote/com.plainrouter/mcp.1` | 2026-09-23T162819780933 -> 2026-09-25T120452975520 | 1 changed | quiet |
| 2026-09-25 | `remote/com.peopleanalyst/discovery` | 2026-09-24T120337894129 -> 2026-09-25T120448381980 | 1 removed | quiet |
| 2026-09-25 | `remote/ltd.qianyuan/qy-evolution` | 2026-09-23T202421561616 -> 2026-09-25T120458141008 | 1 changed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/pubchem-mcp-server` | 2026-09-23T160905822628 -> 2026-09-25T120444362710 | 8 changed | quiet |
| 2026-09-25 | `remote/io.github.cyanheads/met-museum-mcp-server` | 2026-09-23T162835673235 -> 2026-09-25T120444135827 | 1 changed | quiet |
| 2026-09-25 | `remote/study.vela/corpus` | 2026-09-23T160823352632 -> 2026-09-25T120442988780 | 1 removed | quiet |
| 2026-09-25 | `remote/net.siteborne/utility` | 2026-09-23T160821822513 -> 2026-09-25T120442629464 | 4 changed, 4 added | quiet |
