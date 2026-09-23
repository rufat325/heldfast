# MCP server tool changes

Last change observed 2026-09-23T20:25:55+00:00. Built by `research/feed/watch.py` on the `main` branch. Watching 9409 npm servers from the official MCP registry (154 daily, the rest weekly) and 18576 hosted endpoints (daily).

1554 releases that changed a tool definition (1308 observed live, 246 from the [churn study](https://github.com/rufat325/mcp-pin/blob/main/docs/CHURN.md)); 3 where `mcp-pin wrap --drift graded` would refuse something.

Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, with the words that moved: [events/](events).

`quiet`: a graded pin forwards every changed tool (new tools still need approval). `review`: a change introduced an agent-directed instruction, hidden character, credential path or look-alike letter. Review means read it, not that it is hostile.

| published | server | release | tools | grade |
|---|---|---|---|---|
| 2026-09-23 | `remote/world.swampai/swamp` | 2026-09-23T163147154506 -> 2026-09-23T202555724031 | 1 changed | quiet |
| 2026-09-23 | `remote/no.restplass/travel-search` | 2026-09-23T163142621101 -> 2026-09-23T202551860693 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.clairwave/clairwave` | 2026-09-23T163126533692 -> 2026-09-23T202539424225 | 1 changed | quiet |
| 2026-09-23 | `remote/se.sistaminuten/travel-search` | 2026-09-23T163012319667 -> 2026-09-23T202538383247 | 1 changed | quiet |
| 2026-09-23 | `remote/dk.afbudsrejser/travel-search` | 2026-09-23T163120159716 -> 2026-09-23T202536967880 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wouhr/catalog` | 2026-09-23T163118289797 -> 2026-09-23T202535914220 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wosneaker/catalog` | 2026-09-23T163128774666 -> 2026-09-23T202535895597 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wopool/catalog` | 2026-09-23T163116794905 -> 2026-09-23T202534482925 | 1 changed | quiet |
| 2026-09-23 | `remote/com.whenisbins/bin-collections` | 2026-09-23T163112242335 -> 2026-09-23T202532173891 | 3 changed | quiet |
| 2026-09-23 | `remote/com.eatmundo/dishes` | 2026-09-23T161024811950 -> 2026-09-23T202529126289 | 1 added | quiet |
| 2026-09-23 | `remote/com.contrie/contrie` | 2026-09-23T163000060309 -> 2026-09-23T202527535474 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wovitamine/catalog` | 2026-09-23T161020490377 -> 2026-09-23T202525004868 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wostrom/catalog` | 2026-09-23T161020420240 -> 2026-09-23T202524677799 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wohandy/catalog` | 2026-09-23T161019105213 -> 2026-09-23T202523445549 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wogrill/catalog` | 2026-09-23T161019033104 -> 2026-09-23T202523049375 | 1 changed | quiet |
| 2026-09-23 | `remote/de.woebike/catalog` | 2026-09-23T161018959496 -> 2026-09-23T202523059873 | 1 changed | quiet |
| 2026-09-23 | `remote/fyi.whatsnew/changelogs` | 2026-09-23T161015451773 -> 2026-09-23T202520375330 | 1 changed | quiet |
| 2026-09-23 | `remote/ai.thebotique.www/sigil` | 2026-09-23T162954931528 -> 2026-09-23T202509169699 | 2 added | quiet |
| 2026-09-23 | `remote/com.topologyindex/topology-index` | 2026-09-23T162928237593 -> 2026-09-23T202458837281 | 6 changed (every tool) | quiet |
| 2026-09-23 | `remote/com.youspot/youspot` | 2026-09-23T160901540392 -> 2026-09-23T202453379576 | 2 changed, 1 added | quiet |
| 2026-09-23 | `remote/com.luxurylodgingpm.stay/luxury-lodging` | 2026-09-23T163014376089 -> 2026-09-23T202452904325 | 6 changed (every tool) | quiet |
| 2026-09-23 | `remote/fi.akkilahdot/travel-search` | 2026-09-23T162933423583 -> 2026-09-23T202452357859 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wospeicher/catalog` | 2026-09-23T162932536330 -> 2026-09-23T202451870036 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wolaptop/catalog` | 2026-09-23T162931532139 -> 2026-09-23T202450978870 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wokonsole/catalog` | 2026-09-23T162931433696 -> 2026-09-23T202450846132 | 1 changed | quiet |
| 2026-09-23 | `remote/tech.viewprinter/viewprinter` | 2026-09-23T162923851847 -> 2026-09-23T202443606956 | 1 changed | quiet |
| 2026-09-23 | `remote/com.scentverdict/fragrances` | 2026-09-23T162953594710 -> 2026-09-23T202435318084 | 3 changed | quiet |
| 2026-09-23 | `remote/app.repopilot/repopilot` | 2026-09-23T160916878572 -> 2026-09-23T202427763145 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.IO31-WEB/synapse-lounge` | 2026-09-23T162904163736 -> 2026-09-23T202425197606 | 58 changed (every tool) | quiet |
| 2026-09-23 | `remote/de.wotablet/catalog` | 2026-09-23T160834179974 -> 2026-09-23T202425537483 | 1 changed | quiet |
| 2026-09-23 | `remote/de.wosolar/catalog` | 2026-09-23T160833855992 -> 2026-09-23T202425554114 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.jkbngb/handelsregister` | 2026-09-23T162938922642 -> 2026-09-23T202424759987 | 1 added | quiet |
| 2026-09-23 | `remote/de.woroller/catalog` | 2026-09-23T160833683877 -> 2026-09-23T202425425344 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.socialloopai/socialloop-mcp.1` | 2026-09-23T162853588470 -> 2026-09-23T202416713047 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.brawlaphant/vealth` | 2026-09-23T160822568409 -> 2026-09-23T202413925478 | 5 changed, 2 added | quiet |
| 2026-09-23 | `remote/io.github.cloakmaster/pact0` | 2026-09-23T162909564690 -> 2026-09-23T202405024458 | 1 changed, 2 added | quiet |
| 2026-09-23 | `remote/com.remoshift/jobs` | 2026-09-23T162833956353 -> 2026-09-23T202358486407 | 1 changed | quiet |
| 2026-09-23 | `remote/com.numbru/client-compass` | 2026-09-23T162859186512 -> 2026-09-23T202356849841 | 1 changed | quiet |
| 2026-09-23 | `remote/com.radar-cnpj/radar-cnpj` | 2026-09-23T162829158189 -> 2026-09-23T202354642932 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.ulasarslan6262-ui/speedbot` | 2026-09-23T160755167571 -> 2026-09-23T202346878217 | 58 changed, 23 added | quiet |
| 2026-09-23 | `remote/online.pageaudit/pageaudit` | 2026-09-23T162809856777 -> 2026-09-23T202336444727 | 2 changed | quiet |
| 2026-09-23 | `remote/io.github.cnghockey/sats4ai` | 2026-09-23T160738484878 -> 2026-09-23T202331815693 | 3 changed | quiet |
| 2026-09-23 | `remote/sh.tibia/tibiawiki-mcp` | 2026-09-23T162818429036 -> 2026-09-23T202329225325 | 1 changed, 1 added | quiet |
| 2026-09-23 | `remote/be.vibedeploy/vibedeploy` | 2026-09-23T160808451348 -> 2026-09-23T202327048710 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.newspacemarket-com/mrd` | 2026-09-23T162759085769 -> 2026-09-23T202324487993 | 5 changed | quiet |
| 2026-09-23 | `remote/com.multicinesortega/cartelera` | 2026-09-23T162755766526 -> 2026-09-23T202321439506 | 1 changed | quiet |
| 2026-09-23 | `remote/com.pontofato/pontofato` | 2026-09-23T160719974524 -> 2026-09-23T202311511621 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.samuelzcom/chauffeur-booking` | 2026-09-23T163039393391 -> 2026-09-23T202316499859 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.yzlee/opcmenu` | 2026-09-23T162747907327 -> 2026-09-23T202304876978 | 2 changed | quiet |
| 2026-09-23 | `remote/com.shipstatic/mcp` | 2026-09-23T162727917753 -> 2026-09-23T202256186106 | 1 changed | quiet |
| 2026-09-23 | `remote/io.github.resemble-ai/resemble-mcp` | 2026-09-23T162723429908 -> 2026-09-23T202251798279 | 11 added | quiet |
| 2026-09-23 | `remote/ai.greenlandai/greenlandai` | 2026-09-23T162717831227 -> 2026-09-23T202245398427 | 4 changed | quiet |
| 2026-09-23 | `remote/com.nursinghomedatabase/mcp` | 2026-09-23T162713916941 -> 2026-09-23T202242152313 | 2 changed | quiet |
| 2026-09-23 | `remote/io.github.jmrplens/libgen-mcp` | 2026-09-23T160720018842 -> 2026-09-23T202239811850 | 4 changed (every tool) | quiet |
| 2026-09-23 | `remote/com.jobyap/jobs` | 2026-09-23T160719936205 -> 2026-09-23T202238915521 | 1 added | quiet |
| 2026-09-23 | `remote/io.insourcia/insourcia` | 2026-09-23T160718312856 -> 2026-09-23T202237839099 | 1 removed | quiet |
| 2026-09-23 | `remote/com.giftroam/giftroam` | 2026-09-23T160708617906 -> 2026-09-23T202228271709 | 2 changed | quiet |
| 2026-09-23 | `remote/com.interzoid/mcp-server` | 2026-09-23T162652355298 -> 2026-09-23T202223221145 | 58 changed (every tool) | quiet |
| 2026-09-23 | `remote/com.gojinko.mcp/jinko` | 2026-09-23T162647111519 -> 2026-09-23T202217898199 | 3 changed | quiet |
| 2026-09-23 | `remote/ing.crank/crank` | 2026-09-23T160653278958 -> 2026-09-23T202213719071 | 3 changed, 3 added | quiet |
