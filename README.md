# MCP server tool changes

Last change observed 2026-09-24T21:24:06+00:00. Built by `research/feed/watch.py` on the `main` branch. Watching 9409 npm servers from the official MCP registry (154 daily, the rest weekly) and 18576 hosted endpoints (daily).

7605 releases that changed a tool definition (7359 observed live, 246 from the [churn study](https://github.com/rufat325/heldfast/blob/main/docs/CHURN.md)); 6 where `heldfast wrap --drift graded` would refuse something.

Subscribe: [feed.xml](feed.xml) (Atom) or [feed.json](feed.json). Every event, with the words that moved: [events/](events).

`quiet`: a graded pin forwards every changed tool (new tools still need approval). `review`: a change introduced an agent-directed instruction, hidden character, credential path or look-alike letter. Review means read it, not that it is hostile.

| published | server | release | tools | grade |
|---|---|---|---|---|
| 2026-09-24 | `remote/fi.akkilahdot/travel-search` | 2026-09-24T205753767814 -> 2026-09-24T212407089496 | 1 changed | quiet |
| 2026-09-24 | `remote/se.sistaminuten/travel-search` | 2026-09-24T205537462030 -> 2026-09-24T212329956535 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.socialloopai/socialloop-mcp.1` | 2026-09-24T205724075892 -> 2026-09-24T212311522504 | 1 changed | quiet |
| 2026-09-24 | `remote/com.thejohnsonbros/plumbing-booking` | 2026-09-23T160809132838 -> 2026-09-24T212230794091 | 2 changed, 1 added | quiet |
| 2026-09-24 | `remote/no.restplass/travel-search` | 2026-09-24T205538178621 -> 2026-09-24T212219594251 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.cyanheads/wsdot-mcp-server` | 2026-09-23T163119183678 -> 2026-09-24T212208712750 | 6 changed | quiet |
| 2026-09-24 | `remote/dk.afbudsrejser/travel-search` | 2026-09-24T205527257144 -> 2026-09-24T212209300150 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.cyanheads/npi-providers-mcp-server` | 2026-09-23T160844428861 -> 2026-09-24T212146624653 | 2 changed | quiet |
| 2026-09-24 | `remote/dev.archstone.hosted/artvinci` | 2026-09-23T162617342861 -> 2026-09-24T212027274895 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.mirabello-consultancy/mcp-server` | 2026-09-23T162730463506 -> 2026-09-24T211953151853 | 3 changed | quiet |
| 2026-09-24 | `remote/so.darwin/darwin` | 2026-09-24T202310496324 -> 2026-09-24T211934930519 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/vessel-tracking` | 2026-09-24T120030533335 -> 2026-09-24T211920622499 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/nationalize` | 2026-09-24T120019398434 -> 2026-09-24T211855051765 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/taiwan-stocks` | 2026-09-24T115938935000 -> 2026-09-24T211853905817 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/gong` | 2026-09-24T120013382831 -> 2026-09-24T211833687676 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/fara` | 2026-09-24T120010492601 -> 2026-09-24T211830557020 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/dod-contract-announcements` | 2026-09-24T120008330718 -> 2026-09-24T211822430618 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/data-fortworth` | 2026-09-24T120005189326 -> 2026-09-24T211810263343 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/data-colorado` | 2026-09-24T120004533401 -> 2026-09-24T211809751546 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/china-disclosures` | 2026-09-24T120001342201 -> 2026-09-24T211804119003 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/arcgis-charlotte` | 2026-09-24T115955981668 -> 2026-09-24T211748067203 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.tettertotter/fundinglandscape` | 2026-09-24T205055524443 -> 2026-09-24T211738970497 | 2 changed | quiet |
| 2026-09-24 | `remote/es.elpujante/subastas` | 2026-09-23T160455308090 -> 2026-09-24T211725165791 | 7 changed (every tool) | quiet |
| 2026-09-24 | `remote/space.btw/btw` | 2026-09-23T160418000116 -> 2026-09-24T211649511509 | 2 changed, 1 added | quiet |
| 2026-09-24 | `remote/com.daedalmap/reverse-geocoding` | 2026-09-24T115830852854 -> 2026-09-24T211614989059 | 2 changed | quiet |
| 2026-09-24 | `remote/io.github.whiteknightonhorse/apibase` | 2026-09-24T201935152635 -> 2026-09-24T211606580080 | 2 added | quiet |
| 2026-09-24 | `gdharness` | 1.0.30 -> 1.0.31 | 1 changed | quiet |
| 2026-09-24 | `trace-mcp` | 3.31.5 -> 3.32.0 | 1 changed | review |
| 2026-09-24 | `@cyanheads/npi-providers-mcp-server` | 0.1.9 -> 0.2.0 | 2 changed | quiet |
| 2026-09-24 | `@withone/mcp` | 1.3.1 -> 1.4.0 | 3 changed | quiet |
| 2026-09-24 | `remote/fi.akkilahdot/travel-search` | 2026-09-24T202749065228 -> 2026-09-24T205753767814 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.JustJuice55/telegram-catalog` | 2026-09-24T202729164086 -> 2026-09-24T205737118865 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.socialloopai/socialloop-mcp.1` | 2026-09-24T202716696002 -> 2026-09-24T205724075892 | 1 changed | quiet |
| 2026-09-24 | `remote/com.remoshift/jobs` | 2026-09-24T202659869345 -> 2026-09-24T205707843491 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.newspacemarket-com/mrd` | 2026-09-24T202628425748 -> 2026-09-24T205632034191 | 1 added | quiet |
| 2026-09-24 | `remote/io.github.cyanheads/medical-codes-mcp-server` | 2026-09-24T202615585756 -> 2026-09-24T205621591606 | 2 changed | quiet |
| 2026-09-24 | `remote/com.sonarconnections/sonar-connections` | 2026-09-24T202613969930 -> 2026-09-24T205620032736 | 3 changed | quiet |
| 2026-09-24 | `remote/io.github.brawlaphant/vealth` | 2026-09-24T202809115099 -> 2026-09-24T205546788409 | 2 added | quiet |
| 2026-09-24 | `remote/no.restplass/travel-search` | 2026-09-24T202622456606 -> 2026-09-24T205538178621 | 1 changed | quiet |
| 2026-09-24 | `remote/se.sistaminuten/travel-search` | 2026-09-24T202704248467 -> 2026-09-24T205537462030 | 1 changed | quiet |
| 2026-09-24 | `remote/dk.afbudsrejser/travel-search` | 2026-09-24T202609207416 -> 2026-09-24T205527257144 | 1 changed | quiet |
| 2026-09-24 | `remote/com.donebear/donebear` | 2026-09-23T162631834922 -> 2026-09-24T205520073354 | 7 changed | quiet |
| 2026-09-24 | `remote/xyz.trusteed/mcp-gateway` | 2026-09-24T202553594916 -> 2026-09-24T205513089842 | 11 changed | quiet |
| 2026-09-24 | `remote/com.topologyindex/topology-index` | 2026-09-24T120305259296 -> 2026-09-24T205502300845 | 1 changed | quiet |
| 2026-09-24 | `remote/nl.taklo/taklo-evi` | 2026-09-23T160946482715 -> 2026-09-24T205453756780 | 1 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/woocommerce` | 2026-09-24T120031054856 -> 2026-09-24T205408778839 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/usda-fdc` | 2026-09-24T120030031765 -> 2026-09-24T205407693432 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/travelpayouts` | 2026-09-24T120029503859 -> 2026-09-24T205406807902 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/translate` | 2026-09-24T120029193530 -> 2026-09-24T205406512885 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/septa` | 2026-09-24T120026082547 -> 2026-09-24T205345577658 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/seo-serp` | 2026-09-24T120026068556 -> 2026-09-24T205345636239 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/seo-competitors` | 2026-09-24T120025995639 -> 2026-09-24T205345592923 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/scrapingdog` | 2026-09-24T120025549722 -> 2026-09-24T205345032755 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/repology` | 2026-09-24T120024930418 -> 2026-09-24T205344066277 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/plaid` | 2026-09-24T120023556798 -> 2026-09-24T205328206277 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.smarterweather/weather` | 2026-09-23T162811399345 -> 2026-09-24T205326500544 | 1 changed, 1 added | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/overheid-nl` | 2026-09-24T120022294023 -> 2026-09-24T205326051073 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/osrm` | 2026-09-24T120022070962 -> 2026-09-24T205325478382 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/opentopography` | 2026-09-24T120021947562 -> 2026-09-24T205325006694 | 4 changed | quiet |
| 2026-09-24 | `remote/io.github.pipeworx-io/openparliament-ca` | 2026-09-24T120021471407 -> 2026-09-24T205324505543 | 4 changed | quiet |
