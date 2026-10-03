# Privacy

heldfast is a tool you run. It has no service behind it, no accounts, no
telemetry and no analytics. Nothing is sent to the maintainer, ever. What it
reads stays on your machine, and the files it writes -- the lockfile, reports,
audit logs -- are written where you tell it to and nowhere else.

It does make network connections, only in the cases below, and only to the
places named. Each is a consequence of a command or flag you chose. A
`GITHUB_TOKEN` or `GH_TOKEN` in your environment is sent to `api.github.com`
when that fallback is used, and to no other host.

| When | Where it connects | What that party learns |
|---|---|---|
| `approve` for a server launched as `npx pkg@1.2.3` or `uvx pkg==1.2.3`, and `scan` or `ci` once the lockfile has recorded that package's hash -- never under `--safe` | `registry.npmjs.org` or `pypi.org` | the pinned package names and versions, to fetch or compare their published integrity hash |
| `--probe`, `wrap`, `guard`, `gateway` | the MCP servers in your configuration: local ones are started as processes, remote ones are contacted at the URL you configured | whatever those servers log about a client connecting |
| `approve --from-feed` | `github.com` and `raw.githubusercontent.com` (and `api.github.com`, only when `github.com` cannot say which commit the feed is at); `api.osv.dev` | that the drift feed was read, and which package versions were looked up; OSV learns the package names and versions, to say whether any is reported as malware |
| `verify`, and `approve --probe` for a hosted server at a public address | the same GitHub hosts | that the public log was read, and the log entries of your hosted servers that it holds -- not their URLs, which are matched on your machine. Local and private addresses are never looked up. `verify` also downloads the whole public record of tool definitions (`lookup/all.json.gz`) and searches it here, which says nothing about your tools; it keeps the record in your cache directory under the feed commit, so it is downloaded once per feed commit. With `--lookup buckets` it fetches one bucket per approved tool instead -- the first three characters of each fingerprint -- and the set of buckets can identify which public servers you use; `--lookup off` fetches neither |
| `updates` | the same, and `registry.npmjs.org` | the pinned package names, their versions and the newer ones, to check advisories, publish dates and install scripts before a release is proposed |
| `fleet --advisories` | `api.osv.dev` | the names and exact versions of the packages the inventories list, to say whether any is reported as malware -- nothing about which machines run them |
| `--llm` (off by default, needs an extra install and your own API key) | Anthropic's API | the tool and skill text sent for classification, under your key and Anthropic's terms |

`--safe` opens no connection at all, and says which guarantee that cost.

**Inventories** (`heldfast inventory`) open no connection and start no
process. The file one writes goes where you send it, and carries the
machine's name (or the `--label` you give), its MCP servers' names, packages,
versions and hosted addresses -- without queries, user info or any path
segment that looks like a token -- and the config files' paths with the home
directory written `~`. It never carries environment values, headers or
arguments. `heldfast fleet` reads those files and contacts nothing unless
`--advisories` is given. What is in one, field by field:
[docs/FLEET.md](docs/FLEET.md#what-an-inventory-carries-and-what-it-does-not).

**The MCP server** (`heldfast serve`) opens no connection and starts no
process; every tool it exposes is read-only, and a test fails if one reaches
the network. Path scanning is off unless `MCP_PIN_ALLOW_PATH_SCAN` is set.
The one exception is opt-in: with `MCP_PIN_ALLOW_FEED` set, it also lists
`server_history`, which reads the public drift feed from GitHub
(`github.com`, `raw.githubusercontent.com`) and so tells GitHub that the
feed was read. The server asked about is looked up in the downloaded index on
your machine; a local or private address is never looked up.

**The Claude Code plugin** runs on your machine. It reads `.mcp-pin.lock`
and the environment variable `HELDFAST_ALLOW_UNPINNED`, and by default runs
nothing else and sends nothing anywhere. When an organisation policy is in
force -- the machine's managed one, or one `HELDFAST_ORG_POLICY` names -- it
also reads that file and the MCP server entries in the project's `.mcp.json`
and your `~/.claude.json`, on your machine, to see what each server starts. With `HELDFAST_SESSION_CHECK=1`, it
runs the `heldfast` you installed once per session to read the tool lists of
the hosted servers your lockfile records, at the URLs recorded there, with no
credentials: those servers learn that a client connected.

**Secrets.** Findings pass through a redaction step before any report or tool
result is written, so a credential seen during analysis is not repeated back.
Servers launched by `--probe` and `wrap` do not receive heldfast's own
environment variables, and `--isolate-env` withholds yours too.

**The drift feed** (`.github/workflows/feed.yml`, published on the `feed`
branch) runs on GitHub, not on your machine. It measures public npm packages
listed in the public MCP registry and publishes what their tools say. It holds
no information about anyone who uses heldfast.

Questions: open an issue on
[github.com/rufat325/heldfast](https://github.com/rufat325/heldfast/issues).
Anything sensitive: [SECURITY.md](SECURITY.md) describes the private route.
