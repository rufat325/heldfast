# Privacy

mcp-pin is a tool you run. It has no service behind it, no accounts, no
telemetry and no analytics. Nothing is sent to the maintainer, ever. What it
reads stays on your machine, and the files it writes -- the lockfile, reports,
audit logs -- are written where you tell it to and nowhere else.

It does make network connections, only in the cases below, and only to the
places named. Each is a consequence of a command or flag you chose.

| When | Where it connects | What that party learns |
|---|---|---|
| `approve` for a server launched as `npx pkg@1.2.3` or `uvx pkg==1.2.3`, and `scan` or `ci` once the lockfile has recorded that package's hash -- never under `--safe` | `registry.npmjs.org` or `pypi.org` | the pinned package names and versions, to fetch or compare their published integrity hash |
| `--probe`, `wrap`, `guard`, `gateway` | the MCP servers in your configuration: local ones are started as processes, remote ones are contacted at the URL you configured | whatever those servers log about a client connecting |
| `approve --from-feed` | `api.github.com` and `raw.githubusercontent.com`; `api.osv.dev` | that the drift feed was read, and which package versions were looked up; OSV learns the package names and versions, to say whether any is reported as malware |
| `verify`, and `approve --probe` for a hosted server at a public address | `api.github.com` and `raw.githubusercontent.com` | that the public log was read, and the log entries of your hosted servers that it holds -- not their URLs, which are matched on your machine. Local and private addresses are never looked up. `verify` also fetches one lookup bucket per approved tool: the first three characters of its fingerprint, which place it among a few dozen others and say nothing more |
| `updates` | the same, and `registry.npmjs.org` | the pinned package names, their versions and the newer ones, to check advisories, publish dates and install scripts before a release is proposed |
| `--llm` (off by default, needs an extra install and your own API key) | Anthropic's API | the tool and skill text sent for classification, under your key and Anthropic's terms |

`--safe` opens no connection at all, and says which guarantee that cost.

**The MCP server** (`mcp-pin serve`) opens no connection and starts no
process; every tool it exposes is read-only, and a test fails if one reaches
the network. Path scanning is off unless `MCP_PIN_ALLOW_PATH_SCAN` is set.

**The Claude Code plugin** runs on your machine. It reads `.mcp-pin.lock`, and
with `MCP_PIN_DRIFT=graded` it runs the `mcp-pin` you installed. It sends
nothing anywhere.

**Secrets.** Findings pass through a redaction step before any report or tool
result is written, so a credential seen during analysis is not repeated back.
Servers launched by `--probe` and `wrap` do not receive mcp-pin's own
environment variables, and `--isolate-env` withholds yours too.

**The drift feed** (`.github/workflows/feed.yml`, published on the `feed`
branch) runs on GitHub, not on your machine. It measures public npm packages
listed in the public MCP registry and publishes what their tools say. It holds
no information about anyone who uses mcp-pin.

Questions: open an issue on
[github.com/rufat325/mcp-pin](https://github.com/rufat325/mcp-pin/issues).
Anything sensitive: [SECURITY.md](SECURITY.md) describes the private route.
