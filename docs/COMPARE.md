# Scan vs pin vs refuse-call vs refuse-spawn

Four jobs. They are not the same product.

| | scan | pin | refuse-call | refuse-spawn |
|---|---|---|---|---|
| What it answers | Does this config look wrong *now*? | Is this the tool I approved? | May this call go through? | May this process start? |
| Artifact | report / SARIF | `.mcp-pin.lock` | the same lock | the same lock |
| Command | `mcp-pin doctor` / `mcp-pin ci` | `mcp-pin approve --probe` | `mcp-pin wrap -- …` / Claude Code hook | `mcp-pin wrap` / `gateway` at start |
| Fails the PR | MCPA014, MCPA015, and `--fail-on high` | the file is the pin | n/a (runtime) | n/a (runtime) |
| Launches a server | only with `--probe` | `--probe` records live tools | yes, the child | yes, after the pin gate |
| Who else occupies it | Snyk, Cisco (text looks evil) | this tool | this tool, gateways (auth/DLP) | this tool |

Snyk and Cisco own "does this text look evil." Gateways own auth and DLP. mcp-pin owns **the lock**.

`--safe` is the scan you can run on a laptop that is not disposable: nothing is executed, nothing is contacted. `--probe` is how you write the lock, because a tool description does not live in your config. Do that in an isolate. Pinning is not sandboxing.

## The other mcp-pin

[GautamTalksDev/mcp-pin](https://github.com/GautamTalksDev/mcp-pin) is a different program that shares this name. It pins on first connect (TOFU). This one records a review (`--yes-tool` for a critical change) and then refuses the rest. `npx mcp-pin` is theirs. This tool is `pipx install mcp-pin`. The npm shim in `js/mcp-pin-wrap` is not published, so there is no `npx` spelling of this one yet.

If Warden and Gautam keep their own hashes, a PR that fails on *this* file is still the win.
