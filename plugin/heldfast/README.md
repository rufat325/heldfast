# Claude Code plugin

Enforcement without rewriting `mcpServers` argv. One lock feeds wrap, CI, and this hook.

```
/plugin marketplace add rufat325/heldfast
/plugin install heldfast@heldfast
```

Or copy `plugin/heldfast` into a marketplace you already use.

- **SessionStart** reads `.mcp-pin.lock` in the project and prints what is pinned. It does not launch servers and it does not rewrite hashes.
- **PreToolUse** matches `mcp__<server>__<tool>`. A missing lock, a server the lock does not name, or a tool that was not present at approval: deny. The server is found by matching the tool name against the servers in the lock, written the way Claude Code writes them (every character outside letters, digits, `_` and `-` becomes `_`), so a server or tool whose name contains `__` is still read correctly.

This is not TOFU. An unpinned project refuses MCP calls until `heldfast approve --probe` writes the file.

**Names, not definitions.** Claude Code gives a PreToolUse hook the tool's name and the arguments the model wrote. It never gives the hook the tool's definition. So this hook checks names: it cannot see a tool whose description or schema changed under an approved name. `heldfast wrap` and `heldfast gateway` sit between the client and the server and see the definitions; put one of them in the path for that. An earlier version hashed a definition when one appeared in the arguments. The model writes those, so it proved nothing; it is gone, and `MCP_PIN_DRIFT=graded` no longer does anything here.

**Hosted servers, read at session start (opt-in).** Set `HELDFAST_SESSION_CHECK=1` and SessionStart reads each hosted (HTTP) server the lock records, once, through `heldfast hosted-drift` -- the same reading `scan --probe --no-stdio-probe` does, which runs no server code -- and PreToolUse refuses, for that session, an approved tool whose definition has changed. It needs `heldfast` on `PATH` (or `MCP_PIN_PYTHON`). A server that wants a login cannot be read without its credentials, so it is reported as not verified and not refused. Stdio servers are not read: reading one means launching it, which is what `wrap` is for. The check never writes the lock. It is off by default because it is the one thing this plugin does that reaches the network.

**Other plugins' MCP servers.** Claude Code names a tool from a plugin-bundled server `mcp__plugin_<plugin>_<server>__<tool>`. `heldfast approve --probe` finds the servers your installed, enabled plugins declare (their `.mcp.json` and the `mcpServers` in their manifest) and records them as `claude-code-plugin:<plugin>:<server>`; from then on they are checked like any other. MCP bundles (`.mcpb`, `.dxt`) and plugins synced from claude.ai are not read, and approval says so. A plugin server the lock does not name is refused with a message saying how to approve it. To call one anyway, unpinned, list its server exactly as it appears after `mcp__` in `HELDFAST_ALLOW_UNPINNED`, comma-separated:

```
HELDFAST_ALLOW_UNPINNED=plugin_other-plugin_db
```

Each call it lets through is reported on stderr as unpinned. Only `plugin_` names are honoured; a server from your own configuration is pinned with `heldfast approve`, not skipped.
