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

**Other plugins' MCP servers.** Claude Code names a tool from a plugin-bundled server `mcp__plugin_<plugin>_<server>__<tool>`. heldfast cannot pin those yet, so they are refused, with a message saying so. To call one anyway, unpinned, list its server exactly as it appears after `mcp__` in `HELDFAST_ALLOW_UNPINNED`, comma-separated:

```
HELDFAST_ALLOW_UNPINNED=plugin_other-plugin_db
```

Each call it lets through is reported on stderr as unpinned. Only `plugin_` names are honoured; a server from your own configuration is pinned with `heldfast approve`, not skipped.
