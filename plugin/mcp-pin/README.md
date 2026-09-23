# Claude Code plugin

Enforcement without rewriting `mcpServers` argv. One lock feeds wrap, CI, and this hook.

```
/plugin marketplace add rufat325/mcp-pin
/plugin install mcp-pin@mcp-pin
```

Or copy `plugin/mcp-pin` into a marketplace you already use.

- **SessionStart** reads `.mcp-pin.lock` in the project and prints what is pinned. It does not launch servers and it does not rewrite hashes.
- **PreToolUse** matches `mcp__server__tool`. Missing lock, missing server, missing tool, or a live definition whose digest drifted: deny.

This is not TOFU. An unpinned project refuses MCP calls until `mcp-pin approve --probe` writes the file.

**Graded drift.** Set `MCP_PIN_DRIFT=graded` and a changed tool is allowed when the change introduced no signal -- no new agent-directed instruction, hidden character, credential path or look-alike letter -- and denied, with what it gained, when it did. The hook asks `mcp-pin grade-drift` (the same test `wrap --drift graded` runs), so it needs `mcp-pin` on `PATH`, or `MCP_PIN_PYTHON` pointing at an interpreter that has it. If the grader cannot run, the call is denied. It is a heuristic: see [MANUAL.md](../../docs/MANUAL.md#upgrades-without-the-re-approval-treadmill---drift-graded).
