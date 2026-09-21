# Client compatibility

Frozen 2026-09-21. This is not a discoverer race. Seventeen entries; Goose and Codex are reported as found-but-unparsed (YAML / TOML).

| id | name | last verified | notes |
|---|---|---|---|
| claude-desktop | Claude Desktop | 2026-09-21 | `claude_desktop_config.json` |
| claude-code | Claude Code | 2026-09-21 | `.mcp.json`, `~/.claude.json`; also the plugin in `plugin/mcp-pin` |
| cursor | Cursor | 2026-09-21 | `.cursor/mcp.json` |
| vscode | VS Code | 2026-09-21 | servers under `servers` |
| windsurf | Windsurf | 2026-09-21 | |
| zed | Zed | 2026-09-21 | `context_servers` |
| cline | Cline | 2026-09-21 | VS Code globalStorage |
| roo | Roo Code | 2026-09-21 | |
| kilo | Kilo Code | 2026-09-21 | |
| continue | Continue | 2026-09-21 | |
| lmstudio | LM Studio | 2026-09-21 | |
| opencode | opencode | 2026-09-21 | |
| gemini-cli | Gemini CLI | 2026-09-21 | |
| amp | Amp | 2026-09-21 | |
| witsy | Witsy | 2026-09-21 | |
| goose | Goose | 2026-09-21 | YAML; discovered, not parsed |
| codex | Codex CLI | 2026-09-21 | TOML; discovered, not parsed |

The registry is `src/mcp_pin/clients.py`. Adding a client is out of scope until this table is wrong.
