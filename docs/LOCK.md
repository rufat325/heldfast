# Lock spec

The file you commit is the same check that runs in CI and on the wire.

If the tool the model can see is not the tool you approved, the call does not happen.

This is the digest other tools implement. It is not a second lock format. `.mcp-pin.lock` is JSON, version `1`, no hostname, no env values.

## Tool digest

SHA-256, hex, of the UTF-8 bytes of:

```
json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

`body` is:

| key | rule |
|---|---|
| `name` | string; missing becomes `""` |
| `title` | string; missing becomes `""` |
| `description` | string; missing becomes `""` |
| `input_schema` | object; missing becomes `{}`. Wire name `inputSchema` is accepted. |
| `annotations` | object; missing becomes `{}` |
| `output_schema` | object; **omitted** when missing or `{}`. Wire name `outputSchema` is accepted. |
| `icons` | array; **omitted** when missing or empty |

Omitted keys are load-bearing. Writing `output_schema: {}` into every hash would rug-pull every existing lockfile on upgrade.

Key order in the input object does not change the digest. `tests/golden/tools/04-schema-key-order-a.json` and `05-schema-key-order-b.json` are the same hex.

Integers in goldens are integers. Do not emit `1.0` for `1`.

## Vectors

`tests/golden/tools/` — twelve objects, ten cases (one pair is key order). A checker that disagrees with any file is wrong.

```bash
python -c "from mcp_pin.digest import tool_digest; ..."
npx mcp-pin-check --golden tests/golden/tools
```

## File

```json
{
  "version": 1,
  "generated": "2026-09-21T00:00:00Z",
  "servers": {
    "claude-code:files": {
      "name": "files",
      "command_line": "npx -y @scope/server@1.0.0",
      "tools": {
        "read_file": {
          "fingerprint": "<64 hex>",
          "description_preview": "Read a file from disk."
        }
      }
    }
  },
  "skills": {}
}
```

- Version newer than the tool understands is refused (`T-LOCK-FUTURE`).
- Hostname does not belong in a portable lock.
- Env values do not belong in a portable lock. The launch command is pinned (`T-LAUNCH`); logs redact env.
- `mcp-pin check` / `mcp-pin-check` verify the file without launching anything.
- Missing file is MCPA014. Drifted tool is MCPA015.

Python: `mcp_pin.digest.tool_digest`. JavaScript: `js/mcp-pin-check`. Claude Code: `plugin/mcp-pin`.
