# Lock spec

The file you commit is the same check that runs in CI and on the wire.

If the tool the model can see is not the tool you approved, the call does not happen.

This is the digest other tools implement. It is not a second lock format. `.mcp-pin.lock` is JSON, version `2`, no hostname, no env values.

## Tool digest

SHA-256, hex, of the UTF-8 bytes of the **RFC 8785 (JCS)** canonical form of
`body`.

```
sha256(jcs(body))
```

JCS is what makes "same object, same digest, any language" a specification
rather than a hope. It pins the number formatting and key ordering that two
hand-matched implementations will always eventually disagree about:

| case | JCS writes |
|---|---|
| `1.0` | `1` — an integral float loses its decimal |
| `-0.0` | `0` |
| `1e16` | `10000000000000000` — full decimals below `1e21` |
| `1e21` | `1e+21` — exponent notation at and above it |
| `1e-7` | `1e-7` — full decimals down to `1e-6` |
| a lone surrogate | escaped as `\udXXX`, rather than refused |
| keys | sorted by **UTF-16 code unit**, not by code point |

Two consequences worth stating outright:

- A key mixing BMP and astral characters sorts differently under UTF-16 than
  under code point. In `{"": 1, "😀": 2}` the emoji comes first.
- An integer that cannot survive a double round-trip — `9007199254740993` —
  is **refused**, not hashed. JavaScript has already lost it by the time its
  parser is done, so no canonical form could agree on it. The refusal happens
  in Python at approve time, because that is the only side that can still see
  the difference. Magnitude is not the test: `10000000000000000` is larger
  and exact, and hashes fine.

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

`1` and `1.0` are now the same digest, which is the point of the change: a
Pydantic or FastMCP server emitting `"minimum": 0.0` used to hash differently
in Python and in JavaScript, so the Claude Code plugin hook reported drift on
tools that had been approved correctly.

## Vectors

`tests/golden/tools/` — twelve objects, ten cases (one pair is key order). A checker that disagrees with any file is wrong.

`tests/golden/jcs_vectors.json` — the canonicalization contract itself, read
by `tests/test_digest_parity.py` and by `js/mcp-pin-check/test.js`. Both
languages assert the same strings from the same file, so the two
implementations cannot drift apart again without a test going red.

```bash
python -c "from mcp_pin.digest import tool_digest; ..."
node js/mcp-pin-check/bin.js --golden tests/golden/tools
```

## File

```json
{
  "version": 2,
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
- **A version 1 lock is reported, not silently re-read.** Its fingerprints
  came from the pre-JCS digest, and this tool cannot tell which of them the
  change affected. `scan` says the lock needs re-approving instead of
  comparing against it, and `mcp-pin-check` returns `T-LOCK-STALE-DIGEST`.
  Run `mcp-pin approve` to re-record it.

  In practice **most digests do not change**: all twelve golden vectors hash
  to the same hex under both algorithms, because ordinary tool objects
  contain none of the constructs JCS pins down. A digest moves only if the
  object holds an integral float (`1.0`, the common one), a value like
  `1e16`, a `-0.0`, or keys mixing BMP with astral characters. The version
  bump is there because nothing can tell you *which* locks those are without
  rehashing them, and quietly reporting a changed algorithm as a rug pull is
  the failure this whole change exists to prevent.
- Hostname does not belong in a portable lock.
- Env values do not belong in a portable lock. The launch command is pinned (`T-LAUNCH`); logs redact env.
- `mcp-pin check` / `mcp-pin-check` verify the file without launching anything.
- Missing file is MCPA014. Drifted tool is MCPA015.

Python: `mcp_pin.digest.tool_digest`. JavaScript: `js/mcp-pin-check`. Claude Code: `plugin/mcp-pin`.
