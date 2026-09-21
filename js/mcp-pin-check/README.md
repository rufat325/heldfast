# mcp-pin-check

Zero-dependency verifier for `.mcp-pin.lock`. Same digest the Python wheel writes. Does not launch servers.

```bash
npx mcp-pin-check
npx mcp-pin-check --lock path/to/.mcp-pin.lock
npx mcp-pin-check --golden tests/golden/tools
```

Missing file exits 1 (`MCPA014`). A version this checker does not understand exits 2.

This is not `npx mcp-pin`. That package is [GautamTalksDev/mcp-pin](https://github.com/GautamTalksDev/mcp-pin).
