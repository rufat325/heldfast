# mcp-pin-check

Zero-dependency verifier for `.mcp-pin.lock`. Same digest the Python wheel writes. Does not launch servers.

Not published to npm yet, so run it from a clone:

```bash
node bin.js
node bin.js --lock path/to/.mcp-pin.lock
node bin.js --golden tests/golden/tools
```

Missing file exits 1 (`MCPA014`). A version this checker does not understand exits 2.

This is not `npx mcp-pin`. That package is [GautamTalksDev/mcp-pin](https://github.com/GautamTalksDev/mcp-pin).
