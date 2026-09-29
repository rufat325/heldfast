# heldfast-check

Zero-dependency verifier for `.mcp-pin.lock`. Same digest the Python wheel writes. Does not launch servers.

```bash
npx heldfast-check
npx heldfast-check --lock path/to/.mcp-pin.lock
```

Missing file exits 1 (`MCPA014`). A version this checker does not understand exits 2.

The lockfile is written by [heldfast](https://github.com/rufat325/heldfast): `pipx install heldfast`.
