# Lookup: has anyone else been shown this exact tool?

Chrome asks Safe Browsing about a site before it opens it. An MCP client can
ask the same kind of question about a tool before an agent trusts it: *has any
public server ever shown this exact definition, and since when?*

The drift feed has recorded every tool definition it read from the official
MCP registry's servers -- npm packages it launched in a container, hosted
servers it read as an anonymous client -- about 120,000 distinct definitions.
It publishes all of them as static files, bucketed so that a client can look
a tool up without telling anyone which tool it has.

`heldfast verify` does this for every tool in your lockfile. This page is the
protocol, for any other client to do the same.

## What an answer means

| answer | meaning |
|---|---|
| seen, since a date, on N servers | this exact definition -- name, words, schemas, annotations, icons -- was shown publicly. One that thousands of people were shown was not crafted for you |
| not in the bucket | as far as the public record goes, this definition exists only where you got it. Normal for a server you wrote or run privately; worth reading for one you installed |

Not seen is not an accusation, and seen is not a clean bill of health: a
public definition can still be a bad one. What the lookup tells you is
whether you are looking at the same thing as everyone else.

## The protocol

1. **Fingerprint the tool** exactly as the lockfile does: the tool digest in
   [LOCK.md](LOCK.md#tool-digest), lowercase hex. Implementations that already
   write `.mcp-pin.lock` have it on disk.
2. **Take the first three hex characters.** That names one of 4,096 buckets.
3. **Fetch the bucket:**
   `https://raw.githubusercontent.com/rufat325/heldfast/<commit>/lookup/<abc>.json`,
   where `<commit>` is the `feed` branch resolved to a commit (or `feed` itself,
   if you do not need to record which state of the log you read).
4. **Search it locally.** The file is
   `{"prefix": "abc", "tools": {"<fingerprint>": {"first_seen": "YYYY-MM-DD", "servers": N}}}`.
   Present means seen; absent means not.

`lookup/meta.json` gives the prefix length and the count, so a client can
check it is reading the layout it expects.

**What the log learns:** the three characters, and so that your tool is one
of the few dozen in that bucket (a median of 29 today). Not which one, and
nothing else about you -- the same trick Have I Been Pwned uses to check a
password without seeing it. The files are static; there is no server that
could log more than GitHub already does for any file you fetch.

## A client in 20 lines

```python
import json, urllib.request

LOG = "https://raw.githubusercontent.com/rufat325/heldfast/feed/lookup"

def seen(fingerprint: str) -> dict | None:
    """What the public log says about one tool fingerprint, or None."""
    fp = fingerprint.lower()
    with urllib.request.urlopen(f"{LOG}/{fp[:3]}.json", timeout=15) as resp:
        bucket = json.load(resp)
    return bucket["tools"].get(fp)

# fingerprints from a lockfile:
lock = json.load(open(".mcp-pin.lock"))
for server in lock["servers"].values():
    for name, tool in (server.get("tools") or {}).items():
        row = seen(tool["fingerprint"])
        print(server["name"], name,
              f"public since {row['first_seen']} on {row['servers']} server(s)" if row
              else "never seen publicly")
```

The same in JavaScript is a `fetch` and a property lookup. Computing the
fingerprint from a live `tools/list` is the one part with rules to follow:
[LOCK.md](LOCK.md#tool-digest) has them, with test vectors.

## What it is built from, and its limits

- **Published daily** by the feed's publishing job, from every catalogue it
  holds. A bucket changes only when a new definition or a new server appears,
  so the files are stable and cache well.
- **Coverage is the registry's.** Servers listed in the official MCP registry:
  npm packages with a stdio transport, and hosted servers that answer without
  credentials. A server that is not listed, or that needs a login, is not in
  it -- so "never seen" is expected for those.
- **One publisher.** The buckets are derived from this project's feed, a git
  history anyone can fetch and recompute them from. Nothing yet has other
  parties independently reading the same servers; see
  [TRANSPARENCY.md](TRANSPARENCY.md#where-this-goes).
