# Lookup: has anyone else been shown this exact tool?

Chrome asks Safe Browsing about a site before it opens it. An MCP client can
ask the same kind of question about a tool before an agent trusts it: *has any
public server ever shown this exact definition, and since when?*

The drift feed has recorded every tool definition it read from the official
MCP registry's servers -- npm packages it launched in a container, hosted
servers it read as an anonymous client -- about 120,000 distinct definitions.
It publishes all of them as static files: the whole record in one file, and
the same record split into buckets.

`heldfast verify` does this for every tool in your lockfile. This page is the
protocol, for any other client to do the same -- and what each way of asking
tells whoever serves the files.

## What an answer means

| answer | meaning |
|---|---|
| seen, since a date, on N servers | this exact definition -- name, words, schemas, annotations, icons -- was shown publicly. One that thousands of people were shown was not crafted for you |
| not in the record | as far as the public record goes, this definition exists only where you got it. Normal for a server you wrote or run privately; worth reading for one you installed |

Not seen is not an accusation, and seen is not a clean bill of health: a
public definition can still be a bad one. What the lookup tells you is
whether you are looking at the same thing as everyone else.

## Two ways to ask, and what each reveals

**The whole record** (`lookup/all.json`, the default for `verify`). One file,
every fingerprint the log has seen. The client searches it locally. Whoever
serves it learns that someone downloaded the record, and nothing about which
tools or servers they have. It is about 13.5 MB today and grows as new
definitions are logged.

**Buckets** (`lookup/<abc>.json`, `verify --lookup buckets`). The same record
split 4,096 ways by the first three hex characters of the fingerprint, a few
dozen definitions per bucket (a median of 29). One bucket hides one tool
among its neighbours, the way Have I Been Pwned hides a password. **It does
not hide a server.** A lookup asks about every tool a server has, at once,
and the set of buckets those tools fall in is unique to that server for 85%
of the 13,170 servers logged -- most of the rest are the same catalogue
listed several times. Whoever serves the buckets, and anyone who can see
those requests, can tell which public servers you use. Use buckets when that
does not matter, or when downloading the whole record does.

A tool that is not in the record at all -- one you wrote -- is not revealed
either way: its bucket name matches nothing anyone else has.

## The protocol

1. **Fingerprint the tool** exactly as the lockfile does: the tool digest in
   [LOCK.md](LOCK.md#tool-digest), lowercase hex. Implementations that already
   write `.mcp-pin.lock` have it on disk.
2. **Fetch the record**, from
   `https://raw.githubusercontent.com/rufat325/heldfast/<commit>/lookup/all.json`,
   where `<commit>` is the `feed` branch resolved to a commit (or `feed` itself,
   if you do not need to record which state of the log you read). It is
   `{"prefix_length": 3, "tools": {"<fingerprint>": {"first_seen": "YYYY-MM-DD", "servers": N}}}`.
   *Or*, knowing what it reveals, fetch only `lookup/<first three hex characters>.json`,
   which is `{"prefix": "abc", "tools": {...}}` with the same entries.
3. **Search it locally.** Present means seen; absent means not.

`lookup/meta.json` gives the prefix length and the count, so a client can
check it is reading the layout it expects.

## A client in 20 lines

```python
import json, urllib.request

LOG = "https://raw.githubusercontent.com/rufat325/heldfast/feed/lookup"

# The whole record: nothing about your tools leaves this machine.
with urllib.request.urlopen(f"{LOG}/all.json", timeout=60) as resp:
    record = json.load(resp)["tools"]

# fingerprints from a lockfile:
lock = json.load(open(".mcp-pin.lock"))
for server in lock["servers"].values():
    for name, tool in (server.get("tools") or {}).items():
        row = record.get(tool["fingerprint"].lower())
        print(server["name"], name,
              f"public since {row['first_seen']} on {row['servers']} server(s)" if row
              else "never seen publicly")
```

The same in JavaScript is a `fetch` and a property lookup. Computing the
fingerprint from a live `tools/list` is the one part with rules to follow:
[LOCK.md](LOCK.md#tool-digest) has them, with test vectors.

## What it is built from, and its limits

- **Published daily** by the feed's publishing job, from every catalogue it
  holds. A bucket, and a line of the whole record, changes only when a new
  definition or a new server appears, so the files are stable and cache well.
- **Coverage is the registry's.** Servers listed in the official MCP registry:
  npm packages with a stdio transport, and hosted servers that answer without
  credentials. A server that is not listed, or that needs a login, is not in
  it -- so "never seen" is expected for those.
- **The requests are ordinary HTTPS requests.** Whoever serves the files --
  GitHub today -- sees the address a request came from, for either way of
  asking.
- **One publisher.** The record is derived from this project's feed, a git
  history anyone can fetch and recompute it from. Nothing yet has other
  parties independently reading the same servers; see
  [TRANSPARENCY.md](TRANSPARENCY.md#where-this-goes).
