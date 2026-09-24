# A public log for the MCP servers nobody can scan

Every supply-chain security tool starts from a package. OSV, Socket, Amazon
Inspector, Dependabot, an SBOM: each takes a name and a version, downloads
the code, and reads it. That is how every malicious MCP release so far was
caught -- the worm releases of Postman's, Browserbase's and AntV's servers,
the postmark-mcp backdoor, the "local-only" scanner that uploaded your code
(see [how `updates` screens for them](MANUAL.md#keeping-pins-current-updates)).

Most MCP servers do not have a package. Of the 27,985 servers and endpoints
the drift feed watches in the official MCP registry, **18,576 are hosted**:
a URL your client connects to. There is nothing to download and no version.
What a hosted server tells your agent can change between one request and the
next, with no release to announce it -- in a single day the feed saw hosted
servers change their tools about 5,400 times. And it can differ between one
client and the next.

That last property is the dangerous one. A hosted server can show every
scanner, directory and researcher a clean tool, and show one company's agent
a poisoned one. Nothing is published, so nothing is scanned; the scanners
were shown the clean version, so they report it clean. No tool that starts
from a package can see this, because there is no package.

## The web had this problem

Around 2011, certificate authorities were issuing certificates for sites like
google.com to people who were not Google, and nobody could see it happening:
each fake was shown only to its victims. The fix was not a better scanner. It
was **Certificate Transparency**: every certificate has to be written to a
public log, and browsers refuse one the log has not seen. An attacker can
still issue a fake -- but only in public, where the owner is watching.

## The same idea for hosted MCP servers

The drift feed already is that log. Every day it connects to each hosted
server in the registry that answers without credentials, as an anonymous
client, and keeps every tool list it was given, in git, at a commit anyone
can fetch.

`heldfast verify` asks the question Certificate Transparency asks:
*is this server showing me what it shows everyone?*

```
$ heldfast verify
heldfast verify -- public log rufat325/heldfast@87b7b05a...

  claude-code:kb               same as the public log: 12 tool(s), last logged 2026-09-24
  claude-code:crm              DIFFERS from the public log
      shows you a definition the public log has never recorded: search
      the server is telling you something it has not told anyone else. Read these tools
      before any agent uses them.
  claude-code:docs             2 tool(s) the public log has never seen: admin_export, audit
      expected if you are signed in and the public is not; read them
  claude-code:internal         a local or private address; no public log can hold it

1 server(s) show you tools the public log has never recorded.
```

Each tool is compared by the same fingerprint the lockfile records --
description, title, both schemas, annotations, icons -- not by name:

| what you see | what it means | what happens |
|---|---|---|
| **same** | every definition you were shown, the log recorded | nothing |
| **differs** | the log knows the tool by name, but never recorded the definition you were shown | `verify` exits 1; `approve` refuses it unless you name it with `--yes-tool` |
| **unlogged** | a tool the log has never seen at all | reported. Normal behind a login; `--strict` fails on it |
| **not in the log** | the feed does not read this URL | reported |

It is also built into approval. Trust on first use trusts whatever the server
chose to show you first; for a hosted server at a public address, `approve
--probe` now has a second witness. A definition shown to you that the public
never saw is not written into the lock until you have read it and named it.
After that, the lock does what it always did: any change is refused at the
call site.

## What it cannot do

Said plainly, because a security tool that overclaims is worse than none:

- **The log is one reader, once a day.** A server that recognises the feed's
  requests and shows it the same poisoned tool it shows you is not caught
  here -- but it has then published the poison, where every other check can
  see it. Transparency does not stop an attack; it takes away the option of
  attacking in private.
- **Signed-in clients see more.** The log reads what an anonymous client is
  shown. Tools behind a login are reported as unlogged, not as differing,
  because most of them are simply private.
- **Some servers change on their own.** A few publishers rewrite their tool
  text constantly; their definitions can read as differing between readings.
  `verify` says when the log has seen a server change often.
- **One publisher.** Today the log is this project's git history: a record
  cannot change without its commit changing, and `verify` prints the commit
  it read -- but it is published by one party. Certificate Transparency works because
  several independent logs and monitors watch each other. That is the next
  step, and it is the part worth doing with the registry rather than alone.

## Where this goes

- **Independent readers.** The same reading, taken from different networks by
  different operators, published side by side. A server that shows one reader
  something different from the rest is found by the log itself.
- **Tamper evidence.** Signed checkpoints of the log, so a client can hold
  proof of what the log said on a given day, and show that no reading was
  later rewritten.
- **A registry field.** The MCP registry already verifies who publishes a
  server. Recording the digest of what a hosted server says, at each reading,
  next to that entry would make "is this what everyone sees?" a question any
  client can ask.

The same log also answers the smaller question for any tool, hosted or not
-- has anyone else been shown this exact definition? -- without learning which
tool you asked about: [LOOKUP.md](LOOKUP.md).

The data behind this is public: the `feed` branch of this repository, read
at the commit `verify` prints.
