# A public log for the MCP servers nobody can scan

Every supply-chain security tool starts from a package. OSV, Socket, Amazon
Inspector, Dependabot, an SBOM: each takes a name and a version, downloads
the code, and reads it. That is how the malicious MCP releases reported so far
were caught -- the worm releases of Postman's, Browserbase's and AntV's servers,
the postmark-mcp backdoor, the "local-only" scanner that uploaded your code
(see [how `updates` screens for them](MANUAL.md#keeping-pins-current-updates)).

Most MCP servers do not have a package. Of the 29,458 servers and endpoints
the drift feed watched in the official MCP registry on 28 September 2026,
**19,746 were hosted**: a URL your client connects to. There is nothing to
download and no version. What a hosted server tells your agent can change
between one request and the next, with no release to announce it -- on
24 September 2026 the feed saw hosted servers change their tools 6,028 times
([the first week, measured](FIRST-WEEK.md)). And it can differ between one
client and the next.

That last property is the dangerous one. A hosted server can show every
scanner, directory and researcher a clean tool, and show one company's agent
a poisoned one. Nothing is published, so nothing is scanned; the scanners
were shown the clean version, so they report it clean. No tool that starts
from a package can see this, because there is no package.

## The web had this problem

In 2011, certificate authorities issued certificates for sites like
google.com to people who were not Google, and each fake was shown only to its
victims. DigiNotar's came to light because it was used against users in Iran
and Chrome happened to pin Google's keys
([Google, August 2011](https://security.googleblog.com/2011/08/update-on-attempted-man-in-middle.html)).
The fix was not a better scanner. It was **Certificate Transparency**
([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)): every certificate has to
be written to public logs, and browsers refuse one without proof that it was. An attacker can
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

- **It records what a server says, not what it does.** A tool can keep an
  identical description and schema while the code behind it changes, and the
  log would not record that as a change. What a tool does when called is
  outside what the log reads.
- **The log is one reader, a few times a day.** Each hosted server is read
  daily, and every four hours while it has changed in the last three days. A
  quiet server that shows a version for only a few hours between two daily
  readings is still never logged. A server that recognises the feed's
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
  cannot change without its commit changing, `verify` prints the commit it
  read, and each day's commit is anchored in Bitcoin ([checkpoints](#checkpoints))
  -- but it is published by one party. Certificate Transparency works because
  several independent logs and monitors watch each other. That is the next
  step, and it is the part worth doing with the registry rather than alone.

## Why it runs continuously, and who reads it

The feed is built by `.github/workflows/feed.yml` in this repository, and it
is the data several heldfast commands run on. `approve --from-feed` pins a
server from a catalogue the feed measured, instead of running the server
here. `updates` grades each newer release by the feed's measurement before
proposing it. `verify`, and `approve --probe` for a hosted server, compare
what a server shows you with what the feed read. `verify` also looks each
approved tool up in `lookup/`. The opt-in `server_history` tool of `heldfast
serve` answers from its index. A hosted server has no release to go back to:
a version it shows for a few hours exists in the record only if it was read
during those hours. That is why the measuring is daily, and every four hours
for servers that changed recently, rather than done once when someone asks.

## Checkpoints

Every date in the log is written by whoever holds the push credential: a
commit date, an `observed_at`. So "the log saw this first" would be only as
good as a claim this project makes about itself. Checkpoints put a bound on
those dates that nobody holding this repository's credentials can move.

**What is anchored.** After each daily publish, the feed repository gets
`checkpoints/YYYY-MM-DD.json`. It names one published commit (`feed_commit`)
and gives `manifest_sha256`: the SHA-256 of a manifest listing the SHA-256 of
every file in that commit, outside `checkpoints/` itself. The file also says
how many files and events that commit holds, and which heldfast version and
`main` commit wrote it. Beside it, `checkpoints/YYYY-MM-DD.json.ots` is an
[OpenTimestamps](https://opentimestamps.org) proof of the checkpoint file. A
calendar server folds the file's digest into a Bitcoin transaction, so the
proof ties the checkpoint, and every byte it digests, to a Bitcoin block. A
fresh proof is pending until that transaction confirms, a few hours later.
The next day's run upgrades it and commits the complete proof. Git's own
object IDs are SHA-1, which is why the manifest hashes file contents itself
instead of relying on the commit ID.

**From which date.** From the first daily run after checkpoints were added.
Nothing before that is anchored, and it never can be: a stamp made today
proves only that the data existed today.

**If the daily run does not come.** GitHub starts scheduled runs late under
load, sometimes by hours, and occasionally drops one, while the four-hourly
passes keep publishing. So the feed repository's watchdog looks for the
day's checkpoint every hour. If there is none by 10:00 UTC and no feed run
is under way, it starts the daily run itself, up to three times; without
the token that allows this, it opens an issue instead. A run that would
publish after midnight UTC is too late: that day has no checkpoint, and the
watchdog says so rather than hiding the gap. The watchdog's own hourly check is
dropped by GitHub as often as the daily run, so there is a second net: from
12:00 UTC, the four-hourly pass that re-reads busy hosted servers records the
day's checkpoint itself if there is still none. That day is then anchored
without its npm measuring, which lands in the next day's checkpoint.

**How to verify one.** Rebuild the manifest from the commit, compare the
digest, then verify the proof. On Linux:

```bash
git clone https://github.com/rufat325/heldfast-feed feed
cd feed
day=2026-09-28   # the checkpoint to check
commit=$(python3 -c "import json; print(json.load(open('checkpoints/$day.json'))['feed_commit'])")
mkdir ../at && git -c core.autocrlf=false archive "$commit" | tar -x -C ../at
(cd ../at && find . -type f ! -path './checkpoints/*' -printf '%P\0' \
  | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
# compare with "manifest_sha256" in checkpoints/$day.json
pip install opentimestamps-client
ots verify checkpoints/$day.json.ots
```

The manifest's lines are exactly what `sha256sum` prints: the digest, two
spaces, the path, one line per file, sorted by path as bytes. `python3
research/feed/watch.py checkpoint --data feed --commit $commit --day $day
--generator-commit <its main_commit> --out /tmp/cp.json` from a clone of
`main` rebuilds the whole checkpoint file byte for byte.

`ots verify` checks the proof against the Bitcoin block headers, which it
reads from a local Bitcoin Core node (a pruned one is enough). Without a
node, `ots --no-bitcoin verify` prints the block height and the Merkle root
the proof commits to. You can compare those with any block explorer, but
then you are trusting the explorer.

**A second witness.** While the feed is collected in GitHub Actions, each
checkpoint is also signed with [Sigstore](https://www.sigstore.dev), keyless:
`checkpoints/YYYY-MM-DD.json.sigstore.json` is the bundle, and the signature
sits in the public Rekor log with the identity of the workflow that made it.
Verify it with cosign 3:

```bash
cosign verify-blob --bundle checkpoints/$day.json.sigstore.json \
  --certificate-identity https://github.com/rufat325/heldfast/.github/workflows/feed.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checkpoints/$day.json
```

That adds what the Bitcoin anchor cannot say: the checkpoint came from this
repository's feed workflow, on `main`, and Rekor recorded when. It rests on
trusting GitHub's identity tokens and Sigstore's log, where the anchor rests
on Bitcoin alone; that is why it is the second witness and not the first.
Only the signing job holds the permission to sign as the workflow, and it
runs cosign and nothing else. A missing signature costs nothing else: the
anchor does not depend on it.

**What it proves.** The checkpoint, and every file in the commit it
describes, existed no later than the time of the Bitcoin block. An event the
log claims to have observed on a day is in that day's checkpoint or it is
not, and one inserted into the history later is missing from every
checkpoint before it.

**What it does not prove.** That the data is accurate: a lying server, or a
lying collector, is anchored just as faithfully. That a server showed
everyone what it showed the log. That the log has not left something out.
Only an upper bound on each date is anchored, never when a reading was
really taken.

## Copies outside GitHub

The whole record lived in one repository on one host. It is now also kept in
two other places, built by `.github/workflows/feed.yml` after each day's
checkpoint:

- **The Hugging Face dataset
  [rufat325/heldfast-feed](https://huggingface.co/datasets/rufat325/heldfast-feed)**:
  every checkpoint with its proofs, one archive a day of what changed
  (`daily/YYYY-MM-DD.tar.gz`), a snapshot of the whole tree at each month's
  first checkpoint (`snapshot-YYYY-MM.tar.gz`), and `MIRRORED_FROM`, the feed
  commit the copy is current to.
- **Releases of the feed repository**: each monthly snapshot, as a release
  tagged `archive-YYYY-MM`, split into parts past GitHub's 2 GB asset limit.

Every archive is deterministic -- members sorted, one fixed timestamp, no
owners, gzip without a name or a time -- so the same commit always packs to
the same bytes, and `research/feed/archive.py` rebuilds any of them from the
feed repository for comparison. A snapshot and the daily archives after it
rebuild the tree at a later checkpoint, and the manifest digest of what they
rebuild is the one that checkpoint states: the copies are checked by the same
anchor as the original. `archive.py verify --checkpoint FILE ARCHIVE...` does
that in memory. Use it rather than unpacking on Windows or macOS: the feed
holds paths that differ only in letter case, which those disks fold into one. Each upload is read back and its SHA-256 compared
before the job reports success. The job that uploads to Hugging Face holds
only that token, and the one that publishes releases only the feed
repository's, so neither copy can be written by what writes the other.

## Comparing with another record

Another record can name the same tool definition by a different digest. The
key here is the native digest of [LOCK.md](LOCK.md): `tools/` holds each
definition once, named by it, and every catalogue lists a tool by it. The feed
stores no other digest. A digest from another record is recomputed from
`tools/`, so a comparison needs nothing a clone does not already hold.

One profile is implemented: `agentavow.mcp-tool-definition.v1`, the digest
AgentAvow's signed attestations carry for each tool
([their description and vectors](https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards/tool-manifest-digest-vectors-v1)).
`src/heldfast/profiles.py` implements the rules as that page states them. No
file of theirs is copied into this repository, because the folder carries no
licence of its own; the one test that reads their vectors runs only when
`AGENTAVOW_VECTORS_DIR` names a local copy.

`research/feed/profile_index.py` reads a checkout of the feed and writes
nothing inside it:

```bash
python3 research/feed/profile_index.py --data feed --lookup sha256:<profile digest>
python3 research/feed/profile_index.py --data feed --check <package> <tool> sha256:<profile digest>
python3 research/feed/profile_index.py --data feed --index ../native-to-profile.json
```

`--lookup` names the tool files whose definition has that profile digest.
`--check` lists the readings of one tool, with `measured_at`, whose definition
yields it, and the first and last seen. `--index` writes the native-to-profile
map for every tool file, to a file outside the checkout.

**The first raw seen.** A profile digest here is computed from the definition
`tools/` holds, which is the first raw seen under a native digest (the
first-layout catalogues carry each reading's own). The native digest folds
distinct shapes of a field -- missing, `null`, `""` or `{}` -- into one, and
this profile does not. A server that serves one definition in two such shapes
has one file in `tools/`, and the profile digest of the shape it served later
cannot be re-derived from it. Measured on the feed at commit `cdd6cc6`, as of
1 October 2026:

- 1,326 of 120,018 tool files (1.105%) have a hashed field present in a shape
  the native digest folds. That is the class in which such a flip is possible.
- 0 of 240,344 native digests map to more than one profile digest, counting
  every file in `tools/` and the 587,436 readings the first-layout catalogues
  keep whole.

**What it does not say.** A digest the record does not hold means the feed did
not read that definition, and the feed is one anonymous reader a few times a
day (above). heldfast reproduces the published digests and key encoding for the
pinned fixture as of 2 October 2026. It makes no claim about AgentAvow's
grades.

## Where this goes

- **Independent readers.** The same reading, taken from different networks by
  different operators, published side by side. A server that shows one reader
  something different from the rest is found by the log itself.
- **Tamper evidence.** Daily checkpoints are anchored today (above), which
  bounds when each reading can have been written. Next: signed checkpoints a
  client can hold, so it can show what the log told it on a given day.
- **A registry field.** The MCP registry already verifies who publishes a
  server. Recording the digest of what a hosted server says, at each reading,
  next to that entry would make "is this what everyone sees?" a question any
  client can ask.

The same log also answers the smaller question for any tool, hosted or not
-- has anyone else been shown this exact definition? By default the client
downloads the whole record, so the log never learns which tools you asked
about; what the lighter bucket lookup gives away is in [LOOKUP.md](LOOKUP.md).

The data behind this is public: [rufat325/heldfast-feed](https://github.com/rufat325/heldfast-feed),
read at the commit `verify` prints. Until 27 September 2026 it was the `feed`
branch of this repository; the history moved with it, dates and checkpoints
included.
