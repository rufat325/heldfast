# Across an organisation: inventory, policy, fleet

A lockfile answers one repository's question: what did we approve here? A
security team is asked a different one, about every laptop and every
repository at once:

- Which MCP servers run here at all, on how many machines, at which versions?
- How many of them did anyone approve, and how many are checked when called?
- Who is running something we said no to?
- A release was just reported as malware. Which machines run it?

Three commands answer that, and none of them needs a service:

| command | runs on | what it does |
|---|---|---|
| `heldfast inventory` | every machine and every repository's CI | writes what that machine runs to one JSON file. Launches nothing, opens no connection |
| an organisation policy | one file you write, deployed to each machine or named per project | which servers are allowed or denied, and what each must have -- refused at launch by `wrap` and `gateway` |
| `heldfast fleet` | wherever the inventories are collected | joins them into one report: text, JSON, or a single HTML page |

```bash
heldfast inventory --label "$(whoami)@$(hostname)" -f json -o "$(hostname).json"
heldfast inventory --policy org-policy.json      # check this machine; exit 1 on a violation
heldfast fleet inventories/ --policy org-policy.json --html report.html
heldfast fleet inventories/ --advisories          # which machines run a release reported as malware?
```

## One machine: `inventory`

The `status` page as data. For every MCP server configured on the machine (or
in the repository, with `--no-user-configs`): which client configures it, what
it runs -- a registry package and version, a hosted address, or a local
command -- whether a lockfile approves it, whether its tool definitions were
pinned, what checks it at call time, and how many findings of each severity
it carries.

```
  alice-mbp   4 server(s) in 2 client(s), 0 skill(s)   heldfast 0.2.3
  lockfile: ~/payments/.mcp-pin.lock
  Claude Code plugin: on

  UNPINNED    claude-code:filesystem  package wrap     npm:@modelcontextprotocol/server-filesystem@2026.8.31
  UNPINNED    claude-code:linear      hosted  plugin   https://mcp.linear.app/sse  (1 medium)
  UNAPPROVED  cursor:github           package none     npm:@modelcontextprotocol/server-github@(no version)  floating  (1 high)
  UNAPPROVED  cursor:tunnel           hosted  none     https://a1b2-203-0-113-7.ngrok-free.app/mcp  (1 high)

  policy Acme engineering  sha256:369994a93706
  DENY  cursor:github: no lockfile approves this server
  DENY  cursor:github: @modelcontextprotocol/server-github runs whatever was published last; pin an exact version
  DENY  cursor:tunnel: https://a1b2-203-0-113-7.ngrok-free.app/mcp is denied: a tunnel to someone's laptop
```

`enforced` says what checks a call: `wrap` (the server runs inside `heldfast
wrap`), `gateway` (reached through `heldfast gateway`), `plugin` (a Claude
Code server, with the [plugin](../plugin/heldfast/README.md) installed and on
-- which checks server and tool names, not definitions), or `none`.

`-f json` is the file `fleet` reads. `-f cyclonedx` writes the same thing as a
CycloneDX 1.6 BOM: each package is a component with its purl, each hosted
server a service with its endpoint, and heldfast's verdicts ride along as
`heldfast:*` properties -- so Dependency-Track, or anything else that ingests a
BOM, shows your MCP servers beside the rest of your dependencies, including
which of them nobody approved.

### What an inventory carries, and what it does not

It is made to be copied off the machine, so it carries less than `status`:

| carried | not carried |
|---|---|
| server and client names, the config file's path with your home directory written `~` | environment values, headers, arguments -- where an MCP config keeps its credentials |
| a package's name and version | the rest of the launch command |
| a hosted server's scheme, host, port and path | its query, fragment and user info; any path segment that looks like a token is `{redacted}` |
| rule ids, severities and titles of findings | the evidence behind them |
| the machine's name (`--label` to choose another) | anything about the user beyond what the label says |

Those are theorems (T-INVENTORY-SECRETLESS, T-INVENTORY-INERT in
[GUARANTEES.md](GUARANTEES.md)), with tests that fail if either is broken.

It launches nothing: the collection is `scan --safe`'s, and `inventory` does
not accept `--probe`. That is what makes it safe to push to every machine --
and it is also its limit, below.

## The policy

One JSON file, written once, checked everywhere:

```json
{
  "policy": "heldfast.org-policy/1",
  "name": "Acme engineering",
  "allow": [
    {"package": "npm:@modelcontextprotocol/*"},
    {"package": "pypi:mcp-server-fetch"},
    {"url": "https://mcp.linear.app/*"},
    {"command": "node", "kind": "local", "reason": "internal servers"}
  ],
  "deny": [
    {"package": "npm:postmark-mcp", "versions": ["1.0.16"],
     "reason": "1.0.16 copied every email it sent to its author"},
    {"url": "https://*.ngrok-free.app/*", "reason": "a tunnel to someone's laptop"}
  ],
  "unlisted": "warn",
  "require": {"approved": true, "pinned": false, "exact_versions": true,
              "enforced": false, "no_drift": true, "fail_on": "high"}
}
```

**Selectors.** A rule matches when every selector it gives matches. Globs
are `*` (any run of characters) and `?` (one character); nothing else is
special.

| selector | matches |
|---|---|
| `package` | `<npm\|pypi\|*>:<name glob>`. PyPI names are compared normalised (PEP 503) |
| `versions` | globs over the exact version, beside a `package`. A server that pins no exact version may run any release, so it matches a deny rule that names versions and never an allow rule that does |
| `url` | `<scheme>://<host glob>[:port][/<path glob>]`. Host and path are matched apart, so `https://*.acme.com/*` is not met by `https://evil.example/.acme.com/`; user info never names the host. Host without case, path with it. No port means any port; no path means any path. An address URL parsers could read differently -- a backslash, a second `@`, `%` or non-ASCII in the host, `%` or `..` in the path -- matches every URL deny rule and no allow rule |
| `command` | a glob over the launched program's name: `node`, `docker`, `npx` |
| `kind` | `hosted`, `package` or `local` |

**Order.** A denied server is reported as denied and nothing else. A server
that matches no allow rule, when there is an allow list, is `unlisted`:
reported as a warning, or as a violation with `"unlisted": "deny"`, or not at
all with `"allow"`. Then each requirement is checked:

| requirement | a server fails it when |
|---|---|
| `approved` | no lockfile approves it |
| `pinned` | it was approved without its tool definitions (`approve` without `--probe` or `--from-feed`) |
| `exact_versions` | its package names no exact release -- npm reads `pkg@1.2` as 1.2.x |
| `enforced` | nothing checks the lockfile when it is called |
| `no_drift` | it no longer matches what was approved, in what an inventory can see |
| `fail_on` | it has a finding at or above this severity. MCPA014 is left to `approved` |

A key this version does not know -- anywhere in the file -- is an error, not
something skipped (T-ORG-POLICY-UNKNOWN). A policy that skipped a misspelt
`"requre"` would report every machine compliant with a requirement nothing
checks.

## At launch: the policy as a boundary

Checked in a report, a policy says who broke it. Checked at launch, it stops
them. `heldfast wrap` (`guard`) and `heldfast gateway` read the organisation
policy before they start a server, and refuse -- before the process exists --
one that the policy:

- denies;
- does not list, when `"unlisted": "deny"`;
- requires to be `approved` and no lockfile approves. `--allow-unapproved`
  cannot waive this: it is the developer's flag, and the policy is not theirs;
- requires to be `pinned`, and the approval pins nothing;
- requires `exact_versions`, and the package floats.

`enforced` holds by being asked there at all, `no_drift` is already the
lockfile's to refuse, and findings are a scan's to judge, so those three are
left to `inventory` and `fleet`.

With the policy above at the managed path:

```
$ heldfast wrap --name postmark -- npx -y postmark-mcp@1.0.16
heldfast guard: lockfile: /home/alice/work/.mcp-pin.lock (found in the working directory; pass --lock to pin it)
heldfast guard: server 'postmark' is not in .mcp-pin.lock, so its tools are withheld. Run `heldfast approve --probe` to review and pin it, or pass --allow-unapproved to forward it unchecked.
heldfast guard: organisation policy Acme engineering (sha256:369994a93706) from /etc/heldfast/org-policy.json
heldfast guard: organisation policy Acme engineering (sha256:369994a93706) refuses this server: postmark-mcp@1.0.16 is denied: 1.0.16 copied every email it sent to its author
```

Exit 2, and `npx` never ran.

**In Claude Code.** Claude Code starts its MCP servers itself, so heldfast
meets them at the call instead: with the [plugin](../plugin/heldfast/README.md)
installed, a call to a server the policy refuses is denied. The plugin reads
the same policy on every call, makes the same decision `wrap` makes -- the
JS and the Python are held to one answer by shared vectors and a differential
test (T-ORG-PARITY) -- and judges the server both as the lockfile approved it
and as Claude Code's own config (`.mcp.json`, `~/.claude.json`) now starts it,
so a lock entry for an allowed release cannot speak for a config that was
changed to run a denied one (T-ORG-HOOK). A policy that is there and cannot be
read refuses every MCP call.

**Where the policy comes from.** The machine's managed path, where MDM puts
it, is always in force:

| platform | managed path |
|---|---|
| Linux | `/etc/heldfast/org-policy.json` |
| macOS | `/Library/Application Support/heldfast/org-policy.json` |
| Windows | `%ProgramData%\heldfast\org-policy.json` |

A policy named with `--org-policy FILE` or `HELDFAST_ORG_POLICY` is checked as
well, never instead: a project can tighten the organisation's policy and
cannot loosen it (T-ORG-MANAGED). A managed file that exists and cannot be read
-- not JSON, an unknown key, a permission error -- refuses every launch until
it can be: a policy someone wrote and this cannot read is not one to guess
past. `heldfast inventory` without `--policy` reports against the managed
policy too, so a machine checks itself against the file its administrator
deployed.

## Many machines: `fleet`

```
$ heldfast fleet inventories/ --policy org-policy.json --advisories

  12 machine(s), 9 distinct server(s), 34 install(s)
  policy Acme engineering  sha256:369994a93706
  approved in a lockfile   20 of 34
  tool definitions pinned  0 of 34
  checked at call time     3 of 34
  exact package versions   21 of 25
  tool definitions were not read on any machine (inventories never probe)

  MALWARE npm:postmark-mcp@1.0.16 (MAL-2025-47604) runs on: bob-xps, ivan-mbp

  servers, by how many machines run them
    12  package npm:@modelcontextprotocol/server-filesystem  1 floating, 5 unapproved
              versions: 2026.8.31 x9, (floating), 2026.6.2, 2026.7.1
     6  hosted  https://mcp.linear.app/sse  1 unapproved
     6  package npm:@modelcontextprotocol/server-memory  1 unapproved
     3  package npm:@modelcontextprotocol/server-github  3 floating, 2 unapproved
     2  package npm:postmark-mcp  denied, 2 unapproved
     2  package pypi:mcp-server-fetch  1 unapproved
     1  hosted  https://a1b2-203-0-113-7.ngrok-free.app/mcp  denied, 1 unapproved
     1  hosted  https://actions.zapier.com/mcp/{redacted}/sse  unlisted, 1 unapproved
     1  local   local:internal-db

  6 machine(s) break the policy
    ivan-mbp  4 violation(s), 3 unapproved
    frank-mbp  4 violation(s), 2 unapproved
    ...
```

That is a twelve-machine sample organisation: real config files, the real
`inventory` on each, and the policy above. The machine it was run on could not
reach OSV, so OSV's answer for that one release was stood in from its record,
[MAL-2025-47604](https://osv.dev/vulnerability/MAL-2025-47604); every other
line is the command's own output.

Counts, never a score: "41 of 60" says where the gap is, and a percentage
invites raising the number rather than closing the gap
([coverage](MANUAL.md#where-the-guarantees-stop-coverage) makes the same
choice). One row per package, hosted address or local command, joined across
every inventory, with the versions in use -- version sprawl is usually the
first thing a fleet report shows. Exit 1 when a machine breaks the policy at
deny level or runs a release reported as malware; 2 when there was nothing to
read.

`--html report.html` writes one self-contained page to send to the people a
security team reports to: no script, font, stylesheet or image is fetched, and
its Content-Security-Policy allows no script at all. Every name on it came
from a config on some machine, so every one is escaped (T-FLEET-UNTRUSTED).

`--policy` judges every inventory by one policy and replaces whatever each
machine was checked against. Without it, each machine's own result is used,
and the report says when machines were checked against different policies.

`--advisories` asks [OSV](https://osv.dev) about every exact package release
in the fleet, a thousand to a request: package names and versions, nothing
about the machines. A release OSV marks as malware (`MAL-`) is named at the
top with every machine that runs it. If OSV cannot be asked, the report says
the answer is unknown -- never that no machine runs malware
(T-ADVISORY-UNKNOWN).

An inventory is read as data from an untrusted source: a field of the wrong
type is replaced, a file that is not an inventory is set aside with a note,
and two files claiming one label keep the newer and say so.

## Collecting inventories

`fleet` reads files; how they arrive is yours. Whatever you already use to
push a script to machines and pull a file back works.

**Developer machines**, from MDM, a login script or a scheduled task:

```bash
heldfast inventory --label "$(whoami)@$(hostname)" --policy /etc/acme/org-policy.json \
  -f json -o "/var/tmp/heldfast-$(hostname).json"
# then copy it wherever inventories are collected
```

Run without paths it reads the current directory and every per-user client
config heldfast knows (17 clients, [CLIENTS.md](CLIENTS.md)). Run it as the
developer, not as root: the configs are under their home directory.

**Repositories**, from the GitHub Action, with two inputs:

```yaml
- uses: rufat325/heldfast@<commit> # pin a SHA
  with:
    inventory: heldfast-inventory.json     # this repository's inventory
    org-policy: .github/org-policy.json    # and fail the job when it breaks the policy
- uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
  with:
    name: heldfast-inventory
    path: heldfast-inventory.json
```

The label defaults to `owner/repo`. A scheduled job in one repository can
download each repository's latest artifact and run `fleet` over them.

## What this does not do

- **An inventory is what a machine says about itself.** Anyone who can write
  to the place inventories are collected can write one, and a machine that
  never runs `inventory` is simply absent. `fleet` marks an inventory older
  than `--max-age` days (14) as stale, so a machine that stops reporting
  shows; it cannot show one that never started.
- **No tool definitions are read.** Inventories never probe, so a tool
  rewritten under an approved name does not show in `inventory` or `fleet`.
  That is what `wrap`, `gateway` and [`verify`](TRANSPARENCY.md) are for, and
  why "checked at call time" is in the report.
- **The policy stops what heldfast is in the path of.** `wrap` and `gateway`
  refuse to start a denied server, and the Claude Code plugin refuses to call
  one. In Claude Code that means the process has already started -- Claude
  Code starts its servers itself, and a hook only sees calls -- so a server
  whose harm is in starting at all wants `wrap` as well. A client with none of
  the three is not stopped by anything here. That is why `"enforced": true`
  exists: the fleet report shows every server that goes around, by machine.
- **A managed policy is as strong as the directory it lives in.** It is
  meant to be written by whoever manages the machine into a directory its
  user cannot write. A user who can write there, or who runs a heldfast they
  modified, is not stopped by it.
- **Path redaction is a heuristic.** A credential in a URL path that is short,
  or all letters, or all digits, is not recognised as one. Credentials belong
  in headers, which an inventory never carries.
- **One label per inventory.** A machine with several users reports what the
  user who ran it can read.
