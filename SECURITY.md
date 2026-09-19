# Security

Report vulnerabilities privately. Do not open a public issue for a hole
in scanning, enforcement, or the GitHub Action.

**GitHub:** Security tab → Report a vulnerability
(https://github.com/rufat325/mcp-pin/security/advisories/new)

Include a reproduction. A config and the command you ran is enough.

What is in scope: a finding that should have fired and did not, a call
the lockfile should have refused and did not, a secret that reached a
report or a child process it was not declared on, or a hole in
`action.yml`.

What is not: `--probe` launches configured servers. That is documented.
A child that is allowed to run can still do whatever the OS allows;
this tool is a pin, not a sandbox.

The GitHub Action must be pinned to a commit SHA. `@main` moves.
The third-party actions this repo uses are pinned the same way.

The PyPI name `mcp-pin` is reserved for this project. Until a tag is
published, install from git at a SHA.
