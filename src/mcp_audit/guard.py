"""A transparent MCP proxy that enforces the approval lockfile at runtime.

`scan` tells you a server changed. This refuses to pass the change through.

    client  --stdio-->  mcp-audit guard  --stdio-->  real server

The proxy speaks the protocol in both directions and forwards everything
untouched except one thing: the `tools/list` response. Each advertised tool is
fingerprinted and compared against `.mcp-audit.lock`, and anything unapproved
is handled according to policy before the client ever sees it.

WHY THIS IS NOT JUST A SECOND COPY OF THE SCANNER
-------------------------------------------------
The interesting part is that it reads the *same lockfile* the CI gate reads.
Other wrappers keep their own private pin store, which means the thing your
pipeline approved and the thing your machine enforces are two separate facts
that can disagree. Here they are one artifact: `.mcp-audit.lock` is committed
to the repository, so a tool description changing shows up as a diff in code
review, fails the build, *and* is refused at the call site -- all from the
file the reviewer actually looked at.

FAILURE POSTURE
---------------
Two different failures, two different answers, both deliberate:

- A *security* event (a tool changed, a tool is unapproved) fails closed. That
  is the entire point.
- An *internal* error (the lockfile is corrupt, a rule raises) fails open, and
  says so loudly on stderr. A scanner bug should not take down the user's
  agent; silently breaking every tool call is how a security tool gets ripped
  out and never reinstalled. `--strict` inverts this for people who would
  rather lose the agent than lose the guarantee.

Everything diagnostic goes to stderr. Stdout is the protocol channel and
carries nothing but JSON-RPC.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .findings import Severity
from .lockfile import DEFAULT_LOCK_NAME, Lock
from .model import ServerSpec, ToolSpec
from .rules import AuditContext, run_rules

# What to do with a tool that is not approved, or whose definition changed.
POLICIES = ("block", "strip", "warn")
DEFAULT_POLICY = "block"


@dataclass
class GuardStats:
    forwarded: int = 0
    tools_seen: int = 0
    tools_blocked: list[str] = field(default_factory=list)
    tools_unapproved: list[str] = field(default_factory=list)
    tools_drifted: list[str] = field(default_factory=list)
    findings_blocked: list[str] = field(default_factory=list)
    internal_errors: list[str] = field(default_factory=list)


class Guard:
    def __init__(self, server_name: str, lock: Lock, *, policy: str = DEFAULT_POLICY,
                 strict: bool = False, block_severity: Severity = Severity.CRITICAL,
                 quiet: bool = False) -> None:
        self.server_name = server_name
        self.lock = lock
        self.policy = policy
        self.strict = strict
        self.block_severity = block_severity
        self.quiet = quiet
        self.stats = GuardStats()
        self._locked_tools = self._load_locked_tools()

    # -- lockfile ----------------------------------------------------------

    def _load_locked_tools(self) -> dict[str, str] | None:
        """Approved name -> fingerprint, or None when the server is unknown."""
        for entry in self.lock.servers.values():
            if not isinstance(entry, dict):
                continue
            if entry.get("name") != self.server_name:
                continue
            tools = entry.get("tools")
            if isinstance(tools, dict):
                return {
                    name: meta.get("fingerprint", "")
                    for name, meta in tools.items()
                    if isinstance(meta, dict)
                }
            return {}
        return None

    def log(self, message: str) -> None:
        if not self.quiet:
            print(f"mcp-audit guard: {message}", file=sys.stderr, flush=True)

    # -- policy ------------------------------------------------------------

    def _verdict(self, tool: ToolSpec) -> tuple[str, str]:
        """Return (verdict, reason). Verdict is 'allow' or 'deny'."""
        if self._locked_tools is None:
            return "allow", "server not in lockfile; nothing to enforce"

        locked = self._locked_tools.get(tool.name)
        if locked is None:
            self.stats.tools_unapproved.append(tool.name)
            return "deny", "tool was not present at approval"
        if locked != tool.fingerprint():
            self.stats.tools_drifted.append(tool.name)
            return "deny", "tool definition changed since approval"
        return "allow", "matches approved fingerprint"

    def _content_verdict(self, tool: ToolSpec) -> tuple[str, str]:
        """Run the poisoning rules over this tool's own text."""
        try:
            spec = ServerSpec(name=self.server_name, source="<guard>", client="guard",
                              transport="stdio")
            findings = run_rules(AuditContext(servers=[spec], tools=[tool]))
        except Exception as exc:  # a rule bug must not break the connection
            self.stats.internal_errors.append(f"rules raised: {exc}")
            self.log(f"INTERNAL ERROR running rules on {tool.name}: {exc}")
            return ("deny", "internal error and --strict is set") if self.strict else \
                   ("allow", "internal error; failing open")

        worst = [f for f in findings if f.severity >= self.block_severity]
        if worst:
            top = worst[0]
            self.stats.findings_blocked.append(f"{tool.name}: {top.rule_id}")
            return "deny", f"{top.rule_id} ({top.severity.label}): {top.title}"
        return "allow", ""

    def filter_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        kept: list[dict[str, Any]] = []
        for raw in tools:
            if not isinstance(raw, dict):
                kept.append(raw)
                continue
            self.stats.tools_seen += 1
            tool = ToolSpec(
                server=self.server_name,
                name=str(raw.get("name") or ""),
                description=str(raw.get("description") or ""),
                input_schema=raw.get("inputSchema") or {},
            )

            verdict, reason = self._verdict(tool)
            if verdict == "allow":
                verdict, content_reason = self._content_verdict(tool)
                if verdict == "deny":
                    reason = content_reason

            if verdict == "allow":
                kept.append(raw)
                continue

            self.stats.tools_blocked.append(tool.name)
            if self.policy == "warn":
                self.log(f"ALLOWED (policy=warn) {tool.name}: {reason}")
                kept.append(raw)
            elif self.policy == "strip":
                self.log(f"STRIPPED {tool.name}: {reason}")
            else:  # block
                self.log(f"BLOCKED {tool.name}: {reason}")
                blocked = dict(raw)
                # Replaced rather than removed, so the agent is told the tool
                # exists but is refused. Silently vanishing tools look like a
                # broken server and send people hunting the wrong problem.
                blocked["description"] = (
                    f"[BLOCKED BY mcp-audit] This tool is not approved: {reason}. "
                    f"It cannot be used. Run `mcp-audit approve --probe` after "
                    f"reviewing the change."
                )
                blocked["inputSchema"] = {"type": "object", "properties": {}}
                kept.append(blocked)
        return kept

    # -- message handling --------------------------------------------------

    def handle_server_message(self, message: dict[str, Any]) -> dict[str, Any]:
        """Inspect a message travelling server -> client."""
        try:
            result = message.get("result")
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                result["tools"] = self.filter_tools(result["tools"])
        except Exception as exc:
            self.stats.internal_errors.append(str(exc))
            self.log(f"INTERNAL ERROR inspecting message: {exc}")
            if self.strict:
                raise
        return message

    def summary(self) -> str:
        s = self.stats
        bits = [f"{s.forwarded} messages", f"{s.tools_seen} tools"]
        if s.tools_drifted:
            bits.append(f"{len(s.tools_drifted)} drifted ({', '.join(s.tools_drifted)})")
        if s.tools_unapproved:
            bits.append(f"{len(s.tools_unapproved)} unapproved")
        if s.findings_blocked:
            bits.append(f"{len(s.findings_blocked)} failed content rules")
        if s.internal_errors:
            bits.append(f"{len(s.internal_errors)} internal errors")
        return ", ".join(bits)


def run(argv: list[str], *, lock_path: Path, policy: str = DEFAULT_POLICY,
        server_name: str | None = None, strict: bool = False,
        block_severity: Severity = Severity.CRITICAL, quiet: bool = False) -> int:
    """Launch `argv` and proxy stdio between it and our own stdin/stdout."""
    if not argv:
        print("mcp-audit guard: no server command given", file=sys.stderr)
        return 2

    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        print(f"mcp-audit guard: {exc}", file=sys.stderr)
        if strict:
            return 2
        lock = Lock(path=lock_path)

    name = server_name or Path(argv[0]).stem
    guard = Guard(name, lock, policy=policy, strict=strict,
                  block_severity=block_severity, quiet=quiet)

    if guard._locked_tools is None:
        guard.log(
            f"server {name!r} is not in {lock_path.name}; forwarding without enforcement. "
            "Run `mcp-audit approve --probe` to pin it."
        )
    else:
        guard.log(f"enforcing {len(guard._locked_tools)} approved tool(s) for {name!r} "
                  f"(policy={policy})")

    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
    except OSError as exc:
        print(f"mcp-audit guard: cannot launch {argv[0]!r}: {exc}", file=sys.stderr)
        return 2

    def pump_client_to_server() -> None:
        try:
            for line in sys.stdin:
                if proc.stdin is None:
                    break
                proc.stdin.write(line)
                proc.stdin.flush()
        except (OSError, ValueError):
            pass
        finally:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except OSError:
                pass

    upstream = threading.Thread(target=pump_client_to_server, daemon=True)
    upstream.start()

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            stripped = line.strip()
            if not stripped:
                continue
            guard.stats.forwarded += 1
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                # Not JSON. Pass it through untouched rather than dropping it;
                # some servers emit banner text before the protocol starts.
                sys.stdout.write(line)
                sys.stdout.flush()
                continue
            if isinstance(message, dict):
                message = guard.handle_server_message(message)
            sys.stdout.write(json.dumps(message) + "\n")
            sys.stdout.flush()
    except (OSError, ValueError) as exc:
        guard.log(f"transport error: {exc}")
    finally:
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass
        guard.log(guard.summary())

    return proc.returncode or 0
