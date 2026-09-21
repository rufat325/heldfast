"""mcp-pin as an MCP server.

The rest of this package is an MCP *client*: it connects to servers and reads
what they advertise. This module is the mirror image -- it exposes the
scanner's own analysis over MCP, so an agent can ask "is this config safe?"
before a human installs anything.

The useful case is the one that happens before the damage: someone pastes a
server config from a README or a registry listing, and the agent can check it
against every rule in this package without writing it to disk first.

SECURITY POSTURE
----------------
This server is deliberately narrow, because a tool an agent can call is a
tool an attacker who controls the agent can call:

- Everything here is read-only analysis. No tool writes, deletes, or
  executes anything.
- Probing is not exposed at all. `--probe` *launches local processes*, and
  reaching that over a tool call would turn "an agent read a web page" into
  "an agent started a process". The CLI keeps that capability; this does not.
- Path scanning is opt-in per deployment via MCP_PIN_ALLOW_PATH_SCAN,
  because an agent that can scan arbitrary paths can use findings as an
  oracle for what exists on the filesystem.
- Findings pass through the same redaction chokepoint as every other output,
  so a credential discovered during analysis is never returned to the model.

The tool descriptions below are written the way this scanner would want to
read them: they describe what the tool does and nothing else. No imperatives
aimed at the agent, no instructions about other tools, no mandated side
effects. `mcp-pin` scanning its own server is expected to come back clean,
and a test asserts exactly that.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .findings import Severity
from .parsers import parse_config
from .rules import AuditContext, all_rules, run_rules

# This server answers both eras, for the same reason probe.py speaks both.
# The current revision replaced the initialize handshake with `server/discover`;
# a client that only knows the new method would otherwise get "method not
# found" from the security scanner's own server. Advertising a protocol two
# revisions old while shipping a rule about protocol currency is not a
# position worth defending.
PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_VERSIONS = [PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION]
SERVER_INFO = {"name": "mcp-pin", "version": __version__}

ALLOW_PATH_SCAN = os.environ.get("MCP_PIN_ALLOW_PATH_SCAN", "").lower() in ("1", "true", "yes")


def _tool_definitions() -> list[dict[str, Any]]:
    tools = [
        {
            "name": "check_config",
            "description": (
                "Analyzes a Model Context Protocol server configuration supplied as JSON "
                "text and returns the security findings for it. Accepts the same shape as "
                "a claude_desktop_config.json or .mcp.json file, including the mcpServers "
                "object. The configuration is analyzed in memory and is not added to any "
                "client. Returns each finding with its rule identifier, severity, the "
                "evidence for it, and the suggested remediation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "config": {
                        "type": "string",
                        "description": (
                            "The configuration to analyze, as JSON text. May contain "
                            "comments and trailing commas."
                        ),
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": [s.label for s in Severity],
                        "description": "Omits findings below this severity. Defaults to info.",
                    },
                },
                "required": ["config"],
            },
        },
        {
            "name": "list_rules",
            "description": (
                "Returns the catalog of checks this scanner implements: the rule "
                "identifier, default severity, and a one-line summary for each."
            ),
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "explain_rule",
            "description": (
                "Returns the full description of a single check, given its rule "
                "identifier such as MCPA015."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "A rule identifier, for example MCPA001.",
                    }
                },
                "required": ["rule_id"],
            },
        },
    ]
    if ALLOW_PATH_SCAN:
        tools.append({
            "name": "scan_path",
            "description": (
                "Analyzes Model Context Protocol configuration files and agent skill "
                "files found under a filesystem path, and returns the security findings "
                "for them. Reads files only; no server is started and nothing is "
                "modified."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory or file to analyze.",
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": [s.label for s in Severity],
                        "description": "Omits findings below this severity. Defaults to info.",
                    },
                },
                "required": ["path"],
            },
        })
        # Gated with scan_path and for the same reason: both read the local
        # filesystem and describe what is configured on this machine.
        tools.append({
            "name": "check_coverage",
            "description": (
                "Reports which of this installation's security guarantees are actually "
                "in force for each configured Model Context Protocol server: whether it "
                "was approved, whether its tool definitions and its code are pinned, "
                "whether its arguments are constrained, whether anything enforces that "
                "at runtime, and which declared identities may reach it. For each "
                "guarantee that is not in force, returns the reason and the command "
                "that would change it. Reads the approval lockfile and the "
                "configuration files under a path. Reads files only; no server is "
                "started and nothing is modified."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to read configuration from.",
                    },
                    "lock": {
                        "type": "string",
                        "description": (
                            "Path to the approval lockfile. Defaults to "
                            ".mcp-pin.lock beside the configuration."
                        ),
                    },
                },
                "required": ["path"],
            },
        })
    return tools


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _findings_payload(findings, scanned: dict[str, Any]) -> dict[str, Any]:
    counts = {s.label: sum(1 for f in findings if f.severity == s) for s in Severity}
    return {
        "scanned": scanned,
        "summary": {
            "total": len(findings),
            "by_severity": {k: v for k, v in counts.items() if v},
            "highest": max((f.severity for f in findings), default=Severity.INFO).label,
        },
        "findings": [f.to_dict() for f in findings],
    }


def tool_check_config(args: dict[str, Any]) -> dict[str, Any]:
    raw = args.get("config")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("config must be a non-empty JSON string")
    floor = Severity.parse(str(args.get("min_severity") or "info"))

    # parse_config reads from disk, so the supplied text goes to a temporary
    # file that is removed immediately. Nothing is written to a real client
    # configuration, which is the point of this tool.
    tmp = Path(tempfile.mkdtemp(prefix="mcp-pin-")) / ".mcp.json"
    try:
        tmp.write_text(raw, encoding="utf-8")
        servers, errors = parse_config(tmp, "supplied")
        if errors and not servers:
            # Never answer "0 findings" for input we could not read. An agent
            # relaying that to a user would be reporting a clean bill of
            # health for a config nothing actually checked.
            detail = "; ".join(e.split(": ", 1)[-1] for e in errors)
            raise ValueError(f"could not parse the supplied configuration: {detail}")
        ctx = AuditContext(servers=servers, config_errors=errors)
        findings = [f for f in run_rules(ctx) if f.severity >= floor]
        payload = _findings_payload(findings, {"servers": len(servers)})
        if errors:
            # Stripped the same way the raise path above strips it. The temp
            # directory is an implementation detail of this tool, and every
            # other field in this payload already hides it.
            payload["errors"] = [e.split(": ", 1)[-1] for e in errors]
        # The temp path is an implementation detail; do not leak it back.
        for item in payload["findings"]:
            item["path"] = "<supplied config>"
        return payload
    finally:
        try:
            tmp.unlink(missing_ok=True)
            tmp.parent.rmdir()
        except OSError:
            pass


def tool_list_rules(_args: dict[str, Any]) -> dict[str, Any]:
    return {
        "rules": [
            {"id": r.id, "severity": r.default_severity.label, "name": r.name}
            for r in all_rules()
        ]
    }


def tool_explain_rule(args: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(args.get("rule_id") or "").upper()
    for r in all_rules():
        if r.id == rule_id:
            return {
                "id": r.id,
                "name": r.name,
                "severity": r.default_severity.label,
                "description": r.description,
            }
    raise ValueError(f"unknown rule id {rule_id!r}; call list_rules for the catalog")


def tool_scan_path(args: dict[str, Any]) -> dict[str, Any]:
    if not ALLOW_PATH_SCAN:
        raise ValueError("path scanning is not enabled on this server")
    from .discovery import discover_config_files
    from .parsers import discover_skills

    target = Path(str(args.get("path") or "."))
    if not target.exists():
        raise ValueError(f"{target}: no such file or directory")
    floor = Severity.parse(str(args.get("min_severity") or "info"))

    servers, errors = [], []
    for cfg, client in discover_config_files([target], scan_user=False):
        s, e = parse_config(cfg, client)
        servers.extend(s)
        errors.extend(e)
    skills = discover_skills([target], scan_user=False)
    ctx = AuditContext(servers=servers, skills=skills, config_errors=errors)
    findings = [f for f in run_rules(ctx) if f.severity >= floor]
    return _findings_payload(
        findings, {"path": str(target), "servers": len(servers), "skills": len(skills)}
    )


def tool_check_coverage(args: dict[str, Any]) -> dict[str, Any]:
    """Answer "am I actually protected" for the agent asking it.

    `serve` had drifted three cycles behind the rest of the tool: it could
    report on a configuration's *findings* and knew nothing about whether any
    of this installation's guarantees were in force. That is the question an
    agent using mcp-pin as a server most obviously has about itself, and the
    one the command line had just learned to answer.
    """
    if not ALLOW_PATH_SCAN:
        raise ValueError("path scanning is not enabled on this server")
    from . import coverage as coverage_mod
    from .discovery import discover_config_files
    from .lockfile import Lock, resolve_lock_path

    target = Path(str(args.get("path") or "."))
    if not target.exists():
        raise ValueError(f"{target}: no such file or directory")

    lock_path = resolve_lock_path(args.get("lock"), cwd=target if target.is_dir() else target.parent)
    try:
        lock = Lock.load(lock_path)
    except ValueError as exc:
        raise ValueError(f"could not read {lock_path}: {exc}") from exc

    servers = []
    for cfg, client in discover_config_files([target], scan_user=False):
        found, _ = parse_config(cfg, client)
        servers.extend(found)

    payload = coverage_mod.build(lock, servers)
    payload["lockfile"] = str(lock_path)
    # Absent is not the same as satisfied, and an agent relaying "0 gaps" for
    # a machine with no lockfile would be reporting a boundary that does not
    # exist. No rule runs here to say so, so this does.
    if not lock.servers:
        payload["note"] = (
            "No approval lockfile was found, so nothing is pinned and none of these "
            "guarantees can be in force. Run `mcp-pin approve --probe` first."
        )
    return payload


HANDLERS = {
    "check_config": tool_check_config,
    "list_rules": tool_list_rules,
    "explain_rule": tool_explain_rule,
    "scan_path": tool_scan_path,
    "check_coverage": tool_check_coverage,
}


# ---------------------------------------------------------------------------
# JSON-RPC plumbing
# ---------------------------------------------------------------------------

def _send(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _result(req_id: Any, result: dict[str, Any]) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def _error(req_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    req_id = message.get("id")

    if method == "server/discover":
        _result(req_id, {
            "serverInfo": SERVER_INFO,
            "capabilities": {"tools": {}},
            "supportedVersions": SUPPORTED_VERSIONS,
        })
        return

    if method == "initialize":
        # A legacy client negotiates a single version here, so it gets the one
        # it can actually speak rather than the newest one we know.
        _result(req_id, {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })
        return

    if method in ("notifications/initialized", "initialized"):
        return  # notification: no response

    if method == "ping":
        _result(req_id, {})
        return

    if method == "tools/list":
        _result(req_id, {"tools": _tool_definitions()})
        return

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        handler = HANDLERS.get(str(name))
        if handler is None or (name == "scan_path" and not ALLOW_PATH_SCAN):
            _error(req_id, -32602, f"unknown tool: {name}")
            return
        try:
            payload = handler(params.get("arguments") or {})
        except Exception as exc:
            # Tool failures are results, not protocol errors: the agent should
            # see what went wrong rather than the connection breaking.
            _result(req_id, {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            })
            return
        _result(req_id, {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
            "isError": False,
        })
        return

    if req_id is not None:
        _error(req_id, -32601, f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict):
            handle(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
