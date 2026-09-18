"""Show what is installed, without judging any of it.

`scan` answers "is this dangerous". `inspect` answers the question that comes
before it: what is actually configured on this machine, and by which client.

That is worth its own command because the honest first reaction to an agent
security tool is usually "wait, how many MCP servers do I even have?" -- and
answering that should not require reading a findings report and mentally
subtracting the opinions.

It never prints a secret. Environment variables are shown by name with their
value classified as a reference, a placeholder, or a literal, because whether
a config uses indirection is a fact about the config worth seeing at a glance.
"""

from __future__ import annotations

from typing import Any, Iterable

from .clients import display_name
from .model import ServerSpec, SkillSpec, ToolSpec
from .parsers import normalize_tool_grants
from .rules.credentials import classify_secret, is_indirect_or_placeholder


def classify_env_value(key: str, value: str) -> str:
    """Describe an env value without revealing it."""
    v = (value or "").strip()
    if not v:
        return "empty"
    if v.startswith("${") or (v.startswith("$") and v[1:].replace("_", "").isalnum()):
        return "reference"
    # Ask the detector before the placeholder heuristic, for the same reason
    # classify_secret does: a value can look placeholder-ish and still be a
    # real key. AWS's own key format contains the word EXAMPLE.
    if classify_secret(key, v):
        return "LITERAL SECRET"
    if is_indirect_or_placeholder(v):
        return "placeholder"
    return f"literal ({len(v)} chars)"


def build(servers: list[ServerSpec], skills: list[SkillSpec],
          tools: list[ToolSpec], errors: Iterable[str]) -> dict[str, Any]:
    by_server: dict[str, list[ToolSpec]] = {}
    for t in tools:
        by_server.setdefault(t.server, []).append(t)

    by_client: dict[str, list[dict[str, Any]]] = {}
    for s in servers:
        entry: dict[str, Any] = {
            "name": s.name,
            "source": s.source,
            "transport": s.transport,
            "disabled": s.disabled,
            "env": {k: classify_env_value(k, v) for k, v in sorted(s.env.items())},
        }
        if s.command:
            entry["command"] = s.command_line
        if s.url:
            entry["url"] = s.url
        if s.headers:
            entry["headers"] = sorted(s.headers)
        observed = by_server.get(s.name)
        if observed is not None:
            entry["tools"] = [
                {"name": t.name, "description": (t.description or "").strip()[:120]}
                for t in sorted(observed, key=lambda t: t.name)
            ]
        by_client.setdefault(s.client, []).append(entry)

    return {
        "clients": {
            client: {"name": display_name(client), "servers": entries}
            for client, entries in sorted(by_client.items())
        },
        "skills": [
            {
                "name": sk.name,
                "path": sk.path,
                "allowed_tools": normalize_tool_grants(sk.frontmatter),
                "description": str(sk.frontmatter.get("description") or "")[:120],
                "body_lines": len(sk.body.splitlines()),
            }
            for sk in sorted(skills, key=lambda s: s.name.lower())
        ],
        "errors": list(errors),
        "totals": {
            "clients": len(by_client),
            "servers": len(servers),
            "skills": len(skills),
            "tools": len(tools),
        },
    }


def render(data: dict[str, Any], *, color: bool = False, verbose: bool = False) -> str:
    bold = (lambda s: f"\033[1m{s}\033[0m") if color else (lambda s: s)
    dim = (lambda s: f"\033[90m{s}\033[0m") if color else (lambda s: s)
    warn = (lambda s: f"\033[33m{s}\033[0m") if color else (lambda s: s)

    out: list[str] = ["", bold("  mcp-audit inspect"), ""]
    totals = data["totals"]
    out.append(dim(
        f"  {totals['servers']} server(s) across {totals['clients']} client(s), "
        f"{totals['skills']} skill(s), {totals['tools']} tool(s)"
    ))
    out.append("")

    if not data["clients"]:
        out.append(dim("  No MCP servers configured."))

    for client, block in data["clients"].items():
        out.append(f"  {bold(block['name'])} {dim('(' + client + ')')}")
        for s in block["servers"]:
            flag = dim("  [disabled]") if s["disabled"] else ""
            out.append(f"    {s['name']}{flag}")
            target = s.get("command") or s.get("url") or "(nothing configured)"
            out.append(f"      {dim(s['transport'] + ':')} {target[:110]}")
            if s.get("headers"):
                out.append(f"      {dim('headers:')} {', '.join(s['headers'])}")
            for key, kind in s.get("env", {}).items():
                marker = warn(kind) if kind == "LITERAL SECRET" else dim(kind)
                out.append(f"      {dim('env:')} {key} = {marker}")
            for tool in s.get("tools", []):
                out.append(f"      {dim('tool:')} {tool['name']}")
                if verbose and tool["description"]:
                    out.append(f"            {dim(tool['description'])}")
            out.append(f"      {dim(s['source'])}")
        out.append("")

    if data["skills"]:
        out.append(f"  {bold('Skills')}")
        for sk in data["skills"]:
            grants = sk["allowed_tools"]
            grant_text = ", ".join(str(g) for g in grants) if grants else "none declared"
            out.append(f"    {sk['name']} {dim('(' + str(sk['body_lines']) + ' lines)')}")
            out.append(f"      {dim('allowed-tools:')} {grant_text}")
            if verbose and sk["description"]:
                out.append(f"      {dim(sk['description'])}")
            out.append(f"      {dim(sk['path'])}")
        out.append("")

    for err in data["errors"]:
        out.append(f"  {warn('note')} {err}")
    if data["errors"]:
        out.append("")

    out.append(dim("  Nothing here is a judgement. Run `mcp-audit scan` for that."))
    out.append("")
    return "\n".join(out)
