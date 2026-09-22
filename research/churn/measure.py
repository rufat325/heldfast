"""Tool-definition churn across published MCP servers, official and third-party.

Launches each version, asks for its catalogue, digests every tool the way a
lockfile would, and writes the result for analyse_wide.py to compare.

A server that needs credentials usually still answers tools/list -- the token
is checked when a tool is called, not when it is described -- so most of these
work with no configuration. Ones that do not are recorded as unreachable
rather than dropped silently, because "we could not measure it" and "it did
not change" must not look the same.
"""
import json
import os
import re
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from mcp_pin.digest import tool_digest  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "sandbox")
os.makedirs(WORK, exist_ok=True)

OFFICIAL = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
]

THIRD_PARTY = [
    "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server",
    "@sentry/mcp-server",
    "@apify/actors-mcp-server",
    "@heroku/mcp-server",
    "@browserstack/mcp-server",
    "@supabase/mcp-server-supabase",
    "@winor30/mcp-server-datadog",
    "hostinger-api-mcp",
    "chrome-devtools-mcp",
    "kubernetes-mcp-server",
    "@hubspot/mcp-server",
]

# Only server-filesystem insists on a path argument; everything else here
# starts bare.
ARGS = {"@modelcontextprotocol/server-filesystem": [WORK]}

MAX_VERSIONS = 6


def vkey(v):
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.\-+]", v))


def versions_of(package):
    url = "https://registry.npmjs.org/" + package.replace("/", "%2F")
    # Bytes, not text: `text=True` decodes with the system codepage, and a
    # large registry document contains bytes cp1251 has no mapping for. That
    # raised inside subprocess's reader thread and the package came back
    # looking like it had no published versions at all -- a measurement
    # failure wearing the costume of a result.
    raw = subprocess.run(["curl", "-s", url], capture_output=True).stdout
    try:
        meta = json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        return []
    if "versions" not in meta:
        return []
    stable = [v for v in meta["versions"]
              if not re.search(r"(alpha|beta|rc|next|canary|dev)", v, re.I)]
    return sorted(stable, key=vkey)[-MAX_VERSIONS:]


def catalogue(package, version, timeout=120):
    argv = ["npx.cmd", "-y", f"{package}@{version}", *ARGS.get(package, [])]
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True,
                             encoding="utf-8", errors="replace", bufsize=1,
                             cwd=WORK, env=dict(os.environ))
    except OSError:
        return None
    got = {}

    def read():
        try:
            for line in p.stdout:
                line = line.strip()
                if not line or line[0] != "{":
                    continue
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                if m.get("id") == 2:
                    got["tools"] = (m.get("result") or {}).get("tools") or []
                elif m.get("id") == 1:
                    got["init"] = True
        except (OSError, ValueError):
            pass

    threading.Thread(target=read, daemon=True).start()

    def send(obj):
        try:
            p.stdin.write(json.dumps(obj) + "\n")
            p.stdin.flush()
        except OSError:
            pass

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "churn", "version": "1"}}})
    t0 = time.time()
    while "init" not in got and time.time() - t0 < timeout:
        time.sleep(0.1)
    if "init" in got:
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        time.sleep(0.4)
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        t0 = time.time()
        while "tools" not in got and time.time() - t0 < 40:
            time.sleep(0.1)
    try:
        p.stdin.close()
    except OSError:
        pass
    p.terminate()
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill()
    return got.get("tools")


def shape(tool):
    return {
        "digest": tool_digest(tool),
        "description": tool.get("description") or "",
        "schema": json.dumps(tool.get("inputSchema") or {}, sort_keys=True),
        "fields": sorted(tool),
    }


def main():
    results, unreachable = {}, []
    for package in OFFICIAL + THIRD_PARTY:
        vs = versions_of(package)
        if len(vs) < 2:
            unreachable.append((package, "fewer than two published versions"))
            print(f"{package}: skipped, {len(vs)} version(s)", flush=True)
            continue
        print(f"\n=== {package}: {' '.join(vs)}", flush=True)
        per_version = {}
        for v in vs:
            tools = catalogue(package, v)
            if not tools:
                print(f"  {v}: no catalogue", flush=True)
                continue
            per_version[v] = {t["name"]: shape(t) for t in tools}
            print(f"  {v}: {len(tools)} tools", flush=True)
        if len(per_version) >= 2:
            results[package] = per_version
        else:
            unreachable.append((package, "could not read two catalogues"))
    with open(os.path.join(HERE, "wide.json"), "w", encoding="utf-8") as fh:
        json.dump({"catalogues": results, "unreachable": unreachable},
                  fh, indent=1, sort_keys=True)
    print(f"\nmeasured {len(results)} packages; {len(unreachable)} unreachable",
          flush=True)


if __name__ == "__main__":
    main()
