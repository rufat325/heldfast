"""Choose which servers the churn study measures, by a rule anyone can rerun.

A hand-picked list invites the obvious objection: you chose the ones that
made your point. So the sample frame is the official MCP registry, and the
rule is mechanical:

  1. every server whose latest registry entry ships an npm package over stdio
  2. ranked by npm downloads over the last month
  3. keep the top N that have at least two stable published versions

The frame, the rank and the date are written to sample.json, so the question
"why this server and not that one" has an answer that is not us.

Stdlib only, like everything else here. Contacts registry.modelcontextprotocol.io,
registry.npmjs.org and api.npmjs.org. Runs nothing.
"""
import argparse
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
OFFICIAL_SCOPE = "@modelcontextprotocol/"
UNSTABLE = re.compile(r"(alpha|beta|rc|next|canary|dev|pre|snapshot)", re.I)


DOWNLOADS_CACHE = os.path.join(HERE, "downloads-cache.json")


def get_json(url, tries=12):
    """GET and parse, waiting out rate limits rather than failing the run.

    api.npmjs.org answers a burst of per-package lookups with 429. Giving up
    after a minute of backoff lost a half-hour frame build, so this honours
    Retry-After and caps the wait instead of the attempt count mattering.
    """
    delay = 2.0
    for attempt in range(tries):
        wait = delay
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "heldfast-churn"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code not in (429, 500, 502, 503, 504) or attempt == tries - 1:
                raise
            after = e.headers.get("Retry-After") if e.headers else None
            if after and after.isdigit():
                wait = max(wait, float(after))
        except (urllib.error.URLError, TimeoutError):
            if attempt == tries - 1:
                raise
        time.sleep(min(wait, 120.0))
        delay = min(delay * 2, 120.0)
    return None


def launch_args(pkg):
    """(argv after the package name, required inputs we could not fill).

    Several of the most-downloaded entries are general CLIs whose MCP server
    is a subcommand -- `snyk mcp -t stdio`, `azure/mcp server start` -- so
    launching the bare package measures a help screen, not a server.

    Publishers disagree about where that subcommand goes. The schema says
    runtimeArguments are for the runner (npx) and packageArguments for the
    package; firebase-tools puts `mcp` in runtimeArguments. A positional value
    handed to npx is never what anyone meant, so it is treated as the
    package's. Named runtime flags stay out: they really are for npx.
    """
    argv, unfilled = [], []
    runtime = [a for a in pkg.get("runtimeArguments") or []
               if a.get("type") == "positional"]
    for a in runtime + list(pkg.get("packageArguments") or []):
        value = a.get("value") if a.get("value") is not None else a.get("default")
        if a.get("type") == "named":
            if value is not None:
                argv += [a["name"], str(value)]
            elif a.get("isRequired"):
                unfilled.append(a.get("name"))
        elif value is not None:
            argv.append(str(value))
        elif a.get("isRequired"):
            unfilled.append(a.get("valueHint") or "positional")
    return argv, unfilled


def registry_npm_stdio():
    """Every npm/stdio package named by a latest registry entry."""
    found, cursor, pages = {}, None, 0
    while True:
        q = {"limit": "100", "version": "latest"}
        if cursor:
            q["cursor"] = cursor
        page = get_json(REGISTRY + "?" + urllib.parse.urlencode(q))
        pages += 1
        for entry in page["servers"]:
            server = entry["server"]
            for pkg in server.get("packages") or []:
                if pkg.get("registryType") != "npm":
                    continue
                if (pkg.get("transport") or {}).get("type") != "stdio":
                    continue
                required = [e.get("name") for e in pkg.get("environmentVariables") or []
                            if e.get("isRequired")]
                argv, unfilled = launch_args(pkg)
                found.setdefault(pkg["identifier"], {
                    "registry_name": server["name"],
                    "required_env": required,
                    "args": argv,
                    "unfilled_args": unfilled,
                })
        cursor = page["metadata"].get("nextCursor")
        if pages % 25 == 0:
            print(f"  registry: {pages} pages, {len(found)} npm stdio packages",
                  file=sys.stderr, flush=True)
        if not cursor:
            return found, pages


def monthly_downloads(names):
    """Last-month npm downloads. Bulk for unscoped names, one call per scoped.

    Counts are cached in downloads-cache.json as they arrive, so a run that
    dies on the thousandth scoped lookup resumes from there.
    """
    out = {}
    if os.path.exists(DOWNLOADS_CACHE):
        with open(DOWNLOADS_CACHE, encoding="utf-8") as fh:
            wanted = set(names)
            out = {n: d for n, d in json.load(fh).items() if n in wanted}
    lock = threading.Lock()

    def save():
        with lock:
            with open(DOWNLOADS_CACHE + ".tmp", "w", encoding="utf-8",
                      newline="\n") as fh:
                json.dump(out, fh)
            os.replace(DOWNLOADS_CACHE + ".tmp", DOWNLOADS_CACHE)

    unscoped = [n for n in names if not n.startswith("@") and n not in out]
    scoped = [n for n in names if n.startswith("@") and n not in out]
    for i in range(0, len(unscoped), 128):
        chunk = unscoped[i:i + 128]
        blob = get_json("https://api.npmjs.org/downloads/point/last-month/"
                        + ",".join(chunk)) or {}
        if len(chunk) == 1:
            blob = {chunk[0]: blob}
        for n in chunk:
            out[n] = ((blob.get(n) or {}).get("downloads")) or 0
    save()

    def one(n):
        blob = get_json("https://api.npmjs.org/downloads/point/last-month/"
                        + urllib.parse.quote(n, safe="@")) or {}
        return n, blob.get("downloads") or 0

    with ThreadPoolExecutor(max_workers=3) as pool:
        for i, (n, d) in enumerate(pool.map(one, scoped), 1):
            out[n] = d
            if i % 100 == 0:
                save()
                print(f"  downloads: {i}/{len(scoped)} scoped",
                      file=sys.stderr, flush=True)
    save()
    return out


def stable_versions(name):
    meta = get_json("https://registry.npmjs.org/" + name.replace("/", "%2F"))
    if not meta or "versions" not in meta:
        return []
    return [v for v in meta["versions"] if not UNSTABLE.search(v)]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--top", type=int, default=150)
    ap.add_argument("--out", default=os.path.join(HERE, "sample.json"))
    args = ap.parse_args()

    frame, pages = registry_npm_stdio()
    print(f"frame: {len(frame)} npm stdio packages from {pages} registry pages",
          file=sys.stderr, flush=True)
    downloads = monthly_downloads(sorted(frame))
    ranked = sorted(frame, key=lambda n: (-downloads.get(n, 0), n))

    chosen, skipped = [], []
    for name in ranked:
        if len(chosen) >= args.top:
            break
        versions = stable_versions(name)
        row = {"package": name, "downloads_last_month": downloads.get(name, 0),
               "official": name.startswith(OFFICIAL_SCOPE),
               "stable_versions": len(versions), **frame[name]}
        if len(versions) < 2:
            skipped.append({**row, "why": "fewer than two stable versions"})
            continue
        chosen.append(row)

    # LF on every OS, so the committed sample does not churn by platform.
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({
            "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "rule": "registry.modelcontextprotocol.io latest entries; npm packages "
                    "with stdio transport; ranked by npm last-month downloads; "
                    f"top {args.top} with >= 2 stable versions",
            "frame_size": len(frame),
            "sample": chosen,
            "skipped_above_cutoff": skipped,
        }, fh, indent=1)
    print(f"sample: {len(chosen)} packages (skipped {len(skipped)} above the "
          f"cutoff); wrote {os.path.relpath(args.out)}", file=sys.stderr)


if __name__ == "__main__":
    main()
