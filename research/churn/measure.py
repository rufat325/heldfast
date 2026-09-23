"""Tool-definition churn across published MCP servers, official and third-party.

Launches each version, asks for its catalogue, digests every tool the way a
lockfile would, and writes one result file per package under results/ for
merge (below) to fold into wide.json.gz, which analyse.py reads.

This downloads and runs other people's code. Run it in the container
(research/churn/Dockerfile) or on a machine you are willing to lose. Even
there, the children get almost nothing: a fixed environment with no inherited
variables, so a token in the shell that started this is not a token the
server under test can read. A variable the registry says is required gets a
placeholder -- most servers check credentials when a tool is called, not when
it is described -- and the result records that it did.

A server that will not answer tools/list is recorded with the reason, never
counted as unchanged: "we could not look" and "nothing moved" must not share
a bucket.

  python measure.py                   # sample.json + the four official servers
  python measure.py --jobs 2          # in parallel (6 crashed a host; 2 held)
  python measure.py merge             # results/*.json -> wide.json.gz
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from mcp_pin.digest import tool_digest  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")

OFFICIAL = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
]

PLACEHOLDER = "mcp-pin-churn-placeholder"
UNSTABLE = re.compile(r"(alpha|beta|rc|next|canary|dev|pre|snapshot)", re.I)
POSIX = os.name == "posix"


def registry_meta(package):
    import urllib.request
    url = "https://registry.npmjs.org/" + package.replace("/", "%2F")
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-pin-churn"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            # Bytes, then utf-8: a large registry document contains bytes a
            # system codepage has no mapping for, and a decode error here once
            # made a package look like it had no versions at all.
            return json.loads(r.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None


def recent_versions(meta, keep):
    """The last `keep` stable versions, ordered by when they were published.

    Publish order, not semver order: a 1.x backport published after 2.0 is
    what a user upgrading on that date would have received.
    """
    times = meta.get("time") or {}
    stable = [v for v in meta.get("versions") or {}
              if not UNSTABLE.search(v) and v in times]
    stable.sort(key=lambda v: times[v])
    return [(v, times[v]) for v in stable[-keep:]]


def child_env(workdir, required):
    """A fixed environment. Nothing is inherited except what finds node."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": workdir,
        "USERPROFILE": workdir,
        "TMPDIR": workdir, "TEMP": workdir, "TMP": workdir,
        "npm_config_cache": os.environ.get("npm_config_cache")
        or os.path.join(tempfile.gettempdir(), "mcp-pin-churn-npm"),
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "npm_config_audit": "false",
        "NO_COLOR": "1",
    }
    for key in ("SystemRoot", "SYSTEMROOT", "APPDATA", "LOCALAPPDATA", "ComSpec"):
        if key in os.environ:
            env[key] = os.environ[key]
    for name in required:
        env.setdefault(name, PLACEHOLDER)
    return env


def stop(p):
    try:
        p.stdin.close()
    except OSError:
        pass
    try:
        if POSIX:
            os.killpg(p.pid, signal.SIGTERM)
        else:
            p.terminate()
        p.wait(timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if POSIX:
                os.killpg(p.pid, signal.SIGKILL)
            else:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                               capture_output=True)
        except OSError:
            pass


def catalogue(package, version, argv_tail, required, boot_timeout=240):
    """(tools, why). tools is None when the catalogue could not be read."""
    npx = shutil.which("npx") or shutil.which("npx.cmd")
    if not npx:
        return None, "npx not found"
    workdir = tempfile.mkdtemp(prefix="churn-")
    # Some registry entries paste npx's own syntax into the package's
    # arguments: `-y -p <package> <bin>` means "run <bin> from <package>",
    # and a leading -y is npx's flag, not the server's.
    tail = list(argv_tail)
    while tail[:1] == ["-y"]:
        tail = tail[1:]
    if tail[:2] == ["-p", package]:
        argv = [npx, "-y", "-p", f"{package}@{version}", *tail[2:]]
    else:
        argv = [npx, "-y", f"{package}@{version}", *tail]
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True,
                             encoding="utf-8", errors="replace", bufsize=1,
                             cwd=workdir, env=child_env(workdir, required),
                             start_new_session=POSIX)
    except OSError as e:
        return None, f"spawn failed: {e}"
    got, err = {}, []

    def read_out():
        try:
            for line in p.stdout:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                if m.get("id") == 1:
                    got["init"] = m.get("result") or {"error": m.get("error")}
                elif m.get("id") == 2:
                    if "error" in m:
                        got["tools_error"] = m["error"]
                    else:
                        got["tools"] = (m.get("result") or {}).get("tools") or []
        except (OSError, ValueError):
            pass

    def read_err():
        try:
            for line in p.stderr:
                err.append(line.rstrip())
                del err[:-15]
        except (OSError, ValueError):
            pass

    threading.Thread(target=read_out, daemon=True).start()
    threading.Thread(target=read_err, daemon=True).start()

    def send(obj):
        try:
            p.stdin.write(json.dumps(obj) + "\n")
            p.stdin.flush()
        except OSError:
            pass

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "mcp-pin-churn", "version": "2"}}})
    t0 = time.time()
    while "init" not in got and p.poll() is None and time.time() - t0 < boot_timeout:
        time.sleep(0.1)
    if "init" in got:
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        time.sleep(0.4)
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        t0 = time.time()
        while ("tools" not in got and "tools_error" not in got
               and p.poll() is None and time.time() - t0 < 60):
            time.sleep(0.1)
    exited = p.poll()
    stop(p)
    shutil.rmtree(workdir, ignore_errors=True)

    if "tools" in got:
        return got["tools"], None
    tail = " | ".join(err[-3:])[-300:]
    if "tools_error" in got:
        return None, f"tools/list error: {json.dumps(got['tools_error'])[:200]}"
    if "init" in got:
        return None, "initialized, no tools/list answer"
    if exited is not None:
        return None, f"exited {exited} before initialize: {tail}"
    return None, f"no initialize answer in {boot_timeout}s: {tail}"


def shape(tool):
    return {
        "digest": tool_digest(tool),
        "description": tool.get("description") or "",
        "schema": json.dumps(tool.get("inputSchema") or {}, sort_keys=True),
        "fields": sorted(tool),
        "raw": tool,
    }


def result_path(package):
    return os.path.join(RESULTS, package.replace("/", "__") + ".json")


def measure(row, keep):
    package = row["package"]
    required = row.get("required_env") or []
    # sample.py carries the registry's launch arguments; the official four are
    # not in the registry frame, and only server-filesystem needs one.
    tail = list(row.get("args") or [])
    if package.endswith("/server-filesystem"):
        tail = [tempfile.gettempdir()]
    meta = registry_meta(package)
    out = {"package": package, "required_env_placeholders": required,
           "args": tail, "unfilled_args": row.get("unfilled_args") or [],
           "downloads_last_month": row.get("downloads_last_month"),
           "official": package.startswith("@modelcontextprotocol/"),
           "versions": {}, "failures": {}}
    if meta is None:
        out["unreachable"] = "npm registry lookup failed"
    else:
        versions = recent_versions(meta, keep)
        if len(versions) < 2:
            out["unreachable"] = "fewer than two stable versions"
        for v, published in versions:
            tools, why = catalogue(package, v, tail, required)
            if tools is None:
                out["failures"][v] = {"published": published, "why": why}
                print(f"  {package}@{v}: {why}", flush=True)
                continue
            out["versions"][v] = {"published": published,
                                  "tools": {t["name"]: shape(t) for t in tools}}
            print(f"  {package}@{v}: {len(tools)} tools", flush=True)
        if len(out["versions"]) < 2 and "unreachable" not in out:
            out["unreachable"] = "could not read two catalogues"
    tmp = result_path(package) + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    os.replace(tmp, result_path(package))
    return package, len(out["versions"])


def run(args):
    os.makedirs(RESULTS, exist_ok=True)
    rows = [{"package": p} for p in OFFICIAL]
    with open(args.sample, encoding="utf-8") as fh:
        seen = set(OFFICIAL)
        for r in json.load(fh)["sample"]:
            if r["package"] not in seen:
                rows.append(r)
                seen.add(r["package"])
    if args.limit:
        rows = rows[:args.limit]
    todo = [r for r in rows if args.redo or not os.path.exists(result_path(r["package"]))]
    print(f"{len(rows)} packages, {len(rows) - len(todo)} already measured, "
          f"{len(todo)} to go", flush=True)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for i, (package, n) in enumerate(pool.map(lambda r: measure(r, args.keep), todo), 1):
            print(f"[{i}/{len(todo)}] {package}: {n} catalogues", flush=True)


def merge(args):
    """Fold results/ into the wide.json shape analyse.py reads."""
    catalogues, unreachable, meta = {}, [], {}
    for name in sorted(os.listdir(RESULTS)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(RESULTS, name), encoding="utf-8") as fh:
            r = json.load(fh)
        meta[r["package"]] = {
            "downloads_last_month": r.get("downloads_last_month"),
            "required_env_placeholders": r.get("required_env_placeholders"),
            "published": {v: x["published"] for v, x in r["versions"].items()},
            "failures": r.get("failures"),
        }
        if r.get("unreachable") or len(r["versions"]) < 2:
            unreachable.append((r["package"], r.get("unreachable") or "under two catalogues"))
            continue
        # The schema goes in as its hash. analyse.py only asks whether two
        # schemas are equal, and the full text made wide.json 50 MB -- too big
        # to commit beside the claims it backs. The schemas themselves stay
        # in results/.
        catalogues[r["package"]] = {
            v: {t: {"digest": s["digest"], "description": s["description"],
                    "schema": hashlib.sha256(s["schema"].encode("utf-8")).hexdigest(),
                    "fields": s["fields"]}
                for t, s in x["tools"].items()}
            for v, x in r["versions"].items()}
    blob = json.dumps({"catalogues": catalogues, "unreachable": unreachable,
                       "meta": meta}, indent=1, sort_keys=True).encode("utf-8")
    if args.out.endswith(".gz"):
        # mtime=0 so the same results produce the same bytes: a rerun that
        # changes nothing should not show up as a changed file.
        with open(args.out, "wb") as raw, gzip.GzipFile(
                filename="wide.json", mode="wb", fileobj=raw, mtime=0,
                compresslevel=9) as fh:
            fh.write(blob)
    else:
        with open(args.out, "wb") as fh:
            fh.write(blob)
    print(f"merged {len(catalogues)} measured, {len(unreachable)} unreachable "
          f"-> {os.path.relpath(args.out)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", nargs="?", default="run", choices=["run", "merge"])
    ap.add_argument("--sample", default=os.path.join(HERE, "sample.json"))
    ap.add_argument("--keep", type=int, default=6, help="versions per package")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0, help="first N packages only")
    ap.add_argument("--redo", action="store_true", help="remeasure finished packages")
    ap.add_argument("--out", default=os.path.join(HERE, "wide.json.gz"))
    args = ap.parse_args()
    (merge if args.command == "merge" else run)(args)


if __name__ == "__main__":
    main()
