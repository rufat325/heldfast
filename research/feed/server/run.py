"""Run the drift feed's collector somewhere other than GitHub Actions.

.github/workflows/feed.yml is the collector today. This does the same work,
phase for phase, on a machine you control, so that if GitHub ever restricts
or disables the crawler, moving takes a day instead of leaving a gap in the
record. It is written and tested; it is deployed nowhere. MOVING.md is the
runbook; systemd/ has the timers, shipped and not enabled.

Phases, each its own command so each can run as its own user:

  measure   one container per shard (research/feed/Dockerfile, the same
            flags feed.yml uses), each on a throwaway clone of the feed with
            no credential in it; what a shard changed is collected as its
            upload, exactly as the Actions job uploads an artifact
  publish   admit each shard's upload with the code from this checkout
            (never from anything a shard wrote), verify, fold, render,
            verify the whole feed, commit; on a daily run, write the day's
            checkpoint. --push to push
  anchor    stamp the checkpoint with OpenTimestamps and upgrade pending
            proofs, with the client at --ots; writes only its own folder
  record    admit the anchor's output (watch.py admit-anchor) and commit it.
            --push to push
  archive   pack what the mirror does not have yet (archive.py)
  mirror    upload the archives and checkpoints to the Hugging Face dataset,
            with huggingface_hub from --hf-python and HF_TOKEN in the
            environment
  sync      rebuild the watchlist from the registry (weekly)
  dry-run   all of the above that matters, on a temporary clone with a small
            watchlist, pushing nothing; ends with watch.py verify --complete

Separation, which is the point: a measuring container gets a copy of the
feed and nothing else -- no credential, no host environment, no capability.
Only the publishing user can read the push credential. The third-party
clients (OpenTimestamps, huggingface_hub) run as users that cannot read it.
The Sigstore witness is not here: keyless signing needs the identity token
only Actions provides, and the Bitcoin anchor does not depend on it.

Layout under --state (default /var/lib/heldfast-feed):
  feed/                 the feed repository checkout (publish user's)
  runs/<id>/deltas/     one folder per shard's upload
  runs/<id>/work/       the shards' throwaway clones
  checkpoint/, anchor/, archive/
  lock                  held for every phase, so runs never overlap

Stdlib only; needs git and docker on PATH.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
FEED_DIR = os.path.dirname(HERE)
TOOL = os.path.dirname(os.path.dirname(FEED_DIR))
WATCH = os.path.join(FEED_DIR, "watch.py")
ARCHIVE = os.path.join(FEED_DIR, "archive.py")
FEED_URL = "https://github.com/rufat325/heldfast-feed.git"
DATASET = "rufat325/heldfast-feed"
MIRROR = f"https://huggingface.co/datasets/{DATASET}/resolve/main"
NPM_SHARDS, REMOTE_SHARDS = 16, 4
IMAGE = "heldfast-feed"


def log(message: str) -> None:
    print(f"[{datetime.now(timezone.utc):%H:%M:%S}] {message}", flush=True)


def run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, **kw)


def git(repo: str, *args: str, **kw) -> subprocess.CompletedProcess:
    return run(["git", "-C", repo, "-c", "core.autocrlf=false", *args], **kw)


def watch(*args: str) -> None:
    run([sys.executable, WATCH, *args])


def today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


# -- measure ---------------------------------------------------------------

def build_image(image: str, platform: str = "") -> None:
    argv = ["docker", "build", "-f", os.path.join(FEED_DIR, "Dockerfile"), "-t", image]
    if platform:
        argv = ["docker", "buildx", "build", "--load", "--platform", platform,
                "-f", os.path.join(FEED_DIR, "Dockerfile"), "-t", image]
    run(argv + [TOOL])


def container(image: str, data: str, args: list[str], memory: str, pids: int) -> list[str]:
    """The same isolate feed.yml runs: no capabilities, no privilege gain,
    bounded memory, CPU and processes, no host environment (docker passes
    none unless asked), and as the invoking user where there is one."""
    argv = ["docker", "run", "--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", memory, "--cpus", "2", "--pids-limit", str(pids)]
    if hasattr(os, "getuid"):
        argv += ["--user", f"{os.getuid()}:{os.getgid()}"]
    return argv + ["-v", f"{os.path.abspath(data)}:/data", image, *args]


def shard(feed: str, work: str, deltas: str, kind: str, index: int, of: int, image: str,
          budget: int, jobs: int, busy: bool, day: str) -> None:
    """One shard, like one matrix job: a throwaway clone, the container, and
    the files it changed collected as that shard's upload."""
    copy = os.path.join(work, f"{kind}-{index}")
    run(["git", "clone", "-q", "--shared", feed, copy])
    label = f"{kind}-{index}"
    if kind == "npm":
        args = ["check", "--data", "/data", "--jobs", str(jobs), "--budget", str(budget),
                "--shard", f"{index}/{of}", "--label", f"npm-{index}", "--day", day]
        memory, pids = "6g", 2048
    else:
        args = ["check-remote", "--data", "/data", "--jobs", "8", "--shard", f"{index}/{of}",
                "--label", f"remote-{index}", "--day", day] + (["--busy"] if busy else [])
        memory, pids = "2g", 512
    log(f"shard {label}: measuring")
    result = subprocess.run(container(image, copy, args, memory, pids))
    if result.returncode in (125, 126, 127):
        # Docker could not run the container at all (no image, no daemon, no
        # permission): nothing was measured, and saying "0 files changed"
        # would publish a day with nothing in it as if it were quiet.
        raise SystemExit(f"shard {label}: docker could not start the container "
                         f"(exit {result.returncode})")
    if result.returncode:
        log(f"shard {label}: exited {result.returncode}; what it measured is still collected")
    changed = git(copy, "ls-files", "-m", "-o", "--exclude-standard", "-z",
                  capture_output=True).stdout.decode("utf-8").split("\0")
    out = os.path.join(deltas, f"feed-delta-{kind}-{index}")
    for rel in filter(None, changed):
        target = os.path.join(out, *rel.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(os.path.join(copy, *rel.split("/")), target)
    log(f"shard {label}: {len([c for c in changed if c])} file(s) changed")
    shutil.rmtree(copy, ignore_errors=True)


def measure(args: argparse.Namespace) -> str:
    run_dir = os.path.join(args.state, "runs", args.run_id)
    # The timers reuse a run id per kind of run: what the last one uploaded is
    # not this one's to publish.
    shutil.rmtree(run_dir, ignore_errors=True)
    deltas, work = os.path.join(run_dir, "deltas"), os.path.join(run_dir, "work")
    os.makedirs(deltas, exist_ok=True)
    os.makedirs(work, exist_ok=True)
    feed = os.path.join(args.state, "feed")
    if not args.busy:
        for i in range(args.npm_shards):
            shard(feed, work, deltas, "npm", i, args.npm_shards, args.image, args.budget,
                  args.jobs, False, args.day)
    for i in range(args.remote_shards):
        shard(feed, work, deltas, "remote", i, args.remote_shards, args.image, 0, 8,
              args.busy, args.day)
    return deltas


# -- publish, anchor, record ----------------------------------------------

def publish(args: argparse.Namespace) -> None:
    feed = os.path.join(args.state, "feed")
    run_dir = os.path.join(args.state, "runs", args.run_id)
    incoming = os.path.join(run_dir, "incoming-delta")
    watch("admit", "--data", feed, "--deltas", os.path.join(run_dir, "deltas"), "--into", incoming,
          "--day", args.day, "--npm-shards", str(args.npm_shards),
          "--remote-shards", str(args.remote_shards))
    watch("verify", "--data", incoming)
    shutil.copytree(incoming, feed, dirs_exist_ok=True)
    watch("fold", "--data", feed)
    watch("render", "--data", feed)
    watch("verify", "--data", feed, "--complete")
    git(feed, "add", "-A")
    if subprocess.run(["git", "-C", feed, "diff", "--cached", "--quiet"]).returncode:
        git(feed, "-c", "user.name=heldfast feed", "-c", "user.email=feed@heldfast.invalid",
            "commit", "-q", "-m", f"feed: {args.day}")
    else:
        log("nothing moved")
    if args.push:
        git(feed, "push", "origin", "HEAD:main")
    if not args.busy:
        out = os.path.join(args.state, "checkpoint", f"{args.day}.json")
        described = subprocess.run(
            [sys.executable, WATCH, "checkpoint", "--data", feed, "--commit", "HEAD", "--day", args.day,
             "--out", out], check=True, capture_output=True, text=True).stdout
        with open(os.path.join(args.state, "checkpoint", "outputs.env"), "w", encoding="utf-8") as fh:
            fh.write(described)
        log("checkpoint: " + described.replace("\n", " "))


def _outputs(state: str) -> dict:
    with open(os.path.join(state, "checkpoint", "outputs.env"), encoding="utf-8") as fh:
        return dict(line.strip().split("=", 1) for line in fh if "=" in line)


def anchor(args: argparse.Namespace) -> None:
    """The anchor job: stamp today's checkpoint, upgrade pending proofs. Runs
    the OpenTimestamps client, so it writes only state/anchor."""
    out = _outputs(args.state)
    day, feed = out["day"], os.path.join(args.state, "feed")
    dest = os.path.join(args.state, "anchor", "checkpoints")
    shutil.rmtree(os.path.dirname(dest), ignore_errors=True)
    os.makedirs(dest)
    if not os.path.exists(os.path.join(feed, "checkpoints", f"{day}.json")):
        shutil.copy2(os.path.join(args.state, "checkpoint", f"{day}.json"), dest)
        run([args.ots, "stamp", os.path.join(dest, f"{day}.json")])
    folder = os.path.join(feed, "checkpoints")
    for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        proof = os.path.join(folder, name)
        if not name.endswith(".ots"):
            continue
        with open(proof, "rb") as fh:
            if bytes.fromhex("0588960d73d71901") in fh.read():
                continue
        work = os.path.join(args.state, "anchor", "work", name)
        os.makedirs(os.path.dirname(work), exist_ok=True)
        shutil.copy2(proof, work)
        subprocess.run([args.ots, "upgrade", work])
        with open(proof, "rb") as a, open(work, "rb") as b:
            if a.read() != b.read():
                shutil.copy2(work, dest)


def record(args: argparse.Namespace) -> None:
    out = _outputs(args.state)
    feed = os.path.join(args.state, "feed")
    watch("admit-anchor", "--data", feed, "--incoming", os.path.join(args.state, "anchor"),
          "--day", out["day"], "--feed-commit", out["feed_commit"],
          "--manifest-sha256", out["manifest_sha256"], "--checkpoint-sha256", out["checkpoint_sha256"])
    git(feed, "add", "checkpoints")
    if subprocess.run(["git", "-C", feed, "diff", "--cached", "--quiet"]).returncode:
        git(feed, "-c", "user.name=heldfast feed", "-c", "user.email=feed@heldfast.invalid",
            "commit", "-q", "-m", f"feed: checkpoint {out['day']}")
        if args.push:
            git(feed, "push", "origin", "HEAD:main")


# -- archive and mirror ----------------------------------------------------

def archive(args: argparse.Namespace) -> None:
    import urllib.request
    out = _outputs(args.state)
    day, commit, feed = out["day"], out["feed_commit"], os.path.join(args.state, "feed")
    dest = os.path.join(args.state, "archive")
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest)
    try:
        with urllib.request.urlopen(f"{MIRROR}/MIRRORED_FROM", timeout=30) as resp:
            last = resp.read(200).decode().split()
    except OSError:
        last = []
    last_commit, last_day = (last + ["", ""])[:2]
    if not last_commit or last_day[:7] != day[:7]:
        run([sys.executable, ARCHIVE, "snapshot", "--data", feed, "--commit", commit, "--day", day,
             "--out", os.path.join(dest, f"snapshot-{day[:7]}.tar.gz")])
    if last_commit and last_commit != commit:
        run([sys.executable, ARCHIVE, "daily", "--data", feed, "--from", last_commit, "--to", commit,
             "--day", day, "--out", os.path.join(dest, "daily", f"{day}.tar.gz")])
    with open(os.path.join(dest, "MIRRORED_FROM"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{commit} {day}\n")
    run([sys.executable, ARCHIVE, "card", "--out", os.path.join(dest, "README.md")])
    shutil.copytree(os.path.join(feed, "checkpoints"), os.path.join(dest, "checkpoints"))


def mirror(args: argparse.Namespace) -> None:
    """Runs huggingface_hub, from its own interpreter, with HF_TOKEN."""
    script = ("import os,sys\nfrom huggingface_hub import HfApi\n"
              "HfApi(token=os.environ['HF_TOKEN']).upload_folder(repo_id=sys.argv[1], "
              "repo_type='dataset', folder_path=sys.argv[2], commit_message='mirror')\n")
    run([args.hf_python, "-c", script, DATASET, os.path.join(args.state, "archive")])


def sync(args: argparse.Namespace) -> None:
    feed = os.path.join(args.state, "feed")
    watch("sync", "--data", feed)
    watch("verify", "--data", feed)
    git(feed, "add", "watchlist.json")
    if subprocess.run(["git", "-C", feed, "diff", "--cached", "--quiet"]).returncode:
        git(feed, "-c", "user.name=heldfast feed", "-c", "user.email=feed@heldfast.invalid",
            "commit", "-q", "-m", f"feed: watchlist {args.day}")
        if args.push:
            git(feed, "push", "origin", "HEAD:main")


# -- dry run ---------------------------------------------------------------

def trim_watchlist(feed: str, npm: int, hosted: int) -> list[str]:
    """Keep a few daily npm servers and hosted endpoints, and forget the npm
    ones' state, so each is really launched rather than found unchanged."""
    path = os.path.join(feed, "watchlist.json")
    with open(path, encoding="utf-8") as fh:
        body = json.load(fh)
    rows = body["packages"]
    npm_rows = [r for r in rows if r.get("kind", "npm") == "npm" and r.get("tier", "daily") == "daily"
                and not r.get("required_env")][:npm]
    hosted_rows = [r for r in rows if r.get("kind") == "remote"][:hosted]
    body["packages"] = npm_rows + hosted_rows
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(body, fh, indent=1, sort_keys=True)
        fh.write("\n")
    import watch as w
    for r in npm_rows:
        state = os.path.join(feed, "state", w.safe(r["package"]) + ".json")
        if os.path.exists(state):
            os.remove(state)
    git(feed, "-c", "user.name=dry", "-c", "user.email=dry@heldfast.invalid",
        "commit", "-q", "-am", "dry run: a small watchlist")
    return [r["package"] for r in npm_rows + hosted_rows]


def dry_run(args: argparse.Namespace) -> int:
    sys.path.insert(0, FEED_DIR)
    state = args.state if args.state_given else tempfile.mkdtemp(prefix="heldfast-feed-dry-")
    args.state = state  # every phase below reads it
    feed = os.path.join(state, "feed")
    log(f"dry run in {state}; nothing is pushed")
    if "://" in args.feed:
        run(["git", "clone", "-q", "--depth", "1", args.feed, feed])
    else:
        # A local repository, at any ref it holds (a remote-tracking one too):
        # the clone shares its objects, so checking out the commit needs no copy.
        sha = git(args.feed, "rev-parse", "--verify", (args.ref or "HEAD") + "^{commit}",
                  capture_output=True, text=True).stdout.strip()
        run(["git", "clone", "-q", "--shared", "--no-checkout", args.feed, feed])
        git(feed, "checkout", "-q", "-B", "main", sha)
    watched = trim_watchlist(feed, args.npm, args.hosted)
    log("watching " + ", ".join(watched))
    if not args.no_build:
        build_image(args.image, args.platform)
    args.npm_shards, args.remote_shards, args.busy, args.push = 1, 1, False, False
    measure(args)
    publish(args)
    if args.ots:
        anchor(args)
        record(args)
    watch("verify", "--data", feed, "--complete")
    log(f"dry run complete: the feed in {feed} verifies")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("command", choices=("measure", "publish", "anchor", "record", "archive",
                                        "mirror", "sync", "dry-run"))
    ap.add_argument("--state", default="")
    ap.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
    ap.add_argument("--day", default=today())
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--platform", default="", help="build the image for this platform (linux/arm64)")
    ap.add_argument("--npm-shards", type=int, default=NPM_SHARDS)
    ap.add_argument("--remote-shards", type=int, default=REMOTE_SHARDS)
    ap.add_argument("--budget", type=int, default=120, help="npm launches per shard per day")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--busy", action="store_true", help="the four-hourly pass: hosted servers only")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--ots", default="", help="the OpenTimestamps client (anchor)")
    ap.add_argument("--hf-python", default="", help="an interpreter with huggingface_hub (mirror)")
    ap.add_argument("--feed", default=FEED_URL, help="dry-run: the feed to clone (URL or local repo)")
    ap.add_argument("--ref", default="", help="dry-run: the branch of a local repo to clone")
    ap.add_argument("--npm", type=int, default=3, help="dry-run: npm servers to watch")
    ap.add_argument("--hosted", type=int, default=5, help="dry-run: hosted endpoints to watch")
    ap.add_argument("--no-build", action="store_true", help="dry-run: use the image as built")
    args = ap.parse_args()
    if sys.platform == "win32":
        # The feed holds paths past Windows' 260-character limit and two that
        # differ only in case; a Windows checkout loses one of those and would
        # commit its deletion. A Linux file system is required, and WSL is one.
        print("run.py needs Linux (or WSL): the feed's paths do not fit a Windows "
              "checkout", file=sys.stderr)
        return 2
    args.state_given = bool(args.state)
    args.state = args.state or "/var/lib/heldfast-feed"
    if args.command == "dry-run":
        return dry_run(args)
    {"measure": measure, "publish": publish, "anchor": anchor, "record": record,
     "archive": archive, "mirror": mirror, "sync": sync}[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
