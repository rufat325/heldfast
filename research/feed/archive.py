"""Packed copies of the feed, for keeping it somewhere other than GitHub.

The whole record lives in one repository. This packs it so it can live
elsewhere too -- the Hugging Face mirror and the feed repository's releases
(.github/workflows/feed.yml) -- in two kinds of archive:

  snapshot-YYYY-MM.tar.gz   the whole tree at one checkpointed commit
  daily/YYYY-MM-DD.tar.gz   what changed from one checkpointed commit to the
                            next: the files added or changed, and a list of
                            the files deleted

Every archive is deterministic: members sorted by path as bytes, one fixed
modification time, owner and group 0 with no names, mode 0644, GNU tar, and
gzip with no name and no timestamp. The same tree always gives the same bytes
and so the same SHA-256, and anyone can rebuild an archive from the commit
and compare. Each carries `.heldfast-archive/meta.json` (which commits, which
day) and a daily one `.heldfast-archive/deleted` (one path per line).

A snapshot and the dailies after it rebuild the tree at a later checkpoint
(`rebuild`), and its manifest digest is the checkpoint's: that is what the
tests check, and what anyone can check against the mirror.

  archive.py snapshot --data DIR --commit SHA --day D --out FILE
  archive.py daily    --data DIR --from SHA --to SHA --day D --out FILE
  archive.py rebuild  --into DIR ARCHIVE...
  archive.py verify   --checkpoint FILE ARCHIVE...
                                        rebuild in memory, compare the digest
  archive.py card     --out FILE        the dataset card for the mirror

Reads git objects, not a working tree; stdlib only.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from datetime import date, datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import watch  # noqa: E402

META = ".heldfast-archive/meta.json"
DELETED = ".heldfast-archive/deleted"


def _mtime(day: str) -> int:
    return int(datetime.combine(date.fromisoformat(day), datetime.min.time(),
                                tzinfo=timezone.utc).timestamp())


def pack(members: list[tuple[str, bytes]], day: str, out: str) -> str:
    """Write a deterministic .tar.gz of (path, bytes) to `out`; return its SHA-256."""
    stamp = _mtime(day)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for path, body in sorted(members, key=lambda m: m[0].encode("utf-8")):
            info = tarfile.TarInfo(path)
            info.size, info.mtime, info.mode = len(body), stamp, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(body))
    packed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=packed, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    data = packed.getvalue()
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as fh:
        fh.write(data)
    digest = hashlib.sha256(data).hexdigest()
    with open(out + ".sha256", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{digest}  {os.path.basename(out)}\n")
    return digest


def _meta(**fields: str) -> tuple[str, bytes]:
    return META, (json.dumps(fields, indent=1, sort_keys=True) + "\n").encode("utf-8")


def snapshot(data: str, commit: str, day: str, out: str) -> str:
    commit = watch._resolve_commit(data, commit)
    members = list(watch.git_files(data, commit))
    members.append(_meta(kind="snapshot", commit=commit, day=day))
    return pack(members, day, out)


def changed(data: str, frm: str, to: str) -> tuple[list[str], list[str]]:
    """(paths added or changed, paths deleted) from one commit to another."""
    listing = subprocess.run(["git", "-C", data, "diff", "--name-status", "-z", "--no-renames",
                              frm, to], capture_output=True, check=True).stdout.split(b"\0")
    kept, gone = [], []
    for status, path in zip(listing[0::2], listing[1::2]):
        (gone if status == b"D" else kept).append(path.decode("utf-8"))
    return sorted(kept), sorted(gone)


def daily(data: str, frm: str, to: str, day: str, out: str) -> str:
    frm, to = watch._resolve_commit(data, frm), watch._resolve_commit(data, to)
    kept, gone = changed(data, frm, to)
    wanted = set(kept)
    members = [(p, b) for p, b in watch.git_files(data, to) if p in wanted]
    members.append(_meta(kind="daily", commit=to, since=frm, day=day))
    members.append((DELETED, "".join(p + "\n" for p in gone).encode("utf-8")))
    return pack(members, day, out)


def replay(archives: list[str]) -> tuple[dict[str, bytes], dict]:
    """The tree a snapshot and the dailies after it describe, in memory:
    ({path: bytes}, the last archive's meta). No file system is involved, so
    the answer does not depend on one: the feed holds paths that differ only
    in case, which a case-insensitive disk would fold into one."""
    tree: dict[str, bytes] = {}
    meta: dict = {}
    for n, path in enumerate(archives):
        with tarfile.open(path, "r:gz") as tar:
            members = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
        meta = json.loads(members.pop(META))
        if (n == 0) != (meta.get("kind") == "snapshot"):
            raise ValueError(f"{path}: a snapshot must come first, and only first")
        for gone in members.pop(DELETED, b"").decode("utf-8").splitlines():
            tree.pop(gone, None)
        for name, body in members.items():
            if name.startswith("/") or "\\" in name or ".." in name.split("/"):
                raise ValueError(f"{path}: {name!r} escapes the tree")
            tree[name] = body
    return tree, meta


def verify(archives: list[str], checkpoint: dict) -> str | None:
    """Why the archives do not rebuild the checkpointed tree, or None."""
    tree, meta = replay(archives)
    if meta.get("commit") != checkpoint.get("feed_commit"):
        return f"the archives end at {meta.get('commit')}, the checkpoint names {checkpoint.get('feed_commit')}"
    digest = hashlib.sha256(watch.manifest(tree.items())).hexdigest()
    if digest != checkpoint.get("manifest_sha256"):
        return f"the rebuilt tree's manifest is {digest}, the checkpoint's {checkpoint.get('manifest_sha256')}"
    return None


def _case_insensitive(folder: str) -> bool:
    probe = os.path.join(folder, ".heldfast-Case-Probe")
    with open(probe, "w", encoding="utf-8"):
        pass
    try:
        return os.path.exists(probe.lower())
    finally:
        os.remove(probe)


def rebuild(into: str, archives: list[str]) -> dict:
    """Write the tree the archives describe into `into`. Returns the last meta.

    Refused on a disk that folds case when two paths would fold into one: the
    tree written would not be the tree described. `verify` needs no disk."""
    tree, meta = replay(archives)
    os.makedirs(into, exist_ok=True)
    folded: dict[str, str] = {}
    for name in tree:
        other = folded.setdefault(name.lower(), name)
        if other != name and _case_insensitive(into):
            raise ValueError(f"{name!r} and {other!r} differ only in case, and this disk "
                             f"does not tell them apart; use `archive.py verify`, or a "
                             f"case-sensitive disk")
    for name, body in tree.items():
        target = os.path.join(into, *name.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(body)
    return meta


def tree_files(root: str):
    """(path, bytes) for every file under `root`, the shape watch.manifest reads."""
    for base, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            with open(full, "rb") as fh:
                yield rel, fh.read()


CARD = """---
pretty_name: heldfast drift feed
license: cc-by-4.0
tags:
- mcp
- model-context-protocol
- security
- supply-chain
size_categories:
- 10K<n<100K
---

# heldfast drift feed

A running record of what MCP servers tell AI agents about their tools, and
when it changes: every npm stdio server and every hosted endpoint in the
official MCP registry that answers without credentials, read by
[heldfast](https://github.com/rufat325/heldfast). This dataset is a copy of
[rufat325/heldfast-feed](https://github.com/rufat325/heldfast-feed), kept
outside GitHub.

## What is here

- `snapshot-YYYY-MM.tar.gz` -- the whole feed at the month's first checkpoint,
  with its SHA-256 in `snapshot-YYYY-MM.tar.gz.sha256`
- `daily/YYYY-MM-DD.tar.gz` -- what changed since the previous archive: the
  files added or changed, and `.heldfast-archive/deleted`
- `checkpoints/` -- each day's checkpoint, its OpenTimestamps proof and its
  Sigstore bundle, as they are in the feed
- `MIRRORED_FROM` -- the feed commit this copy is current to, and its day

Unpack a snapshot, then each daily archive after it in order, deleting the
paths each lists, and you have the feed at that day's checkpoint. Every
archive is deterministic, so it can be rebuilt from the feed repository and
compared byte for byte. The feed holds paths that differ only in letter case,
which Windows and macOS disks fold into one: there, check a copy with
`python research/feed/archive.py verify --checkpoint checkpoints/<day>.json
snapshot-<month>.tar.gz daily/...` from the heldfast repository, which
rebuilds it in memory.

## How it is collected

One vantage point, in GitHub Actions: npm servers are launched in a
container with no capabilities and no credentials when they publish a new
release; hosted servers are read daily, and every four hours while they keep
changing, by a client that identifies itself as heldfast. Hosted history
starts on 23 September 2026. What each file holds, and why the collection
runs continuously: [TRANSPARENCY.md](https://github.com/rufat325/heldfast/blob/main/docs/TRANSPARENCY.md).

## Verifying it

Each day's commit is described by `checkpoints/YYYY-MM-DD.json`, a digest of
every file in it, anchored in Bitcoin with OpenTimestamps and signed with
Sigstore. Rebuild the tree, compute the manifest the checkpoint describes,
compare the digest, then verify the proof:
[how](https://github.com/rufat325/heldfast/blob/main/docs/TRANSPARENCY.md#checkpoints).
A checkpoint proves the data existed no later than its anchor; it does not
prove the data is accurate.

## Caveats

- One anonymous reader. A hosted server can recognise it and show it what it
  shows everyone, change between readings, or show signed-in clients tools
  this never sees.
- A few operators account for most of the changes, many of them only a
  number ticking. `stats.json` counts every event by operator and kind.
- The tool descriptions are the servers' own text, recorded as they were
  sent. They belong to their authors.

## Licence

This project's own data -- the measurements, dates, grades, counts,
digests, checkpoints and the archives' structure -- is licensed under
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/).
Credit it as "heldfast drift feed (rufat325/heldfast-feed)".

The tool names, descriptions and schemas recorded in it are the MCP
servers' own text, written by their authors, and are not licensed by this
project. They are included as a record of what each server published, and
remain their authors'. To ask for something to be removed, open an issue at
[rufat325/heldfast-feed](https://github.com/rufat325/heldfast-feed/issues).
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("--data", required=True)
    s.add_argument("--commit", required=True)
    s.add_argument("--day", required=True)
    s.add_argument("--out", required=True)
    d = sub.add_parser("daily")
    d.add_argument("--data", required=True)
    d.add_argument("--from", dest="frm", required=True)
    d.add_argument("--to", required=True)
    d.add_argument("--day", required=True)
    d.add_argument("--out", required=True)
    r = sub.add_parser("rebuild")
    r.add_argument("--into", required=True)
    r.add_argument("archives", nargs="+")
    v = sub.add_parser("verify")
    v.add_argument("--checkpoint", required=True, help="checkpoints/YYYY-MM-DD.json")
    v.add_argument("archives", nargs="+")
    c = sub.add_parser("card")
    c.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.command == "snapshot":
        print(snapshot(args.data, args.commit, args.day, args.out))
    elif args.command == "daily":
        print(daily(args.data, args.frm, args.to, args.day, args.out))
    elif args.command == "rebuild":
        print(json.dumps(rebuild(args.into, args.archives)))
    elif args.command == "verify":
        with open(args.checkpoint, encoding="utf-8") as fh:
            why = verify(args.archives, json.load(fh))
        print(why or "ok: the archives rebuild the tree the checkpoint describes")
        return 1 if why else 0
    else:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(CARD)
    return 0


if __name__ == "__main__":
    sys.exit(main())
