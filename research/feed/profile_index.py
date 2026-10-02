"""Compare the feed's record with another party's, by a second digest.

The feed's key is the native digest (docs/LOCK.md): tools/ holds every
definition once, named by it. Another record can name the same definition by
a different digest (src/heldfast/profiles.py). Nothing here is stored in the
feed. A profile digest is recomputed from the definitions that are, so this
reads a checkout and writes nothing inside it.

  profile_index.py --data DIR --lookup DIGEST
      the tool files whose definition has this profile digest
  profile_index.py --data DIR --check PACKAGE TOOL DIGEST
      the readings of that tool in the record whose definition has this
      profile digest, oldest to newest, with the first and last seen
  profile_index.py --data DIR --index OUT
      the native-to-profile map for every tool file, written to OUT, which
      must be outside DIR
  profile_index.py --data DIR --audit
      how often the native digest folds distinct shapes of a definition: the
      tool files in the shape class where that can happen, and the native
      digests that map to more than one profile digest (see `audit`)

`--check` follows both catalogue layouts. The current one lists a tool by its
native digest and the definition is the file in tools/, which holds the first
raw seen under that digest. The first layout, gzipped, carries each reading's
own definition. DIGEST is `sha256:<hex>`, or the hex alone.

Exit status: 0 when something was found (or the index was written, or an audit
found no native digest with several profile digests), 1 when nothing matched
(or an audit found one), 2 when the arguments or the checkout are not usable.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

import watch  # noqa: E402
from heldfast.profiles import PROFILE_AGENTAVOW_V1, agentavow_v1_digest  # noqa: E402

PROFILES = {PROFILE_AGENTAVOW_V1: agentavow_v1_digest}
WANTED = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")


def _json_load(path: str):
    """The JSON in a feed file, or None when it is missing, too big or not JSON."""
    try:
        if os.path.islink(path) or os.path.getsize(path) > watch.MAX_FILE:
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def tool_files(data: str):
    """(native digest, path) for every file in tools/, in path order."""
    top = os.path.join(data, "tools")
    for folder in sorted(os.listdir(top)) if os.path.isdir(top) else []:
        for name in sorted(os.listdir(os.path.join(top, folder))):
            rel = f"tools/{folder}/{name}"
            if watch.TOOL_FILE.match(rel):
                yield name[:-len(".json")], os.path.join(top, folder, name)


def lookup(data: str, wanted: str, profile: str):
    """[(native digest, tool name)] of every tool file with the profile digest."""
    make, found, unread = PROFILES[profile], [], 0
    for native, path in tool_files(data):
        raw = _json_load(path)
        if not isinstance(raw, dict):
            unread += 1
        elif make(raw) == wanted:
            found.append((native, raw.get("name")))
    return found, unread


def readings(data: str, package: str, tool: str):
    """Every reading of one tool in one server's catalogues, oldest first.

    A reading is (measured_at, version, native digest, definition). A catalogue
    whose tool file is missing from tools/ yields nothing for that tool; the
    publishing job's `verify --complete` is what reports that.
    """
    out = []
    folder = watch.safe(package)
    for pkg_dir, version in watch.catalogue_versions(data):
        if pkg_dir != folder:
            continue
        base = os.path.join(data, "catalogues", pkg_dir, version)
        if os.path.exists(base + ".json"):
            body = _json_load(base + ".json")
            listed = [(e.get("digest"), None) for e in (body or {}).get("tools") or []
                      if isinstance(e, dict) and e.get("name") == tool]
        else:
            try:
                body = watch.read_gz(base + ".json.gz")
            except (OSError, ValueError, EOFError):
                body = None
            listed = [(None, t) for t in (body or {}).get("tools") or []
                      if isinstance(t, dict) and t.get("name") == tool]
        if not isinstance(body, dict) or body.get("package") != package:
            continue
        when = str(body.get("measured_at") or body.get("published") or "")
        for digest, raw in listed:
            if raw is None and isinstance(digest, str) and watch.DIGEST.match(digest):
                raw = _json_load(watch.tool_path(data, digest))
            if isinstance(raw, dict):
                try:
                    digest = digest or watch.tool_digest(raw)
                except ValueError:
                    continue
                out.append((when, version, digest, raw))
    return sorted(out, key=lambda r: (r[0], r[1]))


def _quote(text: object) -> str:
    return json.dumps(text)  # ASCII, so a hostile name cannot break the terminal


def check(data: str, package: str, tool: str, wanted: str, profile: str) -> int:
    make = PROFILES[profile]
    seen = readings(data, package, tool)
    head = f"{package} {_quote(tool)}"
    if not seen:
        print(f"{head}: the record holds no reading of this tool")
        return 1
    hits = [r for r in seen if make(r[3]) == wanted]
    print(f"{head}: {len(seen)} reading(s), {len(hits)} with {profile} {wanted}")
    if not hits:
        distinct: dict = {}
        for when, version, _native, raw in seen:
            row = distinct.setdefault(make(raw), [when, when, 0])
            row[1], row[2] = when, row[2] + 1
        print("it was recorded with:")
        for digest, (first, last, count) in sorted(distinct.items(), key=lambda kv: kv[1][0]):
            print(f"  {digest}  {count} reading(s), {first} to {last}")
        return 1
    print(f"first seen {hits[0][0]}  ({hits[0][1]})")
    print(f"last seen  {hits[-1][0]}  ({hits[-1][1]})")
    for when, version, native, _raw in hits:
        print(f"  {when}  {version}  native {native}")
    return 0


# The fields the profile hashes besides the name. The native digest turns a
# missing one, a null, "" and {} into the same bytes (a non-object schema into
# {}), and the profile keeps them apart, so a definition served in two of those
# shapes has one native digest and two profile digests.
_SHAPE_FIELDS = ("title", "description", "inputSchema", "outputSchema", "annotations")


def _folded(field: str, value: object) -> bool:
    """Is `value`, present in the definition, a shape the native digest folds?"""
    if field in ("title", "description"):
        return value is None or value == "" or not isinstance(value, str)
    return value is None or value == {} or not isinstance(value, dict)


def audit(data: str, profile: str) -> dict:
    """What it would take for a profile digest to disagree with the native one.

    Two counts, over the same files a reader can open:
    - the shape class: tool files in which a hashed field is present in a
      shape the native digest folds. Only these can have been served in two
      shapes under one native digest.
    - the native digests that map to more than one profile digest, over every
      file in tools/ and every reading the first-layout catalogues keep whole
      (each carries its own definition). The current layout lists a tool by
      digest, so it adds no definition tools/ does not hold.
    """
    make = PROFILES[profile]
    mapped: dict = {}  # native digest -> the set of profile digests seen
    stats = {"tool_files": 0, "unreadable": 0, "no_profile_digest": 0, "folded": 0,
             "by_field": dict.fromkeys(_SHAPE_FIELDS, 0), "legacy_catalogues": 0,
             "legacy_unreadable": 0, "legacy_readings": 0}
    for native, path in tool_files(data):
        raw = _json_load(path)
        if not isinstance(raw, dict):
            stats["unreadable"] += 1
            continue
        stats["tool_files"] += 1
        digest = make(raw)
        stats["no_profile_digest"] += digest is None
        mapped.setdefault(native, set()).add(digest)
        hit = [f for f in _SHAPE_FIELDS if f in raw and _folded(f, raw[f])]
        stats["folded"] += bool(hit)
        for field in hit:
            stats["by_field"][field] += 1
    for pkg_dir, version in watch.catalogue_versions(data):
        base = os.path.join(data, "catalogues", pkg_dir, version)
        if os.path.exists(base + ".json") or not os.path.exists(base + ".json.gz"):
            continue
        stats["legacy_catalogues"] += 1
        try:
            body = watch.read_gz(base + ".json.gz")
        except (OSError, ValueError, EOFError):
            stats["legacy_unreadable"] += 1
            continue
        for raw in (body.get("tools") if isinstance(body, dict) else None) or []:
            if isinstance(raw, dict):
                try:
                    native = watch.tool_digest(raw)
                except ValueError:  # a number JSON cannot hold; verify refuses it too
                    continue
                stats["legacy_readings"] += 1
                mapped.setdefault(native, set()).add(make(raw))
    stats["native_digests"] = len(mapped)
    stats["with_several_profile_digests"] = sum(len(v) > 1 for v in mapped.values())
    return stats


def _print_audit(stats: dict, profile: str) -> None:
    n, d = stats["tool_files"], stats["native_digests"]
    pct = 100 * stats["folded"] / n if n else 0.0
    by = ", ".join(f"{f} {c:,}" for f, c in stats["by_field"].items() if c)
    print(f"audit of {profile}")
    print(f"tool files read: {n:,} ({stats['unreadable']:,} unreadable, "
          f"{stats['no_profile_digest']:,} with no profile digest)")
    print(f"shape class: {stats['folded']:,} of {n:,} ({pct:.3f}%)"
          + (f" [{by}; a file can be in several]" if by else ""))
    print(f"readings kept whole by {stats['legacy_catalogues']:,} first-layout catalogues: "
          f"{stats['legacy_readings']:,} ({stats['legacy_unreadable']:,} catalogues unreadable)")
    print(f"native digests: {d:,}; with more than one profile digest: "
          f"{stats['with_several_profile_digests']:,}")


def _inside(path: str, folder: str) -> bool:
    path, folder = os.path.realpath(path), os.path.realpath(folder)
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # another drive
        return False


def index(data: str, out: str, profile: str) -> int:
    if _inside(out, data):
        print(f"refused: {out} is inside {data}; this never writes into a feed checkout",
              file=sys.stderr)
        return 2
    make, rows, skipped = PROFILES[profile], [], 0
    for native, path in tool_files(data):
        raw = _json_load(path)
        digest = make(raw) if isinstance(raw, dict) else None
        if digest is None:
            skipped += 1
        else:
            rows.append((native, digest))
    # One line per tool, as lookup/all.json does, so two runs can be diffed.
    body = ('{"profile": %s, "tools": {\n' % json.dumps(profile)
            + ",\n".join(f"{json.dumps(n)}: {json.dumps(d)}" for n, d in rows)
            + "\n}}\n").encode("utf-8")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    watch._write(out, body)
    print(f"wrote {len(rows)} native-to-profile pair(s) to {out}; {skipped} tool file(s) "
          f"had no profile digest", file=sys.stderr)
    return 0


def _digest(text: str) -> str:
    match = WANTED.match(text.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError("not a digest: want sha256:<64 hex> or the hex")
    return "sha256:" + match.group(1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", required=True, help="a checkout of the feed (read only)")
    ap.add_argument("--profile", default=PROFILE_AGENTAVOW_V1, choices=sorted(PROFILES))
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument("--lookup", metavar="DIGEST", type=_digest)
    what.add_argument("--check", nargs=3, metavar=("PACKAGE", "TOOL", "DIGEST"))
    what.add_argument("--index", metavar="OUT")
    what.add_argument("--audit", action="store_true")
    args = ap.parse_args(argv)
    if not (os.path.isdir(os.path.join(args.data, "tools"))
            or os.path.isdir(os.path.join(args.data, "catalogues"))):
        print(f"{args.data} has no tools/ or catalogues/: not a feed checkout", file=sys.stderr)
        return 2
    if args.index:
        return index(args.data, args.index, args.profile)
    if args.audit:
        stats = audit(args.data, args.profile)
        _print_audit(stats, args.profile)
        return 0 if not stats["with_several_profile_digests"] else 1
    if args.check:
        try:
            wanted = _digest(args.check[2])
        except argparse.ArgumentTypeError as exc:
            print(exc, file=sys.stderr)
            return 2
        try:
            return check(args.data, args.check[0], args.check[1], wanted, args.profile)
        except ValueError as exc:  # a package name outside what the feed stores
            print(exc, file=sys.stderr)
            return 2
    found, unread = lookup(args.data, args.lookup, args.profile)
    for native, name in found:
        print(f"{native}  tools/{native[:2]}/{native}.json  {_quote(name)}")
    print(f"{len(found)} tool file(s) with {args.profile} {args.lookup}"
          + (f"; {unread} unreadable" if unread else ""))
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
