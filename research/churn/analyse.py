"""Turn the measured catalogues into the numbers docs/CHURN.md reports.

Every figure in that document comes out of this script. Run it against
wide.json.gz and the output should match what is published, or one of the two
is wrong.
"""
import gzip
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OFFICIAL_SCOPE = "@modelcontextprotocol/"


def vkey(v):
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.\-+]", v))


def classify(before, after):
    """What moved between two definitions of the same tool."""
    if before["description"] != after["description"]:
        return "description"
    if before["schema"] != after["schema"]:
        return "schema"
    return "other"          # annotations, title, outputSchema, icons


def main():
    path = os.path.join(HERE, sys.argv[1] if len(sys.argv) > 1 else "wide.json.gz")
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:
        blob = json.load(fh)
    data = blob["catalogues"]
    published = {p: m.get("published") or {} for p, m in (blob.get("meta") or {}).items()}

    pairs = []
    for package, by_version in sorted(data.items()):
        # Publish order when the data recorded it -- the order a user
        # upgrading would have met the releases in, and the order
        # suspicious.py compares them in. Older data has only version strings.
        when = published.get(package) or {}
        if all(v in when for v in by_version):
            versions = sorted(by_version, key=lambda v: when[v])
        else:
            versions = sorted(by_version, key=vkey)
        for a, b in zip(versions, versions[1:]):
            A, B = by_version[a], by_version[b]
            carried = sorted(set(A) & set(B))
            moved = [n for n in carried if A[n]["digest"] != B[n]["digest"]]
            kinds = {}
            for n in moved:
                kinds[classify(A[n], B[n])] = kinds.get(classify(A[n], B[n]), 0) + 1
            pairs.append({
                "package": package, "from": a, "to": b,
                "official": package.startswith(OFFICIAL_SCOPE),
                "carried": len(carried), "moved": len(moved),
                "added": len(set(B) - set(A)), "removed": len(set(A) - set(B)),
                "kinds": kinds,
                "wide": len(carried) > 1 and len(moved) == len(carried),
                "described": any(A[n]["description"] != B[n]["description"]
                                 for n in carried),
            })

    def report(rows, label):
        carried = sum(r["carried"] for r in rows)
        moved = sum(r["moved"] for r in rows)
        wide = [r for r in rows if r["wide"]]
        iso = [r for r in rows if r["moved"] and not r["wide"]]
        kinds = {}
        for r in rows:
            for k, v in r["kinds"].items():
                kinds[k] = kinds.get(k, 0) + v
        iso_desc = sum(r["kinds"].get("description", 0) for r in iso)
        print(f"\n## {label}")
        print(f"  packages ................ {len({r['package'] for r in rows})}")
        print(f"  release pairs ........... {len(rows)}")
        print(f"  tool-versions carried ... {carried}")
        if not carried:
            return
        print(f"  digests moved ........... {moved} ({100.0*moved/carried:.1f}%)")
        print(f"    description ........... {kinds.get('description', 0)}")
        print(f"    input schema .......... {kinds.get('schema', 0)}")
        print(f"    other fields only ..... {kinds.get('other', 0)}")
        print(f"  releases moving ALL tools {len(wide)} "
              f"({sum(r['moved'] for r in wide)} tool-versions)")
        print(f"  releases moving SOME .... {len(iso)} "
              f"({sum(r['moved'] for r in iso)} tool-versions)")
        print(f"  isolated description drift {iso_desc} "
              f"({100.0*iso_desc/carried:.2f}% of carried)")
        print(f"  tools added / removed ... {sum(r['added'] for r in rows)}"
              f" / {sum(r['removed'] for r in rows)}")
        # What a user of a pin meets: not tool-versions but upgrades that stop.
        stops = [r for r in rows if r["moved"] or r["added"] or r["removed"]]
        worded = [r for r in rows if r["described"]]
        print(f"  releases a pin stops on . {len(stops)} ({100.0*len(stops)/len(rows):.0f}%)"
              f" in {len({r['package'] for r in stops})} packages")
        print(f"  ...that edit a description {len(worded)} ({100.0*len(worded)/len(rows):.0f}%)"
              f" in {len({r['package'] for r in worded})} packages")

    report(pairs, "All servers")
    report([r for r in pairs if r["official"]], "Official (@modelcontextprotocol)")
    report([r for r in pairs if not r["official"]], "Third-party")

    print("\n## Releases that moved every tool at once")
    for r in pairs:
        if r["wide"]:
            k = ", ".join(f"{v} {n}" for n, v in sorted(r["kinds"].items()))
            print(f"  {r['package']} {r['from']} -> {r['to']}: "
                  f"{r['moved']}/{r['carried']} ({k})")

    print("\n## Releases that moved some but not all")
    for r in pairs:
        if r["moved"] and not r["wide"]:
            k = ", ".join(f"{v} {n}" for n, v in sorted(r["kinds"].items()))
            print(f"  {r['package']} {r['from']} -> {r['to']}: "
                  f"{r['moved']}/{r['carried']} ({k})")

    if blob.get("unreachable"):
        print("\n## Not measured")
        for package, why in blob["unreachable"]:
            print(f"  {package}: {why}")


if __name__ == "__main__":
    main()
