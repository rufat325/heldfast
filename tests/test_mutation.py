"""A kernel check that can be deleted without a test failing is not a check.

Each mutant in tests/mutants.py is a fail-open edit of policy, fingerprint or
JSONC. The probe for that mutant must observe the hole. Survival is a CI
failure: the score is 100% of the catalog, not a percentage of random edits.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutants import MUTANTS, Mutant  # noqa: E402


PKG = ROOT / "src" / "mcp_audit"
KILL_THRESHOLD = 1.0  # every catalogued mutant must die


def _apply(mutant: Mutant, dest: Path) -> None:
    target = dest / "mcp_audit" / mutant.path
    text = target.read_text(encoding="utf-8")
    count = text.count(mutant.original)
    if count != 1:
        raise AssertionError(
            f"{mutant.id}: original snippet occurs {count} time(s) in "
            f"{mutant.path}; the catalog is stale"
        )
    target.write_text(text.replace(mutant.original, mutant.replacement, 1),
                      encoding="utf-8")


def _probe(mutant: Mutant, dest: Path) -> dict:
    script = textwrap.dedent(f"""
        import json, sys
        sys.path.insert(0, {str(dest)!r})
        FAIL_OPEN = None
{textwrap.indent(textwrap.dedent(mutant.probe).strip(), "        ")}
        if FAIL_OPEN is None:
            raise SystemExit("probe did not assign FAIL_OPEN")
        print(json.dumps({{"fail_open": bool(FAIL_OPEN)}}))
    """)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(dest)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{mutant.id}: probe crashed rather than failing open\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    line = result.stdout.strip().splitlines()[-1]
    return json.loads(line)


def _kill(mutant: Mutant) -> bool:
    with tempfile.TemporaryDirectory(prefix="mcp-audit-mutant-") as tmp:
        dest = Path(tmp)
        shutil.copytree(
            PKG, dest / "mcp_audit",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        _apply(mutant, dest)
        return bool(_probe(mutant, dest)["fail_open"])


class TestCatalogIsLoadBearing(unittest.TestCase):
    def test_every_snippet_still_occurs_once(self) -> None:
        stale = []
        for mutant in MUTANTS:
            text = (PKG / mutant.path).read_text(encoding="utf-8")
            count = text.count(mutant.original)
            if count != 1:
                stale.append(f"{mutant.id} x{count}")
        self.assertFalse(stale, f"stale mutants: {stale}")

    def test_the_catalog_is_not_empty(self) -> None:
        self.assertGreaterEqual(len(MUTANTS), 12)

    def test_every_mutant_names_a_theorem(self) -> None:
        text = (ROOT / "docs" / "GUARANTEES.md").read_text(encoding="utf-8")
        missing = [f"{m.id}:{m.theorem}" for m in MUTANTS if m.theorem not in text]
        self.assertFalse(missing, f"mutants name unknown theorems: {missing}")


class TestFailOpenMutantsDie(unittest.TestCase):
    def test_every_catalogued_mutant_is_killed(self) -> None:
        survived = []
        killed = 0
        for mutant in MUTANTS:
            with self.subTest(mutant.id):
                dead = _kill(mutant)
                if dead:
                    killed += 1
                else:
                    survived.append(mutant.id)
                self.assertTrue(
                    dead,
                    f"{mutant.id} survived: {mutant.harm} "
                    f"({mutant.theorem} still holds after the edit)",
                )
        score = killed / len(MUTANTS)
        self.assertGreaterEqual(
            score, KILL_THRESHOLD,
            f"mutation score {score:.2f} below {KILL_THRESHOLD:.2f}; "
            f"survived: {survived}",
        )


if __name__ == "__main__":
    unittest.main()
