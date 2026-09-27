"""The feed lives in rufat325/heldfast-feed, and nothing points at where it was.

It was the `feed` branch of this repository until 27 September 2026, so every
clone of the tool downloaded the whole log. That branch is no longer updated,
so a link, a checkout or a client that still reads it reads a record that has
stopped. This fails on any address of the old location in the code, the
workflows or the documents.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import feedlock  # noqa: E402

OWNER = "rufat325/" + "heldfast"
# Every way the old location was addressed. Assembled from pieces, so this
# file does not have to exempt itself from its own rule.
OLD = (
    "github.com/" + OWNER + "/tree/" + "feed",
    "raw.githubusercontent.com/" + OWNER + "/",
    "repos/" + OWNER + "/commits/" + "feed",
    "repos/$REPO/commits/" + "feed",
    OWNER + ".git/info/refs",
    "ref: " + "feed\n",
    "HEAD:" + "feed",
)
SCANNED = ("README.md", "PRIVACY.md", "SECURITY.md", "CONTRIBUTING.md", "action.yml",
           "updates/action.yml")
SCANNED_TREES = (("docs", "*.md"), ("src", "*.py"), ("research", "*.py"), ("research", "*.yml"),
                 (".github/workflows", "*.yml"), ("plugin", "*.*"), ("js", "*.js"))


def files() -> list[Path]:
    out = [ROOT / p for p in SCANNED if (ROOT / p).exists()]
    for folder, pattern in SCANNED_TREES:
        out += sorted((ROOT / folder).rglob(pattern))
    return [p for p in out if p.is_file()]


class TestTheFeedIsWhereItLives(unittest.TestCase):
    def test_the_client_reads_the_feed_repository(self) -> None:
        self.assertEqual("rufat325/heldfast-feed", feedlock.REPO)
        self.assertEqual("main", feedlock.BRANCH)
        self.assertIn("github.com/rufat325/heldfast-feed.git/info/refs", feedlock.ADVERT_URL)
        self.assertTrue(feedlock.RAW_URL.startswith(
            "https://raw.githubusercontent.com/rufat325/heldfast-feed/"))

    def test_nothing_addresses_the_old_branch(self) -> None:
        found = []
        for path in files():
            text = path.read_text(encoding="utf-8", errors="replace")
            for old in OLD:
                if old in text:
                    found.append(f"{path.relative_to(ROOT)}: {old.strip()}")
        self.assertEqual([], found)

    def test_the_scan_covers_the_places_that_had_it(self) -> None:
        """A scan that found nothing because it read nothing would pass."""
        scanned = {p.relative_to(ROOT).as_posix() for p in files()}
        for must in ("README.md", "docs/LOOKUP.md", "src/heldfast/feedlock.py",
                     "research/feed/watch.py", ".github/workflows/feed.yml",
                     "research/feed/feed-repo-watchdog.yml", "updates/action.yml"):
            self.assertIn(must, scanned)


if __name__ == "__main__":
    unittest.main()
