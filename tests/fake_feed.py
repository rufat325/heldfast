"""The feed's head and the lookup cache, for tests that fake the feed.

Those tests replace `feedlock.get_json` and answer `HEAD_URL` with a commit.
`resolve()` now asks git's ref advertisement first and the REST API second,
neither through `get_json`, and `lookup.everything()` keeps what it read in the
user's cache directory. `install()` answers both head lookups from the same
fake `get_json` and moves the cache into a temporary directory, so no test
reaches GitHub or writes to the real cache.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def install() -> None:
    from heldfast import feedlock, lookup

    def head() -> str:
        body = feedlock.get_json(feedlock.HEAD_URL)
        if not isinstance(body, dict):
            raise feedlock.FeedError("the fake feed has no head")
        return body.get("sha")

    tmp = tempfile.mkdtemp(prefix="heldfast-cache-")
    for patch in (mock.patch.object(feedlock, "branch_head", head),
                  mock.patch.object(feedlock, "rest_head", head),
                  mock.patch.object(lookup, "cache_dir", lambda: Path(tmp))):
        patch.start()
        unittest.addModuleCleanup(patch.stop)
    unittest.addModuleCleanup(shutil.rmtree, tmp, ignore_errors=True)
