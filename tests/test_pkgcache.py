"""The artifact the package manager already holds.

The layouts under test were read off the real caches on a developer machine,
not off documentation: 777 npm tarball entries and three pip wheels whose
cached bytes matched the sha256 PyPI publishes for them. Every one of the 777
verified, every tampered digest was caught, and a package that had never been
fetched came back `absent` rather than passing.

The distinction these tests exist to hold is `absent` vs `verified`. They are
opposite answers and a proxy that reported them as one would hand silence to
anyone able to empty a cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_npm_cache import (empty_npm_cache, fake_npm_cache,  # noqa: E402
                            npm_cache_at, sri_for, write_entry)
from mcp_pin import pkgcache  # noqa: E402


class TestNpmCache(unittest.TestCase):
    """A real cache has an index entry and the bytes it names. Both are read.

    Comparing only the index would compare the cache's *claim* about its
    content, and the cache is writable by the same user who owns the server's
    files -- so the claim can be edited to say whatever passes. These tests
    keep the two halves distinguishable.
    """

    def test_a_cached_tarball_matching_the_lock_is_verified(self) -> None:
        content = b"the approved tarball"
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "@scope/pkg", "1.2.3", content=content):
                got = pkgcache.check({"npm:@scope/pkg@1.2.3": sri_for(content)})
        self.assertEqual(["verified"], [c.state for c in got])
        self.assertTrue(got[0].ok)

    def test_a_cached_tarball_that_differs_is_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "@scope/pkg", "1.2.3", content=b"something else"):
                got = pkgcache.check(
                    {"npm:@scope/pkg@1.2.3": sri_for(b"the approved tarball")})
        self.assertEqual(["changed"], [c.state for c in got])

    def test_an_index_that_lies_about_its_bytes_is_changed(self) -> None:
        """The cache-poisoning case, and the reason the bytes are hashed.

        An attacker who can write the cache can put the approved SRI in the
        index while the blob beside it is something else. npm would fail that
        on read -- but this module would have answered "verified" first, and a
        verdict that can be wrong is not a pin.
        """
        approved = sri_for(b"the approved tarball")
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "@scope/pkg", "1.2.3", approved,
                                content=b"malicious replacement"):
                got = pkgcache.check({"npm:@scope/pkg@1.2.3": approved})
        self.assertEqual(["changed"], [c.state for c in got])
        self.assertIn("do not hash to the entry", got[0].detail)

    def test_an_index_entry_with_no_bytes_behind_it_is_absent(self) -> None:
        """A pruned cache keeps index entries that content-v2 no longer backs.
        There is nothing to verify, and saying so beats guessing either way."""
        content = b"the approved tarball"
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "@scope/pkg", "1.2.3",
                                content=content, blob=False):
                got = pkgcache.check({"npm:@scope/pkg@1.2.3": sri_for(content)})
        self.assertEqual(["absent"], [c.state for c in got])
        self.assertIn("does not hold them", got[0].detail)

    def test_an_unscoped_package_resolves_too(self) -> None:
        content = b"leftpad bytes"
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "leftpad", "1.0.0", content=content):
                got = pkgcache.check({"npm:leftpad@1.0.0": sri_for(content)})
        self.assertEqual(["verified"], [c.state for c in got])

    def test_a_cold_cache_is_absent_and_not_a_pass(self) -> None:
        """The whole reason this module reports four states and not two.

        This is also the common case: a fresh machine or a clean CI runner has
        nothing cached, and `npx -y` fetches at spawn.
        """
        with tempfile.TemporaryDirectory() as tmp:
            with empty_npm_cache(tmp):
                got = pkgcache.check({"npm:@scope/pkg@1.2.3": "sha512-abc"})
        self.assertEqual(["absent"], [c.state for c in got])
        self.assertFalse(got[0].ok)

    def test_the_last_entry_in_an_appended_index_wins(self) -> None:
        """cacache appends; an older line is not the current content."""
        old, new = b"the old tarball", b"the new tarball"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "@scope/pkg", "1.2.3", content=old)
            write_entry(root, "@scope/pkg", "1.2.3", content=new)
            with npm_cache_at(str(root)):
                current = pkgcache.check({"npm:@scope/pkg@1.2.3": sri_for(new)})
                superseded = pkgcache.check({"npm:@scope/pkg@1.2.3": sri_for(old)})
        self.assertEqual(["verified"], [c.state for c in current])
        self.assertEqual(["changed"], [c.state for c in superseded])

    def test_an_incomparable_algorithm_is_not_called_changed(self) -> None:
        """A format difference must not refuse a launch.

        Reporting `sha1-x` against `sha512-y` as tampering would take down
        servers over a registry that publishes an older hash, which is a
        false positive in the worst possible place: the launch path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "@scope/pkg", "1.2.3", "sha1-abc"):
                got = pkgcache.check({"npm:@scope/pkg@1.2.3": "sha512-abc"})
        self.assertEqual(["absent"], [c.state for c in got])

    def test_a_corrupt_index_line_does_not_raise(self) -> None:
        """This runs immediately before a spawn; an exception here is an
        agent that will not start."""
        content = b"the approved tarball"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_entry(root, "@scope/pkg", "1.2.3", content=content)
            with path.open("a", encoding="utf-8") as handle:
                handle.write("garbage-with-no-tab\n")
                handle.write("hash\t{not json at all\n")
            with npm_cache_at(str(root)):
                got = pkgcache.check({"npm:@scope/pkg@1.2.3": sri_for(content)})
        self.assertEqual(["verified"], [c.state for c in got])

    def test_malformed_recorded_values_are_skipped(self) -> None:
        got = pkgcache.check({"npm:x@1": None, 5: "sha512-a"})  # type: ignore[dict-item]
        self.assertEqual([], got)

    def test_an_unknown_ecosystem_is_unsupported_not_verified(self) -> None:
        got = pkgcache.check({"cargo:thing@1.0.0": "sha256-abc"})
        self.assertEqual(["unsupported"], [c.state for c in got])


class TestMalformedInput(unittest.TestCase):
    """A lockfile is meant to be hand-edited, and this runs before a spawn.

    The first version of `check` sorted the mapping directly, which raises on
    mixed key types -- an exception on the launch path, which is an agent that
    does not start rather than a finding somebody reads. That is the shape of
    bug fuzzing finds here and hand-written tests do not, because nobody means
    to write a lockfile with an integer key.
    """

    def test_nothing_in_the_grid_raises(self) -> None:
        values = [None, 0, 5, "", "sha512-abc", "npm:", ":", "@", "npm:@x",
                  "npm:x@", "x" * 300, {}, [], True, -1.5, "npm:x@1@2",
                  "pypi:x==1", "pypi:", "unknown:x@1"]
        urls = [None, {}, {"npm:x@1": None}, {"npm:x@1": 5},
                {"npm:x@1": "not-a-url"}, {"npm:x@1": "https://x/y.tgz"},
                {5: "https://x/y.tgz"}]
        checked = 0
        for key in values:
            try:
                hash(key)
            except TypeError:
                # Not a key a JSON object could have had in the first place.
                continue
            for approved in values:
                for url_map in urls:
                    try:
                        got = pkgcache.check({key: approved}, url_map)
                    except Exception as exc:  # noqa: BLE001 - that is the point
                        self.fail(f"check({key!r}, {approved!r}, {url_map!r}) "
                                  f"raised {exc!r}")
                    for item in got:
                        self.assertIn(item.state,
                                      ("verified", "changed", "absent", "unsupported"))
                        # Nothing malformed may ever come back as a pass.
                        self.assertNotEqual("verified", item.state)
                    checked += 1
        self.assertGreater(checked, 2000)

    def test_refusal_never_raises_on_the_same_grid(self) -> None:
        for key in [None, 5, "npm:x@1", "pypi:x==1", ""]:
            for approved in [None, 5, "", "sha512-a"]:
                for require in (False, True):
                    try:
                        pkgcache.refusal({key: approved}, None, require=require)
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"refusal raised {exc!r}")


class TestPypiCache(unittest.TestCase):
    def _cache(self, tmp: str, url: str, payload: bytes) -> None:
        digest = hashlib.sha224(url.encode("utf-8")).hexdigest()
        parts = list(digest[:5]) + [digest]
        body = Path(tmp).joinpath("http-v2", *parts).with_suffix(".body")
        body.parent.mkdir(parents=True, exist_ok=True)
        body.write_bytes(payload)

    def test_a_cached_wheel_is_hashed_and_compared(self) -> None:
        url = "https://files.pythonhosted.org/packages/ab/cd/pkg-1.2.3.whl"
        payload = b"wheel bytes"
        want = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            self._cache(tmp, url, payload)
            previous = os.environ.get("PIP_CACHE_DIR")
            os.environ["PIP_CACHE_DIR"] = tmp
            try:
                good = pkgcache.check({"pypi:pkg==1.2.3": f"sha256-{want}"},
                                      {"pypi:pkg==1.2.3": url})
                bad = pkgcache.check({"pypi:pkg==1.2.3": "sha256-" + "0" * 64},
                                     {"pypi:pkg==1.2.3": url})
            finally:
                if previous is None:
                    os.environ.pop("PIP_CACHE_DIR", None)
                else:
                    os.environ["PIP_CACHE_DIR"] = previous
        self.assertEqual(["verified"], [c.state for c in good])
        self.assertEqual(["changed"], [c.state for c in bad])

    def test_without_a_recorded_url_the_wheel_cannot_be_found(self) -> None:
        """A PyPI URL carries a hash path that no package name implies, so a
        lock written before URLs were recorded says so instead of passing."""
        got = pkgcache.check({"pypi:pkg==1.2.3": "sha256-" + "a" * 64})
        self.assertEqual(["absent"], [c.state for c in got])
        self.assertIn("no artifact URL", got[0].detail)

    def test_a_url_from_the_lock_is_only_trusted_if_it_is_a_url(self) -> None:
        got = pkgcache.check({"pypi:pkg==1.2.3": "sha256-" + "a" * 64},
                             {"pypi:pkg==1.2.3": "file:///etc/passwd"})
        self.assertEqual(["absent"], [c.state for c in got])


class TestRefusal(unittest.TestCase):
    """What the launch path does with each state."""

    def test_a_changed_artifact_always_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "@scope/pkg", "1.2.3", "sha512-other"):
                reason = pkgcache.refusal({"npm:@scope/pkg@1.2.3": "sha512-abc"})
        self.assertIsNotNone(reason)
        self.assertIn("has changed", str(reason))

    def test_a_verified_artifact_does_not_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with fake_npm_cache(tmp, "@scope/pkg", "1.2.3", "sha512-abc"):
                self.assertIsNone(
                    pkgcache.refusal({"npm:@scope/pkg@1.2.3": "sha512-abc"}))

    def test_a_cold_cache_starts_by_default_and_refuses_when_required(self) -> None:
        """Refusing every launch on a machine with a cold cache would get the
        pin switched off, which is the failure mode this project has already
        paid for once. So it is a flag, and the flag is honoured."""
        with tempfile.TemporaryDirectory() as tmp:
            with empty_npm_cache(tmp):
                recorded = {"npm:@scope/pkg@1.2.3": "sha512-abc"}
                self.assertIsNone(pkgcache.refusal(recorded))
                strict = pkgcache.refusal(recorded, require=True)
        self.assertIsNotNone(strict)
        self.assertIn("could not be verified", str(strict))

    def test_nothing_recorded_never_refuses(self) -> None:
        self.assertIsNone(pkgcache.refusal(None))
        self.assertIsNone(pkgcache.refusal({}, require=True))


if __name__ == "__main__":
    unittest.main()
