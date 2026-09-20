"""The tarball behind a version string."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_npm_cache import empty_npm_cache  # noqa: E402
from mcp_pin import integrity as integ  # noqa: E402
from mcp_pin.lockfile import Lock  # noqa: E402
from mcp_pin.model import ServerSpec  # noqa: E402
from mcp_pin.rules import AuditContext, run_rules  # noqa: E402


def _npx(version: str = "1.2.3") -> ServerSpec:
    return ServerSpec(
        name="notes", source="/x/.mcp.json", client="test",
        transport="stdio", command="npx",
        args=["-y", f"@scope/pkg@{version}"],
    )


class TestLookup(unittest.TestCase):
    def setUp(self) -> None:
        self._real = integ.get_json

    def tearDown(self) -> None:
        integ.get_json = self._real

    def test_npm_records_the_integrity_field(self) -> None:
        integ.get_json = lambda url: {"dist": {"integrity": "sha512-abc"}}
        got = integ.lookup(_npx())
        self.assertEqual({"npm:@scope/pkg@1.2.3": "sha512-abc"}, got)

    def test_a_floating_version_is_not_looked_up(self) -> None:
        integ.get_json = lambda url: {"dist": {"integrity": "sha512-abc"}}
        spec = ServerSpec(name="n", source="/x", client="c", transport="stdio",
                          command="npx", args=["-y", "@scope/pkg"])
        self.assertEqual({}, integ.lookup(spec))

    def test_a_failed_fetch_is_not_a_finding(self) -> None:
        integ.get_json = lambda url: None
        self.assertEqual({}, integ.lookup(_npx()))

    def test_a_changed_tarball_fires_mcpa036(self) -> None:
        spec = _npx()
        lock = Lock()
        lock.record([spec], [], [])
        lock.servers[spec.identity()]["integrity"] = {
            "npm:@scope/pkg@1.2.3": "sha512-old",
        }
        integ.get_json = lambda url: {"dist": {"integrity": "sha512-new"}}
        found = [f for f in run_rules(AuditContext(
            servers=[spec], lock={"servers": lock.servers, "skills": {}}))
            if f.rule_id == "MCPA036"]
        self.assertEqual(1, len(found))

    def test_pypi_records_the_sha256(self) -> None:
        integ.get_json = lambda url: {"urls": [{"digests": {"sha256": "deadbeef"}}]}
        spec = ServerSpec(name="n", source="/x", client="c", transport="stdio",
                          command="uvx", args=["pkg==1.2.3"])
        self.assertEqual({"pypi:pkg==1.2.3": "sha256-deadbeef"}, integ.lookup(spec))

    def test_a_failed_fetch_with_a_recorded_hash_is_not_a_finding(self) -> None:
        spec = _npx()
        lock = Lock()
        lock.record([spec], [], [])
        lock.servers[spec.identity()]["integrity"] = {
            "npm:@scope/pkg@1.2.3": "sha512-abc",
        }
        integ.get_json = lambda url: None
        found = [f for f in run_rules(AuditContext(
            servers=[spec], lock={"servers": lock.servers, "skills": {}}))
            if f.rule_id == "MCPA036"]
        self.assertEqual([], found)

    def test_stamp_records_the_hash(self) -> None:
        from mcp_pin.cli import _stamp_integrity
        spec = _npx()
        lock = Lock()
        lock.record([spec], [], [])
        integ.get_json = lambda url: {"dist": {"integrity": "sha512-abc"}}
        _stamp_integrity(lock, [spec])
        self.assertEqual({"npm:@scope/pkg@1.2.3": "sha512-abc"},
                         lock.servers[spec.identity()]["integrity"])

    def test_a_matching_tarball_is_silent(self) -> None:
        spec = _npx()
        lock = Lock()
        lock.record([spec], [], [])
        lock.servers[spec.identity()]["integrity"] = {
            "npm:@scope/pkg@1.2.3": "sha512-abc",
        }
        integ.get_json = lambda url: {"dist": {"integrity": "sha512-abc"}}
        found = [f for f in run_rules(AuditContext(
            servers=[spec], lock={"servers": lock.servers, "skills": {}}))
            if f.rule_id == "MCPA036"]
        self.assertEqual([], found)



class TestSilenceMeansOneThing(unittest.TestCase):
    """"Verified unchanged" and "could not look" are different facts.

    Reporting them as one hands silence to anyone who can make the lookup
    fail, and hands the same silence to an offline build runner by accident,
    which is worse because nobody was even trying.
    """

    def setUp(self) -> None:
        self._real = integ.get_json
        self.spec = _npx()
        self.lock = Lock()
        self.lock.record([self.spec], [], [])
        self.lock.servers[self.spec.identity()]["integrity"] = {
            "npm:@scope/pkg@1.2.3": "sha512-abc",
        }
        self._tmp = tempfile.TemporaryDirectory()
        self._cold = empty_npm_cache(self._tmp.name)
        self._cold.__enter__()

    def tearDown(self) -> None:
        integ.get_json = self._real
        self._cold.__exit__(None, None, None)
        self._tmp.cleanup()

    def _run(self, **options):
        return run_rules(AuditContext(
            servers=[self.spec],
            lock={"servers": self.lock.servers, "skills": {}},
            options=options))

    def test_an_unreachable_registry_is_reported_not_ignored(self) -> None:
        integ.get_json = lambda url: None
        ids = [f.rule_id for f in self._run()]
        self.assertIn("MCPA037", ids)
        self.assertNotIn("MCPA036", ids)

    def test_it_is_low_by_default_so_an_offline_runner_is_not_broken(self) -> None:
        integ.get_json = lambda url: None
        found = [f for f in self._run() if f.rule_id == "MCPA037"]
        self.assertEqual("low", found[0].severity.label)

    def test_require_integrity_makes_it_fail_the_build(self) -> None:
        """A runner that must not pass on 'could not see' asks for this, and
        `--fail-on high` then stops it."""
        integ.get_json = lambda url: None
        found = [f for f in self._run(require_integrity=True)
                 if f.rule_id == "MCPA037"]
        self.assertEqual("high", found[0].severity.label)

    def test_a_verified_artifact_says_nothing(self) -> None:
        integ.get_json = lambda url: {"dist": {"integrity": "sha512-abc"}}
        ids = [f.rule_id for f in self._run()]
        self.assertNotIn("MCPA037", ids)
        self.assertNotIn("MCPA036", ids)

    def test_safe_contacts_nothing_and_says_it_could_not_see(self) -> None:
        """`--safe` promises to execute nothing and connect to nothing. A
        registry lookup is a connection, and it also tells npm and PyPI which
        packages you run."""
        calls = []
        integ.get_json = lambda url: calls.append(url) or None
        found = [f for f in self._run(offline=True) if f.rule_id == "MCPA037"]
        self.assertEqual([], calls)
        self.assertTrue(found)
        self.assertIn("--safe", found[0].evidence)

    def test_the_registry_is_asked_once_for_two_rules(self) -> None:
        """Both rules read the same answer. Two lookups would double the
        latency and double what the registry is told."""
        calls = []
        integ.get_json = lambda url: calls.append(url) or {
            "dist": {"integrity": "sha512-elsewhere"}}
        self._run()
        self.assertEqual(1, len(calls))


class TestAMalformedPinDoesNotTakeTheScanDown(unittest.TestCase):
    """`run_rules` does not catch a rule exception, and the lockfile is meant
    to be hand-edited.

    So a mapping somebody typed badly must produce a finding, not a traceback
    that stops every other rule in the run from being reported. The same bug
    shape was found in `pkgcache.check` by fuzzing it the day it was written.
    """

    def setUp(self) -> None:
        self._real = integ.get_json
        integ.get_json = lambda url: None

    def tearDown(self) -> None:
        integ.get_json = self._real

    def _scan(self, integrity: object) -> list:
        spec = _npx()
        lock = Lock()
        lock.record([spec], [], [])
        lock.servers[spec.identity()]["integrity"] = integrity
        return run_rules(AuditContext(
            servers=[spec], lock={"servers": lock.servers, "skills": {}}))

    def test_mixed_key_types_do_not_raise(self) -> None:
        found = self._scan({5: "sha512-a", "npm:@scope/pkg@1.2.3": "sha512-b"})
        self.assertIn("MCPA037", [f.rule_id for f in found])

    def test_the_wrong_shape_entirely_is_ignored(self) -> None:
        for shape in ("a string", ["a", "list"], 7, None, {}):
            with self.subTest(shape=shape):
                ids = [f.rule_id for f in self._scan(shape)]
                self.assertNotIn("MCPA036", ids)
                self.assertNotIn("MCPA037", ids)


class TestApprovalRecordsWhatItCouldNotDo(unittest.TestCase):
    def setUp(self) -> None:
        self._real = integ.get_json

    def tearDown(self) -> None:
        integ.get_json = self._real

    def test_the_artifact_url_is_recorded_alongside_the_hash(self) -> None:
        """pkgcache needs it: a PyPI URL carries a hash path that no package
        name implies, so without it the local wheel cannot be found."""
        from mcp_pin.cli import _stamp_integrity
        spec = ServerSpec(name="n", source="/x", client="c", transport="stdio",
                          command="uvx", args=["pkg==1.2.3"])
        lock = Lock()
        lock.record([spec], [], [])
        integ.get_json = lambda url: {"urls": [{
            "digests": {"sha256": "deadbeef"},
            "url": "https://files.pythonhosted.org/packages/ab/cd/pkg-1.2.3.whl"}]}
        _stamp_integrity(lock, [spec])
        entry = lock.servers[spec.identity()]
        self.assertEqual({"pypi:pkg==1.2.3": "sha256-deadbeef"}, entry["integrity"])
        self.assertIn("pkg-1.2.3.whl", entry["artifact_urls"]["pypi:pkg==1.2.3"])

    def test_a_failed_lookup_is_reported_to_the_operator(self) -> None:
        """An approval that could not record the hash is a weaker approval,
        and the moment to say so is while somebody is deciding."""
        from mcp_pin.cli import _stamp_integrity
        spec = _npx()
        lock = Lock()
        lock.record([spec], [], [])
        integ.get_json = lambda url: None
        missed = _stamp_integrity(lock, [spec])
        self.assertEqual(1, len(missed))
        self.assertIn("did not answer", missed[0])
        self.assertNotIn("integrity", lock.servers[spec.identity()])

    def test_safe_records_nothing_and_names_what_went_unpinned(self) -> None:
        from mcp_pin.cli import _stamp_integrity
        spec = _npx()
        lock = Lock()
        lock.record([spec], [], [])
        calls = []
        integ.get_json = lambda url: calls.append(url) or {"dist": {}}
        missed = _stamp_integrity(lock, [spec], offline=True)
        self.assertEqual([], calls)
        self.assertEqual(1, len(missed))
        self.assertIn("--safe", missed[0])

    def test_a_server_with_no_package_is_not_reported_as_a_miss(self) -> None:
        """Only a launch that *would* have had a tarball counts. Listing a
        plain `node server.js` here would make the warning noise, and noise
        is how a warning stops being read."""
        from mcp_pin.cli import _stamp_integrity
        spec = ServerSpec(name="local", source="/x", client="c",
                          transport="stdio", command="node", args=["server.js"])
        lock = Lock()
        lock.record([spec], [], [])
        self.assertEqual([], _stamp_integrity(lock, [spec], offline=True))


if __name__ == "__main__":
    unittest.main()
