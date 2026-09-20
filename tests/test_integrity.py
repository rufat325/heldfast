"""The tarball behind a version string."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

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


if __name__ == "__main__":
    unittest.main()
