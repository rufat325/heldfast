"""Which guarantees are in force, and the reason when one is not.

The reason is the part under test. A verdict of "no" is cheap and mostly
useless: `npx -y pkg` cannot be pinned by digest and never will be, while an
approval made without --probe can be fixed in thirty seconds, and a report
that prints the same word for both is a nag rather than a tool.

One of these tests exists because the first version guessed. A server that was
launched at approve time and never answered has no tools recorded, exactly
like one that was never probed -- and it told the operator to run
`approve --probe`, which is the command that had already failed. The lockfile
now records which happened, and the test below is why.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit import coverage  # noqa: E402
from mcp_audit.lockfile import Lock  # noqa: E402
from mcp_audit.model import ServerSpec, ToolSpec  # noqa: E402


def spec(name: str, command: str = "node", args: list | None = None,
         url: str = "", transport: str = "stdio") -> ServerSpec:
    return ServerSpec(name=name, source=str(ROOT / "tests" / ".mcp.json"),
                      client="claude-code", transport=transport,
                      command=command, args=args if args is not None else ["s.js"],
                      url=url)


def layers(lock: Lock, servers: list) -> dict[str, dict[str, coverage.Layer]]:
    out = {}
    configured = {s.identity(): s for s in servers}
    for key in sorted(set(lock.servers) | set(configured)):
        found = coverage.for_server(lock, key, configured.get(key))
        out[key] = {layer.name: layer for layer in found}
    return out


class TestTheCodeLayerKnowsWhyNot(unittest.TestCase):
    """The layer that most needs its reason, because most of the ecosystem
    cannot satisfy it and reporting that as failure would be permanent noise."""

    def _code(self, server: ServerSpec, entry: dict | None = None) -> coverage.Layer:
        lock = Lock()
        lock.record([server], [], [])
        if entry:
            lock.servers[server.identity()].update(entry)
        return layers(lock, [server])[server.identity()]["code pinned"]

    def test_a_registry_launch_with_a_floating_version_is_a_real_gap(self) -> None:
        layer = self._code(spec("github", "npx", ["-y", "@scope/server-github"]))
        self.assertEqual("no", layer.state)
        self.assertIn("no local file to hash", layer.detail)
        self.assertIn("@scope/server-github@", layer.remedy)

    def test_a_registry_launch_at_a_pinned_version_is_not_a_gap(self) -> None:
        """The version *is* the pin. Demanding a digest as well would put a
        permanent mark on the most correct thing a user can write."""
        layer = self._code(spec("github", "npx", ["-y", "@scope/srv@1.2.3"]))
        self.assertEqual("n/a", layer.state)
        self.assertIn("1.2.3", layer.detail)

    def test_the_pep508_spelling_counts_and_reads_properly(self) -> None:
        layer = self._code(spec("fetch", "uvx", ["mcp-server-fetch==0.6.2"]))
        self.assertEqual("n/a", layer.state)
        self.assertIn("0.6.2", layer.detail)
        self.assertNotIn("==", layer.detail)

    def test_the_python_remedy_uses_the_python_spelling(self) -> None:
        layer = self._code(spec("fetch", "uvx", ["mcp-server-fetch"]))
        self.assertIn("mcp-server-fetch==", layer.remedy)

    def test_a_remote_server_launches_nothing_to_hash(self) -> None:
        layer = self._code(spec("remote", "", [], url="https://x.example/sse",
                                transport="sse"))
        self.assertEqual("n/a", layer.state)
        self.assertIn("remote", layer.detail)

    def test_a_local_script_with_a_digest_is_covered(self) -> None:
        layer = self._code(spec("local"), {"artifacts": {"/p/s.js": "abc"}})
        self.assertEqual("yes", layer.state)

    def test_a_resolvable_script_with_no_digest_is_a_gap(self) -> None:
        """An entry written before digests existed, or a file too large to
        hash. The script is there and nothing is watching it."""
        server = spec("local", "python", ["fixtures/fake_server.py"])
        lock = Lock()
        lock.record([server], [], [])
        lock.servers[server.identity()].pop("artifacts", None)
        layer = layers(lock, [server])[server.identity()]["code pinned"]
        self.assertEqual("no", layer.state)
        self.assertIn("no digest was recorded", layer.detail)

    def test_a_named_script_that_is_not_there_is_a_broken_launch(self) -> None:
        """Distinct from having nothing to pin: this command cannot start at
        all, and reporting it as "nothing to hash" would hide that."""
        layer = self._code(spec("local", "node", ["server.js"]))
        self.assertEqual("no", layer.state)
        self.assertIn("not a file on this machine", layer.detail)
        self.assertIn("server.js", layer.detail)

    def test_a_bare_interpreter_with_no_script_names_nothing(self) -> None:
        layer = self._code(spec("odd", "node", []))
        self.assertEqual("n/a", layer.state)
        self.assertIn("names no script", layer.detail)


class TestProbedAndUnprobedAreDifferent(unittest.TestCase):
    """The case that made the lockfile record a probe result at all."""

    def _tools(self, entry: dict) -> coverage.Layer:
        server = spec("alpha")
        lock = Lock()
        lock.record([server], [], [])
        lock.servers[server.identity()].update(entry)
        return layers(lock, [server])[server.identity()]["tools pinned"]

    def test_never_probed_says_to_probe(self) -> None:
        layer = self._tools({})
        self.assertEqual("no", layer.state)
        self.assertIn("without --probe", layer.detail)
        self.assertIn("approve --probe", layer.remedy)

    def test_probed_and_silent_does_not_send_you_back_to_the_same_command(self) -> None:
        layer = self._tools({"probe": "no response: could not launch"})
        self.assertEqual("no", layer.state)
        self.assertIn("did not answer", layer.detail)
        self.assertIn("could not launch", layer.detail)
        self.assertNotIn("approve --probe", layer.remedy)
        self.assertIn("does not start", layer.remedy)

    def test_answered_and_pinned(self) -> None:
        layer = self._tools({"probe": "answered",
                             "tools": {"read": {"fingerprint": "x"}}})
        self.assertEqual("yes", layer.state)


class TestTheLockfileRecordsIt(unittest.TestCase):
    def test_record_stores_the_probe_outcome(self) -> None:
        lock = Lock()
        lock.record([spec("alpha"), spec("beta")], [], [],
                    probe_status={"alpha": "answered",
                                  "beta": "no response: timed out"})
        self.assertEqual("answered", lock.servers["claude-code:alpha"]["probe"])
        self.assertIn("timed out", lock.servers["claude-code:beta"]["probe"])

    def test_a_server_nobody_probed_carries_no_field_at_all(self) -> None:
        """Absent means not attempted. Writing "not attempted" would make the
        field present in every lockfile for no gain."""
        lock = Lock()
        lock.record([spec("alpha")], [], [], probe_status={})
        self.assertNotIn("probe", lock.servers["claude-code:alpha"])

    def test_it_is_carried_forward_like_the_other_observations(self) -> None:
        """`approve` without --probe must not erase what the last probe found,
        including the fact that the server never answered."""
        previous = Lock()
        previous.record([spec("alpha")], [], [], probe_status={"alpha": "answered"})
        fresh = Lock()
        fresh.record([spec("alpha")], [], [], previous=previous)
        fresh.merge_unprobed(previous)
        self.assertEqual("answered", fresh.servers["claude-code:alpha"]["probe"])


class TestIdentityLayer(unittest.TestCase):
    def _identity(self, identities: dict, name: str = "alpha") -> coverage.Layer:
        server = spec(name)
        lock = Lock()
        lock.record([server], [], [])
        lock.identities = identities
        return layers(lock, [server])[server.identity()]["identity"]

    def test_none_declared_is_not_a_gap(self) -> None:
        """Demanding access control from a single-agent setup that does not
        need it is how a coverage report gets ignored."""
        layer = self._identity({})
        self.assertEqual("n/a", layer.state)

    def test_a_granting_identity_is_named(self) -> None:
        layer = self._identity({"finance": {"servers": ["alpha"]}})
        self.assertEqual("yes", layer.state)
        self.assertIn("finance", layer.detail)

    def test_granted_to_nobody_is_not_claimed_as_a_restriction(self) -> None:
        """No identity grants it, but a gateway started without --as is not
        acting as any identity and reaches it anyway. Saying "yes" would claim
        a restriction the launch command decides, not the lockfile."""
        layer = self._identity({"finance": {"servers": ["other"]}})
        self.assertEqual("n/a", layer.state)
        self.assertIn("without --as", layer.detail)


class TestTheWholeReport(unittest.TestCase):
    def _built(self, lock: Lock, servers: list) -> dict:
        return coverage.build(lock, servers)

    def test_an_unapproved_server_is_included(self) -> None:
        lock = Lock()
        lock.record([spec("alpha")], [], [])
        data = self._built(lock, [spec("alpha"), spec("gamma")])
        keys = {row["identity"] for row in data["servers"]}
        self.assertIn("claude-code:gamma", keys)

    def test_a_server_no_longer_configured_is_marked(self) -> None:
        lock = Lock()
        lock.record([spec("alpha"), spec("beta")], [], [])
        data = self._built(lock, [spec("alpha")])
        beta = next(r for r in data["servers"] if r["identity"] == "claude-code:beta")
        self.assertFalse(beta["configured"])

    def test_a_fully_covered_server_counts_as_one(self) -> None:
        server = spec("alpha", "npx", ["-y", "pkg@1.0.0"])
        lock = Lock()
        lock.record([server], [ToolSpec(server="alpha", name="read",
                                        description="Reads.", input_schema={})], [])
        lock.servers[server.identity()]["policy"] = {"read": {"paths": ["/w/**"]}}
        data = self._built(lock, [server])
        self.assertEqual(1, data["fully_covered"])
        self.assertEqual(1, data["total"])

    def test_nothing_anywhere_says_so(self) -> None:
        text = coverage.render(coverage.build(Lock(), []), color=False)
        self.assertIn("Nothing configured", text)

    def test_no_color_means_no_escapes(self) -> None:
        lock = Lock()
        lock.record([spec("alpha")], [], [])
        text = coverage.render(self._built(lock, [spec("alpha")]), color=False)
        self.assertNotIn("\033", text)

    def test_the_payload_is_json_serialisable(self) -> None:
        lock = Lock()
        lock.record([spec("alpha")], [], [])
        lock.identities = {"finance": {"servers": ["alpha"]}}
        json.dumps(self._built(lock, [spec("alpha")]))

    def test_the_reason_reaches_the_rendered_page(self) -> None:
        """A state word with no reason beside it is the thing this replaces."""
        lock = Lock()
        lock.record([spec("github", "npx", ["-y", "@scope/srv"])], [], [])
        text = coverage.render(self._built(
            lock, [spec("github", "npx", ["-y", "@scope/srv"])]), color=False)
        self.assertIn("no local file to hash", text)
        self.assertIn("@scope/srv@", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
