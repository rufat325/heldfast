"""The lockfile never carries a credential from a server's launch line.

`approve` records servers from user-level configs as well as the project's,
and the lock is committed: a `--token ghp_...` argument or an `?api_key=`
URL in ~/.claude.json went into the repository with it. The lock now records
both redacted, beside `launch_sha256` of the real values, which is what the
launch pin and the drift rule compare.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from heldfast.lockfile import Lock, launch_mismatch  # noqa: E402
from heldfast.model import ServerSpec  # noqa: E402
from heldfast.rules.base import AuditContext  # noqa: E402
from heldfast.rules.drift import command_drift  # noqa: E402

TOKEN = "ghp_R3alLo0kingT0kenValue1234567890abcdEF"


def spec(token: str = TOKEN, extra: list[str] | None = None) -> ServerSpec:
    return ServerSpec(name="gh", source="~/.claude.json", client="claude-code",
                      transport="stdio", command="npx",
                      args=["-y", "srv@1.0.0", "--token", token] + (extra or []))


class TestTheLockHoldsNoCredential(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = Lock()
        self.lock.record([spec()], [], [])
        self.entry = self.lock.servers[spec().identity()]

    def test_the_written_file_has_no_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".mcp-pin.lock"
            self.lock.save(path)
            text = path.read_text(encoding="utf-8")
        self.assertNotIn("R3alLo0kingT0ken", text)
        self.assertIn("srv@1.0.0", text)
        self.assertIn("launch_sha256", json.loads(text)["servers"][spec().identity()])

    def test_the_launch_pin_still_matches_the_real_command(self) -> None:
        digest = self.entry["launch_sha256"]
        self.assertIsNone(launch_mismatch(self.entry["command_line"], spec().argv,
                                          digest=digest))
        self.assertIsNotNone(launch_mismatch(self.entry["command_line"],
                                             spec(extra=["--evil"]).argv, digest=digest))

    def drift(self, current: ServerSpec) -> list:
        ctx = AuditContext(servers=[current])
        ctx.lock = {"servers": {current.identity(): self.entry}}
        return list(command_drift(ctx))

    def test_no_drift_when_nothing_changed(self) -> None:
        self.assertEqual([], self.drift(spec()))

    def test_a_changed_command_is_reported_without_the_token(self) -> None:
        found = self.drift(spec(extra=["--evil"]))
        self.assertTrue(found)
        self.assertNotIn("R3alLo0kingT0ken", json.dumps([f.evidence for f in found]))

    def test_a_rotated_token_is_reported_as_the_credential(self) -> None:
        found = self.drift(spec(token="ghp_An0therT0kenValue1234567890abcdEFGHIJ"))
        self.assertTrue(found)
        self.assertIn("credential", found[0].evidence)
        self.assertNotIn("An0therT0ken", found[0].evidence)

    def test_an_ordinary_launch_is_recorded_as_before(self) -> None:
        plain = ServerSpec(name="fs", source="/p/.mcp.json", client="claude-code",
                           transport="stdio", command="npx", args=["-y", "fs@1.0.0", "/work"])
        lock = Lock()
        lock.record([plain], [], [])
        entry = lock.servers[plain.identity()]
        self.assertEqual(plain.command_line, entry["command_line"])
        self.assertNotIn("launch_sha256", entry)


if __name__ == "__main__":
    unittest.main()
