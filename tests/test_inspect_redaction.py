"""`heldfast inspect` does not print a server's credentials.

Its launch line showed the command and URL verbatim, so a `--token ghp_...`
argument or a `?api_key=...` URL went straight into whatever the output was
pasted into. Environment values were already classified, never printed.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from heldfast import inspect as inspect_mod  # noqa: E402
from heldfast.model import ServerSpec  # noqa: E402
from heldfast.secrets import redact  # noqa: E402

TOKEN = "ghp_R3alLo0kingT0kenValue1234567890abcdEF"


class TestInspectRedacts(unittest.TestCase):
    def test_launch_lines_carry_no_credentials(self) -> None:
        servers = [
            ServerSpec(name="gh", source="/p/.mcp.json", client="test", transport="stdio",
                       command="npx", args=["-y", "srv@1.0.0", "--token", TOKEN]),
            ServerSpec(name="remote", source="/p/.mcp.json", client="test", transport="http",
                       url="https://admin:S3cretPassw0rd@api.example.com/mcp?api_key=plainkey99"),
        ]
        data = inspect_mod.build(servers, [], [], [])
        out = json.dumps(data) + inspect_mod.render(data)
        for secret in ("R3alLo0kingT0ken", "S3cretPassw0rd", "plainkey99"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, out)
        self.assertIn("srv@1.0.0", out)
        self.assertIn("api.example.com/mcp", out)


class TestRedactByPosition(unittest.TestCase):
    def test_secrets_found_by_where_they_sit(self) -> None:
        cases = {
            "srv --api-key abc123plain --port 8080": "abc123plain",
            "srv --password=hunter2 --verbose": "hunter2",
            "postgres://admin:S3cretPassw0rd@db:5432/app": "S3cretPassw0rd",
            "https://h/mcp?token=abcdef1234&page=2": "abcdef1234",
            "https://h/mcp?sig=zzz#frag": "zzz",
        }
        for text, secret in cases.items():
            with self.subTest(text=text):
                self.assertNotIn(secret, redact(text))

    def test_ordinary_arguments_survive(self) -> None:
        for text in ("npx -y @scope/server-memory@1.0 --port 3000 --keyboard-layout us",
                     "node server.js --monkey banana", "https://user@host/x",
                     "https://h/mcp?page=2&sort=asc"):
            with self.subTest(text=text):
                self.assertEqual(text, redact(text))


if __name__ == "__main__":
    unittest.main()
