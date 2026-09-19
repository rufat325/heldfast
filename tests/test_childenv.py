"""One server's token should not reach the next one.

The gateway launched every backend with the whole parent environment, so a
token exported once -- for the GitHub server, say -- arrived at the filesystem
server, the postgres server and everything else behind the same endpoint. Each
of those is a different publisher's code.

Every MCP client does this, so it is not a regression; it is the one thing the
gateway is uniquely placed to fix, and a component calling itself an admission
boundary while handing every backend every secret on the machine is not one.

The risk in fixing it is entirely in the allowlist. Withhold too much and
every server breaks, in ways that look like unrelated bugs -- a Windows
process without SystemRoot cannot open a socket. So the base set is
evidence-led: 2,406 real server files were read for every environment variable
they actually consult, and the 192 names divide cleanly into infrastructure
and credentials.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.childenv import BASE, build, notable  # noqa: E402
from mcp_pin.model import ServerSpec  # noqa: E402

PARENT = {
    "PATH": "/usr/bin", "HOME": "/home/me", "SystemRoot": "C:/Windows",
    "LANG": "en_US.UTF-8", "VIRTUAL_ENV": "/venv", "HTTPS_PROXY": "http://p:8080",
    "GITHUB_TOKEN": "ghp_real", "OPENAI_API_KEY": "sk-real",
    "DB_PASSWORD": "hunter2", "AWS_SECRET_ACCESS_KEY": "aws-real",
    "MY_LAPTOP_NICKNAME": "bertha",
}


def spec(**env) -> ServerSpec:
    return ServerSpec(name="s", source="/p/.mcp.json", client="claude-code",
                      transport="stdio", command="node", args=["s.js"], env=env)


class TestWhatGetsThrough(unittest.TestCase):
    def test_an_undeclared_secret_is_withheld(self) -> None:
        env, withheld = build(spec(), PARENT)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertIn("GITHUB_TOKEN", withheld)

    def test_a_declared_literal_is_passed(self) -> None:
        env, _ = build(spec(GITHUB_TOKEN="ghp_declared"), PARENT)
        self.assertEqual("ghp_declared", env["GITHUB_TOKEN"])

    def test_a_declared_reference_is_resolved_from_the_parent(self) -> None:
        """`"env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}` is how servers are
        documented, and it keeps the secret out of the config file. It has to
        keep working or isolation just breaks the recommended shape."""
        for written in ("${GITHUB_TOKEN}", "$GITHUB_TOKEN", "%GITHUB_TOKEN%"):
            with self.subTest(written=written):
                env, _ = build(spec(GITHUB_TOKEN=written), PARENT)
                self.assertEqual("ghp_real", env["GITHUB_TOKEN"])

    def test_an_unresolvable_reference_is_left_as_written(self) -> None:
        """Substituting an empty string would turn "you forgot to export it"
        into "the server got a blank token", and a blank token fails in ways
        nobody traces back to here."""
        env, _ = build(spec(NOPE="${NOT_SET_ANYWHERE}"), PARENT)
        self.assertEqual("${NOT_SET_ANYWHERE}", env["NOPE"])

    def test_a_declaration_can_override_the_base_set(self) -> None:
        """That is what declaring it means."""
        env, _ = build(spec(HOME="/sandbox"), PARENT)
        self.assertEqual("/sandbox", env["HOME"])


class TestTheServerStillRuns(unittest.TestCase):
    """The allowlist is the whole risk. Everything here is something a real
    server needs, and withholding any of it produces a failure that looks
    like an unrelated bug."""

    def test_the_runtime_essentials_survive(self) -> None:
        env, _ = build(spec(), PARENT)
        for name in ("PATH", "HOME", "LANG"):
            self.assertIn(name, env, f"{name} must reach the server")

    def test_windows_gets_system_root(self) -> None:
        """A Windows process without SystemRoot cannot create a socket, and
        the error says nothing about an environment variable."""
        env, _ = build(spec(), PARENT)
        self.assertIn("SystemRoot", env)

    def test_the_interpreter_can_still_find_its_own_code(self) -> None:
        env, _ = build(spec(), PARENT)
        self.assertIn("VIRTUAL_ENV", env)

    def test_the_proxy_survives(self) -> None:
        """A server behind a corporate proxy reaches nothing without it."""
        env, _ = build(spec(), PARENT)
        self.assertIn("HTTPS_PROXY", env)

    def test_the_base_set_is_matched_case_insensitively(self) -> None:
        """Windows spells it SystemRoot, POSIX tooling spells things in caps,
        and a case-sensitive allowlist silently drops half of them."""
        env, _ = build(spec(), {"SyStEmRoOt": "C:/Windows", "Path": "/usr/bin"})
        self.assertEqual({"SyStEmRoOt", "Path", "PYTHONUNBUFFERED"}, set(env))

    def test_an_ordinary_non_secret_is_still_withheld(self) -> None:
        """Not a judgement about danger. A backend gets what it declared;
        everything else is simply not its business."""
        env, _ = build(spec(), PARENT)
        self.assertNotIn("MY_LAPTOP_NICKNAME", env)


class TestTheEscapeHatches(unittest.TestCase):
    def test_share_env_lets_one_through_for_everybody(self) -> None:
        env, _ = build(spec(), PARENT, share={"OPENAI_API_KEY"})
        self.assertEqual("sk-real", env["OPENAI_API_KEY"])
        self.assertNotIn("GITHUB_TOKEN", env)

    def test_isolate_false_restores_the_old_behaviour(self) -> None:
        env, withheld = build(spec(), PARENT, isolate=False)
        self.assertEqual("ghp_real", env["GITHUB_TOKEN"])
        self.assertEqual([], withheld)

    def test_references_still_resolve_without_isolation(self) -> None:
        env, _ = build(spec(TOKEN="${GITHUB_TOKEN}"), PARENT, isolate=False)
        self.assertEqual("ghp_real", env["TOKEN"])


class TestWhatGetsSaidOutLoud(unittest.TestCase):
    """A normal shell has sixty variables. Printing all of them would bury the
    one the operator needs, so only the credential-shaped names are named."""

    def test_credential_shaped_names_are_reported(self) -> None:
        _, withheld = build(spec(), PARENT)
        named = set(notable(withheld))
        self.assertEqual(
            {"GITHUB_TOKEN", "OPENAI_API_KEY", "DB_PASSWORD",
             "AWS_SECRET_ACCESS_KEY"}, named)

    def test_an_ordinary_name_is_not_reported(self) -> None:
        _, withheld = build(spec(), PARENT)
        self.assertNotIn("MY_LAPTOP_NICKNAME", notable(withheld))

    def test_the_matching_is_on_whole_words(self) -> None:
        """MONKEY contains KEY. A report that names it teaches people to skim
        past the list, which is where the real one is."""
        _, withheld = build(spec(), {"MONKEY": "x", "TURKEY": "y",
                                     "API_KEY": "z", "PASSWORD": "w"})
        self.assertEqual({"API_KEY", "PASSWORD"}, set(notable(withheld)))


class TestTheBaseSetItself(unittest.TestCase):
    def test_it_holds_no_credential_shaped_name(self) -> None:
        """The allowlist is the one place a mistake is silent: a credential
        name in here would be handed to every backend forever."""
        self.assertEqual([], notable(sorted(BASE)),
                         "a credential-shaped name is in the always-pass set")

    def test_it_is_stored_uppercased(self) -> None:
        self.assertTrue(all(n == n.upper() for n in BASE))


class TestTheProbeIsolatesToo(unittest.TestCase):
    """The riskier of the two launches.

    The gateway starts servers that were approved. Probing is the operation
    that launches code *before* anyone has reviewed it -- that is why it is
    opt-in and why it is gated by severity. Handing a config pasted out of a
    README every secret in the environment, in order to find out whether it is
    hostile, is the wrong order to do things in.
    """

    def setUp(self) -> None:
        import os
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        # A server that reports back which secrets it could see.
        (self.project / "peek.py").write_text(
            "import json, os, sys\n"
            "seen = [k for k in ('SNOOP_TOKEN', 'DECLARED_TOKEN') if k in os.environ]\n"
            "for line in sys.stdin:\n"
            "    line = line.strip()\n"
            "    if not line:\n"
            "        continue\n"
            "    req = json.loads(line)\n"
            "    rid, method = req.get('id'), req.get('method')\n"
            "    if method == 'initialize':\n"
            "        out = {'protocolVersion': '2024-11-05', 'capabilities': {},\n"
            "               'serverInfo': {'name': 'peek', 'version': '1'}}\n"
            "    elif method == 'tools/list':\n"
            "        out = {'tools': [{'name': 'saw_' + ('_'.join(seen) or 'nothing'),\n"
            "                          'description': 'Reports.', 'inputSchema': {}}]}\n"
            "    elif rid is None:\n"
            "        continue\n"
            "    else:\n"
            "        out = {}\n"
            "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': rid,\n"
            "                                 'result': out}) + '\\n')\n"
            "    sys.stdout.flush()\n",
            encoding="utf-8")
        os.environ["SNOOP_TOKEN"] = "should-not-be-seen"
        os.environ["DECLARED_TOKEN"] = "declared-value"

    def tearDown(self) -> None:
        import os
        for name in ("SNOOP_TOKEN", "DECLARED_TOKEN"):
            os.environ.pop(name, None)
        self._tmp.cleanup()

    def _probe(self, **env) -> str:
        from mcp_pin.probe import probe_stdio
        s = ServerSpec(name="peek", source=str(self.project / ".mcp.json"),
                       client="claude-code", transport="stdio",
                       command=sys.executable,
                       args=[str(self.project / "peek.py")], env=env)
        result = probe_stdio(s, timeout=30.0)
        return result.tools[0].name if result.tools else f"<no tools: {result.error}>"

    def test_an_undeclared_secret_does_not_reach_a_probed_server(self) -> None:
        self.assertEqual("saw_nothing", self._probe())

    def test_a_declared_one_does(self) -> None:
        self.assertEqual("saw_DECLARED_TOKEN",
                         self._probe(DECLARED_TOKEN="${DECLARED_TOKEN}"))


class TestMalformedInput(unittest.TestCase):
    def test_nothing_raises(self) -> None:
        class Odd:
            env = None

        for bad in (Odd(), spec(), ServerSpec(name="n", source="s", client="c")):
            with self.subTest(spec=bad):
                build(bad, PARENT)

    def test_non_string_declared_values_are_coerced(self) -> None:
        s = spec()
        s.env = {"PORT": 8080, "DEBUG": True}    # type: ignore[dict-item]
        env, _ = build(s, PARENT)
        self.assertEqual("8080", env["PORT"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
