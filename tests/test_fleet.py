"""`inventory`, the organisation policy, and `fleet`.

An inventory is written on machines nobody is watching and read somewhere
else, so most of this file is about what must not happen on either end: a
credential leaving the machine inside it, a server being launched to write it,
a policy pattern that a crafted address can satisfy, a hostile inventory
rewriting the report it is joined into, and an unanswered advisory lookup
reading as an all-clear.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import advisories, fleet, inventory, orgpolicy  # noqa: E402
from heldfast.fleet_html import render_html  # noqa: E402
from heldfast.lockfile import Lock  # noqa: E402
from heldfast.model import ServerSpec  # noqa: E402

GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
SK = "sk-" + "proj-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp"


def run_cli(*args: str, cwd: Path | None = None, env: dict | None = None
            ) -> subprocess.CompletedProcess:
    full = dict(os.environ, PYTHONPATH=str(ROOT / "src"), NO_COLOR="1")
    full.update(env or {})
    return subprocess.run([sys.executable, "-m", "heldfast", *args], capture_output=True,
                          text=True, env=full, cwd=str(cwd or ROOT))


def spec(name: str = "s", command: str | None = "npx", args: list | None = None,
         url: str | None = None, client: str = "claude-code") -> ServerSpec:
    return ServerSpec(name=name, source="/proj/.mcp.json", client=client,
                      transport="http" if url else "stdio", command=None if url else command,
                      args=[] if url else (args if args is not None else ["-y", "pkg@1.0.0"]),
                      url=url)


def row(identity: str = "claude-code:s", **over) -> dict:
    base = {"identity": identity, "kind": "package", "state": "ok", "enforced": "wrap",
            "package": {"ecosystem": "npm", "name": "pkg", "version": "1.0.0", "exact": True},
            "endpoint": None, "command": "npx", "disabled": False, "top_findings": []}
    base.update(over)
    return base


def policy(**data) -> orgpolicy.OrgPolicy:
    return orgpolicy.parse({"policy": orgpolicy.SCHEMA, **data})


# ---------------------------------------------------------------------------
# The policy file


class TestPolicyIsReadStrictly(unittest.TestCase):
    """A key this version does not know is an error. A policy that skipped
    `"requre"` would report every machine compliant with a requirement
    nothing checks."""

    def test_unknown_keys_anywhere_are_refused(self) -> None:
        for bad in ({"requre": {}}, {"allow": [{"pakage": "npm:x"}]},
                    {"require": {"aproved": True}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                policy(**bad)

    def test_the_schema_is_named(self) -> None:
        with self.assertRaises(ValueError):
            orgpolicy.parse({"allow": []})

    def test_a_rule_that_would_match_everything_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            policy(deny=[{"reason": "everything"}])

    def test_malformed_selectors_are_refused(self) -> None:
        for rule in ({"package": "postmark-mcp"}, {"package": "cargo:x"},
                     {"url": "mcp.example.com"}, {"kind": "remote"},
                     {"versions": ["1.0.0"], "url": "https://x/"},
                     {"package": "npm:x", "versions": "1.0.0"}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                policy(deny=[rule])

    def test_require_values_are_checked(self) -> None:
        for bad in ({"approved": "yes"}, {"fail_on": "severe"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                policy(require=bad)

    def test_load_records_the_digest_of_the_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.json"
            path.write_text(json.dumps({"policy": orgpolicy.SCHEMA}), encoding="utf-8")
            self.assertRegex(orgpolicy.load(path).digest, r"^[0-9a-f]{64}$")


class TestUrlPatterns(unittest.TestCase):
    """Host and path are matched apart. As one glob, `*` crosses `/`, and
    `https://*.acme.com/*` was satisfied by `https://evil.example/.acme.com/`."""

    def matches(self, pattern: str, url: str) -> bool:
        rule = orgpolicy.Rule(url=pattern)
        return orgpolicy.matches(rule, row(kind="hosted", package=None,
                                           endpoint=inventory.endpoint(url)))

    def test_a_host_glob_cannot_be_met_by_a_path(self) -> None:
        self.assertTrue(self.matches("https://*.acme.com/*", "https://mcp.acme.com/sse"))
        self.assertFalse(self.matches("https://*.acme.com/*", "https://evil.example/.acme.com/"))
        self.assertFalse(self.matches("https://*.acme.com/*", "https://evilacme.com/sse"))

    def test_user_info_does_not_name_the_host(self) -> None:
        """`https://mcp.linear.app@evil.example/` connects to evil.example."""
        self.assertFalse(self.matches("https://mcp.linear.app/*",
                                      "https://mcp.linear.app@evil.example/sse"))

    def test_host_case_is_ignored_and_path_case_is_not(self) -> None:
        self.assertTrue(self.matches("https://mcp.linear.app/sse", "HTTPS://MCP.Linear.App/sse"))
        self.assertFalse(self.matches("https://mcp.linear.app/sse", "https://mcp.linear.app/SSE"))

    def test_ports_and_missing_paths(self) -> None:
        self.assertTrue(self.matches("https://mcp.acme.com", "https://mcp.acme.com:8443/x"))
        self.assertFalse(self.matches("https://mcp.acme.com:443", "https://mcp.acme.com:8443/x"))
        self.assertTrue(self.matches("https://mcp.acme.com/*", "https://mcp.acme.com"))


class TestPackagePatterns(unittest.TestCase):
    def test_pypi_names_are_compared_normalised(self) -> None:
        rule = orgpolicy.Rule(package="pypi:Mcp_Server.Fetch")
        self.assertTrue(orgpolicy.matches(rule, row(package={
            "ecosystem": "pypi", "name": "mcp-server-fetch", "version": "1", "exact": True})))

    def test_the_ecosystem_must_agree(self) -> None:
        self.assertFalse(orgpolicy.matches(orgpolicy.Rule(package="pypi:pkg"), row()))
        self.assertTrue(orgpolicy.matches(orgpolicy.Rule(package="*:pkg"), row()))

    def test_a_floating_version_may_be_the_denied_one(self) -> None:
        """It runs whatever was published last, which may be the named release
        -- so it matches a deny rule naming versions, and never an allow rule."""
        floating = row(package={"ecosystem": "npm", "name": "pkg", "version": "latest",
                                "exact": False})
        rule = orgpolicy.Rule(package="npm:pkg", versions=("1.0.16",))
        self.assertTrue(orgpolicy.matches(rule, floating, deny=True))
        self.assertFalse(orgpolicy.matches(rule, floating, deny=False))
        self.assertFalse(orgpolicy.matches(rule, row(), deny=True))


class TestEvaluation(unittest.TestCase):
    def test_a_denied_server_is_reported_as_denied_and_nothing_else(self) -> None:
        p = policy(deny=[{"package": "npm:pkg", "reason": "backdoored"}],
                   require={"approved": True})
        found = orgpolicy.evaluate(p, [row(state="UNAPPROVED")])
        self.assertEqual(["denied"], [v.code for v in found])
        self.assertIn("backdoored", found[0].message)

    def test_unlisted_follows_the_setting(self) -> None:
        for setting, want in (("warn", ["warn"]), ("deny", ["deny"]), ("allow", [])):
            p = policy(allow=[{"package": "npm:other"}], unlisted=setting)
            with self.subTest(setting=setting):
                self.assertEqual(want, [v.level for v in orgpolicy.evaluate(p, [row()])])

    def test_requirements(self) -> None:
        p = policy(require={"approved": True, "pinned": True, "exact_versions": True,
                            "enforced": True, "no_drift": True})
        cases = {
            "unapproved": row(state="UNAPPROVED"),
            "unpinned": row(state="UNPINNED"),
            "floating_version": row(package={"ecosystem": "npm", "name": "pkg",
                                             "version": "", "exact": False}),
            "unenforced": row(enforced="none"),
            "drifted": row(state="DRIFTED"),
        }
        for code, r in cases.items():
            with self.subTest(code=code):
                self.assertEqual([code], [v.code for v in orgpolicy.evaluate(p, [r])])
        self.assertEqual([], orgpolicy.evaluate(p, [row()]))

    def test_fail_on_does_not_require_approval_by_the_back_door(self) -> None:
        """MCPA014 is "no lockfile", which `approved` asks. Counting it under
        `fail_on: high` would fail every unapproved server for a policy that
        never asked for approval."""
        p = policy(require={"fail_on": "high"})
        quiet = row(top_findings=[{"rule_id": "MCPA014", "severity": "high", "title": "x"}])
        loud = row(top_findings=[{"rule_id": "MCPA007", "severity": "critical", "title": "x"}])
        self.assertEqual([], orgpolicy.evaluate(p, [quiet]))
        self.assertEqual(["finding"], [v.code for v in orgpolicy.evaluate(p, [loud])])

    def test_what_is_not_running_is_not_judged(self) -> None:
        p = policy(deny=[{"package": "npm:pkg"}])
        self.assertEqual([], orgpolicy.evaluate(p, [row(disabled=True), row(state="GONE")]))


# ---------------------------------------------------------------------------
# At launch


def writer(marker: Path) -> list:
    """An argv that leaves `marker` behind if anything runs it."""
    return [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('ran')"]


class TestLaunchRefusal(unittest.TestCase):
    """At launch the policy is a refusal: decided before the process exists."""

    def refuse(self, p: orgpolicy.OrgPolicy, r: dict, entry: dict | None = None) -> str | None:
        return orgpolicy.launch_refusal(p, r, entry if entry is not None else {"tools": {"t": {}}})

    def test_what_refuses_a_launch(self) -> None:
        floating = row(package={"ecosystem": "npm", "name": "pkg", "version": "", "exact": False})
        self.assertIn("denied", self.refuse(policy(deny=[{"package": "npm:pkg"}]), row()))
        self.assertIn("allow list", self.refuse(
            policy(allow=[{"package": "npm:other"}], unlisted="deny"), row()))
        self.assertIn("exact version", self.refuse(
            policy(require={"exact_versions": True}), floating))
        self.assertIn("pinned", self.refuse(policy(require={"pinned": True}), row(),
                                            {"command_line": "npx -y pkg@1.0.0"}))

    def test_what_does_not(self) -> None:
        """A warning is a report, and findings are a scan's to judge."""
        self.assertIsNone(self.refuse(policy(allow=[{"package": "npm:other"}],
                                             unlisted="warn"), row()))
        self.assertIsNone(self.refuse(policy(require={"fail_on": "info", "enforced": True,
                                                      "no_drift": True}), row()))

    def test_allow_unapproved_cannot_waive_approval(self) -> None:
        p = policy(require={"approved": True})
        self.assertIn("--allow-unapproved cannot waive",
                      orgpolicy.launch_refusal(p, row(), None))


class TestWhichPoliciesALaunchMeets(unittest.TestCase):
    """The managed policy is always in force; a local one tightens it and
    never replaces it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.managed = self.dir / "managed.json"
        self._real = orgpolicy.managed_path
        orgpolicy.managed_path = lambda platform=None: self.managed  # type: ignore[assignment]
        self.local = self.dir / "local.json"
        self.local.write_text(json.dumps({"policy": orgpolicy.SCHEMA, "name": "local"}))

    def tearDown(self) -> None:
        orgpolicy.managed_path = self._real  # type: ignore[assignment]
        self._tmp.cleanup()

    def test_managed_and_local_both_apply(self) -> None:
        self.managed.write_text(json.dumps({"policy": orgpolicy.SCHEMA, "name": "managed"}))
        names = [p.name for p, _ in orgpolicy.for_launch(str(self.local), env={})]
        self.assertEqual(["managed", "local"], names)
        names = [p.name for p, _ in orgpolicy.for_launch(None, env={orgpolicy.ENV_VAR:
                                                                    str(self.local)})]
        self.assertEqual(["managed", "local"], names)

    def test_no_managed_file_is_no_managed_policy(self) -> None:
        self.assertEqual([], orgpolicy.for_launch(None, env={}))

    def test_a_managed_file_that_cannot_be_read_refuses(self) -> None:
        self.managed.write_text("{ not json")
        with self.assertRaises(ValueError):
            orgpolicy.for_launch(None, env={})

    def test_an_inventory_reports_against_the_managed_policy_by_default(self) -> None:
        self.managed.write_text(json.dumps({"policy": orgpolicy.SCHEMA, "name": "managed"}))
        self.assertEqual("managed", orgpolicy.for_report(None, env={})[0].name)
        self.assertEqual("local", orgpolicy.for_report(str(self.local), env={})[0].name)


class TestGuardAndGatewayRefuse(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.marker = self.dir / "RAN"
        self.deny = self.dir / "deny.json"
        self.deny.write_text(json.dumps({"policy": orgpolicy.SCHEMA, "name": "no-local",
                                         "deny": [{"kind": "local", "reason": "no local"}]}))
        self.approve = self.dir / "approve.json"
        self.approve.write_text(json.dumps({"policy": orgpolicy.SCHEMA,
                                            "require": {"approved": True}}))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_wrap_refuses_before_the_process_exists(self) -> None:
        for p, extra in ((self.deny, []), (self.approve, ["--allow-unapproved"])):
            with self.subTest(policy=p.name):
                r = run_cli("wrap", "--org-policy", str(p), "--lock",
                            str(self.dir / "none.lock"), "--name", "t", *extra,
                            "--", *writer(self.marker))
                self.assertEqual(2, r.returncode, r.stderr)
                self.assertIn("organisation policy", r.stderr)
                self.assertFalse(self.marker.exists(), "the denied server ran")

    def test_an_unreadable_policy_refuses_everything(self) -> None:
        bad = self.dir / "bad.json"
        bad.write_text(json.dumps({"policy": orgpolicy.SCHEMA, "dney": []}))
        r = run_cli("wrap", "--org-policy", str(bad), "--allow-unapproved", "--name", "t",
                    "--", *writer(self.marker))
        self.assertEqual(2, r.returncode)
        self.assertIn("refusing to start anything", r.stderr)
        self.assertFalse(self.marker.exists())

    def test_a_gateway_backend_is_refused_before_it_starts(self) -> None:
        from heldfast.gateway import Backend
        argv = writer(self.marker)
        backend = Backend(spec(name="t", command=argv[0], args=argv[1:]))
        backend.org_policies = [(orgpolicy.load(self.deny), str(self.deny))]
        self.assertFalse(backend.start())
        self.assertIn("organisation policy no-local", str(backend.error))
        self.assertFalse(self.marker.exists())


# ---------------------------------------------------------------------------
# One machine


class TestDescribingAServer(unittest.TestCase):
    def test_an_endpoint_keeps_no_credential(self) -> None:
        cases = {
            "https://user:pw@mcp.example.com/sse?api_key=abc#frag": "https://mcp.example.com/sse",
            "https://actions.zapier.com/mcp/sk-ak-9f8e7d6c5b4a3f2e1d0c9b8a7/sse":
                "https://actions.zapier.com/mcp/{redacted}/sse",
            f"https://gw.example.com/{GHP}/mcp": "https://gw.example.com/{redacted}/mcp",
            "https://mcp.linear.app": "https://mcp.linear.app/",
            "http://[::1]:8080/mcp": "http://[::1]:8080/mcp",
        }
        for url, want in cases.items():
            with self.subTest(url=url):
                self.assertEqual(want, inventory.endpoint(url))

    def test_only_a_full_version_is_exact(self) -> None:
        """npm reads `pkg@1.2` as 1.2.x. Calling that pinned would count a
        floating launch towards "exact package versions"."""
        for version, eco, want in (("1.2.3", "npm", True), ("1.2", "npm", False),
                                   ("1", "npm", False), ("latest", "npm", False),
                                   ("^1.2.3", "npm", False), ("1.2.3-beta.1", "npm", True),
                                   ("==1.2.3", "pypi", True), (">=1.2", "pypi", False),
                                   ("==1.*", "pypi", False), (None, "npm", False)):
            with self.subTest(version=version):
                self.assertEqual(want, inventory.exact(version, eco))

    def test_packages_from_each_runner(self) -> None:
        cases = [
            (spec(args=["-y", "@scope/srv@2.0.1"]), ("npm", "@scope/srv", "2.0.1", True)),
            (spec(command="uvx", args=["mcp-server-fetch==2025.4.7"]),
             ("pypi", "mcp-server-fetch", "2025.4.7", True)),
            (spec(command="pnpm", args=["dlx", "pkg@1.0.0"]), ("npm", "pkg", "1.0.0", True)),
            (spec(command="deno", args=["run", "-A", "npm:pkg@1.0.0"]),
             ("npm", "pkg", "1.0.0", True)),
            (spec(args=["-y", "pkg"]), ("npm", "pkg", "", False)),
        ]
        for s, want in cases:
            with self.subTest(argv=s.argv):
                p = inventory.package_of(s)
                self.assertEqual(want, (p["ecosystem"], p["name"], p["version"], p["exact"]))
        self.assertIsNone(inventory.package_of(spec(args=["-y", "./local-server"])))
        self.assertIsNone(inventory.package_of(spec(command="node", args=["s.js"])))

    def test_a_wrapped_server_is_described_by_what_it_wraps(self) -> None:
        """Listed as `heldfast`, every wrapped server in the fleet would be one
        package used everywhere and none of the servers it enforces."""
        wrapped = spec(command="heldfast",
                       args=["wrap", "--name", "s", "--", "npx", "-y", "pkg@1.0.0"])
        facts = inventory.describe(wrapped)
        self.assertEqual("package", facts["kind"])
        self.assertEqual("pkg", facts["package"]["name"])
        self.assertEqual("npx", facts["command"])


class TestOneMachine(unittest.TestCase):
    def test_a_lock_only_server_behind_the_gateway_is_still_described(self) -> None:
        backend = spec(name="files", args=["-y", "@scope/files@1.0.0"])
        lock = Lock()
        lock.record([backend], [], [])
        gateway = spec(name="everything", command="heldfast", args=["gateway"])
        data = inventory.build(lock, [gateway], [], label="m", scope={})
        (only,) = data["servers"]
        self.assertEqual(("gateway", "@scope/files"),
                         (only["enforced"], only["package"]["name"]))
        self.assertEqual(1, data["gateways"])

    def test_the_plugin_covers_claude_code_and_nothing_else(self) -> None:
        servers = [spec(name="a"), spec(name="b", client="cursor")]
        data = inventory.build(Lock(), servers, [], label="m", scope={}, plugin=True)
        self.assertEqual({"claude-code:a": "plugin", "cursor:b": "none"},
                         {r["identity"]: r["enforced"] for r in data["servers"]})

    def test_cyclonedx_shape(self) -> None:
        servers = [spec(name="a", args=["-y", "@scope/srv@2.0.1"]),
                   spec(name="h", url="https://mcp.example.com/sse?token=x"),
                   spec(name="f", args=["-y", "floaty"])]
        bom = inventory.cyclonedx(inventory.build(Lock(), servers, [], label="m", scope={},
                                                  generated="2026-10-01T00:00:00Z"))
        self.assertEqual(("CycloneDX", "1.6"), (bom["bomFormat"], bom["specVersion"]))
        purls = sorted(c.get("purl", "") for c in bom["components"])
        self.assertEqual(["pkg:npm/%40scope/srv@2.0.1", "pkg:npm/floaty"], purls)
        self.assertEqual(["https://mcp.example.com/sse"], bom["services"][0]["endpoints"])
        self.assertRegex(bom["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")


class TestInventoryCommand(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.marker = self.dir / "LAUNCHED"
        config = {"mcpServers": {
            "gh": {"command": "npx", "args": ["-y", "pkg@1.0.0", "--api-key", SK],
                   "env": {"GITHUB_TOKEN": GHP}},
            "remote": {"url": f"https://mcp.example.com/sse?key={SK}",
                       "headers": {"Authorization": f"Bearer {GHP}"}},
            # Would leave a file behind if anything ran it.
            "trap": {"command": sys.executable,
                     "args": ["-c", f"open({str(self.marker)!r}, 'w').write('x')"]},
        }}
        (self.dir / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def inventory(self, *extra: str) -> subprocess.CompletedProcess:
        return run_cli("inventory", str(self.dir), "--no-user-configs", "--label", "m",
                       *extra)

    def test_no_credential_leaves_the_machine_in_any_format(self) -> None:
        for fmt in ("json", "cyclonedx", "text"):
            with self.subTest(format=fmt):
                r = self.inventory("-f", fmt)
                self.assertEqual(0, r.returncode, r.stderr)
                for secret in (GHP, SK, "Bearer", "api-key"):
                    self.assertNotIn(secret, r.stdout)

    def test_it_launches_nothing_and_cannot_be_asked_to(self) -> None:
        self.assertEqual(0, self.inventory("-f", "json").returncode)
        self.assertFalse(self.marker.exists(), "inventory ran a configured server")
        r = self.inventory("--probe")
        self.assertEqual(2, r.returncode, "inventory accepted --probe")
        self.assertFalse(self.marker.exists())

    def test_policy_sets_the_exit_code(self) -> None:
        strict = self.dir / "strict.json"
        strict.write_text(json.dumps({"policy": orgpolicy.SCHEMA,
                                      "deny": [{"package": "npm:pkg"}]}), encoding="utf-8")
        lenient = self.dir / "lenient.json"
        lenient.write_text(json.dumps({"policy": orgpolicy.SCHEMA}), encoding="utf-8")
        broken = self.dir / "broken.json"
        broken.write_text(json.dumps({"policy": orgpolicy.SCHEMA, "dney": []}),
                          encoding="utf-8")
        self.assertEqual(1, self.inventory("--policy", str(strict)).returncode)
        self.assertEqual(0, self.inventory("--policy", str(lenient)).returncode)
        r = self.inventory("--policy", str(broken))
        self.assertEqual(2, r.returncode)
        self.assertIn("dney", r.stderr)

    def test_the_plugin_is_read_from_the_claude_code_record(self) -> None:
        plugins = self.dir / "plugins"
        install = plugins / "cache" / "heldfast"
        (install / ".claude-plugin").mkdir(parents=True)
        (install / ".claude-plugin" / "plugin.json").write_text('{"name": "heldfast"}')
        (plugins / "installed_plugins.json").write_text(json.dumps(
            {"version": 2, "plugins": {"heldfast@heldfast": [{"installPath": str(install)}]}}))
        env = {"CLAUDE_CONFIG_DIR": str(self.dir), "HOME": str(self.dir),
               "CLAUDE_CODE_PLUGIN_CACHE_DIR": str(plugins)}
        on = run_cli("inventory", str(self.dir), "--label", "m", "-f", "json", env=env)
        self.assertTrue(json.loads(on.stdout)["plugin"], on.stderr)
        (self.dir / "settings.json").write_text(
            json.dumps({"enabledPlugins": {"heldfast@heldfast": False}}))
        off = run_cli("inventory", str(self.dir), "--label", "m", "-f", "json", env=env)
        self.assertFalse(json.loads(off.stdout)["plugin"])


# ---------------------------------------------------------------------------
# Many machines


def inv(label: str, rows: list[dict], generated: str = "2026-10-01T00:00:00Z", **extra) -> dict:
    full = []
    for r in rows:
        if isinstance(r, dict):
            r = dict(r)
            r.setdefault("findings", {"critical": 0, "high": 0, "medium": 0, "low": 0,
                                      "info": 0})
        full.append(r)
    return {"schema": inventory.SCHEMA, "label": label, "generated": generated,
            "servers": full, **extra}


NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


class FleetCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, data: object) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def load(self) -> tuple[list[dict], list[str]]:
        return fleet.load([self.dir])


class TestReadingInventories(FleetCase):
    def test_what_is_not_an_inventory_is_set_aside_with_a_note(self) -> None:
        self.write("a.json", inv("a", [row()]))
        self.write("b.json", {"schema": "something-else"})
        (self.dir / "c.json").write_text("{not json", encoding="utf-8")
        invs, notes = self.load()
        self.assertEqual(["a"], [i["label"] for i in invs])
        self.assertEqual(2, len(notes))

    def test_one_label_two_files_keeps_the_newer_and_says_so(self) -> None:
        """Otherwise one machine can claim another's name and the report
        shows only the claim."""
        self.write("x1.json", inv("same", [row()], generated="2026-10-01T00:00:00Z"))
        self.write("x2.json", inv("same", [], generated="2026-10-02T00:00:00Z"))
        invs, notes = self.load()
        self.assertEqual([[]], [i["servers"] for i in invs])
        self.assertTrue(any("two inventories call themselves 'same'" in n for n in notes))

    def test_every_field_of_a_row_is_checked(self) -> None:
        hostile = row(state="PWNED", enforced=["x"], kind={"a": 1}, tools="many",
                      package={"ecosystem": "cargo", "name": "x"})
        self.write("a.json", inv("a", [hostile, "not a row"]))
        (only,), notes = self.load()
        (r,) = only["servers"]
        self.assertEqual(("UNAPPROVED", "none", "local", 0, None),
                         (r["state"], r["enforced"], r["kind"], r["tools"], r["package"]))
        self.assertTrue(any("unreadable" in n for n in notes))


class TestNoFieldOfAnyTypeTakesTheReportDown(FleetCase):
    """A dict where a word belongs raised TypeError from a set lookup, and
    one inventory took the whole organisation's report down with it."""

    WRONG = (None, 1, 2.5, True, [], {}, ["x"], {"a": 1}, "", "<b>")

    def test_every_wrong_type_in_every_field(self) -> None:
        base = inv("m", [row(findings={"high": 1}, top_findings=[
            {"rule_id": "MCPA007", "severity": "high", "title": "t"}])],
            policy={"sha256": "a" * 64, "violations": [
                {"server": "claude-code:s", "level": "deny", "code": "c", "message": "m"}]})
        fields = [("top", k) for k in base] + [("row", k) for k in base["servers"][0]]
        for where, key in fields:
            for value in self.WRONG:
                data = json.loads(json.dumps(base))
                target = data if where == "top" else data["servers"][0]
                target[key] = value
                with self.subTest(field=f"{where}.{key}", value=value):
                    self.write("m.json", data)
                    invs, notes = self.load()
                    report = fleet.build(invs, now=NOW, notes=notes,
                                         policy=policy(require={"fail_on": "low"}))
                    render_html(report)
                    fleet.render(report, color=False)

    def test_json_nested_past_the_stack_is_set_aside(self) -> None:
        (self.dir / "deep.json").write_text("[" * 200000, encoding="utf-8")
        invs, notes = self.load()
        self.assertEqual([], invs)
        self.assertTrue(any("RecursionError" in n for n in notes), notes)


class TestTheReport(FleetCase):
    def report(self, **kw) -> dict:
        invs, notes = self.load()
        return fleet.build(invs, now=NOW, notes=notes, **kw)

    def test_counts_versions_and_floating(self) -> None:
        floating = {"ecosystem": "npm", "name": "pkg", "version": "latest", "exact": False}
        self.write("a.json", inv("a", [row()]))
        self.write("b.json", inv("b", [row(package=dict(row()["package"], version="1.1.0"))]))
        self.write("c.json", inv("c", [row(package=floating, state="UNAPPROVED",
                                           enforced="none")]))
        report = self.report()
        (entry,) = report["servers"]
        self.assertEqual(({"1.0.0": 1, "1.1.0": 1, "(floating)": 1}, 1, ["a", "b", "c"]),
                         (entry["versions"], entry["floating"], entry["machines"]))
        t = report["totals"]
        self.assertEqual((3, 2, 2, 2, 3), (t["installs"], t["approved"], t["enforced"],
                                           t["exact"], t["packages"]))

    def test_a_given_policy_replaces_what_each_machine_reported(self) -> None:
        reported = {"sha256": "a" * 64, "violations": [
            {"server": "claude-code:s", "level": "deny", "code": "denied", "message": "old"}]}
        self.write("a.json", inv("a", [row()], policy=reported))
        self.assertEqual(1, self.report()["totals"]["deny"])
        self.assertEqual(0, self.report(policy=policy())["totals"]["deny"])

    def test_machines_checked_against_different_policies_are_noted(self) -> None:
        self.write("a.json", inv("a", [row()], policy={"sha256": "a" * 64, "violations": []}))
        self.write("b.json", inv("b", [row()], policy={"sha256": "b" * 64, "violations": []}))
        self.assertTrue(any("2 different policies" in n for n in self.report()["notes"]))

    def test_an_old_inventory_is_stale(self) -> None:
        self.write("a.json", inv("a", [row()], generated="2026-09-01T00:00:00Z"))
        self.write("b.json", inv("b", [row()], generated="2026-10-02T00:00:00Z"))
        stale = {h["label"]: h["stale"] for h in self.report(max_age=14)["machines"]}
        self.assertEqual({"a": True, "b": False}, stale)


class TestAdvisories(FleetCase):
    def setUp(self) -> None:
        super().setUp()
        self._post = advisories.post_json
        self.write("a.json", inv("a", [row(package={"ecosystem": "npm", "name": "postmark-mcp",
                                                    "version": "1.0.16", "exact": True})]))
        self.write("b.json", inv("b", [row()]))

    def tearDown(self) -> None:
        advisories.post_json = self._post
        super().tearDown()

    def test_malware_names_every_machine_that_runs_it(self) -> None:
        asked = []

        def fake(url: str, body: dict) -> dict:
            asked.extend(body["queries"])
            return {"results": [{"vulns": [{"id": "MAL-2025-1"}]}
                                if q["package"]["name"] == "postmark-mcp" else {}
                                for q in body["queries"]]}
        advisories.post_json = fake
        invs, _ = self.load()
        found, error = fleet.ask_osv(invs)
        report = fleet.build(invs, advisories=found, advisory_error=error, now=NOW)
        self.assertEqual([{"release": "npm:postmark-mcp@1.0.16", "ids": ["MAL-2025-1"],
                           "machines": ["a"]}], report["alarms"])
        self.assertTrue(fleet.failed(report))
        # Package names and versions, and nothing about the machines.
        self.assertNotIn("a", json.dumps([q["package"]["name"] for q in asked]).split('"'))
        self.assertEqual({"name", "ecosystem"}, set(asked[0]["package"]))

    def test_an_unanswered_lookup_is_never_an_all_clear(self) -> None:
        def broken(url: str, body: dict) -> dict:
            raise advisories.AdvisoryError("403 Forbidden")
        advisories.post_json = broken
        invs, _ = self.load()
        found, error = fleet.ask_osv(invs)
        self.assertEqual(({}, "403 Forbidden"), (found, error))
        report = fleet.build(invs, advisories=None, advisory_error=error, now=NOW)
        self.assertEqual("failed", report["advisories"])
        page = render_html(report)
        self.assertNotIn("Running malware", page)
        self.assertIn("could not be asked", page)
        self.assertIn("could not be asked", fleet.render(report, color=False))


class TestTheCommand(FleetCase):
    def test_exit_codes(self) -> None:
        self.write("a.json", inv("a", [row()]))
        deny = self.write("deny.json", {"policy": orgpolicy.SCHEMA,
                                        "deny": [{"package": "npm:pkg"}]})
        ok = self.write("ok.json", {"policy": orgpolicy.SCHEMA})
        inventories = self.dir / "inv"
        inventories.mkdir()
        (self.dir / "a.json").rename(inventories / "a.json")
        self.assertEqual(1, run_cli("fleet", str(inventories), "--policy", str(deny)).returncode)
        self.assertEqual(0, run_cli("fleet", str(inventories), "--policy", str(ok)).returncode)
        empty = self.dir / "empty"
        empty.mkdir()
        self.assertEqual(2, run_cli("fleet", str(empty)).returncode)

    def test_inventory_then_fleet_end_to_end(self) -> None:
        machine = self.dir / "machine"
        machine.mkdir()
        (machine / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "files": {"command": "npx", "args": ["-y", "@scope/files@1.0.0"]}}}))
        out = self.dir / "collected" / "m.json"
        out.parent.mkdir()
        r = run_cli("inventory", str(machine), "--no-user-configs", "--label", "m",
                    "-f", "json", "-o", str(out))
        self.assertEqual(0, r.returncode, r.stderr)
        report = json.loads(run_cli("fleet", str(out.parent), "-f", "json").stdout)
        self.assertEqual(["npm:@scope/files"], [s["key"] for s in report["servers"]])
        self.assertEqual(1, report["totals"]["installs"])


class TestTheHtmlCannotBeRewrittenByWhatItReports(FleetCase):
    """Every name on the page came from a config on some machine, and the
    page is opened by the people the security team reports to."""

    def test_hostile_names_are_escaped_and_no_script_can_run(self) -> None:
        evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
        self.write("a.json", inv(evil, [row(identity=evil, name=evil, kind="hosted",
                                            package=None, endpoint=f"https://x.example/{evil}")]))
        invs, notes = self.load()
        page = render_html(fleet.build(invs, now=NOW, notes=notes + [evil],
                                       policy=policy(deny=[{"kind": "hosted",
                                                            "reason": evil}])))
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("<img", page.lower())
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("script-src", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
