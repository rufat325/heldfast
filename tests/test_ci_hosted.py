"""CI reads hosted servers by default, and says what it did not check.

`heldfast ci` never probes and the Action probed only when asked, so a hosted
tool rewritten since approval passed CI while the README said CI caught it.
Reading a hosted server's tool list runs none of its code, so the Action now
does it by default (`scan --probe --no-stdio-probe`). A server that cannot be
read -- it wants a login -- is reported as not verified and fails only under
`--require-probe`. The stub in tests/fixtures/http_server.py stands in for
the server.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

import http_server  # noqa: E402
from heldfast.cli import main  # noqa: E402
from heldfast.report.probe_summary import summary  # noqa: E402

# What the Action runs with its defaults (probe-hosted: true, probe: false).
ACTION = ["--probe", "--no-stdio-probe", "--no-user-configs", "--no-skills"]


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestHostedInCi(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tree = Path(self._tmp.name)
        served = http_server.serve("benign")
        self.url = served.__enter__()
        self.addCleanup(served.__exit__, None, None, None)
        (self.tree / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "invoices": {"type": "http", "url": self.url},
            "files": {"command": "node", "args": ["server.js"]}}}), encoding="utf-8")
        code, _, err = run("approve", str(self.tree), "--probe", "--no-stdio-probe",
                           "--no-user-configs", "--no-skills")
        self.assertEqual(0, code, err)

    def scan(self, *extra: str) -> tuple[int, dict, str]:
        code, out, err = run("scan", str(self.tree), *ACTION, "--format", "json", *extra)
        return code, json.loads(out), err

    def coverage(self, report: dict) -> dict:
        return {p["server"]: p for p in report["probe"]}

    def test_a_rewritten_hosted_tool_fails_with_the_default_inputs(self) -> None:
        http_server.set_mode("poisoned")
        code, report, _ = self.scan()
        self.assertEqual(1, code)
        self.assertIn("MCPA015", {f["rule_id"] for f in report["findings"]})
        self.assertEqual("read", self.coverage(report)["claude-code:invoices"]["state"])

    def test_nothing_is_launched(self) -> None:
        _, report, err = self.scan()
        self.assertNotIn("launches these servers", err)
        files = self.coverage(report)["claude-code:files"]
        self.assertEqual(("stdio", "not read"), (files["transport"], files["state"]))

    def test_a_server_behind_a_login_is_not_verified_and_does_not_fail(self) -> None:
        http_server.set_require_auth(True)
        code, report, _ = self.scan()
        self.assertEqual(0, code)
        invoices = self.coverage(report)["claude-code:invoices"]
        self.assertEqual("could not read", invoices["state"])
        self.assertIn("401", invoices["detail"])

    def test_require_probe_fails_it(self) -> None:
        http_server.set_require_auth(True)
        code, _, err = self.scan("--require-probe")
        self.assertEqual(1, code)
        self.assertIn("could not read claude-code:invoices", err)

    def test_the_text_report_does_not_call_it_clean(self) -> None:
        http_server.set_require_auth(True)
        _, out, _ = run("scan", str(self.tree), *ACTION)
        self.assertIn("could not verify claude-code:invoices", out)
        self.assertNotIn("parse error", out)
        self.assertIn("1 server(s) could not be read", out)
        self.assertNotRegex(out, r"(?m)^\s*clean\s*$")

    def test_the_summary_lists_both(self) -> None:
        http_server.set_require_auth(True)
        _, report, _ = self.scan()
        line = summary(report)
        self.assertIn("Tool definitions checked: none.", line)
        self.assertIn("1 hosted server (could not read: HTTP 401", line)
        self.assertIn("1 stdio server (probe is off for stdio servers", line)

    def test_without_probe_nothing_was_read_and_it_says_so(self) -> None:
        code, out, _ = run("scan", str(self.tree), "--no-user-configs", "--no-skills",
                           "--format", "json")
        report = json.loads(out)
        self.assertEqual({"not read"}, {p["state"] for p in report["probe"]})
        self.assertIn("probe is off", summary(report))


class TestTheSummaryLine(unittest.TestCase):
    def test_the_shape_the_job_summary_prints(self) -> None:
        rows = ([{"transport": "hosted", "state": "read", "detail": ""}] * 3
                + [{"transport": "stdio", "state": "not read", "detail": "probe is off"}] * 2
                + [{"transport": "hosted", "state": "could not read", "detail": "HTTP 401"}])
        self.assertEqual(
            "Tool definitions checked: 3 hosted servers. Not checked: 1 hosted server "
            "(could not read: HTTP 401), 2 stdio servers (probe is off).",
            summary({"probe": rows}))

    def test_no_servers(self) -> None:
        self.assertIn("none", summary({"probe": []}))


if __name__ == "__main__":
    unittest.main()
