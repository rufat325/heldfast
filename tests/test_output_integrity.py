"""A name in a config must not be able to edit the report about it.

Every page this tool prints -- the scan report, `status`, `coverage`, `report`
-- exists to show an operator the truth. Every one of them interpolates names
that came out of a config file, and a config file is the thing people paste
out of a README.

So a server called

    notes\\rok          claude-code:evil    9 tool(s)

rendered as a line whose carriage return returns the cursor to column zero and
overwrites everything before it. The operator saw `ok  claude-code:evil` and
the real verdict was gone. `\\x1b[2K\\x1b[1A` is worse: it erases the line
*above*, so one hostile entry could delete a different server's finding from
the page.

`Finding.__post_init__` was already the chokepoint for keeping secrets out of
a report. It is now the chokepoint for keeping the report readable too, which
is the same idea pointed at a different attack on the same reader: a secret in
the output is a leak, a control character in it is a forgery.

Escaped rather than stripped, because a name containing a control character is
itself worth seeing.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_audit import coverage as coverage_mod  # noqa: E402
from mcp_audit import sessions, status as status_mod  # noqa: E402
from mcp_audit.auditlog import AuditLog  # noqa: E402
from mcp_audit.findings import Finding, Location, Severity  # noqa: E402
from mcp_audit.lockfile import Lock  # noqa: E402
from mcp_audit.model import ServerSpec, ToolSpec  # noqa: E402
from mcp_audit.report import render_terminal  # noqa: E402
from mcp_audit.secrets import safe_name, safe_text  # noqa: E402

# Each of these does something to a terminal that the text around it did not
# ask for.
PAYLOADS = {
    "carriage return": "notes\rok          claude-code:evil    9 tool(s)",
    "newline": "notes\n  ok          claude-code:evil    9 tool(s)",
    "erase line and move up": "notes\x1b[2K\x1b[1A",
    "recolour the rest": "notes\x1b[32m all clear \x1b[0m",
    "backspace over it": "notes" + "\b" * 12 + "safe",
    "vertical tab": "notes\vevil",
    "form feed": "notes\fevil",
    "del": "notes\x7fevil",
    "c1 control": "notes\x9bevil",
}


def controls(text: str) -> list:
    """Control characters that survived into a rendered page.

    Newline is allowed in a page -- the renderer writes them -- so it is
    checked separately, on the fields where it would forge a row.
    """
    return sorted({repr(c) for c in text if ord(c) < 32 and c != "\n"}
                  | {repr(c) for c in text if "\x7f" <= c <= "\x9f"})


def spec(name: str) -> ServerSpec:
    return ServerSpec(name=name, source="/p/.mcp.json", client="claude-code",
                      transport="stdio", command="node", args=["s.js"])


class TestTheSanitizer(unittest.TestCase):
    def test_it_escapes_rather_than_drops(self) -> None:
        """A name carrying a control character is itself a thing to notice."""
        self.assertEqual("notes\\x0dok", safe_name("notes\rok"))
        self.assertIn("\\x1b", safe_name("notes\x1b[2K"))

    def test_ordinary_text_is_untouched(self) -> None:
        for text in ("github", "claude-code:notes", "read_invoice",
                     "@scope/server-github@1.2.3", "a-b_c.d"):
            with self.subTest(text=text):
                self.assertEqual(text, safe_name(text))

    def test_evidence_keeps_its_newlines(self) -> None:
        """MCPA015 prints `was:` and `now:` on their own lines, so the
        multi-line form has to survive."""
        self.assertEqual("was: a\nnow: b", safe_text("was: a\nnow: b"))

    def test_a_name_does_not(self) -> None:
        """A newline in a *name* forges a whole row in the table it lands in,
        which is the carriage return with none of the subtlety."""
        self.assertEqual("notes\\nevil", safe_name("notes\nevil"))

    def test_tabs_survive(self) -> None:
        self.assertEqual("a\tb", safe_text("a\tb"))

    def test_absurd_length_is_bounded(self) -> None:
        self.assertLessEqual(len(safe_name("x" * 10000)), 400)


class TestTheFindingChokepoint(unittest.TestCase):
    """The same single point that already keeps secrets out."""

    def _finding(self, payload: str) -> Finding:
        return Finding(
            rule_id="MCPA010", title=f"title {payload}", severity=Severity.HIGH,
            location=Location(path="/p/.mcp.json", line=1, snippet=payload),
            evidence=f"server {payload} said something",
            remediation=f"fix {payload}", server=payload)

    def test_every_field_that_reaches_a_report(self) -> None:
        for label, payload in PAYLOADS.items():
            with self.subTest(payload=label):
                f = self._finding(payload)
                blob = (f.title + f.evidence + f.remediation
                        + (f.server or "") + f.location.snippet)
                self.assertEqual([], controls(blob))

    def test_a_name_cannot_forge_a_row(self) -> None:
        f = self._finding(PAYLOADS["newline"])
        self.assertNotIn("\n", f.server or "")
        self.assertNotIn("\n", f.location.snippet)

    def test_secrets_are_still_redacted(self) -> None:
        """Adding one scrub must not replace the other."""
        token = "ghp_" + "A" * 36
        f = Finding(rule_id="MCPA005", title="t", severity=Severity.HIGH,
                    location=Location(path="/p", line=1), evidence=f"saw {token}",
                    remediation="r")
        self.assertNotIn(token, f.evidence)


class TestEveryPage(unittest.TestCase):
    """The renderers, driven with a hostile name end to end."""

    def _status(self, name: str) -> str:
        lock = Lock()
        lock.record([spec(name)],
                    [ToolSpec(server=name, name="read", description="Reads.")], [])
        return status_mod.render(status_mod.build(lock, [spec(name)], []), color=False)

    def _coverage(self, name: str) -> str:
        lock = Lock()
        lock.record([spec(name)], [], [])
        return coverage_mod.render(coverage_mod.build(lock, [spec(name)]), color=False)

    def _scan(self, name: str) -> str:
        f = Finding(rule_id="MCPA010", title="Agent-directed instruction",
                    severity=Severity.HIGH,
                    location=Location(path="/p/.mcp.json", line=1, snippet=name),
                    evidence=f"server {name} said something",
                    remediation="r", server=name)
        return render_terminal([f], color=False)

    def _report(self, name: str) -> str:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trail.jsonl"
            trail = AuditLog(path, "gateway")
            trail.record("session_start", subject=name)
            trail.record("request", subject=name)
            trail.record("backend_failed", subject=name, detail=name)
            trail.record("session_end", detail=name)
            return sessions.render(sessions.build(path), color=False)

    def test_no_page_can_be_rewritten_by_a_name(self) -> None:
        for label, payload in PAYLOADS.items():
            for page, render in (("status", self._status),
                                 ("coverage", self._coverage),
                                 ("scan", self._scan),
                                 ("report", self._report)):
                with self.subTest(page=page, payload=label):
                    self.assertEqual([], controls(render(payload)))

    def test_the_verdict_survives_beside_a_hostile_name(self) -> None:
        """The point of the whole exercise: the operator still sees the word
        that matters, on the same line, rather than whatever overwrote it.

        The payload spells out a *forged* row -- `ok  claude-code:evil` -- so
        the test checks that the real state word still leads the line and the
        forgery is visibly escaped rather than rendered.
        """
        text = self._status(PAYLOADS["carriage return"])
        row = next(l for l in text.splitlines() if "claude-code:notes" in l)
        self.assertTrue(row.strip().startswith("ok "), row)
        self.assertIn("\\x0d", row)
        self.assertNotIn("\r", row)

    def test_a_hostile_name_cannot_erase_another_servers_finding(self) -> None:
        """`\\x1b[2K\\x1b[1A` clears the current line and moves up one. Two
        servers on one page means one could delete the other's row."""
        lock = Lock()
        victim, attacker = spec("github"), spec("notes\x1b[2K\x1b[1A")
        lock.record([victim, attacker], [], [])
        text = status_mod.render(
            status_mod.build(lock, [victim, attacker], []), color=False)
        self.assertIn("claude-code:github", text)
        self.assertEqual([], controls(text))


if __name__ == "__main__":
    unittest.main(verbosity=2)
