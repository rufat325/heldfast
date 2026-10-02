"""research/feed/profile_index.py: the feed's record, read by a second digest.

It reads a checkout and writes nothing inside it, so the first thing the
tests below pin is that a checkout is byte for byte what it was. The rest is
what a person comparing two records asks of it: which definitions have this
profile digest, and when did the record first and last show them.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "research" / "feed"))

import profile_index  # noqa: E402
import watch  # noqa: E402
from heldfast.profiles import agentavow_v1_digest  # noqa: E402

APPROVED = "Read an invoice by its identifier and return the parsed fields."
REWORDED = "Read one invoice by its identifier and return the parsed fields."


def tool(name: str, description: str, **more: object) -> dict:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object"}, **more}


def run(*argv: str) -> tuple:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = profile_index.main(list(argv))
        except SystemExit as exc:  # argparse
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def tree(folder: str) -> dict:
    """Every path under `folder` with its bytes' hash and its mtime."""
    seen = {}
    for base, dirs, files in os.walk(folder):
        for name in dirs + files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, folder)
            if os.path.isfile(full):
                with open(full, "rb") as fh:
                    seen[rel] = (hashlib.sha256(fh.read()).hexdigest(),
                                 os.stat(full).st_mtime_ns)
            else:
                seen[rel] = None
    return seen


class Feed(unittest.TestCase):
    PKG = "pkg"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heldfast-profile-")
        self.addCleanup(self._tmp.cleanup)
        self.base = self._tmp.name
        self.data = os.path.join(self.base, "feed")
        self.outside = os.path.join(self.base, "elsewhere")
        os.makedirs(self.data)
        self.approved = tool("read", APPROVED)
        self.reworded = tool("read", REWORDED)
        # approved, reworded, approved again: three readings, two definitions.
        for version, day, definition in (("1.0.1", "01", self.approved),
                                         ("1.0.2", "02", self.reworded),
                                         ("1.0.3", "03", self.approved)):
            self.write(version, day, definition, tool("list", "List invoices."))

    def write(self, version: str, day: str, *tools: dict, package: str = "pkg") -> None:
        snap = watch.snapshot(package, version, f"2026-09-{day}T00:00:00Z", list(tools))
        watch.write_catalogue(self.data, snap, [], measured_at=f"2026-09-{day}T06:00:00Z")

    def legacy(self, version: str, day: str, *tools: dict) -> None:
        path = watch.catalogue_path(self.data, self.PKG, version, legacy=True)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        body = {"package": self.PKG, "version": version, "tools": list(tools),
                "measured_at": f"2026-08-{day}T06:00:00Z"}
        with open(path, "wb") as fh:
            fh.write(gzip.compress(json.dumps(body).encode("utf-8")))


class TestLookup(Feed):
    def test_finds_the_tool_file_by_its_profile_digest(self) -> None:
        wanted = agentavow_v1_digest(self.approved)
        code, out, _ = run("--data", self.data, "--lookup", wanted)
        native = watch.tool_digest(self.approved)
        self.assertEqual(0, code)
        self.assertIn(f"{native}  tools/{native[:2]}/{native}.json  \"read\"", out)
        self.assertIn("1 tool file(s)", out)

    def test_the_digest_may_be_hex_alone_or_upper_case(self) -> None:
        wanted = (agentavow_v1_digest(self.reworded) or "")
        for spelling in (wanted.split(":")[1], wanted.upper().replace("SHA256:", "sha256:")):
            with self.subTest(spelling=spelling[:12]):
                self.assertEqual(0, run("--data", self.data, "--lookup", spelling)[0])

    def test_a_digest_nothing_has_is_not_found(self) -> None:
        code, out, _ = run("--data", self.data, "--lookup", "sha256:" + "0" * 64)
        self.assertEqual(1, code)
        self.assertIn("0 tool file(s)", out)

    def test_the_native_digest_is_not_a_profile_digest(self) -> None:
        native = watch.tool_digest(self.approved)
        self.assertEqual(1, run("--data", self.data, "--lookup", native)[0])

    def test_a_malformed_digest_is_a_usage_error(self) -> None:
        for bad in ("sha256:abc", "xyz", "", "sha256:" + "g" * 64):
            with self.subTest(bad=bad):
                self.assertEqual(2, run("--data", self.data, "--lookup", bad)[0])


class TestCheck(Feed):
    def check(self, definition: dict, name: str = "read", package: str = "pkg") -> tuple:
        return run("--data", self.data, "--check", package, name,
                   agentavow_v1_digest(definition) or "")

    def test_lists_the_readings_with_first_and_last_seen(self) -> None:
        code, out, _ = self.check(self.approved)
        self.assertEqual(0, code)
        self.assertIn("3 reading(s), 2 with", out)
        self.assertIn("first seen 2026-09-01T06:00:00Z  (1.0.1)", out)
        self.assertIn("last seen  2026-09-03T06:00:00Z  (1.0.3)", out)
        self.assertNotIn("1.0.2", out)
        lines = [line for line in out.splitlines() if line.startswith("  2026")]
        self.assertEqual(["1.0.1", "1.0.3"], [line.split()[1] for line in lines])

    def test_a_definition_shown_once_has_one_reading(self) -> None:
        code, out, _ = self.check(self.reworded)
        self.assertEqual(0, code)
        self.assertIn("first seen 2026-09-02T06:00:00Z  (1.0.2)", out)
        self.assertIn("last seen  2026-09-02T06:00:00Z  (1.0.2)", out)

    def test_an_unchanged_tool_is_read_in_every_catalogue(self) -> None:
        code, out, _ = self.check(tool("list", "List invoices."), name="list")
        self.assertEqual(0, code)
        self.assertIn("3 reading(s), 3 with", out)

    def test_a_digest_the_tool_never_had_says_what_it_did_have(self) -> None:
        code, out, _ = run("--data", self.data, "--check", "pkg", "read", "sha256:" + "0" * 64)
        self.assertEqual(1, code)
        self.assertIn("3 reading(s), 0 with", out)
        self.assertIn(agentavow_v1_digest(self.approved) or "?", out)
        self.assertIn(agentavow_v1_digest(self.reworded) or "?", out)
        self.assertIn("2 reading(s), 2026-09-01T06:00:00Z to 2026-09-03T06:00:00Z", out)

    def test_a_tool_the_record_never_listed_is_not_found(self) -> None:
        code, out, _ = self.check(self.approved, name="delete")
        self.assertEqual(1, code)
        self.assertIn("no reading of this tool", out)

    def test_a_server_the_record_does_not_hold_is_not_found(self) -> None:
        self.assertEqual(1, self.check(self.approved, package="other")[0])

    def test_a_package_name_outside_what_the_feed_stores_is_a_usage_error(self) -> None:
        code, _, err = self.check(self.approved, package="../etc")
        self.assertEqual(2, code)
        self.assertIn("outside the safe set", err)

    def test_the_first_layout_carries_its_own_definition_per_reading(self) -> None:
        older = tool("read", "Read an invoice.")
        self.legacy("0.9.0", "01", older)
        code, out, _ = self.check(older)
        self.assertEqual(0, code)
        self.assertIn("4 reading(s), 1 with", out)
        self.assertIn("first seen 2026-08-01T06:00:00Z  (0.9.0)", out)

    def test_the_package_must_say_it_is_the_package_asked_about(self) -> None:
        """A catalogue's own `package` field decides, not only where it sits."""
        path = os.path.join(self.data, "catalogues", "pkg", "1.0.1.json")
        with open(path, encoding="utf-8") as fh:
            body = json.load(fh)
        body["package"] = "someone-else"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
        self.assertIn("2 reading(s)", self.check(self.approved)[1])

    def test_a_name_that_cannot_be_printed_is_printed_as_ascii(self) -> None:
        hostile = tool("a\ud800\U0001F600", "odd")
        self.write("2.0.0", "04", hostile)
        code, out, _ = self.check(hostile, name="a\ud800\U0001F600")
        self.assertEqual(0, code)
        self.assertTrue(out.isascii(), out)

    def test_the_wire_object_is_what_is_hashed(self) -> None:
        """`_meta` is stored in tools/ and never reaches the profile digest."""
        with_meta = tool("read", APPROVED, _meta={"x": 1})
        self.write("2.0.0", "04", with_meta)
        code, out, _ = self.check(self.approved)
        self.assertEqual(0, code)
        self.assertIn("4 reading(s), 3 with", out)


class TestIndex(Feed):
    def test_writes_the_map_outside_the_checkout(self) -> None:
        out = os.path.join(self.outside, "map.json")
        code, _, err = run("--data", self.data, "--index", out)
        self.assertEqual(0, code)
        self.assertIn("wrote 3 native-to-profile pair(s)", err)
        with open(out, encoding="utf-8") as fh:
            body = json.load(fh)
        self.assertEqual("agentavow.mcp-tool-definition.v1", body["profile"])
        for definition in (self.approved, self.reworded, tool("list", "List invoices.")):
            self.assertEqual(agentavow_v1_digest(definition),
                             body["tools"][watch.tool_digest(definition)])

    def test_the_same_checkout_gives_the_same_bytes(self) -> None:
        one, two = (os.path.join(self.outside, n) for n in ("one.json", "two.json"))
        run("--data", self.data, "--index", one)
        run("--data", self.data, "--index", two)
        self.assertEqual(Path(one).read_bytes(), Path(two).read_bytes())

    def test_refuses_to_write_inside_the_checkout(self) -> None:
        for out in (os.path.join(self.data, "map.json"),
                    os.path.join(self.data, "tools", "map.json"),
                    os.path.join(self.data, "new", "deeper", "map.json"),
                    os.path.join(self.data, "..", "feed", "map.json")):
            with self.subTest(out=out):
                before = tree(self.data)
                code, _, err = run("--data", self.data, "--index", out)
                self.assertEqual(2, code)
                self.assertIn("never writes into a feed checkout", err)
                self.assertEqual(before, tree(self.data))

    def test_a_folder_named_like_the_checkout_but_beside_it_is_outside(self) -> None:
        beside = self.data + "-copy"
        code, _, _ = run("--data", self.data, "--index", os.path.join(beside, "map.json"))
        self.assertEqual(0, code)

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "needs symlinks")
    def test_a_link_into_the_checkout_does_not_get_round_the_refusal(self) -> None:
        link = os.path.join(self.base, "link")
        os.symlink(self.data, link)
        before = tree(self.data)
        code, _, _ = run("--data", self.data, "--index", os.path.join(link, "map.json"))
        self.assertEqual(2, code)
        self.assertEqual(before, tree(self.data))

    def test_a_tool_file_that_is_not_json_is_counted_not_fatal(self) -> None:
        bad = os.path.join(self.data, "tools", "ab", "ab" + "0" * 62 + ".json")
        os.makedirs(os.path.dirname(bad), exist_ok=True)
        Path(bad).write_text("{not json", encoding="utf-8")
        code, _, err = run("--data", self.data, "--index", os.path.join(self.outside, "m.json"))
        self.assertEqual(0, code)
        self.assertIn("wrote 3 native-to-profile pair(s)", err)
        self.assertIn("1 tool file(s) had no profile digest", err)

    def test_a_definition_no_profile_digest_can_be_built_for_is_left_out(self) -> None:
        odd = tool("odd", "x", outputSchema={"n": 10 ** 400})  # JSON has no such number
        path = os.path.join(self.data, "tools", "cd", "cd" + "1" * 62 + ".json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_text(json.dumps(odd), encoding="utf-8")
        out = os.path.join(self.outside, "m.json")
        code, _, err = run("--data", self.data, "--index", out)
        self.assertEqual(0, code)
        self.assertIn("1 tool file(s) had no profile digest", err)
        self.assertNotIn("cd" + "1" * 62, Path(out).read_text(encoding="utf-8"))


class TestReadOnly(Feed):
    def test_no_command_changes_the_checkout(self) -> None:
        self.legacy("0.9.0", "01", tool("read", "Read an invoice."))
        before = tree(self.data)
        wanted = agentavow_v1_digest(self.approved) or ""
        run("--data", self.data, "--lookup", wanted)
        run("--data", self.data, "--check", "pkg", "read", wanted)
        run("--data", self.data, "--check", "pkg", "read", "sha256:" + "0" * 64)
        run("--data", self.data, "--index", os.path.join(self.outside, "m.json"))
        self.assertEqual(before, tree(self.data))

    def test_the_checkout_still_verifies_afterwards(self) -> None:
        run("--data", self.data, "--index", os.path.join(self.outside, "m.json"))
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = watch.verify(type("A", (), {"data": self.data, "complete": True})())
        self.assertEqual(0, code)

    def test_a_folder_that_is_not_a_feed_is_refused(self) -> None:
        empty = os.path.join(self.base, "empty")
        os.makedirs(empty)
        for action in (["--lookup", "sha256:" + "0" * 64], ["--check", "p", "t", "0" * 64],
                       ["--index", os.path.join(self.outside, "m.json")]):
            with self.subTest(action=action[0]):
                code, _, err = run("--data", empty, *action)
                self.assertEqual(2, code)
                self.assertIn("not a feed checkout", err)
        self.assertFalse(os.path.exists(os.path.join(self.outside, "m.json")))

    def test_one_action_is_required(self) -> None:
        self.assertEqual(2, run("--data", self.data)[0])


class TestAudit(Feed):
    """The two figures docs/TRANSPARENCY.md states, from the files themselves."""

    def audit(self) -> tuple:
        return run("--data", self.data, "--audit")

    def test_counts_the_shape_class_and_the_digests_that_split(self) -> None:
        # Same native digest as `read`'s file, a different profile digest: a
        # title of "" and no title fold together natively and not here.
        plain = tool("t", "d")
        titled = tool("t", "d", title="")
        self.assertEqual(watch.tool_digest(plain), watch.tool_digest(titled))
        self.assertNotEqual(agentavow_v1_digest(plain), agentavow_v1_digest(titled))
        self.write("2.0.0", "04", plain)
        self.legacy("0.9.0", "01", titled)
        code, out, _ = self.audit()
        self.assertEqual(1, code)
        self.assertIn("native digests: 4; with more than one profile digest: 1", out)
        self.assertIn("tool files read: 4 (0 unreadable, 0 with no profile digest)", out)
        # Only `plain`'s own file is read: nothing in it is in a folded shape.
        self.assertIn("shape class: 0 of 4 (0.000%)", out)

    def test_a_clean_record_passes(self) -> None:
        code, out, _ = self.audit()
        self.assertEqual(0, code)
        self.assertIn("native digests: 3; with more than one profile digest: 0", out)

    def test_the_shape_class_names_the_fields(self) -> None:
        self.write("2.0.0", "04",
                   tool("a", "d", title="", outputSchema={}, annotations=None),
                   tool("b", ""),
                   tool("c", "d", outputSchema={"type": "object"}))
        code, out, _ = self.audit()
        self.assertEqual(0, code)
        self.assertIn("shape class: 2 of 6 (33.333%)", out)
        self.assertIn("title 1, description 1, outputSchema 1, annotations 1", out)

    def test_each_folded_form_is_in_the_class(self) -> None:
        for field, value in (("title", None), ("title", ""), ("title", 5),
                             ("description", ""), ("inputSchema", {}),
                             ("inputSchema", []), ("outputSchema", None),
                             ("annotations", {}), ("annotations", "x")):
            with self.subTest(field=field, value=value):
                self.assertTrue(profile_index._folded(field, value))
        for field, value in (("title", "T"), ("description", "d"),
                             ("inputSchema", {"type": "object"}),
                             ("outputSchema", {"a": 1}), ("annotations", {"a": 1})):
            with self.subTest(field=field, value=value):
                self.assertFalse(profile_index._folded(field, value))

    def test_a_missing_field_is_not_in_the_class(self) -> None:
        """Absent is the common case; the class is the shapes that are present."""
        self.assertEqual(0, profile_index.audit(self.data, "agentavow.mcp-tool-definition.v1")["folded"])

    def test_a_version_held_in_both_layouts_is_read_as_the_current_one(self) -> None:
        """The collector's reader prefers the plain catalogue, so the gzipped
        copy is not a reading of its own."""
        self.legacy("1.0.1", "01", tool("read", APPROVED, title=""))
        self.assertIn("readings kept whole by 0 first-layout catalogues: 0",
                      self.audit()[1])

    def test_the_same_checkout_gives_the_same_report(self) -> None:
        self.legacy("0.9.0", "01", tool("read", "Read an invoice."))
        self.assertEqual(self.audit(), self.audit())

    def test_it_changes_nothing_in_the_checkout(self) -> None:
        self.legacy("0.9.0", "01", tool("read", "Read an invoice."))
        before = tree(self.data)
        self.audit()
        self.assertEqual(before, tree(self.data))

    def test_an_unreadable_file_is_counted_not_fatal(self) -> None:
        bad = os.path.join(self.data, "tools", "ab", "ab" + "0" * 62 + ".json")
        os.makedirs(os.path.dirname(bad), exist_ok=True)
        Path(bad).write_text("{not json", encoding="utf-8")
        legacy = watch.catalogue_path(self.data, self.PKG, "0.8.0", legacy=True)
        os.makedirs(os.path.dirname(legacy), exist_ok=True)
        Path(legacy).write_bytes(b"not gzip")
        code, out, _ = self.audit()
        self.assertEqual(0, code)
        self.assertIn("(1 unreadable,", out)
        self.assertIn("(1 catalogues unreadable)", out)


if __name__ == "__main__":
    unittest.main()
