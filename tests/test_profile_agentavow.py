"""The `agentavow.mcp-tool-definition.v1` profile, beside the native digest.

Every case below is written by hand from the profile's rules. The expected
preimages are literal strings hashed with `hashlib`, so nothing here is
computed by the function under test, and nothing is copied from AgentAvow's
repository, which is source-available and not licensed for that.

`TestConformance` is the one place their published vectors are used, and only
from a directory the person running the suite names in
`AGENTAVOW_VECTORS_DIR`. Unset, it is skipped, and CI never sets it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest
from collections import UserDict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast.digest import tool_digest  # noqa: E402
from heldfast.profiles import (  # noqa: E402
    PROFILE_AGENTAVOW_V1,
    agentavow_v1_digest,
    agentavow_v1_key,
)

LABEL = "agentavow.mcp-tool-definition.v1"


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestDigest(unittest.TestCase):
    def test_the_label_is_the_published_one(self) -> None:
        self.assertEqual(LABEL, PROFILE_AGENTAVOW_V1)

    def test_preimage_is_the_label_and_the_tool_in_canonical_form(self) -> None:
        pre = '{"profile":"agentavow.mcp-tool-definition.v1","tool":{"name":"t"}}'
        self.assertEqual(_sha(pre), agentavow_v1_digest({"name": "t"}))
        self.assertEqual(
            "sha256:f1460378f23621a823ccd400078609e09675d972121c8ec9df0393c3991c0aa5",
            agentavow_v1_digest({"name": "t"}))

    def test_every_hashed_field_reaches_the_preimage(self) -> None:
        tool = {"name": "t", "title": "T", "description": "d",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "string"},
                "annotations": {"readOnlyHint": True}}
        pre = ('{"profile":"agentavow.mcp-tool-definition.v1","tool":'
               '{"annotations":{"readOnlyHint":true},"description":"d",'
               '"inputSchema":{"type":"object"},"name":"t",'
               '"outputSchema":{"type":"string"},"title":"T"}}')
        self.assertEqual(_sha(pre), agentavow_v1_digest(tool))

    def test_the_result_is_prefixed_lowercase_hex(self) -> None:
        self.assertRegex(agentavow_v1_digest({"name": "t"}) or "",
                         r"^sha256:[0-9a-f]{64}$")

    def test_null_equals_missing(self) -> None:
        bare = {"name": "t", "description": "d"}
        nulled = dict(bare, title=None, inputSchema=None, outputSchema=None,
                      annotations=None)
        self.assertEqual(agentavow_v1_digest(bare), agentavow_v1_digest(nulled))
        self.assertEqual(
            _sha('{"profile":"agentavow.mcp-tool-definition.v1","tool":'
                 '{"description":"d","name":"t"}}'),
            agentavow_v1_digest(nulled))

    def test_present_but_empty_is_hashed_not_omitted(self) -> None:
        """The native digest drops an empty outputSchema; this profile does
        not. Only a missing or null field is left out."""
        bare = {"name": "t"}
        for field, empty in (("outputSchema", {}), ("annotations", {}),
                             ("inputSchema", {}), ("title", ""),
                             ("description", "")):
            with self.subTest(field=field):
                self.assertNotEqual(agentavow_v1_digest(bare),
                                    agentavow_v1_digest(dict(bare, **{field: empty})))

    def test_meta_and_unknown_fields_are_never_hashed(self) -> None:
        bare = {"name": "t", "description": "d"}
        noisy = dict(bare, _meta={"x": 1}, icons=[{"src": "i.png"}],
                     execution={"taskSupport": "optional"}, anything="else")
        self.assertEqual(agentavow_v1_digest(bare), agentavow_v1_digest(noisy))

    def test_the_lockfile_spellings_are_unknown_fields(self) -> None:
        """Served definitions say inputSchema. A snake_case key is a field the
        profile never named, so it must not move the digest."""
        bare = {"name": "t"}
        self.assertEqual(
            agentavow_v1_digest(bare),
            agentavow_v1_digest(dict(bare, input_schema={"type": "object"},
                                     output_schema={"type": "string"})))

    def test_key_order_is_irrelevant_at_every_depth(self) -> None:
        a = {"name": "t", "description": "d",
             "inputSchema": {"type": "object", "properties": {"a": {"type": "string"},
                                                              "b": {"type": "number"}}}}
        b = {"inputSchema": {"properties": {"b": {"type": "number"},
                                            "a": {"type": "string"}},
                             "type": "object"},
             "description": "d", "name": "t"}
        self.assertEqual(agentavow_v1_digest(a), agentavow_v1_digest(b))

    def test_one_and_one_point_zero_hash_alike(self) -> None:
        one = {"name": "t", "inputSchema": {"minimum": 1}}
        one_float = {"name": "t", "inputSchema": {"minimum": 1.0}}
        self.assertEqual(agentavow_v1_digest(one), agentavow_v1_digest(one_float))
        self.assertNotEqual(agentavow_v1_digest(one),
                            agentavow_v1_digest({"name": "t",
                                                 "inputSchema": {"minimum": 1.5}}))

    def test_a_changed_word_changes_the_digest(self) -> None:
        self.assertNotEqual(
            agentavow_v1_digest({"name": "t", "description": "read a file"}),
            agentavow_v1_digest({"name": "t", "description": "read a file."}))

    def test_a_different_profile_label_changes_the_digest(self) -> None:
        tool = '"tool":{"name":"t"}}'
        ours = '{"profile":"agentavow.mcp-tool-definition.v1",' + tool
        theirs = '{"profile":"agentavow.mcp-tool-definition.v2",' + tool
        self.assertEqual(_sha(ours), agentavow_v1_digest({"name": "t"}))
        self.assertNotEqual(_sha(theirs), agentavow_v1_digest({"name": "t"}))
        # And the tool alone, with no label at all, is a third answer.
        self.assertNotEqual(_sha('{"name":"t"}'), agentavow_v1_digest({"name": "t"}))

    def test_it_is_not_the_native_digest(self) -> None:
        tool = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
        native = tool_digest(tool)
        theirs = agentavow_v1_digest(tool)
        assert theirs is not None
        self.assertNotEqual(native, theirs)
        self.assertNotEqual(native, theirs.split(":", 1)[1])

    def test_the_native_digest_still_ignores_what_this_profile_reads(self) -> None:
        """Computing a profile digest must leave the native one alone."""
        tool = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
        before = tool_digest(tool)
        agentavow_v1_digest(tool)
        self.assertEqual(before, tool_digest(tool))
        self.assertEqual({"name": "t", "description": "d",
                          "inputSchema": {"type": "object"}}, tool)

    def test_unicode_is_hashed_as_utf8_not_escaped(self) -> None:
        pre = ('{"profile":"agentavow.mcp-tool-definition.v1","tool":'
               '{"description":"café \U0001F600","name":"t"}}')
        self.assertEqual(
            _sha(pre),
            agentavow_v1_digest({"name": "t", "description": "café \U0001F600"}))


class TestKeyEncoding(unittest.TestCase):
    def test_plain_ascii_is_unchanged(self) -> None:
        for name in ("ask_wiki_question", "read-file", "a.b", "~tilde!", "X9"):
            with self.subTest(name=name):
                self.assertEqual("tool:" + name, agentavow_v1_key(name))

    def test_equals_and_percent_are_encoded(self) -> None:
        self.assertEqual("tool:a%3Db", agentavow_v1_key("a=b"))
        self.assertEqual("tool:100%25", agentavow_v1_key("100%"))
        self.assertEqual("tool:%25%3D", agentavow_v1_key("%="))

    def test_space_tab_and_control_bytes_are_encoded(self) -> None:
        self.assertEqual("tool:a%20b", agentavow_v1_key("a b"))
        self.assertEqual("tool:a%09b", agentavow_v1_key("a\tb"))
        self.assertEqual("tool:%0A", agentavow_v1_key("\n"))
        self.assertEqual("tool:%7F", agentavow_v1_key("\x7f"))

    def test_the_range_is_inclusive_at_both_ends(self) -> None:
        self.assertEqual("tool:!~", agentavow_v1_key("!~"))
        self.assertEqual("tool:%20", agentavow_v1_key(" "))

    def test_non_ascii_is_encoded_byte_by_byte_in_uppercase_hex(self) -> None:
        self.assertEqual("tool:caf%C3%A9", agentavow_v1_key("café"))
        self.assertEqual("tool:%F0%9F%98%80", agentavow_v1_key("\U0001F600"))
        self.assertEqual("tool:%E2%82%AC", agentavow_v1_key("€"))

    def test_the_empty_name_has_a_key(self) -> None:
        self.assertEqual("tool:", agentavow_v1_key(""))

    def test_128_encoded_characters_are_kept_whole(self) -> None:
        self.assertEqual("tool:" + "a" * 128, agentavow_v1_key("a" * 128))

    def test_129_encoded_characters_are_cut_and_suffixed(self) -> None:
        name = "a" * 129
        suffix = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
        self.assertEqual("tool:" + "a" * 96 + "~" + suffix, agentavow_v1_key(name))

    def test_the_limit_counts_encoded_characters_not_name_characters(self) -> None:
        # 21 x "é" encodes to 126 characters; two more "a" make exactly 128.
        kept = "é" * 21 + "aa"
        self.assertEqual("tool:" + "%C3%A9" * 21 + "aa", agentavow_v1_key(kept))
        # One more makes 129 and cuts, though the name is only 24 characters.
        name = kept + "a"
        encoded = "%C3%A9" * 21 + "aaa"
        suffix = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
        self.assertEqual("tool:" + encoded[:96] + "~" + suffix,
                         agentavow_v1_key(name))

    def test_a_cut_may_land_inside_a_percent_triplet(self) -> None:
        name = "a" * 95 + " " + "b" * 40          # "%20" starts at column 95
        suffix = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
        key = agentavow_v1_key(name)
        self.assertEqual("tool:" + "a" * 95 + "%" + "~" + suffix, key)
        # The cut left a lone "%": the key is not itself a valid encoding,
        # and it is not repaired.
        self.assertIn("%~", key or "")

    def test_the_suffix_hashes_the_raw_name_so_long_names_do_not_collide(self) -> None:
        one = agentavow_v1_key("a" * 200 + "x")
        two = agentavow_v1_key("a" * 200 + "y")
        assert one is not None and two is not None
        self.assertNotEqual(one, two)
        self.assertEqual(one[:len("tool:") + 96], two[:len("tool:") + 96])
        self.assertEqual(len("tool:") + 96 + 1 + 16, len(one))

    def test_the_suffix_is_lowercase_hex(self) -> None:
        key = agentavow_v1_key("A" * 300)
        assert key is not None
        self.assertRegex(key, r"~[0-9a-f]{16}$")


class TestNeverRaises(unittest.TestCase):
    """A profile is an extra beside a record that stands alone, so a hostile
    definition costs the extra and never the record."""

    def test_a_lone_surrogate_in_a_name_has_no_key(self) -> None:
        self.assertIsNone(agentavow_v1_key("a\ud800b"))
        self.assertIsNone(agentavow_v1_key("\udfff"))

    def test_a_lone_surrogate_in_a_definition_still_hashes(self) -> None:
        """Canonical form escapes it, as JSON.stringify does, so both sides
        can agree on what they hashed."""
        tool = json.loads(r'{"name":"t","description":"x \ud800 y"}')
        pre = ('{"profile":"agentavow.mcp-tool-definition.v1","tool":'
               '{"description":"x \\ud800 y","name":"t"}}')
        self.assertEqual(_sha(pre), agentavow_v1_digest(tool))

    def test_a_non_mapping_tool_has_no_digest(self) -> None:
        for tool in (None, [], [("name", "t")], "t", 5, 1.5, True, b"x"):
            with self.subTest(tool=tool):
                self.assertIsNone(agentavow_v1_digest(tool))

    def test_a_non_string_name_has_no_key(self) -> None:
        for name in (None, 5, 1.5, True, b"t", ["t"], {"t": 1}):
            with self.subTest(name=name):
                self.assertIsNone(agentavow_v1_key(name))

    def test_values_no_canonical_form_can_express_have_no_digest(self) -> None:
        for bad in (float("nan"), float("inf"), 10 ** 400, {1, 2}, object()):
            with self.subTest(bad=repr(bad)[:20]):
                self.assertIsNone(
                    agentavow_v1_digest({"name": "t", "inputSchema": {"x": bad}}))

    def test_a_schema_nested_past_the_recursion_limit_has_no_digest(self) -> None:
        deep: dict[str, Any] = {}
        node = deep
        for _ in range(sys.getrecursionlimit() * 2):
            node["a"] = {}
            node = node["a"]
        self.assertIsNone(agentavow_v1_digest({"name": "t", "inputSchema": deep}))
        # And the interpreter is still usable afterwards.
        self.assertIsNotNone(agentavow_v1_digest({"name": "t"}))

    def test_a_mapping_that_raises_has_no_digest(self) -> None:
        class Hostile(UserDict):  # type: ignore[type-arg]
            def get(self, key: Any, default: Any = None) -> Any:
                raise RuntimeError("no")

            def __getitem__(self, key: Any) -> Any:
                raise RuntimeError("no")

        self.assertIsNone(agentavow_v1_digest(Hostile({"name": "t"})))


VECTORS_DIR = os.environ.get("AGENTAVOW_VECTORS_DIR")
VECTORS_FILE = "tool-manifest-digest-v1-vectors.json"


@unittest.skipUnless(
    VECTORS_DIR,
    "AGENTAVOW_VECTORS_DIR is unset; AgentAvow's vectors are not vendored here")
class TestConformance(unittest.TestCase):
    """Reproduce the published signed digests and key pairs.

    The vectors are read from the directory named by the environment variable
    and from nowhere else. Their licence does not allow copying them into this
    repository, so this test is a local check and never part of CI.
    """

    @classmethod
    def setUpClass(cls) -> None:
        path = Path(VECTORS_DIR or "") / VECTORS_FILE
        cls.data = json.loads(path.read_text(encoding="utf-8"))

    def test_the_signed_digests_are_reproduced(self) -> None:
        signed = self.data["attestation"]["toolDigests"]
        tools = self.data["observed_tools"]
        self.assertGreater(len(tools), 0)
        for tool in tools:
            with self.subTest(tool=tool["name"]):
                key = agentavow_v1_key(tool["name"])
                self.assertIn(key, signed)
                self.assertEqual(signed[key], agentavow_v1_digest(tool))

    def test_every_served_tool_is_signed_and_no_more(self) -> None:
        signed = set(self.data["attestation"]["toolDigests"])
        served = {agentavow_v1_key(t["name"]) for t in self.data["observed_tools"]}
        self.assertEqual(signed, served)

    def test_the_key_encoding_pairs_are_reproduced(self) -> None:
        pairs = self.data["key_encoding"]
        self.assertGreater(len(pairs), 0)
        for pair in pairs:
            with self.subTest(name=pair["name"]):
                self.assertEqual(pair["key"], agentavow_v1_key(pair["name"]))


if __name__ == "__main__":
    unittest.main()
