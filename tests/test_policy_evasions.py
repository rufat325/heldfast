"""The other spellings of the four evasions the policy already knew.

Cycle 19 wrote evasions for the argument policy -- traversal, a
`/workspace-evil` prefix, `api.github.com.evil.io`, stacked SQL, a path hidden
in a nested argument -- and every one of them still passes. Partial coverage is
exactly where the result screen's gap lived, so this asks which *other*
spellings of those same four were never written down.

Five were not, and each is here with the reason it matters:

* `deny` is the only boolean among four keys that are otherwise all lists, so
  `"deny": ["wipe"]` is the natural hand-edit -- and it denied nothing while
  looking like it denied something.
* `https://evil.io\\@api.github.com/x` is a parser differential. Python reads
  the host as api.github.com; WHATWG parsers (browsers, Node, Go) treat `\\`
  as `/` and stop the authority at evil.io. The policy approved one host and
  the server would have fetched another.
* `/*!50000 DROP*/ TABLE t` is a comment to a comment-stripper and a statement
  to MySQL. It was not even recognised as SQL, so the rule never ran.
* `SELECT ... INTO OUTFILE` is a write wearing the one operation that was
  permitted.
* `%2e%2e` and `%252e%252e` reach traversal on any server that decodes its
  argument before opening it.

The last section records two shapes that are still allowed **on purpose**, so
that nobody later reads them as oversights.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_pin.policy import Policy  # noqa: E402


def allows(rules: dict, tool: str, arguments) -> bool:
    return bool(Policy({tool: rules}).check(tool, arguments))


class TestDenyMeansDeny(unittest.TestCase):
    """`deny` is the one boolean among four list-valued keys."""

    def test_the_documented_spelling(self) -> None:
        self.assertFalse(allows({"deny": True}, "wipe", {}))

    def test_the_natural_hand_edit_denies_too(self) -> None:
        """Written as a list, because the three keys beside it are lists. It
        used to be read strictly and so denied nothing at all."""
        for value in (["wipe"], "yes", 1, ["anything"]):
            with self.subTest(deny=value):
                self.assertFalse(allows({"deny": value}, "wipe", {}))

    def test_an_explicit_false_still_allows(self) -> None:
        for value in (False, None, [], "", 0):
            with self.subTest(deny=value):
                self.assertTrue(allows({"deny": value}, "wipe", {}))


class TestPathEncodings(unittest.TestCase):
    RULES = {"paths": ["/workspace/**"]}

    def test_percent_encoded_traversal(self) -> None:
        self.assertFalse(allows(self.RULES, "read",
                                {"path": "/workspace/%2e%2e/etc/passwd"}))

    def test_double_encoded_traversal(self) -> None:
        self.assertFalse(allows(self.RULES, "read",
                                {"path": "/workspace/%252e%252e/etc/passwd"}))

    def test_an_encoded_separator(self) -> None:
        self.assertFalse(allows(self.RULES, "read",
                                {"path": "/workspace%2f..%2fetc/passwd"}))

    def test_the_shapes_that_already_worked(self) -> None:
        for path in ("/etc/passwd", "/workspace/../etc/passwd",
                     "/workspace-evil/a", "~/.ssh/id_rsa",
                     "/workspace/..\\etc\\passwd"):
            with self.subTest(path=path):
                self.assertFalse(allows(self.RULES, "read", {"path": path}))

    def test_ordinary_paths_still_pass(self) -> None:
        for path in ("/workspace/a.txt", "/workspace/./a.txt",
                     "/workspace/sub/", "/workspace/deep/nested/file.md"):
            with self.subTest(path=path):
                self.assertTrue(allows(self.RULES, "read", {"path": path}))

    def test_a_percent_that_is_not_an_escape_is_left_alone(self) -> None:
        """Decoding must not mangle an ordinary name. `100%` is a directory
        somebody has, and `%zz` is not a valid escape."""
        for path in ("/workspace/100% done/a.txt", "/workspace/%zz/a.txt"):
            with self.subTest(path=path):
                self.assertTrue(allows(self.RULES, "read", {"path": path}))


class TestUrlParserDifferentials(unittest.TestCase):
    RULES = {"domains": ["api.github.com"]}

    def test_a_backslash_in_the_authority(self) -> None:
        """Python says the host is api.github.com. A WHATWG parser -- every
        browser, Node's `new URL`, Go -- treats `\\` as `/`, so the authority
        ends at evil.io. Approving one host while the server fetches another
        is the whole failure, and nothing legitimate needs a backslash here."""
        self.assertFalse(allows(self.RULES, "fetch",
                                {"url": "https://evil.io\\@api.github.com/x"}))

    def test_the_userinfo_trick_already_worked(self) -> None:
        for url in ("https://api.github.com@evil.io/x",
                    "https://api.github.com:token@evil.io/x"):
            with self.subTest(url=url):
                self.assertFalse(allows(self.RULES, "fetch", {"url": url}))

    def test_the_suffix_trick_already_worked(self) -> None:
        self.assertFalse(allows(self.RULES, "fetch",
                                {"url": "https://api.github.com.evil.io/x"}))

    def test_ordinary_destinations_still_pass(self) -> None:
        for url in ("https://api.github.com/x", "https://API.GITHUB.COM/x",
                    "https://api.github.com./x", "https://api.github.com:443/x"):
            with self.subTest(url=url):
                self.assertTrue(allows(self.RULES, "fetch", {"url": url}))


class TestSqlThatTheEngineReadsDifferently(unittest.TestCase):
    RULES = {"sql": ["SELECT"]}

    def test_a_mysql_executable_comment(self) -> None:
        """`/*! ... */` is a comment to everything except MySQL, which runs
        it. Stripping it left `TABLE t`, which is not a statement this
        recognises at all -- so the rule was skipped rather than failed."""
        for sql in ("/*!50000 DROP*/ TABLE t",
                    "/*! DROP */ TABLE t",
                    "/*!40101 DELETE FROM t*/"):
            with self.subTest(sql=sql):
                self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_select_that_writes_a_file(self) -> None:
        """Permitting SELECT permits reading. INTO OUTFILE writes to disk as
        the database's user and is still, syntactically, a SELECT."""
        for sql in ("SELECT 1 INTO OUTFILE '/tmp/x'",
                    "SELECT * FROM t INTO DUMPFILE '/tmp/x'",
                    "select a from b into outfile '/tmp/x'"):
            with self.subTest(sql=sql):
                self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_the_shapes_that_already_worked(self) -> None:
        for sql in ("SELECT 1; DROP TABLE t", "/* hi */ DROP TABLE t",
                    "SELECT 1 -- x\n; DROP TABLE t",
                    "WITH x AS (SELECT 1) DELETE FROM t",
                    "UPDATE t SET a=1"):
            with self.subTest(sql=sql):
                self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_ordinary_queries_still_pass(self) -> None:
        for sql in ("SELECT 1", "select 1", "   \n SELECT 1",
                    "SELECT a FROM t WHERE b = 'into outfile'"):
            with self.subTest(sql=sql):
                self.assertTrue(allows(self.RULES, "query", {"sql": sql}))


class TestWhatIsStillAllowedOnPurpose(unittest.TestCase):
    """Two shapes the attack corpus flags and this does not refuse, recorded
    so nobody later reads them as oversights."""

    def test_a_subdomain_of_a_granted_domain(self) -> None:
        """`domains: ["api.github.com"]` admits `evil.api.github.com`, because
        suffix matching is what people mean by granting a domain -- the usual
        case is `example.com` covering its subdomains. Reaching one here would
        require control of GitHub's DNS, which is not the threat this rule is
        for. Grant the exact host if that is not wanted."""
        self.assertTrue(allows({"domains": ["api.github.com"]}, "fetch",
                               {"url": "https://evil.api.github.com/x"}))

    def test_a_destination_in_a_parameter_nothing_calls_a_destination(self) -> None:
        """`evil.io/x` is still not checked when nothing says it is one.

        The note here used to say widening this needed a host-like pattern,
        and that `README.md/section` fits every version of one worth writing.
        That remains true of matching by *shape*. Matching by *name* has no
        such problem, so a parameter the schema calls `url`, `endpoint` or
        `host` is now checked whether or not it carries a scheme -- see
        TestSchemelessDestinations below.

        What is left is a bare string in a parameter with no destination-like
        name, where shape is the only evidence there is. That one stays, and
        stays written down.
        """
        self.assertTrue(allows({"domains": ["api.github.com"]}, "fetch",
                               {"note": "see evil.io/x for details"}))


class TestSchemelessDestinations(unittest.TestCase):
    """A domains rule reads the parameters the schema names as destinations.

    Classifying only by shape meant `domains: ["api.github.com"]` admitted
    `evil.example/upload`, `//evil.example/x` and `{"host": "evil.example"}`,
    because only a leading `scheme://` counted as a URL at all. The server
    resolves every one of those to the same place.
    """

    RULES = {"domains": ["api.github.com"]}

    def test_a_named_parameter_without_a_scheme_is_refused(self) -> None:
        for param, value in (("url", "evil.example/upload"),
                             ("host", "evil.example"),
                             ("endpoint", "evil.example"),
                             ("webhook", "//evil.example/x"),
                             ("uri", "//evil.example/x")):
            with self.subTest(param=param, value=value):
                self.assertFalse(allows(self.RULES, "fetch", {param: value}))

    def test_the_approved_host_still_passes_without_a_scheme(self) -> None:
        for value in ("api.github.com", "api.github.com/repos",
                      "//api.github.com/repos", "https://api.github.com/x"):
            with self.subTest(value=value):
                self.assertTrue(allows(self.RULES, "fetch", {"url": value}))

    def test_a_named_parameter_that_names_no_host_is_refused(self) -> None:
        """An empty or unparseable destination is refused rather than skipped.

        The server will resolve it somehow, and this is the only point at
        which saying no is still possible.
        """
        for value in ("   ", "://", "http://"):
            with self.subTest(value=value):
                self.assertFalse(allows(self.RULES, "fetch", {"url": value}))

    def test_a_comment_inside_a_keyword_is_not_a_bypass(self) -> None:
        """`SEL/**/ECT 1` reads as SELECT here and as `SEL ECT` to an engine,
        because a comment is a token separator rather than nothing. The policy
        allows a string the database will reject, which costs nothing. The
        variant that *does* execute is `/*! */`, and that one is refused."""
        self.assertTrue(allows({"sql": ["SELECT"]}, "query",
                               {"sql": "SEL/**/ECT 1"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
