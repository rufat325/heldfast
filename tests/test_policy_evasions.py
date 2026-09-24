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

from heldfast.policy import Policy  # noqa: E402


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

    def test_a_comment_inside_a_keyword_is_refused(self) -> None:
        """`SEL/**/ECT 1` reads as `SEL` here and as `SEL ECT` to an engine,
        because a comment is a token separator rather than nothing. It was
        allowed on the grounds that the database would reject it anyway.

        It is refused now, and that is a consequence rather than a new
        opinion: a value under a parameter named `sql` goes through
        `sql_is_allowed` whatever it looks like, and `SEL` is not a permitted
        operation. Refusing a string no engine will run costs nothing in this
        direction either, and the gate that used to skip it is the same gate
        that skipped a MySQL `#` comment."""
        self.assertFalse(allows({"sql": ["SELECT"]}, "query",
                                {"sql": "SEL/**/ECT 1"}))


class TestSqlTheGateNeverLookedAt(unittest.TestCase):
    """`looks_like_sql` was the fail-open, not the check behind it.

    The rule only ran `if looks_like_sql(value)`, and that wants a bare
    keyword after optional whitespace and `--` or slash-star comments. Every
    other opening meant the value was not SQL as far as the policy was
    concerned, so a `sql: ["SELECT"]` rule did not run at all -- and
    `sql_is_allowed`, which already refuses an unparseable statement, never
    saw it.

    `paths` matched on the parameter name as well as the shape; that is the
    `.env` fix. `domains` refused a named parameter that resolved to no host.
    The SQL constraint had neither, and it is the one whose failure hands an
    engine a statement.
    """

    RULES = {"sql": ["SELECT"]}

    def test_a_mysql_line_comment_opens_the_statement(self) -> None:
        """`#` is a comment to end of line in MySQL and MariaDB. What follows
        it is a DROP, under a policy that permits only SELECT."""
        for sql in ("# note\nDROP TABLE users",
                    "#\nDELETE FROM t",
                    "   # x\n  DROP TABLE users"):
            with self.subTest(sql=sql):
                self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_punctuation_before_the_keyword(self) -> None:
        for sql in (";DROP TABLE users",
                    "(SELECT 1) UNION SELECT load_file('/etc/passwd')",
                    ")DROP TABLE users"):
            with self.subTest(sql=sql):
                self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_a_named_parameter_is_checked_whatever_it_holds(self) -> None:
        """The rule `paths` already applies: the schema's name for a parameter
        says what it holds, and the text does not get a vote."""
        for name in ("sql", "query", "statement", "expression"):
            with self.subTest(name=name):
                self.assertFalse(allows(self.RULES, "query",
                                        {name: "DROP TABLE users"}))

    def test_a_named_parameter_nested_in_an_object(self) -> None:
        self.assertFalse(allows(self.RULES, "query",
                                {"opts": {"query": "DROP TABLE users"}}))

    def test_an_unnamed_parameter_holding_prose_still_passes(self) -> None:
        """Not a filter on every string in the call. A parameter that neither
        looks like SQL nor is named like it stays out of it."""
        self.assertTrue(allows(self.RULES, "query",
                               {"sql": "SELECT 1", "note": "ran the report"}))


class TestBackslashEscapesDesyncTheLiteralScanner(unittest.TestCase):
    r"""MySQL reads `\'` as an escaped quote; the scanner did not.

    That single character put the checker's idea of where a literal ends out
    of step with the engine's. After it the quote state is inverted, so
    everything the engine reads as code the checker reads as the inside of a
    string, and both documented refusals walked straight through.

    The fix is not to adopt MySQL's reading. PostgreSQL with
    standard_conforming_strings and SQLite read the backslash literally, and
    picking either dialect leaves the hole open for the other. Both readings
    are tried and a violation under either one refuses.
    """

    RULES = {"sql": ["SELECT"]}

    def test_a_stacked_statement_hidden_behind_an_escape(self) -> None:
        for sql in (r"SELECT 1 WHERE x='\''; DROP TABLE users; -- '",
                    r"SELECT a FROM t WHERE b='\''; DELETE FROM t; -- '"):
            with self.subTest(sql=sql):
                self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_into_outfile_hidden_behind_an_escape(self) -> None:
        sql = r"SELECT a FROM t WHERE b='\'' INTO OUTFILE '/var/www/s.php' -- '"
        self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_the_other_dialect_is_covered_too(self) -> None:
        r"""Read with backslash-as-escape this is one statement. Read the
        PostgreSQL way the literal ends at `'a\'` and the DROP is code, so
        only checking the MySQL reading would reopen the hole facing the
        other way."""
        sql = r"SELECT 'a\' ; DROP TABLE users ; --'"
        self.assertFalse(allows(self.RULES, "query", {"sql": sql}))

    def test_a_literal_backslash_is_not_by_itself_a_refusal(self) -> None:
        """Over-refusing every Windows path in a WHERE clause would be its own
        outage. A backslash that changes neither the statement count nor what
        the statement writes is left alone."""
        for sql in (r"SELECT * FROM t WHERE p = 'C:\temp\x'",
                    r"SELECT * FROM t WHERE p LIKE 'a\_b'",
                    "SELECT a FROM t WHERE b = 'into outfile'"):
            with self.subTest(sql=sql):
                self.assertTrue(allows(self.RULES, "query", {"sql": sql}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
