"""The plugin and `wrap` read an organisation policy the same way (T-ORG-PARITY).

`wrap` and `gateway` ask src/heldfast/orgpolicy.py whether a server may start;
the Claude Code hook asks plugin/heldfast/scripts/orgpolicy.js whether it may
be called. Two call sites reading one policy is a hole wherever they differ,
and the difference would be invisible: each side's own tests would pass.

So both are held to one answer twice over. The golden vectors in
tests/golden/orgpolicy_vectors.json are the contract, each with the reason it
exists, and both languages must reproduce them. Then a seeded generator
throws a few thousand odd inputs -- URLs built from the pieces parsers
disagree on, quoting `shlex` has opinions about, argv from every runner,
config entries with the wrong types -- at both and requires the same output.
The generator found several disagreements before this file existed; each is
now a vector.
"""

from __future__ import annotations

import base64
import json
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from heldfast import inventory, orgpolicy  # noqa: E402
from heldfast.model import ServerSpec  # noqa: E402
from heldfast.parsers import parse_config  # noqa: E402

VECTORS = ROOT / "tests" / "golden" / "orgpolicy_vectors.json"
JS = ROOT / "tests" / "fixtures" / "orgpolicy_js.js"
SECTIONS = ("glob", "endpoint", "shlex", "describe", "lock", "config", "parse", "load",
            "refusal")


# ---------------------------------------------------------------------------
# Each language's answers to one batch


def _config_spec(entry: Any, tmp: Path) -> ServerSpec | None:
    """The spec parse_config makes of one Claude Code entry, as the plugin reads it."""
    path = tmp / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {"s": entry}}), encoding="utf-8")
    servers, _ = parse_config(path, "claude-code")
    return servers[0] if servers else None


def _attempt(fn: Any) -> Any:
    try:
        return fn()
    except ValueError:
        return "ERROR"


def _load(data: str, tmp: Path) -> str:
    path = tmp / "p.json"
    path.write_bytes(base64.b64decode(data))
    return _attempt(lambda: (orgpolicy.load(path), "ok")[1])


def _refusal(case: dict[str, Any], tmp: Path) -> Any:
    def run() -> Any:
        policy = orgpolicy.parse(case["policy"], "0" * 64)
        spec = _config_spec(case["spec"], tmp)
        row = dict(inventory.describe(spec), identity="claude-code:s")
        entry = case.get("entry")
        return orgpolicy.launch_refusal(policy, row, entry if isinstance(entry, dict) else None)
    return _attempt(run)


def python_answers(batch: dict[str, list]) -> dict[str, list]:
    def spec(s: dict[str, Any]) -> ServerSpec:
        return ServerSpec(name="s", source="", client="c", transport=s["transport"],
                          command=s.get("command"), args=list(s.get("args") or []),
                          url=s.get("url"))
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        return {
            "glob": [orgpolicy.glob(t, p) for t, p in batch.get("glob", [])],
            "endpoint": [inventory.endpoint(u) for u in batch.get("endpoint", [])],
            "shlex": [_attempt(lambda t=t: shlex.split(t)) for t in batch.get("shlex", [])],
            "describe": [inventory.describe(spec(s)) for s in batch.get("describe", [])],
            "lock": [inventory.describe(inventory._spec_from_lock("c:s", e))
                     for e in batch.get("lock", [])],
            "config": [inventory.describe(_config_spec(e, tmp)) for e in batch.get("config", [])],
            "parse": [_attempt(lambda p=p: (orgpolicy.parse(p), "ok")[1])
                      for p in batch.get("parse", [])],
            "load": [_load(d, tmp) for d in batch.get("load", [])],
            "refusal": [_refusal(c, tmp) for c in batch.get("refusal", [])],
        }


def js_answers(batch: dict[str, list]) -> dict[str, list]:
    proc = subprocess.run(["node", str(JS)], input=json.dumps(batch), capture_output=True,
                          text=True, encoding="utf-8", timeout=120)
    if proc.returncode != 0:
        raise AssertionError(f"the JS half failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def _inputs(cases: dict[str, list[dict[str, Any]]]) -> dict[str, list]:
    return {section: [c["input"] for c in cases.get(section, [])] for section in SECTIONS}


NODE = shutil.which("node")


# ---------------------------------------------------------------------------
# The contract


class TestTheVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = json.loads(VECTORS.read_text(encoding="utf-8"))

    def check(self, answers: dict[str, list], who: str) -> None:
        for section in SECTIONS:
            for case, got in zip(self.cases.get(section, []), answers[section]):
                with self.subTest(language=who, section=section, why=case["why"]):
                    self.assertEqual(case["expect"], got)

    def test_every_section_has_vectors(self) -> None:
        for section in SECTIONS:
            with self.subTest(section=section):
                self.assertGreater(len(self.cases.get(section, [])), 3)
                for case in self.cases[section]:
                    self.assertTrue(case.get("why"), case)

    def test_python_reproduces_them(self) -> None:
        self.check(python_answers(_inputs(self.cases)), "python")

    @unittest.skipUnless(NODE, "node is not installed")
    def test_the_plugin_reproduces_them(self) -> None:
        self.check(js_answers(_inputs(self.cases)), "js")


# ---------------------------------------------------------------------------
# Differential


def _pick(rng: random.Random, pool: list) -> Any:
    return pool[rng.randrange(len(pool))]


def _url(rng: random.Random) -> str:
    """Mostly a URL that parses, with one or two of the pieces parsers disagree on."""
    good = rng.random() < 0.6
    odd = (lambda pool: _pick(rng, pool)) if not good else (lambda pool: pool[0])
    return "".join([
        odd(["", " ", "\t", "\x1c", "\u00a0"]),
        _pick(rng, ["https", "https", "http", "HTTPS", "ws"]) if good
        else _pick(rng, ["h+t", "1x", "", "https"]),
        odd(["://", ":/", ":"]),
        _pick(rng, ["", "", "", "u@", "u:p@"]) if good else _pick(rng, ["a@b@", "x\\@", "@"]),
        _pick(rng, ["mcp.example.com", "EX.Com", "[::1]", "1.2.3.4", "x_y.example", "*.example",
                    "api.vendor.example.com"]) if good
        else _pick(rng, ["[::1", "[fe80::1%25en0]", "b\u00fccher.de", "a%2eb.com", ""]),
        _pick(rng, ["", "", "", ":443", ":0443", ":8080", ":"]) if good
        else _pick(rng, [":99999", ":x", ":1:2", ":\u0661"]),
        _pick(rng, ["", "/", "/sse", "/mcp", "/ok/", "/a/b", "/sk-ak-9f8e7d6c5b4a3f2e1d0c9b8a7",
                    "/x;token=abc", "/--key=v", "/ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
                    "/\u2028", "//x", "/a;session=[REDACTED]"]) if good
        else _pick(rng, ["/a/../b", "/a/./b", "/a%20b", "/a b", "/a\\b"]),
        _pick(rng, ["", "", "?q=1", "#f", "?a@b/c"]),
        odd(["", " ", "\n", "\x0c"]),
    ])


def _derived(rng: random.Random, text: str) -> str:
    """A glob made from `text`, so it matches about half the time."""
    out = []
    for c in text:
        r = rng.random()
        out.append("*" if r < 0.15 else "?" if r < 0.25 else ("x" if r < 0.3 else c))
    if rng.random() < 0.3:
        out.insert(rng.randrange(len(out) + 1), "*")
    return "".join(out)


_COMMANDS = ["npx", "NPX.EXE", "npx.cmd.exe", "cmd", "CMD.exe", "C:\\nodejs\\npx.cmd", "uvx", "pipx",
             "deno", "node", "heldfast", "/usr/bin/heldfast", "\"heldfast\"", "bun", "pnpm", "yarn",
             "python", " npx ", ""]
_ARGS = ["-y", "--yes", "/c", "/K", "dlx", "run", "x", "exec", "--package", "-p", "--from",
         "--registry", "r", "pkg", "pkg@1.2.3", "pkg@1.2", "pkg@v1.2.3", "pkg@=1.2.3",
         "@scope/pkg@2.0.0-beta.1", "@scope/pkg", "@scope", "pkg@latest", "pkg@^1.0.0",
         "pkg@1.x", "mcp-server==1.2.3", "mcp-server>=1", "mcp[x]==1.0", "srv=== 2.0",
         "Mcp_Server ==1", "npm:pkg@1.0.0", "jsr:x", "./local", "~/x", "C:\\x", "wrap", "guard",
         "--", "--name", "heldfast", "gateway", "pkg@\u0661.\u0662.\u0663", "pkg@1.2.3\n", " pkg "]


def _argv(rng: random.Random) -> list[str]:
    return [_pick(rng, _ARGS) for _ in range(rng.randrange(0, 7))]


def _spec(rng: random.Random) -> dict[str, Any]:
    return {"transport": _pick(rng, ["stdio", "stdio", "http", "sse", "unknown"]),
            "command": _pick(rng, _COMMANDS + [None]), "args": _argv(rng),
            "url": _pick(rng, [None, None, None, _url(rng)])}


def _config(rng: random.Random) -> dict[str, Any]:
    if rng.random() < 0.4:
        return {"command": _pick(rng, ["npx", "uvx", "pnpm", "cmd"]),
                "args": _pick(rng, [["-y"], ["dlx"], ["/c", "npx", "-y"], []])
                + [_pick(rng, _ARGS[14:30])] + _argv(rng)[:2]}
    if rng.random() < 0.3:
        return {"type": _pick(rng, ["http", "sse", "streamable-http"]), "url": _url(rng)}
    entry: dict[str, Any] = {}
    for key, pool in (("command", _COMMANDS + [None, {}, True]),
                      ("args", [_argv(rng), _argv(rng), "pkg@1.0.0", {}, None, ["a", True, None]]),
                      ("url", [_url(rng), "", None, {}]), ("serverUrl", [_url(rng)]),
                      ("type", ["stdio", "http", "streamable-http", "SSE", "", None, {}]),
                      ("transport", ["https", "stdio"])):
        if rng.random() < 0.5:
            entry[key] = _pick(rng, pool)
    return entry


_RULES = [{"package": "npm:pkg"}, {"package": "npm:@scope/*"}, {"package": "pypi:Mcp_Server"},
          {"package": "*:pkg", "versions": ["1.2.*"]}, {"package": "npm:pkg", "versions": ["1.0.0"]},
          {"url": "https://*.example.com/*"}, {"url": "https://mcp.example.com"},
          {"url": "https://mcp.example.com:443/sse"}, {"url": "*://ex.com/*"},
          {"command": "node"}, {"command": "NPX"}, {"command": "py*"}, {"kind": "local"},
          {"kind": "hosted", "url": "http://*/*"}, {"package": "npm:pkg", "reason": "r"}]


def _policy(rng: random.Random) -> dict[str, Any]:
    policy: dict[str, Any] = {"policy": orgpolicy.SCHEMA}
    if rng.random() < 0.6:
        policy["deny"] = [_pick(rng, _RULES) for _ in range(rng.randrange(0, 3))]
    if rng.random() < 0.6:
        policy["allow"] = [_pick(rng, _RULES) for _ in range(rng.randrange(0, 3))]
    if rng.random() < 0.5:
        policy["unlisted"] = _pick(rng, ["allow", "warn", "deny"])
    if rng.random() < 0.5:
        policy["require"] = {k: rng.random() < 0.5 for k in ("approved", "pinned",
                                                            "exact_versions")}
    if rng.random() < 0.3:
        policy["name"] = _pick(rng, ["Acme", "", "a\nb"])
    return policy


def _bad_policy(rng: random.Random) -> Any:
    policy = _policy(rng)
    mutation = rng.randrange(8)
    if mutation == 0:
        policy["requre"] = {}
    elif mutation == 1:
        policy["unlisted"] = _pick(rng, [{}, [], None, 1, "maybe"])
    elif mutation == 2:
        policy["deny"] = [_pick(rng, [{}, {"reason": "x"}, {"package": "pkg"},
                                      {"package": "cargo:x"}, {"url": "nope"},
                                      {"versions": ["1"], "url": "https://x/"},
                                      {"package": "npm:x", "versions": "1"}, {"kind": "remote"},
                                      {"package": 1}, {"pakage": "npm:x"}])]
    elif mutation == 3:
        policy["require"] = _pick(rng, [{"approved": 1}, {"fail_on": "severe"}, {"fail_on": []},
                                        [], {"x": True}, {"fail_on": "high"}])
    elif mutation == 4:
        policy["policy"] = _pick(rng, ["heldfast.org-policy/2", None, ""])
    elif mutation == 5:
        policy["name"] = _pick(rng, [1, None, [], "fine"])
    elif mutation == 6:
        return _pick(rng, [[], "x", None, 3])
    return policy


def _load_bytes(rng: random.Random) -> str:
    good = json.dumps({"policy": orgpolicy.SCHEMA, "name": "x"})
    text = _pick(rng, [good, "\ufeff" + good, good.replace('"x"', "NaN"),
                       good.replace('"x"', "Infinity"), "{", good + " ", "",
                       good.replace('"x"', '"\\ud800"'), json.dumps({"policy": orgpolicy.SCHEMA,
                                                                     "description": 1e400})])
    raw = text.encode("utf-8", "surrogatepass")
    if rng.random() < 0.1:
        raw = b"\xff" + raw
    return base64.b64encode(raw).decode("ascii")


def random_batch(seed: int, n: int) -> dict[str, list]:
    rng = random.Random(seed)
    alphabet = "ab*?.-/[]"
    word = lambda: "".join(_pick(rng, list(alphabet)) for _ in range(rng.randrange(0, 9)))  # noqa: E731
    shell = "ab \t'\"\\\n#$"
    return {
        "glob": [[w, _derived(rng, w) if rng.random() < 0.6 else word()]
                 for w in (word() for _ in range(n))],
        "endpoint": [_url(rng) for _ in range(n)],
        "shlex": ["".join(_pick(rng, list(shell)) for _ in range(rng.randrange(0, 11)))
                  for _ in range(n)],
        "describe": [_spec(rng) for _ in range(n)],
        "lock": [{"command_line": " ".join(shlex.quote(a) for a in [_pick(rng, _COMMANDS)]
                                           + _argv(rng)),
                  "transport": _pick(rng, ["stdio", "http", "", None]),
                  "url": _pick(rng, [None, _url(rng), 3])} for _ in range(n)],
        "config": [_config(rng) for _ in range(n)],
        "parse": [_bad_policy(rng) if rng.random() < 0.7 else _policy(rng) for _ in range(n)],
        "load": [_load_bytes(rng) for _ in range(max(n // 10, 10))],
        "refusal": [{"policy": _policy(rng), "spec": _config(rng),
                     "entry": _pick(rng, [None, {}, {"tools": {}}, {"tools": {"t": {}}},
                                          {"instructions": "x"}, {"prompts": []}])}
                    for _ in range(n)],
    }


@unittest.skipUnless(NODE, "node is not installed")
class TestDifferential(unittest.TestCase):
    def test_both_languages_answer_random_inputs_alike(self) -> None:
        for seed in (1, 2, 3):
            batch = random_batch(seed, 400)
            py, js = python_answers(batch), js_answers(batch)
            for section in SECTIONS:
                for item, a, b in zip(batch[section], py[section], js[section]):
                    if a != b:
                        self.fail(f"seed {seed}, {section}: {item!r}\n  python: {a!r}\n  js:     {b!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
