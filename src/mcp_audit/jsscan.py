"""The same question as sourcescan.py, asked of JavaScript and TypeScript.

MCPA030 reads Python: does a handler parameter reach a shell? Most MCP servers
are not Python. The official servers repository is TypeScript, and so is the
larger of the two official SDKs, so a Python-only check covers the minority of
the ecosystem.

This file said, for several cycles, that doing JavaScript meant parsing
JavaScript and that a regex pretending to be a parser is a downgrade. That is
still true, and this is not a regex. It is a tokenizer -- comments, single and
double quotes, template literals with nested `${}`, and the regex-literal
ambiguity -- plus binding resolution and brace-matched scopes. It is not a
full parser and does not claim to be; there is no type checking and no control
flow here.

WHY THE BINDING MATTERS MORE THAN THE PATTERN
---------------------------------------------
`exec(` appears constantly in real TypeScript and is almost never a shell:

    const match = /^description:\\s*(.+)$/m.exec(markdown);   // RegExp
    db.exec(`CREATE TABLE ...`);                             // sqlite
    const { stdout } = await exec(cmd);                      // child_process

Only the third is a shell. Telling them apart needs to know what `exec` is
bound to at that point in the file, which is import tracking, which is the one
thing a line-based scanner cannot do. Of the three, a regex reports all three
or none.

So the identifiers are resolved first:

    import { exec } from "node:child_process"      -> exec is a shell
    import cp from "child_process"                 -> cp.exec is a shell
    const { execSync } = require("child_process")  -> execSync is a shell
    const run = promisify(exec)                    -> run is a shell

and anything not reached that way is left alone, however much it looks like a
command.

WHAT IS A SINK
--------------
`exec` and `execSync` always take a command string and always use a shell.
`spawn`, `spawnSync`, `execFile` and `execFileSync` take an argv array and
reach a shell only when handed `shell: true` -- so they are reported only
then. That asymmetry is the whole remediation: `execFile("wc", ["-l", path])`
is the fix, and reporting it would be reporting the fix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

SHELL_MODULES = {"child_process", "node:child_process"}

# Always spawn a shell, and take the command as one string.
ALWAYS_SHELL = {"exec", "execSync"}
# Take argv, and only reach a shell when told to.
SHELL_ON_REQUEST = {"spawn", "spawnSync", "execFile", "execFileSync"}
# Not a shell; the same ending.
EVAL_SINKS = {"eval"}

# Call names that register something the model can invoke. Counted in the
# official TypeScript sources: registerTool 625, setRequestHandler 497,
# tool 51.
HANDLER_REGISTRARS = {"registerTool", "tool", "setRequestHandler", "resource",
                      "prompt", "registerResource", "registerPrompt"}

_ID = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# After one of these, a `/` begins a regular expression rather than division.
_REGEX_OK_AFTER_KEYWORD = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
}


@dataclass
class Token:
    kind: str        # id | num | str | punct | regex | tmpl
    value: str
    line: int
    pos: int


@dataclass
class JsFlow:
    path: str
    line: int
    function: str
    parameter: str
    sink: str
    snippet: str
    via: str = ""
    confidence: float = 1.0


def tokenize(text: str) -> list[Token]:
    """Tokens, with comments dropped and literals kept whole.

    The point of tokenizing rather than matching lines is that a brace inside
    a string, a `//` inside a URL and a `${}` inside a template all stop being
    special. Template substitutions are tokenized inline, because the
    identifiers inside them are exactly what taint needs to see.
    """
    tokens: list[Token] = []
    i, line, n = 0, 1, len(text)

    def previous_significant() -> Token | None:
        return tokens[-1] if tokens else None

    while i < n:
        ch = text[i]

        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r":
            i += 1
            continue

        # Comments
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            end = n if j < 0 else j + 2
            line += text.count("\n", i, end)
            i = end
            continue

        # Strings
        if ch in "'\"":
            start, quote = i, ch
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\":
                    i += 1
                if i < n and text[i] == "\n":
                    line += 1
                i += 1
            i += 1
            tokens.append(Token("str", text[start:i], line, start))
            continue

        # Template literals, with their substitutions tokenized inline.
        if ch == "`":
            start = i
            i += 1
            tokens.append(Token("tmpl", "`", line, start))
            while i < n and text[i] != "`":
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                    depth, j = 1, i + 2
                    while j < n and depth:
                        if text[j] == "{":
                            depth += 1
                        elif text[j] == "}":
                            depth -= 1
                        elif text[j] in "'\"`":
                            quote, j = text[j], j + 1
                            while j < n and text[j] != quote:
                                j += 2 if text[j] == "\\" else 1
                        j += 1
                    inner = text[i + 2:j - 1]
                    for sub in tokenize(inner):
                        tokens.append(Token(sub.kind, sub.value, line, i))
                    line += text.count("\n", i, j)
                    i = j
                    continue
                if text[i] == "\n":
                    line += 1
                i += 1
            i += 1
            continue

        # Regex literal or division, decided by what came before.
        if ch == "/":
            prev = previous_significant()
            is_regex = True
            if prev is not None:
                if prev.kind in ("id", "num", "str") and prev.value not in _REGEX_OK_AFTER_KEYWORD:
                    is_regex = False
                elif prev.kind == "punct" and prev.value in (")", "]", "}"):
                    is_regex = False
            if is_regex:
                start = i
                i += 1
                in_class = False
                while i < n:
                    c = text[i]
                    if c == "\\":
                        i += 2
                        continue
                    if c == "[":
                        in_class = True
                    elif c == "]":
                        in_class = False
                    elif c == "/" and not in_class:
                        break
                    elif c == "\n":
                        break
                    i += 1
                i += 1
                while i < n and text[i].isalpha():
                    i += 1
                tokens.append(Token("regex", text[start:i], line, start))
                continue

        match = _ID.match(text, i)
        if match:
            tokens.append(Token("id", match.group(0), line, i))
            i = match.end()
            continue

        if ch.isdigit():
            j = i
            while j < n and (text[j].isalnum() or text[j] in "._"):
                j += 1
            tokens.append(Token("num", text[i:j], line, i))
            i = j
            continue

        tokens.append(Token("punct", ch, line, i))
        i += 1

    return tokens


def _matching(tokens: list[Token], start: int, open_ch: str, close_ch: str) -> int:
    """Index of the token closing the group that opens at `start`."""
    depth = 0
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token.kind != "punct":
            continue
        if token.value == open_ch:
            depth += 1
        elif token.value == close_ch:
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def resolve_shell_bindings(tokens: list[Token]) -> tuple[set[str], set[str], set[str]]:
    """(always_shell, shell_on_request, module_aliases) as local names.

    This is the part a regex cannot do, and the reason `/re/.exec(s)` and
    `db.exec(sql)` are not reported while `exec(cmd)` from child_process is.
    """
    always: set[str] = set()
    on_request: set[str] = set()
    modules: set[str] = set()

    def module_string(token: Token) -> bool:
        return token.kind == "str" and token.value.strip("'\"") in SHELL_MODULES

    for index, token in enumerate(tokens):
        window = tokens[index:index + 40]

        # import ... from "child_process"
        if token.kind == "id" and token.value == "import":
            end = next((k for k, t in enumerate(window)
                        if module_string(t)), None)
            if end is None:
                continue
            if not any(t.kind == "id" and t.value == "from" for t in window[:end]):
                continue
            names = window[1:end]
            if any(t.kind == "punct" and t.value == "{" for t in names):
                for t in names:
                    if t.kind == "id" and t.value in ALWAYS_SHELL:
                        always.add(t.value)
                    elif t.kind == "id" and t.value in SHELL_ON_REQUEST:
                        on_request.add(t.value)
            else:
                for t in names:
                    if t.kind == "id" and t.value not in ("from", "as", "type"):
                        modules.add(t.value)

        # const { exec } = require("child_process")  /  const cp = require(...)
        if token.kind == "id" and token.value == "require":
            after = tokens[index:index + 4]
            if not any(module_string(t) for t in after):
                continue
            before = tokens[max(0, index - 12):index]
            if any(t.kind == "punct" and t.value == "}" for t in before):
                for t in before:
                    if t.kind == "id" and t.value in ALWAYS_SHELL:
                        always.add(t.value)
                    elif t.kind == "id" and t.value in SHELL_ON_REQUEST:
                        on_request.add(t.value)
            else:
                for k in range(len(before) - 1, -1, -1):
                    if before[k].kind == "id" and before[k].value not in ("const", "let", "var", "await"):
                        modules.add(before[k].value)
                        break

    # const run = promisify(exec) -- the common async wrapper.
    for index, token in enumerate(tokens):
        if token.kind != "id" or token.value != "promisify":
            continue
        inner = [t.value for t in tokens[index:index + 8] if t.kind == "id"]
        wrapped_always = any(name in ALWAYS_SHELL for name in inner)
        wrapped_request = any(name in SHELL_ON_REQUEST for name in inner)
        if not (wrapped_always or wrapped_request):
            continue
        for k in range(index - 1, max(0, index - 10), -1):
            if tokens[k].kind == "punct" and tokens[k].value == "=":
                for j in range(k - 1, max(0, k - 4), -1):
                    if tokens[j].kind == "id" and tokens[j].value not in ("const", "let", "var"):
                        (always if wrapped_always else on_request).add(tokens[j].value)
                        break
                break

    return always, on_request, modules


def _call_name(tokens: list[Token], index: int) -> tuple[str, str]:
    """(dotted_name, base) for the call whose '(' is at `index`.

    A chain rooted in something that is not an identifier -- /re/.exec(s),
    "str".replace(...), arr[0].exec(...) -- returns an empty base, because the
    method belongs to that literal rather than to any imported name. Without
    this, a file that imports `exec` from child_process and also uses a
    regular expression would have every /re/.exec() read as a shell.
    """
    parts: list[str] = []
    k = index - 1
    rooted_in_literal = False
    while k >= 0:
        if tokens[k].kind == "id":
            parts.append(tokens[k].value)
            if k - 1 >= 0 and tokens[k - 1].kind == "punct" and tokens[k - 1].value == ".":
                previous = tokens[k - 2] if k - 2 >= 0 else None
                if previous is not None and (
                        previous.kind in ("regex", "str", "num", "tmpl")
                        or (previous.kind == "punct" and previous.value in (")", "]"))):
                    rooted_in_literal = True
                    break
                k -= 2
                continue
        break
    parts.reverse()
    if rooted_in_literal:
        return ".".join(parts), ""
    return ".".join(parts), (parts[0] if parts else "")


def _has_shell_true(tokens: list[Token], start: int, end: int) -> bool:
    for k in range(start, end):
        if tokens[k].kind == "id" and tokens[k].value == "shell":
            for j in range(k + 1, min(k + 4, end)):
                if tokens[j].kind == "id" and tokens[j].value == "true":
                    return True
    return False


def _first_arg_is_array(tokens: list[Token], open_paren: int, close_paren: int) -> bool:
    k = open_paren + 1
    return k < close_paren and tokens[k].kind == "punct" and tokens[k].value == "["


def find_handlers(tokens: list[Token]) -> list[tuple[str, list[str], int, int]]:
    """(registrar, parameter names, body start, body end) for each handler.

    The callback is the last function-valued argument of registerTool, tool or
    setRequestHandler. Its parameters are what the model supplies.
    """
    out: list[tuple[str, list[str], int, int]] = []
    for index, token in enumerate(tokens):
        if not (token.kind == "punct" and token.value == "("):
            continue
        name, _base = _call_name(tokens, index)
        if name.split(".")[-1] not in HANDLER_REGISTRARS:
            continue
        close = _matching(tokens, index, "(", ")")

        # Find the arrow of the callback, at the call's own depth.
        depth = 0
        arrow = None
        for k in range(index, close):
            t = tokens[k]
            if t.kind == "punct":
                if t.value in "([{":
                    depth += 1
                elif t.value in ")]}":
                    depth -= 1
                elif t.value == "=" and depth == 1 and k + 1 < close:
                    nxt = tokens[k + 1]
                    if nxt.kind == "punct" and nxt.value == ">":
                        arrow = k
        if arrow is None:
            continue

        # Parameters: either `(a, b) =>` or a single bare identifier.
        params: list[str] = []
        k = arrow - 1

        # TypeScript puts the return type between the two:
        #     async (args): Promise<CallToolResult> => { ... }
        # which is the shape the official `everything` server is written in,
        # so skipping back over it is not a nicety.
        if not (tokens[k].kind == "punct" and tokens[k].value == ")") and \
                tokens[k].kind != "id":
            j = k
            while j > index and not (tokens[j].kind == "punct" and tokens[j].value == ")"):
                j -= 1
            if j > index:
                k = j

        if tokens[k].kind == "punct" and tokens[k].value == ")":
            open_params = None
            depth = 0
            for j in range(k, index, -1):
                if tokens[j].kind == "punct" and tokens[j].value == ")":
                    depth += 1
                elif tokens[j].kind == "punct" and tokens[j].value == "(":
                    depth -= 1
                    if depth == 0:
                        open_params = j
                        break
            if open_params is not None:
                colon_depth = 0
                expect = True
                for j in range(open_params + 1, k):
                    t = tokens[j]
                    if t.kind == "punct":
                        if t.value in "({[":
                            colon_depth += 1
                        elif t.value in ")}]":
                            colon_depth -= 1
                        elif t.value == ",} " .strip() and colon_depth == 0:
                            expect = True
                        elif t.value == "," and colon_depth == 0:
                            expect = True
                        elif t.value == ":":
                            expect = False
                    elif t.kind == "id" and expect:
                        params.append(t.value)
                        expect = False
        elif tokens[k].kind == "id":
            params.append(tokens[k].value)

        body_start = arrow + 2
        while body_start < close and tokens[body_start].kind == "punct" and \
                tokens[body_start].value == ":":
            body_start += 1
        if body_start < len(tokens) and tokens[body_start].kind == "punct" and \
                tokens[body_start].value == "{":
            body_end = _matching(tokens, body_start, "{", "}")
        else:
            body_end = close
        if params:
            out.append((name, params, body_start, body_end))
    return out


def analyze_js(text: str, path: str) -> list[JsFlow]:
    """Handler parameters reaching a shell, in this file."""
    try:
        tokens = tokenize(text)
    except (RecursionError, ValueError):
        return []
    if not tokens:
        return []

    always, on_request, modules = resolve_shell_bindings(tokens)
    if not (always or on_request or modules):
        return []

    lines = text.splitlines()
    flows: list[JsFlow] = []
    seen: set[tuple[int, str]] = set()

    for registrar, params, body_start, body_end in find_handlers(tokens):
        tainted = set(params)

        for k in range(body_start, body_end):
            token = tokens[k]

            # const cmd = `... ${x} ...`  -- taint travels through assignment.
            if token.kind == "punct" and token.value == "=" and \
                    k + 1 < body_end and not (tokens[k + 1].kind == "punct" and
                                              tokens[k + 1].value == "="):
                target = tokens[k - 1] if k else None
                end = k + 1
                while end < body_end and not (tokens[end].kind == "punct" and
                                              tokens[end].value in ";}"):
                    end += 1
                if target is not None and target.kind == "id":
                    if any(t.kind == "id" and t.value in tainted
                           for t in tokens[k + 1:end]):
                        tainted.add(target.value)

            if not (token.kind == "punct" and token.value == "("):
                continue
            name, base = _call_name(tokens, k)
            if not name:
                continue
            leaf = name.split(".")[-1]

            # Resolution comes first and the well-known name second. An alias
            # -- const run = promisify(exec) -- is a shell under a name that
            # appears in no list, so checking the leaf against a hardcoded set
            # before consulting the bindings meant aliases were never found.
            # Every branch requires a base. A call rooted in a literal --
            # /re/.exec(s) -- has none, and without this check its leaf name
            # still matched the imported `exec` in any file that imported one,
            # which is most of the official SDK.
            is_sink = False
            if not base:
                continue
            if name in always or base in always:
                is_sink = True
            elif leaf in ALWAYS_SHELL and base and base in modules:
                is_sink = True
            elif leaf in EVAL_SINKS and len(name.split(".")) == 1 and base:
                is_sink = True
            elif (name in on_request or (base and base in on_request)
                  or (leaf in SHELL_ON_REQUEST and base and base in modules)):
                close = _matching(tokens, k, "(", ")")
                is_sink = _has_shell_true(tokens, k, close) and \
                    not _first_arg_is_array(tokens, k, close)
            if not is_sink:
                continue

            close = _matching(tokens, k, "(", ")")
            carried = next((t.value for t in tokens[k + 1:close]
                            if t.kind == "id" and t.value in tainted), None)
            if carried is None:
                continue

            line = token.line
            key = (line, leaf)
            if key in seen:
                continue
            seen.add(key)
            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            flows.append(JsFlow(
                path=path,
                line=line,
                function=registrar,
                parameter=carried,
                sink=(f"{name}(shell: true)"
                      if leaf in SHELL_ON_REQUEST else f"{name}()"),
                snippet=snippet[:200],
            ))

    return flows


def looks_like_mcp_js(text: str) -> bool:
    return ("modelcontextprotocol" in text or "registerTool" in text
            or "setRequestHandler" in text or "McpServer" in text)


def iter_flows(text: str, path: str) -> Iterable[JsFlow]:
    if not looks_like_mcp_js(text):
        return []
    return analyze_js(text, path)
