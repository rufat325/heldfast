"""Does this MCP server hand a tool argument to a shell?

Everything else in this package reads what a server *declares* -- its config,
its tool descriptions, what it returns. This reads what a server *is*: the
source of the server itself, looking for one specific defect.

An MCP tool parameter is model-controlled. Whatever is steering the agent
chooses its value, and anything that can steer the agent -- a poisoned tool
description, a malicious document, a web page the agent was asked to read --
chooses it too. When that value reaches a shell, the server author has written
remote code execution into their own tool and will usually not know it.

    @mcp.tool()
    def count_lines(path: str) -> str:
        return subprocess.run(f"wc -l {path}", shell=True, capture_output=True)

This is parsed, not grepped. The distinction matters more than it sounds:

- `shlex.quote(path)` clears the taint, so code that does the right thing is
  silent. A line-based scanner sees `subprocess.run` and a variable and
  reports it anyway, which trains people to ignore the scanner.
- `subprocess.run(["wc", "-l", path])` is not reported at all. That is the
  argv form, it never reaches a shell, and it is the fix -- flagging it would
  be flagging the remediation.
- Taint survives f-strings, concatenation, `%`, `.format()` and intermediate
  assignments, none of which a single-line pattern can follow.

Scope, stated plainly because a security tool that overstates its reach is
worse than one that does less:

- Python here; JavaScript and TypeScript in jsscan.py, which had to be given
  a tokenizer of its own. Same question, different machinery, because one
  language ships a parser in the standard library and the other does not.
  Neither is a regex: in JavaScript the whole difficulty is that `exec(` is
  usually a RegExp or a database, and telling those from child_process needs
  the import binding.
- Tools, resources and prompts, because all three take model-chosen input.
  Not CLI entry points: click.command is driven by whoever is at the keyboard.
- One hop. A tool parameter handed to a helper defined in the same module is
  followed into it, because that is how real servers are written -- the
  low-level SDK shape is a `call_tool` dispatcher that forwards to helpers,
  and stopping at the handler would find nothing outside a tutorial. Two hops
  would need a call graph, and a half-built call graph reports paths that do
  not exist.
- No findings here mean "no shell injection", only "none of this shape".
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Only files that look like an MCP server are parsed. Walking a repository and
# parsing every .py file would cost far more than it finds.
_MCP_MARKERS = (
    "modelcontextprotocol", "fastmcp", "from mcp", "import mcp",
    "call_tool", "mcp.tool", "FastMCP", "list_tools",
)

# Decorators that mark a function as reachable with model-chosen input. Only
# the receiver's *attribute* is matched, never the object it hangs off: real
# code writes mcp.tool, server.tool, app.tool, provider.tool, sub_app.tool and
# a dozen other names, and matching the receiver would cover one of them.
#
# Tools are not the whole surface, which is the same mistake this project made
# once already one layer up. A resource template's parameters come out of the
# URI the model asks for -- @mcp.resource("greeting://{name}") binds `name`
# from the request -- and a prompt's arguments arrive in prompts/get. Both are
# as model-controlled as a tool argument and were going unread.
#
# list_tools, list_resources and list_prompts take no input and are absent.
# So is `command`: click.command and app.command are CLI entry points, driven
# by whoever is at the keyboard rather than by whatever is steering the agent.
_TOOL_DECORATORS = {
    "tool", "call_tool",
    "resource", "read_resource",
    "prompt", "get_prompt",
}

# Functions that always involve a shell, whatever else is passed.
_ALWAYS_SHELL = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    # Async servers are common here, and these two are the async pair:
    # create_subprocess_shell always runs a shell, create_subprocess_exec
    # never does. Missing the first would hide the same defect behind `await`.
    ("asyncio", "create_subprocess_shell"),
    ("create_subprocess_shell",),
}

# Functions that involve a shell only when asked to.
_SHELL_ON_REQUEST = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
}

# Not a shell, but the same ending.
_EVAL_SINKS = {"eval", "exec"}

# Calls that make a value safe to interpolate. shlex.quote is the documented
# answer; shlex.split produces a list, which cannot be a command string.
_SANITIZERS = {("shlex", "quote"), ("shlex", "split"), ("pipes", "quote")}

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "site-packages", ".eggs",
}

_MAX_BYTES = 2_000_000


@dataclass
class SourceFlow:
    """One tool parameter reaching one shell, in one function."""

    path: str
    line: int
    function: str
    parameter: str
    sink: str
    snippet: str
    via: str = ""          # call chain, when the sink is not in the handler
    confidence: float = 1.0


def _dotted(node: ast.AST) -> tuple[str, ...]:
    """('subprocess', 'run') for subprocess.run, ('eval',) for eval."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return tuple(reversed(parts))


def _is_sanitizer(func: ast.AST) -> bool:
    name = _dotted(func)
    if name in _SANITIZERS:
        return True
    # `from shlex import quote` leaves a bare name. Only that one: urllib's
    # quote percent-encodes for URLs and is not a shell quoting function, so
    # treating every callable named quote as a sanitizer would hide real
    # findings behind a coincidence of naming.
    return name == ("quote",)


def _taint(node: ast.AST | None, tainted: set[str]) -> str | None:
    """The tainted name this expression carries, if any.

    Recursive rather than a flat ast.walk so that a sanitized subexpression
    can stop the search: shlex.quote(path) contains the name `path` and is
    nonetheless clean, and a walk would report it.
    """
    if node is None:
        return None

    if isinstance(node, ast.Name):
        return node.id if node.id in tainted else None

    if isinstance(node, ast.Call):
        if _is_sanitizer(node.func):
            return None
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            found = _taint(arg, tainted)
            if found:
                return found
        # A method called *on* a tainted value keeps it: path.upper().
        return _taint(node.func, tainted)

    for child in ast.iter_child_nodes(node):
        found = _taint(child, tainted)
        if found:
            return found
    return None


def _shell_is_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell":
            return isinstance(kw.value, ast.Constant) and kw.value.value is True
    return False


def _first_arg_is_argv(call: ast.Call) -> bool:
    """A list or tuple first argument is the argv form, which is the fix."""
    return bool(call.args) and isinstance(call.args[0], (ast.List, ast.Tuple))


def _describe(call: ast.Call, name: tuple[str, ...]) -> str | None:
    """The sink this call represents, or None if it is not one."""
    dotted = ".".join(name)
    if name in _ALWAYS_SHELL:
        return f"{dotted}()"
    if name in _SHELL_ON_REQUEST:
        if _shell_is_true(call) and not _first_arg_is_argv(call):
            return f"{dotted}(shell=True)"
        return None
    if len(name) == 1 and name[0] in _EVAL_SINKS:
        return f"{dotted}()"
    return None


def _tool_decorator(decorator: ast.AST) -> bool:
    node = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(node, ast.Attribute):
        return node.attr in _TOOL_DECORATORS
    if isinstance(node, ast.Name):
        return node.id in _TOOL_DECORATORS
    return False


def _parameters(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = fn.args
    names = [p.arg for p in list(getattr(a, "posonlyargs", [])) + a.args + a.kwonlyargs]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return [n for n in names if n not in ("self", "cls")]


def _local_functions(tree: ast.AST) -> dict[str, ast.AST]:
    """Every function defined in this module, by name.

    Real servers rarely shell out inside the handler. The low-level SDK shape
    is a `call_tool` dispatcher that forwards arguments to helpers, and every
    server in the one corpus available here is written that way, so an
    analysis that stops at the handler boundary would find nothing real.
    """
    out: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(node.name, node)
    return out


def _bind_arguments(call: ast.Call, fn, tainted: set[str]) -> set[str]:
    """Parameters of `fn` that receive a tainted argument at this call."""
    params = _parameters(fn)
    seeded: set[str] = set()
    for index, arg in enumerate(call.args):
        if _taint(arg, tainted) and index < len(params):
            seeded.add(params[index])
    for kw in call.keywords:
        if kw.arg and _taint(kw.value, tainted) and kw.arg in params:
            seeded.add(kw.arg)
    return seeded


def _analyze_function(fn, path: str, source_lines: list[str],
                      local_functions: dict[str, ast.AST] | None = None,
                      seeded: set[str] | None = None,
                      origin_name: str = "",
                      chain: tuple[str, ...] = (),
                      depth: int = 0) -> list[SourceFlow]:
    """Walk one handler in source order, carrying taint forward.

    Source order matters and ast.walk does not provide it -- it is
    breadth-first, so a sink could be examined before the assignment that
    taints its argument. Sorting by position approximates execution order for
    straight-line code, which is the shape this analysis claims to handle.
    """
    local_functions = local_functions or {}
    tainted = set(seeded) if seeded is not None else set(_parameters(fn))
    if not tainted:
        return []
    origin = {name: (origin_name or name) for name in tainted}
    flows: list[SourceFlow] = []
    seen: set[tuple[int, str]] = set()

    nodes = [n for n in ast.walk(fn) if hasattr(n, "lineno")]
    nodes.sort(key=lambda n: (n.lineno, getattr(n, "col_offset", 0)))

    for node in nodes:
        # Assignment propagates taint to the names it binds. This does not
        # skip the rest of the loop body: a sink can sit inside the
        # assignment it feeds, as in `out = subprocess.run(cmd, shell=True)`,
        # and that Call is a node in its own right.
        if isinstance(node, ast.Assign):
            found = _taint(node.value, tainted)
            if found:
                for target in node.targets:
                    for sub in ast.walk(target):
                        if isinstance(sub, ast.Name):
                            tainted.add(sub.id)
                            origin.setdefault(sub.id, origin.get(found, found))

        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            found = _taint(node.value, tainted)
            if found and isinstance(node.target, ast.Name):
                tainted.add(node.target.id)
                origin.setdefault(node.target.id, origin.get(found, found))

        if not isinstance(node, ast.Call):
            continue

        name = _dotted(node.func)
        sink = _describe(node, name)

        if sink is None:
            # Not a sink. It may still be a local helper being handed a
            # tainted value, which is how the dispatcher shape reaches a
            # shell. Followed one hop only: deeper needs a call graph, and a
            # half-built one would report paths that do not exist.
            callee = local_functions.get(name[-1]) if name else None
            if (callee is not None and depth < 1 and callee is not fn):
                passed = _bind_arguments(node, callee, tainted)
                if passed:
                    carried = None
                    for arg in list(node.args) + [kw.value for kw in node.keywords]:
                        carried = _taint(arg, tainted)
                        if carried:
                            break
                    flows.extend(_analyze_function(
                        callee, path, source_lines, local_functions,
                        seeded=passed,
                        origin_name=origin.get(carried, carried or ""),
                        chain=chain + (fn.name,),
                        depth=depth + 1,
                    ))
            continue

        found = None
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            found = _taint(arg, tainted)
            if found:
                break
        if not found:
            continue

        line = getattr(node, "lineno", 0)
        key = (line, sink)
        if key in seen:
            continue
        seen.add(key)
        snippet = source_lines[line - 1].strip() if 0 < line <= len(source_lines) else ""
        flows.append(SourceFlow(
            path=path,
            line=line,
            function=fn.name,
            parameter=origin.get(found, found),
            sink=sink,
            snippet=snippet[:200],
            via=" -> ".join(chain + (fn.name,)) if chain else "",
            confidence=1.0 if not chain else 0.9,
        ))

    return flows


def analyze_source(text: str, path: str) -> list[SourceFlow]:
    """Tool parameters that reach a shell in this file."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        # Somebody else's repository may use syntax this interpreter does not
        # have. A file we cannot parse is a file we say nothing about.
        return []

    lines = text.splitlines()
    local_functions = _local_functions(tree)
    flows: list[SourceFlow] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_tool_decorator(d) for d in node.decorator_list):
            continue
        flows.extend(_analyze_function(node, path, lines, local_functions))

    # The same sink can be reached from two handlers; report it once.
    unique: dict[tuple[str, int, str], SourceFlow] = {}
    for flow in flows:
        unique.setdefault((flow.path, flow.line, flow.sink), flow)
    return list(unique.values())


def looks_like_mcp_server(text: str) -> bool:
    return any(marker in text for marker in _MCP_MARKERS)


_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_SOURCE_SUFFIXES = (".py",) + _JS_SUFFIXES


def _as_source_flow(flow: Any) -> SourceFlow:
    """A JsFlow, in the shape the rest of the package already speaks."""
    return SourceFlow(
        path=flow.path, line=flow.line, function=flow.function,
        parameter=flow.parameter, sink=flow.sink, snippet=flow.snippet,
        via=getattr(flow, "via", ""), confidence=getattr(flow, "confidence", 1.0),
    )


def scan_source_tree(roots: Iterable[Path], max_depth: int = 6) -> list[SourceFlow]:
    """Every MCP server under these roots, analyzed.

    Python here, JavaScript and TypeScript in jsscan. They answer the same
    question and are separate because the answer is reached differently: one
    has a parser in the standard library and the other needed a tokenizer
    written for it.
    """
    from . import jsscan

    flows: list[SourceFlow] = []
    seen_files: set[str] = set()

    for root in roots:
        root = Path(root).resolve()
        if root.is_file():
            candidates = [root] if root.suffix in _SOURCE_SUFFIXES else []
        elif root.is_dir():
            candidates = []
            root_depth = len(root.parts)
            for dirpath, dirnames, filenames in os.walk(root):
                here = Path(dirpath)
                if len(here.parts) - root_depth >= max_depth:
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                candidates.extend(here / f for f in filenames
                                  if f.endswith(_SOURCE_SUFFIXES)
                                  and not f.endswith(".d.ts"))
        else:
            continue

        for file in candidates:
            key = str(file.resolve()).lower()
            if key in seen_files:
                continue
            seen_files.add(key)
            try:
                if file.stat().st_size > _MAX_BYTES:
                    continue
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if file.suffix == ".py":
                if looks_like_mcp_server(text):
                    flows.extend(analyze_source(text, str(file)))
            elif jsscan.looks_like_mcp_js(text):
                flows.extend(_as_source_flow(f) for f in jsscan.analyze_js(text, str(file)))

    return flows
