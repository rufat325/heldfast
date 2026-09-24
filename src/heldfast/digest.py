"""Canonical digest of an MCP tool object.

The lockfile stores this, CI verifies it, wrap refuses a call when it does
not match, and a zero-dependency JavaScript checker must produce the same
hex. Same object, same digest, any language.

The algorithm is RFC 8785 (JSON Canonicalization Scheme) -> UTF-8 -> SHA-256.

WHY JCS AND NOT `json.dumps(sort_keys=True)`
--------------------------------------------
The previous algorithm was Python's `json.dumps` with sorted keys, and the
JavaScript side approximated it. The two did not agree, which is the one
thing this module exists to prevent. Five ways they diverged, every one of
them reachable from an ordinary server:

- `1.0` -- Python wrote `1.0`, JavaScript wrote `1`. Pydantic and FastMCP
  emit `"minimum": 0.0`-style bounds constantly, so this was not exotic: it
  made the plugin hook report drift on correctly approved tools.
- `1e16` -- Python wrote `1e+16`, JavaScript wrote `10000000000000000`.
- Integers that lose precision as doubles, which JavaScript cannot
  represent exactly and Python can.
- `-0.0` -- Python wrote `-0.0`, JavaScript wrote `0`.
- Keys mixing BMP and astral characters: Python sorts by code point,
  JavaScript's `Array.prototype.sort` by UTF-16 code unit.

JCS pins all five: it defines ECMAScript number formatting and UTF-16
code-unit key ordering. It also defines escaping for lone surrogates, which
`str.encode("utf-8")` refuses outright -- a hostile server could previously
take `approve` and `scan` down with a lone surrogate in a description.

The shared golden vectors in `tests/golden/jcs_vectors.json` are checked from
both languages, so the two implementations cannot drift apart again in
silence.

`output_schema` and `icons` are omitted when empty so an upgrade that starts
hashing a newly parsed field does not rug-pull every existing lockfile.
`inputSchema` / `outputSchema` (the wire spellings) are accepted as aliases
of the lockfile names, so a checker sitting on a live `tools/list` frame
hashes the same object the lock recorded.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Mapping

# JSON's own two-character escapes. RFC 8785 section 3.2.2.2 defers to
# ECMAScript `JSON.stringify`, which is exactly this table plus \u00xx for
# the rest of C0.
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_EXPONENT = re.compile(r"^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$")


def _escape(text: str) -> str:
    """A JSON string literal, escaped the way `JSON.stringify` escapes.

    Lone surrogates become `\\udXXX` escapes rather than raising. They are
    legal in a JSON document and a server can put one in a description, so
    refusing to hash them let that server crash the tool.
    """
    out = ['"']
    for char in text:
        escape = _ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif char < "\x20" or "\ud800" <= char <= "\udfff":
            out.append("\\u%04x" % ord(char))
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _number(value: Any) -> str:
    """ECMAScript `Number::toString`, which is what JCS specifies.

    Python and JavaScript already agree on the shortest round-tripping digits
    -- both produce a shortest repr -- so the work here is the formatting
    around them: no trailing `.0` on an integral value, `-0` folded to `0`,
    and exponent notation only outside the range ECMAScript writes in full.
    """
    if isinstance(value, int):
        # Python's ints are arbitrary precision and JavaScript's numbers are
        # doubles, so this is the one place the two languages can hold
        # genuinely different values for the same JSON text. The test is not
        # magnitude -- 10000000000000000 is above 2**53 and still exact --
        # but whether the double round-trip loses anything. It refuses here,
        # at approve time, rather than recording a digest the JavaScript
        # checker would compute differently and report as drift forever.
        try:
            as_double = float(value)
        except OverflowError:
            raise ValueError(
                "integer %d is too large to be a JSON number" % value) from None
        if as_double != value:
            raise ValueError(
                "integer %d cannot round-trip through a JavaScript number, so "
                "no canonical form can agree across both implementations"
                % value)
        value = as_double
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not JSON numbers")
    if value == 0:
        # ECMAScript String(-0) is "0", so JCS folds the sign away.
        return "0"
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    text = repr(value)
    match = _EXPONENT.match(text)
    if match is None:
        return text
    sign, lead, rest, exponent = match.groups()
    power = int(exponent)
    digits = lead + (rest or "")
    # ECMAScript writes decimals in full between 1e-7 and 1e21 and uses
    # exponent notation outside that window.
    if 0 < power < 21:
        return sign + digits.ljust(power + 1, "0")
    if -7 < power < 0:
        return sign + "0." + "0" * (-power - 1) + digits
    mantissa = lead + ("." + rest if rest else "")
    return "%s%se%s%d" % (sign, mantissa, "+" if power > 0 else "-", abs(power))


def _key(text: str) -> tuple[int, ...]:
    """Sort key: UTF-16 code units, as RFC 8785 section 3.2.3 requires.

    Python sorts strings by code point, so an astral character -- two
    surrogate code units in UTF-16 -- sorts after U+FFFF here but between
    U+D7FF and U+E000 in JavaScript. Encoding to UTF-16 first makes the two
    orderings the same.
    """
    return tuple(text.encode("utf-16-be", "surrogatepass"))


def canonical_json(value: Any) -> str:
    """RFC 8785 canonical form of a JSON value."""
    if value is None:
        return "null"
    # bool before int: `isinstance(True, int)` is True in Python.
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(((str(k), v) for k, v in value.items()),
                       key=lambda kv: _key(kv[0]))
        return "{" + ",".join(
            _escape(k) + ":" + canonical_json(v) for k, v in items) + "}"
    raise TypeError("unsupported digest value: " + type(value).__name__)


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def tool_body(tool: Mapping[str, Any]) -> dict[str, Any]:
    """The object that is hashed. Stable across Python and JavaScript."""
    schema = tool.get("input_schema")
    if schema is None:
        schema = tool.get("inputSchema")
    annotations = tool.get("annotations")
    body: dict[str, Any] = {
        "name": str(tool.get("name") or ""),
        "title": str(tool.get("title") or ""),
        "description": str(tool.get("description") or ""),
        "input_schema": _mapping(schema),
        "annotations": _mapping(annotations),
    }
    output = tool.get("output_schema")
    if output is None:
        output = tool.get("outputSchema")
    if isinstance(output, dict) and output:
        body["output_schema"] = dict(output)
    icons = tool.get("icons")
    if isinstance(icons, list) and icons:
        body["icons"] = list(icons)
    return body


def tool_digest(tool: Mapping[str, Any]) -> str:
    payload = canonical_json(tool_body(tool))
    # surrogatepass cannot fire -- _escape already turned every surrogate
    # into an ASCII escape -- but encoding is where the old crash happened,
    # so the guarantee is spelled out rather than assumed.
    return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()
