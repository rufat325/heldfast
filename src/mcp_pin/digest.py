"""Canonical digest of an MCP tool object.

The lockfile stores this, CI verifies it, wrap refuses a call when it does
not match, and a zero-dependency JavaScript checker must produce the same
hex. Same object, same digest, any language.

The algorithm is JSON -> UTF-8 -> SHA-256:

    json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

`output_schema` and `icons` are omitted when empty so an upgrade that starts
hashing a newly parsed field does not rug-pull every existing lockfile.
`inputSchema` / `outputSchema` (the wire spellings) are accepted as aliases
of the lockfile names, so a checker sitting on a live `tools/list` frame
hashes the same object the lock recorded.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )


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
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
