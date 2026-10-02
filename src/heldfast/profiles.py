"""Second tool-digest profiles, published beside the native digest.

The native digest in `digest.py` is what lockfiles and the public lookup
record, and it does not change. A profile here is a different question asked
of the same served definition, under a label another party publishes, so that
two records can be compared byte for byte.

`agentavow.mcp-tool-definition.v1` is AgentAvow's. This is an implementation
of the rules as that profile states them, written from a description of them;
no file from AgentAvow's repository is vendored here, and none of its text
is copied. heldfast reproduces the digests and key encoding. It makes no claim
about anything AgentAvow does with them.

The profile hashes the tool as the server *served* it, so it reads the wire
spellings only (`inputSchema`, `outputSchema`). The native digest also accepts
the lockfile's snake_case spellings; this one does not, because a second
spelling would be a field the profile never named.

NOTHING IN THIS MODULE MAY RAISE
--------------------------------
A profile digest is an extra written beside a record that already stands on
its own. A hostile server can put a lone surrogate in a name, a value
`json.loads` produced that no canonical form can express, or nest a schema
past Python's recursion limit. Each of those returns `None` and the caller
leaves the field out; none of them may take the native record down with it.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Optional

from heldfast.digest import canonical_json

PROFILE_AGENTAVOW_V1 = "agentavow.mcp-tool-definition.v1"

# The only fields the profile reads. `_meta` and anything a server adds are
# never hashed, so a field this tuple does not name cannot move the digest.
_AGENTAVOW_V1_FIELDS = ("name", "title", "description", "inputSchema",
                        "outputSchema", "annotations")

# A key body longer than this is cut to _KEY_KEEP characters, then "~" and
# the first _KEY_HASH hex characters of the SHA-256 of the raw name.
_KEY_MAX = 128
_KEY_KEEP = 96
_KEY_HASH = 16


def agentavow_v1_digest(tool: Any) -> Optional[str]:
    """`"sha256:<hex>"` of the profile preimage, or None if it cannot be built.

    A field that is missing or null is omitted, not hashed as `null`. Anything
    else is hashed as served, whatever its type: restricting the shape is the
    profile's business, and a wrong-typed value is evidence, not an error.
    """
    try:
        if not isinstance(tool, Mapping):
            return None
        served = {field: tool[field] for field in _AGENTAVOW_V1_FIELDS
                  if tool.get(field) is not None}
        preimage = canonical_json(
            {"profile": PROFILE_AGENTAVOW_V1, "tool": served})
        # canonical_json escapes every surrogate, so this encode cannot fail;
        # surrogatepass is the same belt `tool_digest` wears.
        digest = hashlib.sha256(
            preimage.encode("utf-8", "surrogatepass")).hexdigest()
        return "sha256:" + digest
    except Exception:  # noqa: BLE001 - a profile must never break the record
        return None


def agentavow_v1_key(name: Any) -> Optional[str]:
    """`"tool:<body>"` for a tool name, or None if the name cannot be encoded.

    The body keeps the bytes 0x21-0x7E except `%` and `=`, and writes every
    other UTF-8 byte as `%XX` in uppercase. A body past 128 characters is cut
    at a plain character count -- which can land inside a `%XX` -- and joined
    to a digest of the whole name, so two long names that share a prefix
    still get different keys.
    """
    try:
        if not isinstance(name, str):
            return None
        raw = name.encode("utf-8")
    except Exception:  # noqa: BLE001 - a lone surrogate has no UTF-8 form
        return None
    body = "".join(
        chr(byte) if 0x21 <= byte <= 0x7E and byte not in (0x25, 0x3D)
        else "%%%02X" % byte
        for byte in raw)
    if len(body) > _KEY_MAX:
        body = (body[:_KEY_KEEP] + "~"
                + hashlib.sha256(raw).hexdigest()[:_KEY_HASH])
    return "tool:" + body
