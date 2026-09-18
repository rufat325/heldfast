"""An append-only record of what the guard did, that cannot be edited quietly.

The guard enforces the lockfile. This is the evidence that it did, and that
nobody has since rewritten the story: every entry carries the hash of the one
before it, so removing, reordering or altering a line breaks the chain from
that point on and `mcp-audit verify-log` says exactly where.

This is the cheap half of the idea. It proves nobody edited the file after the
fact; it does not prove who wrote it, because that needs a signing key and a
key needs somewhere to live, and a dependency-free scanner has no business
inventing key management. Tamper-evidence is worth having on its own and is
honest about being that and not attestation.

**Arguments are never written.** A tool call's arguments are exactly where a
credential or a customer's data would be, and a security tool that quietly
copies both into a log file on disk has created the problem it was installed
to find. Names, methods, decisions and sizes are recorded; values are not.
That is a deliberate limit, not an oversight: the log answers "what happened"
and refuses to answer "with what".
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

# Fields that make up the hashed body, in a fixed order. Hashing a dict
# rendered with sort_keys would be enough, but naming the fields means an
# entry written by a newer version cannot silently change what was signed.
_BODY_FIELDS = ("seq", "time", "server", "event", "subject", "decision", "detail", "prev")


def _digest(body: dict[str, Any]) -> str:
    canonical = json.dumps({k: body.get(k) for k in _BODY_FIELDS},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Broken:
    line: int
    reason: str


@dataclass
class VerifyResult:
    entries: int = 0
    ok: bool = True
    problems: list[Broken] = field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            return f"{self.entries} entries, chain intact"
        first = self.problems[0]
        return (f"{self.entries} entries, chain broken at line {first.line}: "
                f"{first.reason}")


class AuditLog:
    """Append-only, hash-chained JSON lines."""

    def __init__(self, path: str | os.PathLike, server: str) -> None:
        self.path = Path(path)
        self.server = server
        self.seq = 0
        self.prev = GENESIS
        self.failed: str | None = None
        self._resume()

    def _resume(self) -> None:
        """Continue an existing chain rather than starting a second one.

        A guard restarted against the same log has to pick up the last hash,
        or verification sees two chains and reports the join as tampering.
        """
        try:
            if not self.path.exists():
                return
            last = None
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        last = line
            if last is None:
                return
            entry = json.loads(last)
            self.seq = int(entry.get("seq", 0))
            self.prev = str(entry.get("hash", GENESIS))
        except (OSError, ValueError, TypeError) as exc:
            # A log we cannot read is not a reason to refuse to run: the proxy
            # exists to pass traffic, and losing the audit trail is better
            # than losing the server.
            self.failed = f"could not resume {self.path}: {exc}"

    def record(self, event: str, *, subject: str = "", decision: str = "",
               detail: str = "") -> None:
        if self.failed:
            return
        self.seq += 1
        body = {
            "seq": self.seq,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "server": self.server,
            "event": event,
            "subject": subject,
            "decision": decision,
            "detail": detail,
            "prev": self.prev,
        }
        body["hash"] = _digest(body)
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(body, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            self.failed = f"could not append to {self.path}: {exc}"
            return
        self.prev = body["hash"]


def verify(path: str | os.PathLike) -> VerifyResult:
    """Walk the chain and report the first line that does not add up."""
    result = VerifyResult()
    target = Path(path)
    if not target.exists():
        result.ok = False
        result.problems.append(Broken(0, f"{target} does not exist"))
        return result

    expected_prev = GENESIS
    expected_seq = 1
    with target.open("r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            raw = raw.strip()
            if not raw:
                continue
            result.entries += 1
            try:
                entry = json.loads(raw)
            except ValueError:
                result.problems.append(Broken(number, "not valid JSON"))
                break

            recorded = entry.get("hash")
            if _digest(entry) != recorded:
                result.problems.append(
                    Broken(number, "contents do not match the recorded hash"))
                break
            if entry.get("prev") != expected_prev:
                result.problems.append(
                    Broken(number, "does not follow the previous entry"))
                break
            if entry.get("seq") != expected_seq:
                result.problems.append(
                    Broken(number, f"sequence jumped to {entry.get('seq')}, "
                                   f"expected {expected_seq}"))
                break
            expected_prev = str(recorded)
            expected_seq += 1

    result.ok = not result.problems
    return result
