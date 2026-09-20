"""An append-only record of what the guard did, that cannot be edited quietly.

The guard enforces the lockfile. This is the evidence that it did, and that
nobody has since rewritten the story: every entry carries the hash of the one
before it, so removing, reordering or altering a line breaks the chain from
that point on and `mcp-pin verify-log` says exactly where.

This is the cheap half of the idea, and it is worth being exact about which
half, because an unkeyed chain has two holes that a one-line description of it
hides.

**Any prefix of a valid chain is a valid chain.** Cutting the tail off the file
removes the denial you wanted to hide and leaves something that verifies
perfectly. There is nothing inside the file that can fix this: the fix has to
be a record of where the chain had got to, kept somewhere else. So the writer
keeps a `.head` sidecar -- the last sequence number and hash -- and `verify`
compares the two. `verify-log --expect-head/--expect-count` is the same check
with the values supplied out of band, for when the sidecar is as writable as
the log.

**An unkeyed chain can be recomputed.** The adversary here is a malicious MCP
server that already runs as the user, so it can already write the log; with
SHA-256 alone, dropping an entry and re-chaining the rest costs it one loop.
Setting `MCP_PIN_LOG_KEY` switches the chain to HMAC-SHA256, which that loop
cannot produce. It is not a general answer -- a same-user process can often
read another's environment -- but it raises the cost from trivial to
situational, and the guard does not pass the variable to the server it wraps
(see childenv). With no key set, this is tamper-*evidence* and says so.

It does not prove who wrote the record. That needs a signing key with somewhere
durable to live, and a dependency-free scanner has no business inventing key
management.

**Arguments are never written.** A tool call's arguments are exactly where a
credential or a customer's data would be, and a security tool that quietly
copies both into a log file on disk has created the problem it was installed
to find. Names, methods, decisions and sizes are recorded; values are not.
That is a deliberate limit, not an oversight: the log answers "what happened"
and refuses to answer "with what".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

# The environment variable that turns the chain from a hash into a MAC.
KEY_VAR = "MCP_PIN_LOG_KEY"
HMAC_ALG = "hmac-sha256"

# Fields that make up the hashed body, in a fixed order. Hashing a dict
# rendered with sort_keys would be enough, but naming the fields means an
# entry written by a newer version cannot silently change what was signed.
_BODY_FIELDS = ("seq", "time", "server", "event", "subject", "decision", "detail", "prev")


def log_key() -> bytes | None:
    """The MAC key from the environment, or None for a plain hash chain."""
    raw = os.environ.get(KEY_VAR) or ""
    return raw.encode("utf-8") if raw else None


def _canonical(body: dict[str, Any]) -> bytes:
    fields = {k: body.get(k) for k in _BODY_FIELDS}
    # Written only when the chain is keyed, so an existing unkeyed log hashes
    # exactly as it did before this field existed. A field added to the hash
    # unconditionally would invalidate every log already on disk.
    if body.get("alg"):
        fields["alg"] = body["alg"]
    return json.dumps(fields, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(body: dict[str, Any], key: bytes | None = None) -> str:
    canonical = _canonical(body)
    if key:
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return hashlib.sha256(canonical).hexdigest()


def head_path(path: str | "os.PathLike[str]") -> Path:
    """Where the running head of the chain is kept, beside the log."""
    target = Path(path)
    return target.with_name(target.name + ".head")


def read_head(path: str | "os.PathLike[str]") -> dict[str, Any] | None:
    """The recorded head, or None when there is not one to read."""
    try:
        raw = head_path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class Broken:
    line: int
    reason: str


@dataclass
class VerifyResult:
    entries: int = 0
    ok: bool = True
    problems: list[Broken] = field(default_factory=list)
    # "hmac-sha256" when the chain was keyed, "sha256" otherwise. The
    # difference decides whether this is evidence or something an attacker
    # with write access can simply regenerate, so the summary says which.
    mode: str = "sha256"

    @property
    def keyed(self) -> bool:
        return self.mode == HMAC_ALG

    def summary(self) -> str:
        how = "keyed" if self.keyed else "unkeyed"
        if self.ok:
            return f"{self.entries} entries, chain intact ({how})"
        first = self.problems[0]
        where = f" at line {first.line}" if first.line else ""
        return (f"{self.entries} entries, chain broken{where}: "
                f"{first.reason}")


class AuditLog:
    """Append-only, hash-chained JSON lines."""

    def __init__(self, path: str | "os.PathLike[str]", server: str,
                 key: bytes | None = None) -> None:
        self.path = Path(path)
        self.server = server
        self.key = log_key() if key is None else key
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
        body: dict[str, Any] = {
            "seq": self.seq,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "server": self.server,
            "event": event,
            "subject": subject,
            "decision": decision,
            "detail": detail,
            "prev": self.prev,
        }
        if self.key:
            body["alg"] = HMAC_ALG
        body["hash"] = _digest(body, self.key)
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(body, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            self.failed = f"could not append to {self.path}: {exc}"
            return
        self.prev = str(body["hash"])
        self._write_head()

    def _write_head(self) -> None:
        """Record where the chain has got to, beside the log.

        Truncation cannot be detected from inside the file -- a prefix of a
        valid chain is a valid chain -- so the only thing that catches it is a
        note of the expected length kept outside it. Written whole and renamed
        over the old one, so a crash mid-write leaves the previous head rather
        than half of a new one.
        """
        head = head_path(self.path)
        payload = json.dumps({"seq": self.seq, "hash": self.prev,
                              "alg": HMAC_ALG if self.key else "sha256",
                              "server": self.server}, sort_keys=True)
        temp = head.with_name(head.name + ".tmp")
        try:
            temp.write_text(payload + "\n", encoding="utf-8")
            os.replace(temp, head)
        except OSError:
            # The log is the record; the head is a check on it. Losing the
            # check must not stop the proxy passing traffic.
            pass


def verify(path: str | "os.PathLike[str]", key: bytes | None = None, *,
           expect_head: str | None = None,
           expect_count: int | None = None) -> VerifyResult:
    """Walk the chain, then check it is the *whole* chain.

    Walking alone only proves internal consistency, and a prefix of a valid
    chain is internally consistent -- which is why a truncated log used to
    verify clean. Three things are compared afterwards: the `.head` sidecar the
    writer keeps, and an `expect_head` / `expect_count` supplied out of band
    for when the sidecar is as writable as the log.
    """
    result = VerifyResult()
    target = Path(path)
    if key is None:
        key = log_key()
    result.mode = HMAC_ALG if key else "sha256"
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
            if key and entry.get("alg") != HMAC_ALG:
                result.problems.append(
                    Broken(number, "a key is configured and this entry is not "
                                   "keyed, so it was not written by this chain"))
                break
            if not key and entry.get("alg") == HMAC_ALG:
                result.problems.append(
                    Broken(number, f"this entry is keyed; set {KEY_VAR} to "
                                   f"check it"))
                break
            if _digest(entry, key) != recorded:
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

    if not result.problems:
        _check_completeness(result, path, expected_prev, expect_head, expect_count)

    result.ok = not result.problems
    return result


def _check_completeness(result: VerifyResult, path: str | "os.PathLike[str]",
                        head: str, expect_head: str | None,
                        expect_count: int | None) -> None:
    """Is this the whole chain, or a prefix somebody left behind?

    Everything above this point is answerable from inside the file, and
    truncation is not: cutting the tail off removes whatever you wanted hidden
    and leaves a chain that verifies. These three comparisons are the only
    things that catch it, and each needs a fact from outside the file.
    """
    if expect_count is not None and result.entries != expect_count:
        result.problems.append(Broken(
            0, f"expected {expect_count} entries and found {result.entries}"))
    if expect_head is not None and head != expect_head:
        result.problems.append(Broken(
            0, f"chain ends at {head[:16]}, expected {expect_head[:16]}"))

    recorded = read_head(path)
    if not recorded:
        return
    seq, claimed = recorded.get("seq"), str(recorded.get("hash") or "")
    if not isinstance(seq, int):
        return
    # Direction is the whole discriminator, and it is why this can be reported
    # at all. The head is written *after* the entry it describes, so a killed
    # process leaves the head behind the log -- never ahead of it. A head that
    # knows about entries the log no longer has is removal, not a crash.
    if seq > result.entries:
        result.problems.append(Broken(
            0, f"the head file records {seq} entries and the log has "
               f"{result.entries}; {seq - result.entries} have been removed"))
    elif seq == result.entries and claimed and claimed != head:
        result.problems.append(Broken(
            0, "the head file records a different final entry; the log has "
               "been rewritten"))
