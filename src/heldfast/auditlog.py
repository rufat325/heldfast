"""An append-only record of what the guard did, that cannot be edited quietly.

The guard enforces the lockfile. This is the evidence that it did, and that
nobody has since rewritten the story: every entry carries the hash of the one
before it, so removing, reordering or altering a line breaks the chain from
that point on and `heldfast verify-log` says exactly where.

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

And when neither is there, the summary says so. Deleting the sidecar is cheaper
than forging one, so "no sidecar" must not print the sentence a complete log
prints -- the same reason `keyed` and `unkeyed` are distinguished rather than
both reading "intact".

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
    # Same conditional treatment as `alg`, for the same reason: an entry
    # without a signature must hash as it always did.
    if body.get("sig"):
        fields["sig"] = body["sig"]
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


SEGMENT_EVENT = "segment"
SEGMENT_PREFIX = "heldfast-segment"


def segment_payload(seq: int, head: str) -> bytes:
    """Exactly what a signer signs: the chain's length and where it ended.

    Short and unambiguous on purpose. A signature over "the file" would be a
    signature over whatever the reader happens to have; this commits to a
    specific prefix of a specific chain, which is the claim worth making.
    """
    return f"{SEGMENT_PREFIX}:{int(seq)}:{head}".encode("utf-8")


def split_command(command: str) -> list[str]:
    r"""Split a command line the way the platform means it.

    `shlex` has no good setting for Windows. With `posix=True` it eats the
    backslashes out of `C:\Python\python.exe`; with `posix=False` it leaves
    the quotes attached to the token, so the quoted path is looked up
    literally, quotes and all. Neither finds the program. So: split without
    posix rules, then strip the quotes that splitting was supposed to consume.

    Raw, and it has to be: the path above made this docstring a string with an
    invalid escape in it. That is a SyntaxWarning today and a SyntaxError from
    Python 3.15, and cached bytecode hides it from everyone except a user
    installing for the first time -- which is the worst audience to show it to.
    `compileall` under `-W error::SyntaxWarning` is a CI job for this reason.
    """
    import shlex

    if os.name != "nt":
        return shlex.split(command)
    out = []
    for token in shlex.split(command, posix=False):
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
        out.append(token)
    return out


class Signer:
    """Signing delegated to a command, because the key must not live here.

    The roadmap entry this closes said "needs a key, which needs somewhere to
    live". The answer is that it should not live in this process at all. An
    operator already has somewhere: ssh-agent, a smartcard, a KMS CLI, a
    password manager's agent. So the guard hands a short payload to a command
    on stdin and keeps whatever comes back on stdout.

        heldfast guard --log trail.jsonl \\
          --sign-command "ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n heldfast -q"

    With `ssh-keygen -Y sign -U` the private key stays in the agent and this
    process never sees it. That is the strongest form available without
    inventing key management, and it is why there is no `--signing-key` flag:
    a key passed to this process is a key this process can leak.

    What it does *not* do, stated because the vocabulary of signing invites
    more credit than it earns: on a machine where the attacker already runs as
    you -- the threat model for a malicious MCP server -- it can ask the same
    agent to sign the same payloads. Signing raises tampering from "edit a
    file" to "be present while the guard is running and hold the agent", and
    it makes offline, after-the-fact rewriting of a closed segment impossible.
    It is not proof against a live same-user adversary, and nothing on the same
    host is.
    """

    def __init__(self, command: str, name: str = "", timeout: float = 20.0) -> None:
        self.command = command
        self.name = name or "external-signer"
        self.timeout = timeout
        self.failed: str | None = None

    def sign(self, payload: bytes) -> str | None:
        """The signature, base64 of whatever the command returned, or None."""
        import base64
        import subprocess

        try:
            argv = split_command(self.command)
            proc = subprocess.run(argv, input=payload, capture_output=True,
                                  timeout=self.timeout, check=False)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            self.failed = f"signer failed: {exc}"
            return None
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", errors="replace").strip()[:120]
            self.failed = f"signer exited {proc.returncode}: {tail}"
            return None
        if not proc.stdout.strip():
            self.failed = "signer produced no signature"
            return None
        return base64.b64encode(proc.stdout).decode("ascii")


def verify_segment(command: str, payload: bytes, signature: str,
                   timeout: float = 20.0) -> tuple[bool, str]:
    """Check one segment by handing payload and signature to a command.

    Symmetrical with `Signer`: the public key, the allowed-signers file and the
    policy about which identities count all live wherever the operator keeps
    them, not here.
    """
    import base64
    import binascii
    import subprocess
    import tempfile

    try:
        raw = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error):
        return False, "signature is not valid base64"
    handle = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as fh:
            fh.write(raw)
            handle = fh.name
        argv = [a.replace("{sig}", handle) for a in split_command(command)]
        proc = subprocess.run(argv, input=payload, capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return False, f"verifier failed: {exc}"
    finally:
        if handle:
            try:
                os.unlink(handle)
            except OSError:
                pass
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", errors="replace").strip()[:120]
        return False, f"verifier rejected it: {tail or 'exit %d' % proc.returncode}"
    return True, "signature accepted"


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
    # (through_seq, head_hash, signature, signer) for each signed segment.
    segments: list[tuple[int, str, str, str]] = field(default_factory=list)
    signatures_checked: int = 0
    # Whether anything outside the file confirmed this is the *whole* chain.
    # "head" -- the sidecar agreed. "expected" -- values supplied out of band
    # agreed. "unchecked" -- neither was available, so a truncated tail is
    # invisible. Deleting the sidecar is easier than forging it, and without
    # this the two produced the same sentence as a genuinely complete log.
    completeness: str = "unchecked"

    @property
    def keyed(self) -> bool:
        return self.mode == HMAC_ALG

    def summary(self) -> str:
        how = "keyed" if self.keyed else "unkeyed"
        if self.ok:
            sealed = ""
            if self.signatures_checked:
                sealed = f", {self.signatures_checked} signed segment(s) verified"
            elif self.segments:
                sealed = (f", {len(self.segments)} signed segment(s) not checked "
                          f"(pass --verify-command)")
            if self.completeness == "unchecked":
                how += (", no head file -- a truncated tail would not be "
                        "visible; pass --expect-count")
            return f"{self.entries} entries, chain intact ({how}){sealed}"
        first = self.problems[0]
        where = f" at line {first.line}" if first.line else ""
        return (f"{self.entries} entries, chain broken{where}: "
                f"{first.reason}")


class AuditLog:
    """Append-only, hash-chained JSON lines."""

    def __init__(self, path: str | "os.PathLike[str]", server: str,
                 key: bytes | None = None, signer: "Signer | None" = None) -> None:
        self.path = Path(path)
        self.server = server
        self.key = log_key() if key is None else key
        self.signer = signer
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
               detail: str = "", signature: str = "") -> None:
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
        if signature:
            body["sig"] = signature
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

    def close_segment(self) -> bool:
        """Sign where the chain has reached and record it as an entry.

        A signature over a prefix is what stops that prefix being rewritten
        later: an attacker who recomputes an unkeyed chain can produce every
        hash and cannot produce this. Called at session end, and callable
        periodically by anything that wants shorter windows.
        """
        if self.failed or self.signer is None:
            return False
        signature = self.signer.sign(segment_payload(self.seq, self.prev))
        if signature is None:
            return False
        self.record(SEGMENT_EVENT, subject=self.signer.name,
                    detail=f"through={self.seq}", signature=signature)
        return True

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
           expect_count: int | None = None,
           verify_command: str | None = None) -> VerifyResult:
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
            # A segment signs the head as it stood *before* this entry, so
            # capture that rather than the running value after it.
            if entry.get("event") == SEGMENT_EVENT and entry.get("sig"):
                result.segments.append((int(entry.get("seq") or 0) - 1,
                                        str(expected_prev),
                                        str(entry.get("sig")),
                                        str(entry.get("subject") or "")))
            expected_prev = str(recorded)
            expected_seq += 1

    if not result.problems and verify_command:
        _check_segments(result, verify_command)
    if not result.problems:
        _check_completeness(result, path, expected_prev, expect_head, expect_count)

    result.ok = not result.problems
    return result


def _check_segments(result: VerifyResult, command: str) -> None:
    """Verify every signed segment, or say which one failed.

    A segment commits to a prefix of the chain, so a verified one means that
    prefix cannot have been rewritten -- which is the part an unkeyed hash
    chain cannot give you at all.
    """
    for through, head, signature, signer in result.segments:
        ok, detail = verify_segment(command, segment_payload(through, head), signature)
        if not ok:
            result.problems.append(Broken(
                0, f"segment through entry {through} signed by {signer or 'unknown'} "
                   f"did not verify: {detail}"))
            return
        result.signatures_checked += 1


def _check_completeness(result: VerifyResult, path: str | "os.PathLike[str]",
                        head: str, expect_head: str | None,
                        expect_count: int | None) -> None:
    """Is this the whole chain, or a prefix somebody left behind?

    Everything above this point is answerable from inside the file, and
    truncation is not: cutting the tail off removes whatever you wanted hidden
    and leaves a chain that verifies. These three comparisons are the only
    things that catch it, and each needs a fact from outside the file.
    """
    if expect_count is not None or expect_head is not None:
        result.completeness = "expected"
    if expect_count is not None and result.entries != expect_count:
        result.problems.append(Broken(
            0, f"expected {expect_count} entries and found {result.entries}"))
    if expect_head is not None and head != expect_head:
        result.problems.append(Broken(
            0, f"chain ends at {head[:16]}, expected {expect_head[:16]}"))

    recorded = read_head(path)
    if not recorded:
        # No sidecar, so nothing outside the file says how long it should be.
        # The summary has to say that rather than print the sentence a complete
        # log prints: removing the sidecar is cheaper than forging one.
        return
    seq, claimed = recorded.get("seq"), str(recorded.get("hash") or "")
    if not isinstance(seq, int):
        return
    # Direction is the whole discriminator, and it is why this can be reported
    # at all. The head is written *after* the entry it describes, so a killed
    # process leaves the head behind the log -- never ahead of it. A head that
    # knows about entries the log no longer has is removal, not a crash.
    result.completeness = "head"
    if seq > result.entries:
        result.problems.append(Broken(
            0, f"the head file records {seq} entries and the log has "
               f"{result.entries}; {seq - result.entries} have been removed"))
    elif seq == result.entries and claimed and claimed != head:
        result.problems.append(Broken(
            0, "the head file records a different final entry; the log has "
               "been rewritten"))
