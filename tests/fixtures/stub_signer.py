"""A signer and verifier for tests, so the mechanism can be tested alone.

`--sign-command` is meant to be pointed at `ssh-keygen -Y sign`, an age
identity, or a KMS CLI. Tests must not depend on any of those being installed,
and they must not depend on a real key existing either -- so this stands in
for one, exactly as `tests/test_wire_shape.py` stands a local stub in for the
Anthropic API.

It is an HMAC over a fixed secret, which is not a signature and is not
pretending to be. What is under test is the delegation: that the guard hands
the right payload to a command, keeps what comes back, binds it into the
chain, and that a verifier rejects a payload that was not the one signed.

    sign:    python stub_signer.py sign          < payload  > signature
    verify:  python stub_signer.py verify {sig}  < payload
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys

SECRET = b"a-test-signing-secret"
WRONG = b"the-wrong-signing-secret"


def _mac(payload: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest().encode("ascii")


def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write("usage: stub_signer.py sign|verify [sigfile]\n")
        return 2
    mode = argv[0]
    payload = sys.stdin.buffer.read()
    secret = WRONG if os.environ.get("STUB_SIGNER_WRONG_KEY") else SECRET

    if mode == "sign":
        if os.environ.get("STUB_SIGNER_FAIL"):
            sys.stderr.write("the agent said no\n")
            return 1
        sys.stdout.buffer.write(_mac(payload, secret))
        return 0

    if mode == "verify":
        if len(argv) < 2:
            sys.stderr.write("verify needs a signature file\n")
            return 2
        try:
            with open(argv[1], "rb") as fh:
                offered = fh.read()
        except OSError as exc:
            sys.stderr.write(f"cannot read signature: {exc}\n")
            return 2
        if hmac.compare_digest(offered, _mac(payload, secret)):
            return 0
        sys.stderr.write("signature does not match this payload\n")
        return 1

    sys.stderr.write(f"unknown mode {mode}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
