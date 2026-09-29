"""Did a changed tool gain anything addressed to the agent?

A pin that refuses every change is correct and, measured, unusable: across
the 150 most-downloaded registry servers it stops on 45% of upgrades, and
29% of upgrades reword a description (docs/CHURN.md). Of 1,634 changed tool
definitions in that study, none was hostile. A control that interrupts that
often gets muted, and a muted control still looks like coverage.

This answers the narrower question an upgrade actually raises: compared with
the text that was approved, does the live definition *introduce* a signal --
an instruction to conceal, override or exfiltrate, a hidden character, a
credential path, a look-alike letter, a price. Text the approved version
already said is not introduced; it was reviewed.

A price is not aimed at the agent, but for an agent that pays per call it is
part of what was approved: the feed saw one server raise three tools' prices
three to five times in a change graded quiet. Any amount the approved text
did not state is introduced -- a rise, a cut, a new one -- and an amount
written differently (`$0.05`, `$0.050`) is the same amount. Dollars (`$`,
USD, USDC) and the service units the feed shows (credits, sats) count; a
size (`$80M`, `$100K`) does not. The description is a signal, not the bill:
what is charged is set at call time.

The approved side is what the lockfile recorded: the description preview
(the first PREVIEW_CHARS characters) and its full length. Nothing else was
stored, so everything else in the live definition -- the rest of a long
description, the title, every description inside the input and output
schemas -- is compared against an empty baseline. A signal there counts as
introduced even if an earlier version said the same thing. That costs a few
refusals (9 against 2 with full text, over the same 1,634 changes) and never
lets through what the lock cannot vouch for.

This is a heuristic gate, not a proof. A rewrite phrased to miss every
pattern is forwarded. Which is why `guard --drift graded` is opt-in, and the
default stays: a changed tool is refused.

Pure: no I/O, no environment, the same inputs give the same answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping

from .confusables import mixed_script_words
from .rules.poisoning import SENSITIVE_PATHS, _scan_text, invisible_runs

# review.py's critical words. Kept here too so the runtime gate and the
# approval grade cannot disagree about what counts.
CRITICAL_NEEDLES = (
    "id_rsa", ".ssh/", ".aws/", "begin private", "ignore previous",
    "exfiltrat", "~/.cursor", "do not tell the user",
)

_SPACE = re.compile(r"\s+")

# The two forms prices take in the feed: "$0.012 per call", "0.05 USDC".
# Another form is added with an example from the feed, not in anticipation.
# An amount starts where a number starts. Without the lookbehind every digit
# of a long run was a fresh start, and a description of 100,000 digits took
# minutes to grade (tests/test_redos.py).
_AMOUNT = r"(?<![\d.,])(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?|\.\d+)"
PRICES = (re.compile(r"\$\s?" + _AMOUNT),
          re.compile(_AMOUNT + r"\s?USDC?\b", re.IGNORECASE))
# Prices the feed also states in a service's own units: "debits 8 credits",
# "200 sats per edit". Kept apart from dollars: 8 credits is not $8.
UNIT_PRICES = (("credits", re.compile(_AMOUNT + r"\s?credits?\b", re.IGNORECASE)),
               ("sats", re.compile(_AMOUNT + r"\s?(?:sats?|satoshis?)\b", re.IGNORECASE)))
# "$80M", "US $100K", "$2bn": a size, not what a call costs. Every other
# amount counts. Requiring price words nearby instead ("per call", "costs")
# was measured on the feed and missed real prices phrased without them --
# "$50.10 as a Deadline Notice", "1.00 USD specialist operation" -- and a
# price change that passes as quiet is worse than one review too many.
_SIZE = re.compile(r"\s?(?:[kmb]|bn|mn|million|billion|thousand)\b", re.IGNORECASE)


def _priced(text: str, match: "re.Match[str]") -> bool:
    return _SIZE.match(text, match.end()) is None


def _amount(text: str) -> str:
    """One spelling per amount: "0.050000" and "0.05" are the same price."""
    try:
        value = Decimal(text.replace(",", ""))
    except InvalidOperation:
        return text
    plain = format(value.normalize(), "f")
    return plain if value else "0"


@dataclass(frozen=True, order=True)
class Signal:
    kind: str
    match: str

    def __str__(self) -> str:
        return f"{self.kind} {self.match!r}"


def _norm(text: str) -> str:
    return _SPACE.sub(" ", text).strip().lower()[:120]


def signals(text: str) -> set[Signal]:
    """Every signal in `text`, keyed so the same words found twice are one."""
    out: set[Signal] = set()
    if not text:
        return out
    for sig, m in _scan_text(text, strict=False):
        out.add(Signal("signal:" + sig.category, _norm(m.group(0))))
    for _, codepoint, kind in invisible_runs(text):
        out.add(Signal("hidden:" + kind, codepoint))
    for m in SENSITIVE_PATHS.finditer(text):
        out.add(Signal("credential-path", _norm(m.group(0))))
    for word in mixed_script_words(text):
        out.add(Signal("confusable", word))
    for pattern in PRICES:
        for m in pattern.finditer(text):
            if _priced(text, m):
                out.add(Signal("price", _amount(m.group(1))))
    for unit, pattern in UNIT_PRICES:
        for m in pattern.finditer(text):
            out.add(Signal("price", f"{_amount(m.group(1))} {unit}"))
    lowered = text.lower()
    for needle in CRITICAL_NEEDLES:
        if needle in lowered:
            out.add(Signal("critical-word", needle))
    return out


def schema_text(node: Any, depth: int = 0) -> list[str]:
    """Every `description` and `title` string anywhere in a JSON schema.

    The model reads these as surely as the top-level description, and they
    are where a careful rewrite would put an instruction. Past a nesting
    depth no real schema reaches, the walk stops and says so, rather than
    returning what it had and calling it everything.
    """
    if depth > 64:
        return ["\x00schema nested past the depth this reads"]
    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("description", "title") and isinstance(value, str):
                out.append(value)
            else:
                out.extend(schema_text(value, depth + 1))
    elif isinstance(node, list):
        for value in node:
            out.extend(schema_text(value, depth + 1))
    return out


def approved_baseline(recorded: Mapping[str, Any] | None) -> set[Signal]:
    """Signals in the text the lock says was approved.

    Only the recorded preview is known. When the description was longer than
    the preview, the tail was never seen by this file and contributes nothing.
    """
    if not isinstance(recorded, Mapping):
        return set()
    preview = recorded.get("description_preview")
    return signals(preview) if isinstance(preview, str) else set()


def live_text(description: str, title: str, annotations: Mapping[str, Any],
              input_schema: Any, output_schema: Any) -> str:
    parts = [description or "", title or ""]
    ann_title = annotations.get("title") if isinstance(annotations, Mapping) else None
    if isinstance(ann_title, str):
        parts.append(ann_title)
    parts.extend(schema_text(input_schema))
    parts.extend(schema_text(output_schema))
    return "\n".join(p for p in parts if p)


def introduced(recorded: Mapping[str, Any] | None, live: str) -> list[Signal]:
    """Signals in the live definition that the approved text did not carry.

    An empty list is the only answer that lets a changed tool through graded
    mode. The schema-depth marker is always introduced: a definition this
    could not read to the end is not one it can call clean.
    """
    found = signals(live)
    if "\x00schema nested past the depth this reads" in live:
        found.add(Signal("unreadable", "schema nested too deep to read"))
    return sorted(found - approved_baseline(recorded))


def describe(found: Iterable[Signal], limit: int = 3) -> str:
    items = list(found)
    head = ", ".join(str(s) for s in items[:limit])
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return head + more
