"""Showing the change, not the first 160 characters of something that changed.

`MCPA015` is the finding this project exists to produce: a tool whose
description was rewritten after you approved it. Its evidence printed the
first 160 characters of the approved text and the first 160 of the live text.
A description longer than that -- and a poisoned one usually is, because the
payload is appended to something that reads normally -- produced two
*identical* lines under the words "fingerprint changed":

    tool 'read_file' fingerprint changed
          was: 'Read a file from the filesystem. Read a file from the file...'
          now: 'Read a file from the filesystem. Read a file from the file...'

The finding was correct and its evidence showed nothing. Worse, it showed
nothing in a way that reads like the tool is fine: a reader comparing those
two lines sees no difference and concludes the fingerprint is being fussy.
That is the single demo this tool is sold on, and it hid the payload.

So the window follows the divergence instead of the beginning. Two pieces:

**Find where they differ, then clip around that.** A change at character 900
is shown at character 900, with enough either side to read it in context.

**Say when the answer is not in the lockfile.** The lock stores a prefix of
the approved text, not all of it, so a change past the end of that prefix
cannot be displayed -- the old bytes were never written down. Printing the
prefix twice implies "these are the same"; what is true is "the recorded text
ran out here". The recorded length is kept alongside the preview so the two
cases can be told apart and the second can be said out loud.

The fingerprint is what proves a change happened and is computed over the
whole text either way. Nothing here is load-bearing for detection; it is
load-bearing for whether a human can act on it.
"""

from __future__ import annotations

# How much of the approved text a lockfile keeps. Only a reading aid -- the
# fingerprint covers the whole string -- but 160 was short enough that an
# ordinary tool description overflowed it, which is what made a rewritten
# description undiffable. Long enough now to hold a real description, short
# enough that a server with many tools does not turn the lock into a corpus.
PREVIEW_CHARS = 1024

# Characters shown either side of the first divergence.
CONTEXT = 90

ELLIPSIS = "..."


def first_difference(was: str, now: str) -> int:
    """Index of the first character that differs.

    When one string is a prefix of the other, that is its length: the point
    where one of them stopped having anything to say.
    """
    for index, (left, right) in enumerate(zip(was, now)):
        if left != right:
            return index
    return min(len(was), len(now))


def window(text: str, at: int, *, before: int = CONTEXT,
           after: int = CONTEXT) -> str:
    """`text` around `at`, quoted, with `...` outside the quotes for a clip.

    Asymmetric on purpose at the call sites that need it. When text has been
    appended, the divergence is the *start* of the interesting part and
    everything worth reading is after it, so an evenly centred window spends
    half its width on text the reader has already accepted -- and, in the
    case that produced this, stopped short of the payload.

    The markers sit outside the repr. Inside, they would be
    indistinguishable from three dots that are really in the description --
    and a tool description is attacker-controlled text, so anything that can
    be forged to look like our own output eventually is. repr also escapes
    the control characters such text may carry (T-REDACT).
    """
    start = max(0, at - before)
    end = min(len(text), at + after)
    clipped = text[start:end]
    head = ELLIPSIS if start > 0 else ""
    tail = ELLIPSIS if end < len(text) else ""
    return f"{head}{clipped!r}{tail}"


# Looking forward from an append: a little of what came before for bearings,
# and enough after it to hold the thing that was added.
LOOKBACK = 30
LOOKAHEAD = 2 * CONTEXT


def changed_text(was: str, now: str, *, recorded_length: int | None = None,
                 indent: str = "      ") -> str:
    """The `was:` / `now:` block for a text that changed since approval.

    `was` is what the lockfile recorded, which may be a prefix of what was
    actually approved; `recorded_length` is how long the real thing was, when
    the lock knows. `now` is the live text in full -- pass it unclipped, the
    windowing here is the only place it should be shortened.
    """
    at = first_difference(was, now)

    if at >= len(now):
        # `now` ran out first: the server shortened its own text, and there
        # is no differing character to point at. Checked before the
        # divergence branch, which would otherwise window a `now` that simply
        # stops and leave the reader to notice the missing ellipsis.
        return "\n".join([
            f"{indent}was: {window(was, at)}",
            f"{indent}now: text ends at character {len(now)}",
        ])

    if at < len(was):
        # A real divergence, inside what was written down. Both sides are
        # windowed at the same offset so the lines stay comparable.
        lines = [f"{indent}was: {window(was, at)}",
                 f"{indent}now: {window(now, at)}"]
        if at > CONTEXT:
            lines.append(f"{indent}     (first difference at character {at})")
        return "\n".join(lines)

    ahead = window(now, at, before=LOOKBACK, after=LOOKAHEAD)

    if recorded_length is None:
        # An entry written before the length was recorded. Whether the
        # approved text continued past here is genuinely unknown, and saying
        # "text ended" would assert something this lockfile cannot support.
        return "\n".join([
            f"{indent}was: recorded text ends at character {len(was)}; this "
            f"entry does not say how long the approved text was",
            f"{indent}now: {ahead}",
            f"{indent}     (re-approve to record the full text and its length)",
        ])

    if recorded_length > len(was):
        # The recorded prefix matches, so the change is past the end of it and
        # the old bytes are simply not in the lockfile. Say that rather than
        # printing the prefix twice.
        return "\n".join([
            f"{indent}was: {len(was)} of {recorded_length} characters were "
            f"recorded, and they still match",
            f"{indent}now: {ahead}",
            f"{indent}     (the change is past character {len(was)}; "
            f"re-approve to record the new text in full)",
        ])

    # Appended to text that was recorded in full: the addition is the change,
    # and it starts exactly where the approved text ended.
    return "\n".join([
        f"{indent}was: text ended at character {len(was)}",
        f"{indent}now: {ahead}",
    ])
