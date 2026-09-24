"""Text that reads as English to a human and does not match an English regex.

MCPA010 is a set of phrase patterns, so it is defeated by any spelling of the
phrase it does not know. Most of those are out of scope and say so -- a rule
written in English will not catch an injection written in Russian, and
promising otherwise would be a lie. One is not out of scope, because the text
is *still English*:

    Ignоre all previоus instructiоns

That is the Cyrillic small letter o, U+043E, in place of the Latin one. A
reviewer reads the sentence perfectly; the model reads the sentence perfectly;
`re` does not match it. Nothing about it is a different language, so nothing
about it belongs in the bucket labelled "we do not do other languages".

So agent-facing text is folded to a skeleton -- confusable code points mapped
to the Latin letters they imitate -- and the signals run over that as well as
over the original.

**The fold is the identity on ASCII.** Every character it maps is outside
ASCII, so any text that was already ASCII comes back unchanged and cannot
produce a finding it did not produce before. That is the precision argument,
and it is a property rather than a measurement: `tests/test_evasions.py`
asserts it over the corpus of real tool text this repo ships.

Scope is deliberately narrow. Only scripts with Latin look-alikes are folded
-- Cyrillic, Greek, Armenian, Cherokee, and the fullwidth forms. CJK is not
confusable with Latin letters and is left alone, which matters because Latin
mixed into Chinese or Japanese prose is ordinary and flagging it would be
noise. The mapping is not the full Unicode confusables table; it is the
letters that appear in real homoglyph attacks, which are the ones that look
like ASCII at a glance.
"""

from __future__ import annotations

import re
import unicodedata

# Confusable code point -> the ASCII letter it imitates. Read as "somebody
# could substitute this and the sentence would still look right".
_CONFUSABLE = {
    # Cyrillic
    "а": "a", "А": "A", "е": "e", "Е": "E",
    "о": "o", "О": "O", "р": "p", "Р": "P",
    "с": "c", "С": "C", "у": "y", "У": "Y",
    "х": "x", "Х": "X", "і": "i", "І": "I",
    "ј": "j", "Ј": "J", "һ": "h", "Н": "H",
    "В": "B", "М": "M", "Т": "T", "К": "K",
    "г": "r", "д": "d", "з": "3", "ӏ": "l",
    "Ѕ": "S", "ѕ": "s", "ѵ": "v", "Ѵ": "V",
    # Greek
    "α": "a", "Α": "A", "ε": "e", "Ε": "E",
    "ο": "o", "Ο": "O", "ρ": "p", "Ρ": "P",
    "ι": "i", "Ι": "I", "κ": "k", "Κ": "K",
    "ν": "v", "Ν": "N", "υ": "u", "Υ": "Y",
    "τ": "t", "Τ": "T", "Β": "B", "Μ": "M",
    "Η": "H", "Χ": "X", "Ζ": "Z", "Θ": "O",
    # Armenian
    "ա": "a", "զ": "q", "հ": "h", "ռ": "n",
    "ո": "n", "օ": "o", "կ": "k",
    # Cherokee
    "Ꭰ": "D", "Ꭱ": "R", "Ꭲ": "T", "Ꭺ": "G",
    "Ꭼ": "Z", "Ꮃ": "W", "Ꮎ": "O", "Ꮐ": "G",
    "Ꮓ": "S", "Ꮟ": "b", "Ꮩ": "V", "Ꮮ": "L",
    # Dotless i, which reads as i in almost any font
    "ı": "i",
}
# A mapping key that is not one character cannot be a code-point substitution,
# so it is a typo rather than a rule, and it must not ship as one.
_CONFUSABLE = {k: v for k, v in _CONFUSABLE.items() if len(k) == 1}

# Scripts whose letters imitate Latin. Used to decide whether a *word* mixes
# scripts in a way that has no innocent explanation.
_LATINISH = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")
# Letters only: no digits, underscores, hyphens or other punctuation.
_LETTER_RUNS = re.compile(r"[^\W\d_]+")


def fold(text: str) -> str:
    """Map confusable code points to the ASCII letters they imitate.

    The identity on ASCII input, by construction: every key is non-ASCII.
    Fullwidth and other compatibility forms are handled by NFKC, which is
    also the identity on ASCII.
    """
    if not text:
        return text
    if text.isascii():
        return text
    folded = unicodedata.normalize("NFKC", text)
    return "".join(_CONFUSABLE.get(ch, ch) for ch in folded)


def mixed_script_words(text: str, limit: int = 5) -> list[str]:
    """Words mixing Latin letters with letters that imitate them.

    Not "words containing two scripts" -- Latin inside Chinese or Japanese
    prose is ordinary and flagging it would be noise. This is the narrower
    thing: a single word built from Latin *and* Cyrillic/Greek/Armenian/
    Cherokee letters, which is what a homoglyph substitution leaves behind
    and has close to no innocent use in a tool description.
    """
    if not text or text.isascii():
        return []
    out: list[str] = []
    # A run of letters, not a whitespace-separated word. Ukrainian and
    # Russian technical writing joins a Latin term to a Cyrillic one with a
    # hyphen -- "MCP-сервис", "email-шаблон" -- and splitting on spaces made
    # every such compound a "mixed word". A substitution happens inside a
    # run of letters; a hyphen between two scripts is punctuation.
    for word in _LETTER_RUNS.findall(text):
        latin = confusable = False
        for ch in word:
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            if name.startswith("LATIN"):
                latin = True
            # A letter that imitates a Latin one, not merely any Greek or
            # Cyrillic letter: "ΔG" is Gibbs energy, and Δ passes for nothing.
            elif ch in _CONFUSABLE and name.startswith(_LATINISH):
                confusable = True
        if latin and confusable:
            out.append(word)
            if len(out) >= limit:
                break
    return out
