"""Adversarial robustness layer: undo the tricks scammers use to slip past
keyword filters and AI checkers, and record each trick as evidence.

Handles: full-width letters (ＯＴＰ), invisible / zero-width characters,
bidirectional overrides (RTLO file-name spoofing like 'photo‮gpj.apk'),
Cyrillic/Greek look-alike letters (ЅВІ → SBI), leetspeak (0TP, P@N, upd@te),
and spaced-out keywords (O T P, K-Y-C).

Legitimate messages essentially never use these tricks, so their presence is
itself a strong scam signal.
"""

from __future__ import annotations

import re
import unicodedata

INVISIBLE = {"​", "⁠", "﻿", "­", "᠎", "‎", "‏"}
BIDI = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}
JOINERS = {"‌", "‍"}  # legitimate inside Indic words; suspicious inside Latin words

HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ո": "n", "ν": "v",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J", "У": "Y", "Ү": "Y",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l", "!": "i"})

SENSITIVE = {
    "otp", "kyc", "upi", "pin", "upipin", "mpin", "cvv", "apk", "pan", "aadhaar", "aadhar", "password", "account",
    "blocked", "block", "suspended", "bank", "refund", "verify", "update", "lottery", "prize", "winner",
    "police", "arrest", "customs", "parcel", "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay",
    "rbi", "cbi", "kbc", "reward", "bonus", "loan", "task", "income", "deposit", "transfer", "payment",
    "anydesk", "teamviewer", "link", "click", "login", "yono", "challan", "electricity", "urgent",
    "unblock", "unlock", "deactivate", "deactivated", "suspend", "expire", "expired", "verification",
    "claim", "free", "gift", "cash", "cashback", "money", "fee", "fees", "aadhar", "sim", "esim", "netbanking",
}

_LATIN = re.compile(r"[A-Za-z]")
_NONLATIN_LOOKALIKE = re.compile("[" + "".join(re.escape(c) for c in HOMOGLYPHS) + "]")
_TOKEN = re.compile(r"[^\s,;:()\[\]{}<>\"']+")
_SPACED = re.compile(r"(?<![A-Za-z])((?:[A-Za-z][ .\-_*•·]{1,3}){2,}[A-Za-z])(?![A-Za-z])")


def deobfuscate(text: str) -> tuple[str, list[dict]]:
    if not text:
        return text, []
    findings: list[dict] = []

    def note(code: str, label: str, example: str, weight: float):
        for f in findings:
            if f["code"] == code:
                if example and example not in f["examples"] and len(f["examples"]) < 3:
                    f["examples"].append(example)
                return
        findings.append({"code": code, "label": label, "examples": [example] if example else [], "weight": weight})

    # 1. Bidirectional overrides (file-name spoofing)
    if any(c in BIDI for c in text):
        m = re.search(r"\S*[" + "".join(BIDI) + r"]\S*", text)
        note("bidi_override", "Hidden right-to-left control characters (used to disguise file names such as .apk)", (m.group(0) if m else "").encode("unicode_escape").decode()[:60], 0.6)
        text = "".join(c for c in text if c not in BIDI)

    # 2. Full-width / compatibility characters (ＯＴＰ → OTP)
    if re.search(r"[！-～]", text):
        m = re.search(r"[！-～]+", text)
        note("fullwidth", "Full-width look-alike letters", m.group(0) if m else "", 0.35)
    text = unicodedata.normalize("NFKC", text)

    # 3. Invisible characters
    inv = [c for c in text if c in INVISIBLE]
    if inv:
        note("invisible_chars", f"{len(inv)} invisible character(s) hidden inside words", "", 0.35)
        text = "".join(c for c in text if c not in INVISIBLE)
    # Joiners inside Latin words (not Indic): O‌T‌P
    def _strip_latin_joiners(m):
        return m.group(0).replace("‌", "").replace("‍", "")

    new = re.sub(r"[A-Za-z0-9][‌‍]+[A-Za-z0-9]", _strip_latin_joiners, text)
    if new != text:
        note("invisible_chars", "Invisible joiner characters hidden inside words", "", 0.35)
        text = new

    # 4. Homoglyphs inside Latin-looking words
    def _fix_token(tok: str) -> str:
        if not _NONLATIN_LOOKALIKE.search(tok):
            return tok
        has_latin = bool(_LATIN.search(tok))
        mapped = "".join(HOMOGLYPHS.get(c, c) for c in tok)
        bare = re.sub(r"[^a-z]", "", mapped.lower())
        if has_latin or bare in SENSITIVE or any(s in bare for s in ("sbi", "kyc", "otp", "bank", "upi", "paytm")):
            foreign = sorted({unicodedata.name(c, "?").split()[0].title() for c in tok if c in HOMOGLYPHS})
            note("homoglyph", "Look-alike letters from other alphabets (e.g. Cyrillic) disguising words or links", f"{tok} → {mapped} (hidden {'/'.join(foreign)} letters)", 0.5)
            return mapped
        return tok

    text = _TOKEN.sub(lambda m: _fix_token(m.group(0)), text)

    # 5. Spaced-out keywords (O T P, K-Y-C, U P I)
    def _collapse(m):
        raw = m.group(1)
        joined = re.sub(r"[ .\-_*•·]", "", raw)
        if joined.lower() in SENSITIVE:
            if re.search(r"[ \-_*•·]", raw):
                note("spaced_letters", "Keywords split with spaces/symbols to dodge filters", f"{raw} → {joined}", 0.35)
            return joined
        return raw

    text = _SPACED.sub(_collapse, text)

    # 6. Leetspeak (0TP, P@N, upd@te, bl0cked)
    def _leet(m):
        tok = m.group(0)
        if not (_LATIN.search(tok) and re.search(r"[0134578@$|!]", tok)):
            return tok
        if re.fullmatch(r"(?i)(rs|inr)?[\d,.]+(k|cr|lakh)?", tok):
            return tok
        core = tok.strip(".!?")
        mapped = core.translate(LEET)
        bare = re.sub(r"[^a-z]", "", mapped.lower())
        if bare in SENSITIVE and bare != core.lower():
            note("leetspeak", "Numbers/symbols swapped for letters to dodge filters", f"{core} → {mapped}", 0.35)
            return tok.replace(core, mapped)
        return tok

    text = re.sub(r"[A-Za-z0-9@$|!]{2,}", _leet, text)
    return text, findings
