"""Entity extraction: URLs, UPI IDs, phone numbers, emails, amounts, sender IDs,
account-like numbers and claimed organisations, from free text in any script.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..kb.domains import BRAND_TOKENS, OFFICIAL_BRANDS

COMMON_TLDS = {
    "com", "in", "net", "org", "co", "io", "ai", "app", "info", "biz", "me", "xyz", "top", "club",
    "online", "site", "live", "buzz", "icu", "shop", "vip", "work", "click", "link", "rest", "fit",
    "cfd", "sbs", "monster", "quest", "cam", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "lol", "pw",
    "cyou", "bond", "today", "support", "help", "website", "store", "space", "fun", "life", "world",
    "ink", "win", "bid", "loan", "men", "date", "racing", "download", "stream", "cc", "ws", "su", "ly",
    "gl", "gd", "to", "sh", "us", "uk", "pk", "bd", "cn", "ru", "sbi", "id", "ae", "sg", "my", "au",
    "news", "pro", "tech", "dev", "page", "cloud", "digital", "services", "email", "network", "ws",
    "asia", "global", "group", "media", "agency", "center", "finance", "money", "bank", "pay",
}

URL_EXPLICIT = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"'(){}\[\]|]+)")
URL_BARE = re.compile(
    r"(?i)(?<![@\w.\-/])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(/[^\s<>\"'(){}\[\]|]*)?"
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")
VPA = re.compile(r"(?<![\w.\-])([a-zA-Z0-9][a-zA-Z0-9.\-_]{1,255})@([a-zA-Z][a-zA-Z0-9]{1,63})(?!\.[a-zA-Z])(?![\w\-])")
PHONE_INTL = re.compile(r"(?<![\w+])\+\s?(\d{1,3})[\s\-.]?\(?(\d[\d\s\-.()]{5,15}\d)")
PHONE_IN = re.compile(r"(?<![\d+])(?:(?:\+?91|0)[\s\-]?)?([6-9]\d{4})[\s\-]?(\d{5})(?!\d)")
PHONE_1600 = re.compile(r"(?<!\d)(1600[\s\-]?\d{3}[\s\-]?\d{3})(?!\d)")
PHONE_140 = re.compile(r"(?<!\d)(140[\s\-]?\d{3}[\s\-]?\d{4})(?!\d)")
PHONE_TOLLFREE = re.compile(r"(?<!\d)(1800[\s\-]?\d{3}[\s\-]?\d{3,4})(?!\d)")
SENDER_ID = re.compile(r"\b([A-Z]{2})-([A-Z0-9]{3,9})(?:-([PSTG]))?\b")
IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
AADHAAR_SPACED = re.compile(r"(?<!\d)[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}(?!\d)")
LONG_DIGITS = re.compile(r"(?<![\d.,])\d{9,19}(?![\d,])")
AMOUNT_PATTERNS = [
    re.compile(r"(?i)(?:₹|rs\.?|inr|rupees?)\s?([\d,]+(?:\.\d{1,2})?)\s?(lakh|lac|lakhs|crore|cr|k)?\b"),
    re.compile(r"(?i)\b([\d,]+(?:\.\d+)?)\s?(lakh|lac|lakhs|crore|cr)\b"),
    re.compile(r"(?i)\b([\d,]+(?:\.\d{1,2})?)\s?(?:rupees|rs|/-)(?!\w)"),
    re.compile(r"([\d,]+(?:\.\d+)?)\s?(लाख|करोड़|रुपये|रुपए)"),
    re.compile(r"([\d,]+(?:\.\d+)?)\s?(లక్షలు|లక్ష|కోట్లు|రూపాయలు)"),
]
AGENCIES = {
    "cbi": "CBI", "c.b.i": "CBI", "enforcement directorate": "Enforcement Directorate", "ed officer": "Enforcement Directorate",
    "narcotics": "Narcotics Control Bureau", "ncb": "Narcotics Control Bureau", "customs": "Customs",
    "cyber crime": "Cyber Crime Police", "cyber cell": "Cyber Crime Police", "crime branch": "Crime Branch",
    "police": "Police", "trai": "TRAI", "rbi": "RBI",
    "reserve bank": "RBI", "income tax": "Income Tax Department", "supreme court": "Supreme Court",
    "high court": "High Court", "interpol": "Interpol", "sebi": "SEBI", "nia": "NIA",
    "पुलिस": "Police", "सीबीआई": "CBI", "పోలీస": "Police", "సీబీఐ": "CBI",
}
CHANNEL_HINTS = [
    ("video_call", re.compile(r"(?i)\b(video ?call|skype|whatsapp video|zoom|google meet|facetime)\b|वीडियो कॉल|వీడియో కాల్")),
    ("whatsapp", re.compile(r"(?i)\bwhats\s?app\b|\bwa\.me\b|व्हाट्सएप|వాట్సాప్")),
    ("telegram", re.compile(r"(?i)\btelegram\b|\bt\.me/")),
    ("email", re.compile(r"(?i)\b(e-?mail|gmail|inbox)\b")),
    ("sms", re.compile(r"(?i)\b(sms|text message|texted)\b|\b[A-Z]{2}-[A-Z0-9]{3,9}\b|मैसेज|మెసేజ్")),
    ("call", re.compile(r"(?i)\b(got a call|received a call|called me|caller|phone call|on the call|call from|calling from|(he|she|they|someone) called|rang me|on the phone)\b|कॉल आया|फ़ोन आया|फोन आया|कॉल किया|కాల్ వచ్చింది|ఫోన్ వచ్చింది|కాల్ చేశా")),
    ("social", re.compile(r"(?i)\b(instagram|facebook|fb|twitter|x\.com|linkedin|snapchat|youtube)\b")),
]


@dataclass
class Entities:
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    phones: list[dict] = field(default_factory=list)  # {"raw", "e164", "kind", "cc"}
    sender_ids: list[dict] = field(default_factory=list)
    amounts: list[float] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    cards: list[str] = field(default_factory=list)
    aadhaar: list[str] = field(default_factory=list)
    pan: list[str] = field(default_factory=list)
    ifsc: list[str] = field(default_factory=list)
    txn_ids: list[str] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    agencies: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "urls": len(self.urls),
            "upi_ids": len(self.upi_ids),
            "phones": len(self.phones),
            "emails": len(self.emails),
            "sender_ids": len(self.sender_ids),
            "amounts": self.amounts[:5],
            "brands": self.brands,
            "agencies": self.agencies,
            "channels": self.channels,
            "scripts": self.scripts,
        }


def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        key = x if not isinstance(x, dict) else tuple(sorted(x.items()))
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def luhn_ok(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 13:
        return False
    total, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _amount_value(num: str, unit: str | None) -> float | None:
    try:
        v = float(num.replace(",", ""))
    except ValueError:
        return None
    unit = (unit or "").lower()
    if unit in {"lakh", "lac", "lakhs", "लाख", "లక్ష", "లక్షలు"}:
        v *= 1_00_000
    elif unit in {"crore", "cr", "करोड़", "కోట్లు"}:
        v *= 1_00_00_000
    elif unit == "k":
        v *= 1000
    return v if 0 < v < 1e11 else None


def detect_scripts(text: str) -> list[str]:
    scripts = []
    if re.search(r"[ऀ-ॿ]", text):
        scripts.append("Devanagari")
    if re.search(r"[ఀ-౿]", text):
        scripts.append("Telugu")
    if re.search(r"[஀-௿]", text):
        scripts.append("Tamil")
    if re.search(r"[ঀ-৿]", text):
        scripts.append("Bengali")
    if re.search(r"[ಀ-೿]", text):
        scripts.append("Kannada")
    if re.search(r"[ഀ-ൿ]", text):
        scripts.append("Malayalam")
    if re.search(r"[઀-૿]", text):
        scripts.append("Gujarati")
    if re.search(r"[A-Za-z]", text):
        scripts.append("Latin")
    return scripts


def extract_entities(text: str) -> Entities:
    ent = Entities()
    if not text:
        return ent
    work = text

    # Emails first (so their domains aren't mistaken for URLs)
    ent.emails = _dedupe(EMAIL.findall(work))
    for e in ent.emails:
        work = work.replace(e, " ")

    # UPI IDs (no dot in the handle)
    for local, handle in VPA.findall(work):
        vpa = f"{local}@{handle}"
        ent.upi_ids.append(vpa)
    ent.upi_ids = _dedupe(ent.upi_ids)
    for v in ent.upi_ids:
        work = work.replace(v, " ")

    # URLs: explicit then bare domains
    urls: list[str] = []
    for m in URL_EXPLICIT.finditer(work):
        u = m.group(1).rstrip(".,;:!?)'\"")
        urls.append(u)
    stripped = URL_EXPLICIT.sub(" ", work)
    for m in URL_BARE.finditer(stripped):
        host, tld, path = m.group(1), m.group(2).lower(), m.group(3) or ""
        if tld not in COMMON_TLDS:
            continue
        labels = host.split(".")
        if len(labels) < 2 or all(len(lbl) <= 1 for lbl in labels[:-1]):
            continue
        if re.fullmatch(r"(?i)(rs|no|sr|dr|mr|mrs|ms|vs|st|etc|ie|eg|a/c)\.[a-z]+", host):
            continue
        urls.append((host + path).rstrip(".,;:!?)'\""))
    ent.urls = _dedupe(urls)

    # Sender IDs like VM-HDFCBK-S
    for a, b, c in SENDER_ID.findall(text):
        ent.sender_ids.append({"raw": f"{a}-{b}" + (f"-{c}" if c else ""), "entity": b, "suffix": c or ""})
    ent.sender_ids = _dedupe(ent.sender_ids)

    # Phones
    phone_spans: list[tuple[int, int]] = []

    def add_phone(raw, e164, kind, cc, span):
        phone_spans.append(span)
        ent.phones.append({"raw": raw.strip(), "e164": e164, "kind": kind, "cc": cc})

    for m in PHONE_1600.finditer(text):
        d = re.sub(r"\D", "", m.group(1))
        add_phone(m.group(1), d, "1600-series", "91", m.span())
    for m in PHONE_140.finditer(text):
        d = re.sub(r"\D", "", m.group(1))
        add_phone(m.group(1), d, "140-series", "91", m.span())
    for m in PHONE_TOLLFREE.finditer(text):
        d = re.sub(r"\D", "", m.group(1))
        add_phone(m.group(1), d, "toll-free", "91", m.span())
    for m in PHONE_INTL.finditer(text):
        if any(s <= m.start() < e for s, e in phone_spans):
            continue
        cc_raw, rest = m.group(1), re.sub(r"\D", "", m.group(2))
        # Resolve the country code greedily against known codes
        from ..kb.domains import COUNTRY_CODES

        digits = cc_raw + rest
        cc = None
        for ln in (3, 2, 1):
            if digits[:ln] in COUNTRY_CODES:
                cc = digits[:ln]
                break
        cc = cc or cc_raw
        national = digits[len(cc):]
        if len(national) < 6:
            continue
        add_phone(m.group(0), f"+{cc}{national}", "mobile" if cc == "91" else "international", cc, m.span())
    for m in PHONE_IN.finditer(text):
        if any(s <= m.start() < e or s < m.end() <= e for s, e in phone_spans):
            continue
        num = m.group(1) + m.group(2)
        add_phone(m.group(0), f"+91{num}", "mobile", "91", m.span())
    ent.phones = _dedupe(ent.phones)

    # Sensitive identifiers
    ent.ifsc = _dedupe(IFSC.findall(text))
    ent.pan = _dedupe([p for p in PAN.findall(text) if p not in ent.ifsc])
    ent.aadhaar = _dedupe([a for a in AADHAAR_SPACED.findall(text)])
    phone_digits = {p["e164"][-10:] for p in ent.phones}
    for m in LONG_DIGITS.finditer(text):
        num = m.group(0)
        if num[-10:] in phone_digits and len(num) <= 12:
            continue
        ctx = text[max(0, m.start() - 25): m.start()].lower()
        if re.search(r"(utr|rrn|ref|txn|transaction|upi ref|reference)\W*(no\.?|id|number)?\W*$", ctx):
            ent.txn_ids.append(num)
        elif len(num) == 12 and num[0] in "23456789" and re.search(r"aadh?aa?r", text.lower()):
            ent.aadhaar.append(num)
        elif 13 <= len(num) <= 19 and luhn_ok(num):
            ent.cards.append(num)
        else:
            ent.accounts.append(num)
    ent.txn_ids = _dedupe(ent.txn_ids)
    ent.accounts = _dedupe(ent.accounts)
    ent.cards = _dedupe(ent.cards)
    ent.aadhaar = _dedupe(ent.aadhaar)

    # Amounts
    amounts: list[float] = []
    for pat in AMOUNT_PATTERNS:
        for m in pat.finditer(text):
            v = _amount_value(m.group(1), m.group(2) if m.lastindex and m.lastindex >= 2 else None)
            if v:
                amounts.append(v)
    ent.amounts = _dedupe(amounts)

    # Claimed organisations (ignore UPI handles / email domains such as "@okaxis")
    low = " " + work.lower() + " "
    brands = []
    for token, brand in BRAND_TOKENS.items():
        if len(token) <= 3:
            if re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", low):
                brands.append(brand)
        elif token in low:
            brands.append(brand)
    ent.brands = _dedupe([b for b in brands if b in OFFICIAL_BRANDS])
    agencies = []
    for k, v in AGENCIES.items():
        if (len(k) <= 4 and re.search(rf"(?<![a-z]){re.escape(k.strip())}(?![a-z])", low)) or (len(k) > 4 and k in low):
            agencies.append(v)
    ent.agencies = _dedupe(agencies)

    for name, pat in CHANNEL_HINTS:
        if pat.search(text):
            ent.channels.append(name)
    ent.scripts = detect_scripts(text)
    return ent
