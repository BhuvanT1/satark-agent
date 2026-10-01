"""Forensics for UPI IDs, phone numbers and SMS sender headers."""

from __future__ import annotations

import re

from ..kb.domains import BRAND_TOKENS, COUNTRY_CODES, OFFICIAL_BRANDS, UPI_HANDLES

OFFICIAL_WORDS_IN_VPA = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "rbi", "npci", "cbi", "police", "customs", "court",
    "kyc", "refund", "help", "care", "support", "govt", "gov", "official", "income", "tax", "gst",
    "electricity", "bijli", "challan", "rto", "trai", "fedex", "dhl", "amazon", "flipkart", "paytm",
    "phonepe", "lic", "pmkisan", "yojana", "bank",
]


def _sig(code: str, label: str, weight: float, detail: str = "") -> dict:
    return {"code": code, "label": label, "weight": round(weight, 2), "detail": detail}


def _noisy_or(signals: list[dict]) -> float:
    p = 1.0
    for s in signals:
        if s["weight"] > 0:
            p *= 1 - s["weight"]
    return round(1 - p, 3)


def check_upi_id(vpa: str, official_claim: bool = False, claimed_brands: list[str] | None = None) -> dict:
    vpa = vpa.strip()
    local, _, handle = vpa.partition("@")
    handle_l = handle.lower()
    local_l = local.lower()
    signals: list[dict] = []
    info: list[str] = []
    psp = UPI_HANDLES.get(handle_l)
    if psp:
        info.append(f"Valid-looking handle @{handle_l} ({psp})")
    else:
        signals.append(_sig("unknown_handle", f"Unrecognised UPI handle '@{handle}'", 0.2, vpa))

    is_mobile = bool(re.fullmatch(r"[6-9]\d{9}", local_l))
    merchant = bool(
        re.match(r"^(q\d{6,}|paytmqr|bharatpe|mab\.|gpay-|merchant|pay\.|biz\.|vyapar)", local_l)
        or "qr" in local_l[:8]
    )
    personal = not merchant
    if is_mobile:
        info.append("Mobile-number based personal UPI ID")
    elif merchant:
        info.append("Looks like a merchant/QR collection ID")
    else:
        info.append("Looks like a personal UPI ID")

    impersonation = [w for w in OFFICIAL_WORDS_IN_VPA if w in local_l]
    if impersonation:
        signals.append(_sig(
            "vpa_impersonation",
            "UPI ID uses an official-sounding name (" + ", ".join(impersonation[:3]) + ") — anyone can create such IDs",
            0.35,
            vpa,
        ))
    if official_claim and personal:
        signals.append(_sig(
            "official_fee_to_personal_upi",
            "Government fines, duties, fees or bank charges are never collected into a personal UPI ID",
            0.5,
            vpa,
        ))
    return {
        "upi_id": vpa,
        "handle": handle_l,
        "psp": psp,
        "personal": personal,
        "merchant_like": merchant,
        "signals": signals,
        "info": info,
        "risk": _noisy_or(signals),
    }


def check_phone_number(phone: dict, claimed_brands: list[str] | None = None, claimed_agencies: list[str] | None = None, channels: list[str] | None = None) -> dict:
    claimed_brands = claimed_brands or []
    claimed_agencies = claimed_agencies or []
    channels = channels or []
    kind = phone.get("kind", "mobile")
    cc = phone.get("cc", "91")
    signals: list[dict] = []
    trust: list[dict] = []
    info: list[str] = []
    claims_bank = any(OFFICIAL_BRANDS.get(b, {}).get("type") in {"bank", "fintech"} for b in claimed_brands) and not claimed_agencies
    claims_gov = bool(claimed_agencies) or any(OFFICIAL_BRANDS.get(b, {}).get("type") in {"government", "regulator"} for b in claimed_brands)

    country = COUNTRY_CODES.get(cc, {}).get("country", f"+{cc}")
    if kind == "international":
        risk = COUNTRY_CODES.get(cc, {}).get("risk", 0.25)
        signals.append(_sig("foreign_number", f"International number from {country} (+{cc})", risk, phone.get("raw", "")))
        if claims_bank or claims_gov:
            signals.append(_sig(
                "foreign_claims_indian_authority",
                f"Claims to be an Indian bank/agency but uses a {country} number",
                0.5,
                phone.get("raw", ""),
            ))
    elif kind == "1600-series":
        trust.append(_sig("bank_1600", "1600xx series — reserved for banks/financial institutions' service calls (RBI directive)", 0.3, phone.get("raw", "")))
    elif kind == "140-series":
        info.append("140xx series — registered telemarketer (promotional calls)")
        if claims_bank:
            signals.append(_sig("promo_series_bank_claim", "Promotional 140xx number used for an account-related call", 0.15, phone.get("raw", "")))
    elif kind == "toll-free":
        info.append("Toll-free number — verify it on the organisation's official website (fake helplines are planted in search ads)")
    else:  # Indian mobile
        info.append("Indian mobile number")
        if claims_bank:
            signals.append(_sig(
                "mobile_claims_bank",
                "A regular mobile number claiming to be a bank — banks use 1600xx numbers for service calls",
                0.3,
                phone.get("raw", ""),
            ))
        if claims_gov:
            signals.append(_sig(
                "mobile_claims_agency",
                "Police/CBI/government don't run inquiries from personal mobile or WhatsApp numbers",
                0.35,
                phone.get("raw", ""),
            ))
    if "video_call" in channels and claims_gov:
        signals.append(_sig("video_call_officer", "'Officer' insisting on a video call", 0.4, ""))
    risk = _noisy_or(signals)
    if trust:
        risk = round(risk * 0.5, 3)
    return {
        "number": phone.get("raw", ""),
        "kind": kind,
        "country": country,
        "signals": signals,
        "trust_signals": trust,
        "info": info,
        "risk": risk,
    }


SUFFIX_MEANING = {"T": "transactional", "S": "service", "P": "promotional", "G": "government"}


def check_sender_id(sender: dict, claimed_brands: list[str] | None = None, asks_sensitive: bool = False) -> dict:
    claimed_brands = claimed_brands or []
    entity = sender.get("entity", "").lower()
    suffix = sender.get("suffix", "")
    signals: list[dict] = []
    trust: list[dict] = []
    header_brands = set()
    for token, brand in BRAND_TOKENS.items():
        if len(token) >= 3 and token in entity:
            header_brands.add(brand)
    trust.append(_sig("registered_header", "Registered commercial SMS header (TRAI DLT)", 0.15, sender.get("raw", "")))
    if suffix:
        trust.append(_sig("header_suffix", f"Header suffix -{suffix} = {SUFFIX_MEANING.get(suffix, '?')} message", 0.05, sender.get("raw", "")))
    if suffix == "P" and asks_sensitive:
        signals.append(_sig("promo_header_sensitive", "Promotional (-P) header carrying an account/KYC request", 0.25, sender.get("raw", "")))
    mismatch = [b for b in claimed_brands if OFFICIAL_BRANDS.get(b, {}).get("type") == "bank" and b not in header_brands]
    if mismatch and header_brands == set():
        signals.append(_sig("header_brand_mismatch", "SMS header does not belong to the bank the message claims to be from", 0.25, sender.get("raw", "")))
    risk = 1.0
    for s in signals:
        risk *= 1 - s["weight"]
    return {
        "sender": sender.get("raw", ""),
        "suffix_meaning": SUFFIX_MEANING.get(suffix),
        "header_brands": sorted(header_brands),
        "signals": signals,
        "trust_signals": trust,
        "risk": round(1 - risk, 3),
    }
