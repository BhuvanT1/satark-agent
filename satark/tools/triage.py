"""Golden-hour triage, deadline computation and liability analysis."""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from ..config import IST
from ..kb.facts import E_ZERO_FIR, RBI_COMPENSATION_PROPOSAL_2026, RBI_LIABILITY_2017

MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
WORDNUM = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "ten": 10, "half an": 0.5, "half": 0.5, "few": 3, "couple of": 2}


def _clock(text: str):
    m = re.search(r"(\d{1,2})(?:[:.](\d{2}))?\s*(baje|बजे|గంటలకు|గం)", text, re.I)
    if m:
        h, mi = int(m.group(1)), int(m.group(2) or 0)
        if re.search(r"raat|shaam|sham|dopahar|रात|शाम|दोपहर|రాత్రి|సాయంత్రం|మధ్యాహ్నం", text) and h < 12:
            h += 12
        return h % 24, mi
    m = re.search(r"(\d{1,2})(?:[:.](\d{2}))?\s*(am|pm|a\.m\.|p\.m\.)", text, re.I)
    if m:
        h, mi = int(m.group(1)), int(m.group(2) or 0)
        ap = m.group(3).lower().replace(".", "")
        if ap == "pm" and h < 12:
            h += 12
        if ap == "am" and h == 12:
            h = 0
        return h, mi
    m = re.search(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b", text)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None


def parse_when(text: str | None, now: datetime | None = None) -> tuple[datetime | None, str]:
    """Parse natural-language incident times (English / Hinglish / Hindi / Telugu)."""
    now = now or datetime.now(IST)
    if not text or not str(text).strip():
        return None, "not provided"
    t = str(text).strip().lower()

    words = r"(half an|half|an|a|one|two|three|four|five|six|ten|few|couple of)"

    def _dur(unit_digits: str, unit_words: str):
        m = re.search(r"\b(\d+(?:\.\d+)?)\s*" + unit_digits + r"\b", t)
        if m:
            return float(m.group(1)), m.group(0)
        m = re.search(r"\b" + words + r"\s+" + unit_words + r"\b", t)
        if m:
            return WORDNUM.get(m.group(1), 1), m.group(0)
        return None

    d = _dur(r"(minutes?|mins?|min|m)", r"(minutes?|mins?)")
    if d:
        return now - timedelta(minutes=d[0]), f"{d[1]} ago"
    d = _dur(r"(hours?|hrs?|hr|h)", r"(hours?|hrs?)")
    if d:
        return now - timedelta(hours=d[0]), f"{d[1]} ago"
    d = _dur(r"(days?)", r"(days?)")
    if d:
        return now - timedelta(days=d[0]), f"{d[1]} ago"
    m = re.search(r"(\d+)\s*(घंटे|घंटा|గంటల|గంట)(?!లకు)", t)
    if m:
        return now - timedelta(hours=int(m.group(1))), f"{m.group(1)} hours ago"
    m = re.search(r"(\d+)\s*(मिनट|నిమిష)", t)
    if m:
        return now - timedelta(minutes=int(m.group(1))), f"{m.group(1)} minutes ago"
    if re.search(r"\b(just now|right now|abhi|now)\b|अभी|ఇప్పుడే", t):
        return now - timedelta(minutes=5), "just now"

    base = None
    if re.search(r"\b(yesterday|kal)\b|कल|నిన్న", t):
        base = now - timedelta(days=1)
    elif re.search(r"\b(today|aaj|this morning|this evening|tonight)\b|आज|ఈ రోజు|ఈరోజు", t):
        base = now
    # Absolute dates
    m = re.search(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b", t)
    if m:
        base = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), 12, 0, tzinfo=IST)
    m = m or None
    if base is None:
        m2 = re.search(r"\b(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})\b", t)
        if m2:
            y = int(m2.group(3))
            y = y + 2000 if y < 100 else y
            try:
                base = datetime(y, int(m2.group(2)), int(m2.group(1)), 12, 0, tzinfo=IST)
            except ValueError:
                base = None
    if base is None:
        m3 = re.search(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+([a-z]{3})[a-z]*\.?(?:,?\s+(\d{4}))?", t) or None
        m4 = re.search(r"\b([a-z]{3})[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s+(\d{4}))?", t)
        if m3 and m3.group(2) in MONTHS:
            y = int(m3.group(3)) if m3.group(3) else now.year
            base = datetime(y, MONTHS[m3.group(2)], int(m3.group(1)), 12, 0, tzinfo=IST)
        elif m4 and m4.group(1) in MONTHS:
            y = int(m4.group(3)) if m4.group(3) else now.year
            base = datetime(y, MONTHS[m4.group(1)], int(m4.group(2)), 12, 0, tzinfo=IST)
    clock = _clock(t)
    if base is None and clock:
        base = now
    if base is None:
        return None, "could not parse"
    if clock:
        base = base.replace(hour=clock[0], minute=clock[1], second=0, microsecond=0)
        if base > now and (base - now) < timedelta(hours=18) and not re.search(r"\d{4}|/", t):
            base -= timedelta(days=1)
    if base > now:
        base = now
    return base, base.strftime("%d %b %Y, %I:%M %p IST")


def is_bank_holiday(d: datetime) -> bool:
    """Sundays and 2nd/4th Saturdays (RBI). Public holidays vary by state and are not modelled."""
    if d.weekday() == 6:
        return True
    if d.weekday() == 5:
        nth = (d.day - 1) // 7 + 1
        return nth in (2, 4)
    return False


def add_working_days(start: datetime, n: int) -> datetime:
    d = start
    added = 0
    while added < n:
        d += timedelta(days=1)
        if not is_bank_holiday(d):
            added += 1
    return d.replace(hour=23, minute=59, second=0, microsecond=0)


def working_days_between(start: datetime, end: datetime) -> int:
    d, count = start, 0
    while d.date() < end.date():
        d += timedelta(days=1)
        if not is_bank_holiday(d):
            count += 1
    return count


def golden_hour_triage(money_lost: bool, when_text: str | None, amount: float | None, payment_mode: str | None, state: str | None, now: datetime | None = None) -> dict:
    now = now or datetime.now(IST)
    incident, parsed_as = parse_when(when_text, now)
    result: dict = {
        "money_lost": money_lost,
        "incident_at": incident.isoformat() if incident else None,
        "incident_display": incident.strftime("%d %b %Y, %I:%M %p IST") if incident else None,
        "parsed_as": parsed_as,
        "amount": amount,
        "payment_mode": payment_mode,
        "now": now.isoformat(),
        "deadlines": [],
    }
    if not money_lost:
        result.update({"status": "not_applicable", "elapsed_minutes": None})
        return result

    if incident is None:
        status, elapsed = "unknown", None
    else:
        elapsed = int((now - incident).total_seconds() // 60)
        if elapsed <= 60:
            status = "golden"
        elif elapsed <= 24 * 60:
            status = "urgent"
        else:
            status = "late"
    result["status"] = status
    result["elapsed_minutes"] = elapsed

    ref = incident or now
    dl = result["deadlines"]
    dl.append({"key": "report_now", "label": "Report on 1930 / cybercrime.gov.in", "due": "Immediately", "note": "Funds can only be put on hold while they are still in the receiving (mule) accounts."})
    zero = add_working_days(ref, RBI_LIABILITY_2017["zero_liability_working_days"])
    lim = add_working_days(ref, RBI_LIABILITY_2017["limited_liability_working_days"])
    dl.append({"key": "rbi_zero", "label": "Notify your bank in writing (zero-liability window for unauthorised transactions)", "due": zero.strftime("%a %d %b %Y"), "due_iso": zero.isoformat(), "note": "3 working days from the transaction alert (RBI 2017 circular)."})
    dl.append({"key": "rbi_limited", "label": "Last day of the limited-liability window", "due": lim.strftime("%a %d %b %Y"), "due_iso": lim.isoformat(), "note": "4–7 working days → liability capped at ₹5,000–₹25,000 depending on account type."})
    dl.append({"key": "bank_credit", "label": "Bank should shadow-credit the amount (if eligible)", "due": "Within 10 working days of your notification", "note": "RBI 2017 circular."})
    dl.append({"key": "ombudsman", "label": "Escalate to RBI Ombudsman if unresolved", "due": (now + timedelta(days=30)).strftime("after %d %b %Y"), "note": "If the bank doesn't reply within 30 days or rejects your complaint (cms.rbi.org.in / 14448)."})
    if amount and amount > E_ZERO_FIR["threshold"]:
        delhi = (state or "").strip().lower() == "delhi"
        dl.append({
            "key": "ezero",
            "label": "Convert e-Zero FIR to regular FIR" if delhi else "Register an FIR (loss above ₹10 lakh)",
            "due": "Within 3 days of your complaint" if delhi else "As soon as possible",
            "note": "Delhi pilot: NCRP/1930 complaints above ₹10 lakh become e-Zero FIRs automatically." if delhi else "e-Zero FIR auto-conversion started as a Delhi pilot; elsewhere, file an FIR at your cyber police station.",
        })
    result["working_days_elapsed"] = working_days_between(ref, now) if incident else None
    result["e_zero_fir_applicable"] = bool(amount and amount > E_ZERO_FIR["threshold"] and (state or "").strip().lower() == "delhi")
    return result


def classify_authorisation(signals: set[str], payment_mode: str | None, llm_facts: dict | None = None) -> str:
    llm_facts = llm_facts or {}
    mm = llm_facts.get("money_movement") or {}
    if isinstance(mm, dict):
        if mm.get("authorised_by_victim") is True:
            return "authorised_push"
        if mm.get("otp_shared") is True:
            return "unauthorised_negligence"
        if mm.get("authorised_by_victim") is False and mm.get("otp_shared") is False:
            return "unauthorised_third_party"
    if "otp_shared" in signals or "remote_access" in signals or "apk_install" in signals:
        return "unauthorised_negligence"
    if "no_otp_shared" in signals:
        return "unauthorised_third_party"
    if "authorised_push" in signals or "pin_to_receive" in signals:
        return "authorised_push"
    pm = (payment_mode or "").lower()
    if any(k in pm for k in ["crypto", "gift", "cash"]):
        return "authorised_push"
    return "unknown"


AUTH_LABELS = {
    "authorised_push": "You made / approved the payment under deception (authorised push-payment fraud)",
    "unauthorised_negligence": "Money was taken after OTP/PIN/app access was obtained from you",
    "unauthorised_third_party": "Money was taken without your involvement (unauthorised transaction)",
    "unknown": "Not yet clear how the money left your account",
}


def liability_analysis(auth_class: str, amount: float | None, triage: dict) -> dict:
    points: list[str] = []
    rules = RBI_LIABILITY_2017
    wd = triage.get("working_days_elapsed")
    if auth_class == "unauthorised_third_party":
        if wd is None or wd <= rules["zero_liability_working_days"]:
            points.append("If you notify your bank within 3 working days of the alert, RBI rules give you ZERO liability for a third-party breach — the bank must credit the money back (shadow credit within 10 working days).")
        elif wd <= rules["limited_liability_working_days"]:
            points.append(f"You are {wd} working days in: liability is LIMITED (₹5,000–₹25,000 cap by account type) if you notify the bank now.")
        else:
            points.append("More than 7 working days have passed: your liability depends on your bank's board-approved policy — still notify the bank in writing today.")
    elif auth_class == "unauthorised_negligence":
        points.append("Because credentials/OTP or app access were obtained from you, RBI rules make you bear the loss until you report it — report to the bank immediately so that any further loss is borne by the bank.")
        points.append("Still file the written bank complaint: banks must examine each case, and RBI has proposed compensation even in some OTP-shared cases (see below).")
    elif auth_class == "authorised_push":
        points.append("You authorised the transfer while being deceived, so RBI's unauthorised-transaction rules usually don't apply directly. Your best chance is speed: 1930/NCRP can freeze the money in the receiving (mule) accounts.")
        points.append("Ask your bank to file a fraud report with the beneficiary bank and request a lien/hold on the receiving account, quoting your NCRP acknowledgement number.")
    else:
        points.append("Tell the bank exactly how the transaction happened. If you did not share OTP/PIN and did not approve it, RBI's zero-liability rule (3 working days) can apply.")
    small = amount is not None and 0 < amount <= 55000
    comp = RBI_COMPENSATION_PROPOSAL_2026
    points.append(
        ("Your loss is in the small-value range. " if small else "")
        + "RBI proposed (Feb 2026) compensation of up to ₹25,000 or 85% of the loss (whichever is lower) for small-value digital frauds — "
        + comp["status"]
    )
    return {"class": auth_class, "label": AUTH_LABELS.get(auth_class, auth_class), "points": points, "rule_ref": rules["ref"]}
