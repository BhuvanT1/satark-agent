"""Drafting agent (deterministic templates): NCRP complaint kit, bank dispute
letter, Chakshu report, police complaint and family alert. The LLM (when
available) personalises the narrative fields; these templates guarantee a
complete, correct pack even fully offline."""

from __future__ import annotations

from datetime import datetime

from ..config import IST
from ..kb.facts import LEGAL_SECTIONS, RBI_LIABILITY_2017
from ..kb.i18n import CHANNEL_WORDS, FAMILY_ALERT, t
from ..kb.playbooks import get_playbook


def inr(amount: float | None) -> str:
    if not amount:
        return "[amount]"
    n = int(round(amount))
    s = str(n)
    if len(s) <= 3:
        return "₹" + s
    last3, rest = s[-3:], s[:-3]
    groups = []
    while len(rest) > 2:
        groups.insert(0, rest[-2:])
        rest = rest[:-2]
    if rest:
        groups.insert(0, rest)
    return "₹" + ",".join(groups + [last3])


def _channel(case: dict) -> str:
    facts = case.get("llm_facts") or {}
    ch = facts.get("channel")
    if ch and ch != "unknown":
        return ch
    chans = case["entities"].channels
    for pref in ["video_call", "whatsapp", "telegram", "sms", "email", "call", "social"]:
        if pref in chans:
            return pref
    if case["entities"].sender_ids:
        return "sms"
    return "message"


def _identifiers(case: dict) -> dict[str, list[str]]:
    e = case["entities"]
    return {
        "Mobile numbers": [p["raw"] for p in e.phones if p["kind"] not in {"1600-series"}],
        "UPI IDs": list(e.upi_ids),
        "Websites / links": list(e.urls),
        "Email IDs": list(e.emails),
        "Bank accounts": list(e.accounts),
        "SMS sender IDs": [s["raw"] for s in e.sender_ids],
    }


def _claimed(case: dict) -> str:
    facts = case.get("llm_facts") or {}
    if facts.get("claimed_identity"):
        return str(facts["claimed_identity"])
    e = case["entities"]
    from ..kb.domains import OFFICIAL_BRANDS

    agencies = list(dict.fromkeys(e.agencies))
    if any(a != "Police" and "Police" in a for a in agencies):
        agencies = [a for a in agencies if a != "Police"]
    names = agencies[:2]
    if not names:
        names = [OFFICIAL_BRANDS[b]["name"] for b in e.brands if b in OFFICIAL_BRANDS and OFFICIAL_BRANDS[b]["type"] not in {"platform"}][:1]
    return " / ".join(names)


def ncrp_kit(case: dict) -> dict:
    pb = get_playbook(case.get("playbook_id"))
    money_lost = case.get("money_lost")
    cat = pb["ncrp"] if money_lost else pb["ncrp_nonfin"]
    tri = case.get("triage") or {}
    when = tri.get("incident_display") or case.get("when") or "[date and time]"
    ch_word = t(CHANNEL_WORDS.get(_channel(case), CHANNEL_WORDS["message"]), "en")
    ids = _identifiers(case)
    flat = [f"{k}: {', '.join(v)}" for k, v in ids.items() if v]
    amount = case.get("amount")
    pm = case.get("payment_mode") or "[payment mode]"
    narrative = (
        f"On {when}, I received a {ch_word} from {', '.join(ids['Mobile numbers'] or ids['SMS sender IDs'] or ['[number/ID]'])} "
        + (f"from a person claiming to be {_claimed(case)}. " if _claimed(case) else "from an unknown person. ")
    )
    asks = (case.get("llm_facts") or {}).get("asks") or []
    if asks:
        narrative += "They asked me to " + "; ".join(str(a) for a in asks[:3]) + ". "
    else:
        narrative += f"The communication followed the '{pb['name']['en']}' fraud pattern. "
    if money_lost:
        dest = ", ".join(ids["UPI IDs"] + ids["Bank accounts"]) or "[beneficiary UPI ID / account]"
        narrative += f"As a result, {inr(amount)} was transferred/debited from my account via {pm} to {dest}. "
        narrative += "I request you to immediately freeze the beneficiary account(s), trace the money trail and help me recover the amount."
    else:
        narrative += "I did not make any payment. I am reporting this so that the numbers/IDs used can be blocked and others are protected."
    if flat:
        narrative += " Suspect identifiers — " + "; ".join(flat) + "."
    delay = None
    if money_lost and tri.get("elapsed_minutes") and tri["elapsed_minutes"] > 24 * 60:
        delay = "[Explain briefly why reporting was delayed, e.g. 'I realised it was a fraud only when…']"
    return {
        "category": cat[0],
        "subcategory": cat[1],
        "incident_datetime": when,
        "amount": inr(amount) if money_lost else None,
        "description": narrative,
        "identifiers": ids,
        "delay_reason": delay,
        "evidence": [
            "Screenshots of the chat/SMS and caller details",
            "Bank SMS / statement showing the debit (if any)",
            "UPI transaction ID / UTR number for each transfer",
            "Any links, app names or documents the fraudster sent",
        ],
    }


def bank_letter(case: dict, auth_class: str) -> str:
    today = datetime.now(IST).strftime("%d %B %Y")
    tri = case.get("triage") or {}
    when = tri.get("incident_display") or case.get("when") or "[date and time]"
    amount = inr(case.get("amount"))
    pm = case.get("payment_mode") or "[UPI / card / net banking]"
    ids = _identifiers(case)
    dest = ", ".join(ids["UPI IDs"] + ids["Bank accounts"]) or "[beneficiary UPI ID / account number]"
    utr = ", ".join(case["entities"].txn_ids) or "[UTR / reference number]"
    pb = get_playbook(case.get("playbook_id"))
    lines = [
        "To,",
        "The Branch Manager / Principal Nodal Officer",
        "[Bank name], [Branch]",
        "",
        f"Date: {today}",
        "",
        f"Subject: Fraudulent transaction of {amount} on {when} — request to block, register fraud complaint and reverse the amount",
        "",
        "Respected Sir/Madam,",
        "",
        f"I, [Your full name], hold account no. [XXXXXXXX1234] with your bank. On {when}, {amount} left my account via {pm} as a result of a cyber fraud ({pb['name']['en']}).",
        "",
    ]
    if auth_class in {"unauthorised_third_party", "unknown"}:
        lines += [
            "I did not authorise this transaction and did not share any OTP, PIN or password. "
            f"I am reporting it within {tri.get('working_days_elapsed', 0) or 0} working day(s) of receiving the transaction alert. "
            f"Under {RBI_LIABILITY_2017['ref']} (Customer Protection – Limiting Liability of Customers in Unauthorised Electronic Banking Transactions), I request you to:",
            "  1. Immediately block my card / UPI / net-banking access to prevent further loss;",
            "  2. Register this complaint and share the complaint reference number with me;",
            "  3. Credit (shadow-reverse) the disputed amount within 10 working days as per the circular; and",
            "  4. Resolve the complaint within 90 days.",
        ]
    elif auth_class == "unauthorised_negligence":
        lines += [
            "I was deceived by fraudsters into sharing confidential details / installing an app, after which the above transaction(s) took place. "
            "I am reporting this at the earliest so that no further loss occurs. I request you to:",
            "  1. Immediately block my card / UPI / net-banking access;",
            "  2. Register this complaint, examine it under your customer-protection policy and the RBI circular dated 6 July 2017, and share the reference number;",
            "  3. Raise a fraud report with the beneficiary bank(s) and request a hold/lien on the receiving account(s); and",
            "  4. Inform me of any reversal or compensation I am eligible for.",
        ]
    else:
        lines += [
            "I was deceived into making this transfer by fraudsters"
            + (f" impersonating {_claimed(case)}" if _claimed(case) else "")
            + ". I have reported the fraud on the National Cyber Crime Reporting Portal (acknowledgement no. [__________]) / helpline 1930. I request you to:",
            "  1. Immediately raise a fraud report with the beneficiary bank and request a hold/lien on the beneficiary account(s) below;",
            "  2. Register this complaint and share the complaint reference number with me;",
            "  3. Block my card / UPI if required; and",
            "  4. Inform me whether I am eligible for any reversal or compensation under your policy and applicable RBI directions.",
        ]
    lines += [
        "",
        "Transaction details:",
        f"  • Date & time: {when}",
        f"  • Amount: {amount}",
        f"  • Mode: {pm}",
        f"  • Beneficiary (UPI ID / account): {dest}",
        f"  • UTR / reference no.: {utr}",
        "  • NCRP acknowledgement no.: [__________]",
        "",
        "Copies of the transaction SMS and screenshots are attached.",
        "",
        "Yours faithfully,",
        "[Your name]",
        "[Registered mobile number] · [Email]",
    ]
    return "\n".join(lines)


def chakshu_report(case: dict) -> str | None:
    e = case["entities"]
    ch = _channel(case)
    if ch not in {"call", "video_call", "whatsapp", "sms", "message"} and not e.phones and not e.sender_ids:
        return None
    pb = get_playbook(case.get("playbook_id"))
    medium = {"call": "Call", "video_call": "Call (WhatsApp/video)", "whatsapp": "WhatsApp", "sms": "SMS"}.get(ch, "SMS / Call / WhatsApp")
    who = ", ".join([p["raw"] for p in e.phones] + [s["raw"] for s in e.sender_ids]) or "[number / sender ID]"
    tri = case.get("triage") or {}
    when = tri.get("incident_display") or case.get("when") or "[date and time]"
    claimed = _claimed(case)
    desc = (f"The sender claimed to be {claimed} and the" if claimed else "The") + f" communication matches the '{pb['name']['en']}' fraud pattern. Requesting action against the number/sender."
    return (
        f"Medium: {medium}\n"
        f"Suspected number / sender: {who}\n"
        f"Date & time: {when}\n"
        f"Category (closest match): {pb['chakshu']}\n"
        f"Description: {desc}"
    )


def police_complaint(case: dict) -> str:
    tri = case.get("triage") or {}
    when = tri.get("incident_display") or case.get("when") or "[date and time]"
    amount = inr(case.get("amount"))
    pb = get_playbook(case.get("playbook_id"))
    ids = _identifiers(case)
    flat = "; ".join(f"{k}: {', '.join(v)}" for k, v in ids.items() if v) or "[numbers / UPI IDs / accounts used]"
    return "\n".join([
        "To,",
        "The Station House Officer",
        "[Cyber Crime Police Station / Police Station], [City]",
        "",
        f"Subject: Request to register an FIR — cyber fraud of {amount} on {when}",
        "",
        "Respected Sir/Madam,",
        "",
        f"I, [Your full name], resident of [address], wish to report a cyber fraud ({pb['name']['en']}). On {when}, "
        + (f"a person claiming to be {_claimed(case)}" if _claimed(case) else "an unknown person")
        + f" contacted me and, by deception, caused a loss of {amount}. I have already reported this on the National Cyber Crime "
        "Reporting Portal (acknowledgement no. [__________]) / 1930.",
        "",
        f"Suspect details: {flat}.",
        "",
        f"I request you to register an FIR under {LEGAL_SECTIONS}, and to take steps to trace and freeze the money trail.",
        "",
        "Enclosures: screenshots, bank statement/SMS, NCRP acknowledgement.",
        "",
        "Yours faithfully,",
        "[Name] · [Mobile] · [Date]",
    ])


def family_alert(case: dict, lang: str) -> str:
    pb = get_playbook(case.get("playbook_id"))
    use = lang if lang in FAMILY_ALERT else "en"
    ch = _channel(case)
    ch_word = t(CHANNEL_WORDS.get(ch, CHANNEL_WORDS["message"]), use)
    return FAMILY_ALERT[use].format(typology=t(pb["name"], use), channel=ch_word, truth=t(pb["truth"], use))
