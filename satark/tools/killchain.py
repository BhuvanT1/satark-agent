"""Scam kill-chain analyst.

Maps the evidence onto the 7-stage lifecycle every social-engineering fraud
follows, shows where the victim is right now, and pre-bunks the fraudster's
likely next move — including the "recovery agent" re-victimisation scam that
targets people who have already lost money.
"""

from __future__ import annotations

STAGES = [
    {"id": "hook", "name": "Hook", "desc": "Unsolicited contact with a lure or a threat"},
    {"id": "pretext", "name": "Pretext", "desc": "Poses as a bank, officer, company or relative"},
    {"id": "pressure", "name": "Pressure", "desc": "Fear, greed or urgency to stop you thinking"},
    {"id": "isolation", "name": "Isolation", "desc": "Secrecy, stay-on-call, move to WhatsApp"},
    {"id": "capture", "name": "Capture", "desc": "OTP/PIN, app install, QR scan, link or account details"},
    {"id": "cashout", "name": "Cash-out", "desc": "Money moved to mule accounts / UPI IDs"},
    {"id": "repeat", "name": "Re-victimise", "desc": "More 'fees', blackmail or fake 'recovery agents'"},
]

STAGE_SIGNALS = {
    "hook": {"reward_lure", "job_task", "investment_lure", "loan_lure", "courier_parcel", "electricity_cut", "challan", "kyc_threat",
             "refund_customer_care", "govt_scheme_fee", "tax_refund", "card_reward", "wrong_transfer", "relative_emergency",
             "sim_swap", "pension_life_cert", "marketplace_buyer", "mule_recruit", "sextortion", "digital_arrest", "link_present"},
    "pretext": {"authority_impersonation", "digital_arrest", "relative_emergency", "kyc_threat", "courier_parcel", "marketplace_buyer",
                "refund_customer_care", "sim_swap", "pension_life_cert", "tax_refund", "govt_scheme_fee", "brand_claim"},
    "pressure": {"urgency", "digital_arrest", "sextortion", "loan_harassment", "electricity_cut", "kyc_threat", "reward_lure", "investment_lure", "relative_emergency", "sim_swap"},
    "isolation": {"secrecy", "video_call", "telegram_whatsapp_move", "call_instruction"},
    "capture": {"otp_request", "pin_to_receive", "remote_access", "apk_install", "phishing_link", "mule_recruit", "bidi_spoof"},
    "cashout": {"payment_request", "money_lost", "authorised_push"},
    "repeat": {"repeat_demand"},
}

NEXT_MOVE = {
    "digital_arrest": ("They will demand a 'verification' transfer to an 'RBI safe account', promising a refund after 'clearance'.",
                       "They will demand more money — 'tax', 'bail' or 'clearance' — and threaten arrest again."),
    "kyc_update": ("The link opens a fake bank page that captures your login, card details and OTP; then a 'bank officer' calls for the OTP.",
                   "With your details they can make more transfers or take a loan in your name — block net-banking and cards now."),
    "malicious_apk": ("Once installed, the app silently forwards your SMS OTPs; transfers often start within minutes, frequently at night.",
                      "The app may still be forwarding OTPs — airplane mode and uninstall before anything else."),
    "echallan": ("The page asks for card or UPI details to 'pay the fine', or pushes an e-Challan APK that steals OTPs.",
                 "They may reuse your card details for more purchases — block the card."),
    "electricity_disconnection": ("The 'officer' asks for a small 'bill update' payment via a link or a support app, then drains the account.",
                                  "If a support app is installed they keep remote access — uninstall it and change passwords."),
    "task_job": ("After small payouts they move you to 'prepaid / merchant tasks' that need ever-larger deposits, then demand 'tax' to withdraw.",
                 "They will insist you pay one more 'unlock' or 'tax' fee to withdraw — nothing will ever be paid out."),
    "investment_trading": ("The app shows big 'profits'; when you try to withdraw, they demand 'tax', 'SEBI fees' or 'withdrawal charges'.",
                           "Expect more 'withdrawal fees' and pressure to 'invest more to unlock' — stop all payments."),
    "lottery_prize": ("After the first 'processing fee', new fees appear — GST, insurance, RBI clearance — until you stop paying.",
                      "More 'fees' will follow — none of them release a prize."),
    "courier_customs_gift": ("A 'customs officer' or 'police' call follows, threatening arrest — it can turn into a digital-arrest scam.",
                             "They will invent new duties or penalties — customs never collects money into personal accounts."),
    "upi_qr_receive": ("They will send another QR or request saying the first one 'failed', taking more money each time.",
                       "Expect a second QR/collect request — do not scan or approve anything."),
    "refund_customer_care": ("With screen-sharing they watch you type your PIN and move money while 'processing the refund'.",
                             "They may still have remote access — uninstall screen-sharing apps and change PINs."),
    "relative_emergency": ("They will call again with bigger, more urgent demands — hospital bills, police bail — before you can verify.",
                           "More 'urgent' demands will follow — verify with your relative on their known number first."),
    "sim_swap_esim": ("Once your number moves to their SIM/eSIM, your phone loses signal and they reset banking passwords with your OTPs.",
                      "If your phone shows 'No service', call your telecom operator and bank immediately."),
    "loan_app": ("More 'fees' follow, or — if an app was installed — your contacts and photos are misused for harassment.",
                 "They may harass your contacts — warn them in advance and report the app."),
    "sextortion": ("Paying leads to repeat demands; they may pose as 'police' or 'YouTube officers' to demand more for 'deleting' the video.",
                   "Payment will not stop them — preserve evidence and report; do not pay again."),
    "mule_recruitment": ("Stolen money will pass through your account; when victims complain, the account is frozen and police notices come to you.",
                         "Inform your bank and police now — it protects you legally."),
    "wrong_transfer": ("They send a fake 'credited' SMS and push you to 'refund' fast, perhaps via a collect request.",
                       "Expect more pressure to 'return' money — check your real balance in the bank app."),
    "fake_govt_scheme": ("After the 'registration fee', they ask for Aadhaar, bank details and OTP to 'release the subsidy'.",
                         "They may ask for more 'processing' fees or your OTP — stop all contact."),
    "tax_refund": ("The page asks for net-banking login and OTP to 'credit the refund'.",
                   "With your login they can make transfers — change passwords and inform the bank."),
    "pension_life_cert": ("They ask for the OTP 'to update your life certificate' and use it to withdraw the pension.",
                          "Inform the bank branch that handles the pension immediately."),
    "card_reward": ("The page asks for card number, expiry, CVV and then the OTP — used for an online purchase.",
                    "Block the card — the details can be reused."),
    "generic_suspicious": ("Expect a request for an OTP, a payment, an app install or personal details.",
                           "Expect follow-up demands — stop all contact."),
}

RECOVERY_SCAM_WARNING = (
    "Beware the second scam: fake 'recovery agents', 'cyber lawyers' or 'police' who call promising to get your money back "
    "for a fee. Real recovery happens only through 1930 / cybercrime.gov.in, your bank and the police — never through a paid agent."
)


def analyze_killchain(signals: set[str], url_verdicts: list[str], brands_claimed: bool, money_lost: bool, playbook_id: str | None, tier: str) -> dict:
    sig = set(signals)
    if any(v in {"dangerous", "suspicious"} for v in url_verdicts):
        sig |= {"phishing_link", "link_present"}
    elif url_verdicts:
        sig.add("link_present")
    if brands_claimed:
        sig.add("brand_claim")
    if money_lost and ("repeat_demand" in sig or {"sextortion", "loan_harassment"} & sig):
        sig.add("repeat_demand")

    observed = []
    for st in STAGES:
        hits = sorted(STAGE_SIGNALS[st["id"]] & sig)
        observed.append({**st, "observed": bool(hits), "evidence": hits})
    if tier == "SAFE":
        for o in observed:
            o["observed"] = False
    current = max((i for i, o in enumerate(observed) if o["observed"]), default=-1)
    if money_lost and current < 5:
        current = 5
        observed[5]["observed"] = True
    pre, post = NEXT_MOVE.get(playbook_id or "generic_suspicious", NEXT_MOVE["generic_suspicious"])
    next_index = current + 1 if 0 <= current < len(STAGES) - 1 and tier != "SAFE" else None
    return {
        "stages": observed,
        "current_index": current,
        "next_index": next_index,
        "current_stage": observed[current]["name"] if current >= 0 else None,
        "observed_count": sum(1 for o in observed if o["observed"]),
        "next_move": (post if money_lost else pre) if tier != "SAFE" else None,
        "recovery_scam_warning": RECOVERY_SCAM_WARNING if money_lost else None,
    }
