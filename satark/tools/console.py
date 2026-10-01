"""Action console (one-tap actions) and the machine-readable case file for
bank fraud desks / the 1930 helpline."""

from __future__ import annotations

from urllib.parse import quote


def build_console(money_lost: bool, tier: str, drafts: dict, has_channel: bool) -> list[dict]:
    items: list[dict] = []
    if money_lost or tier in {"SCAM", "HIGH"}:
        items.append({"label": "Call 1930 now", "href": "tel:1930", "primary": True})
    if money_lost or tier in {"SCAM", "HIGH", "SUSPICIOUS"}:
        items.append({"label": "File on cybercrime.gov.in", "href": "https://cybercrime.gov.in/", "primary": money_lost})
    letter = drafts.get("bank_letter")
    if letter:
        subject = next((ln.replace("Subject:", "").strip() for ln in letter.splitlines() if ln.startswith("Subject:")), "Fraud complaint")
        body = letter if len(letter) <= 1800 else letter[:1800] + "\n…"
        items.append({"label": "Email my bank (letter pre-filled)", "href": "mailto:?subject=" + quote(subject) + "&body=" + quote(body), "primary": False})
    if drafts.get("family_alert"):
        items.append({"label": "Warn family on WhatsApp", "href": "https://wa.me/?text=" + quote(drafts["family_alert"]), "primary": False})
    if has_channel and tier != "SAFE":
        items.append({"label": "Report the number (Chakshu)", "href": "https://sancharsaathi.gov.in/", "primary": False})
    if money_lost:
        items.append({"label": "RBI Ombudsman (if bank fails)", "href": "https://cms.rbi.org.in/", "primary": False})
    return items


def build_case_file(result_core: dict) -> dict:
    """result_core keys: case_id, generated_at, verdict, typology_id, killchain, money_lost, amount,
    payment_mode, triage, liability, forensics, entities, fingerprint, obfuscation."""
    f = result_core["forensics"]
    ent = result_core["entities"]
    indicators = []
    for p in f["phones"]:
        indicators.append({"type": "phone", "value": p["number"], "kind": p["kind"], "country": p["country"], "risk": p["risk"], "findings": [s["label"] for s in p["signals"]]})
    for u in f["upi"]:
        indicators.append({"type": "upi", "value": u["upi_id"], "psp": u.get("psp"), "risk": u["risk"], "findings": [s["label"] for s in u["signals"]]})
    for u in f["urls"]:
        indicators.append({"type": "url", "value": u["url"], "host": u["host"], "verdict": u["verdict"], "risk": u["risk"], "domain_age_days": u.get("domain_age_days"), "findings": [s["label"] for s in u["signals"]]})
    for s_ in f["senders"]:
        indicators.append({"type": "sms_header", "value": s_["sender"], "risk": s_["risk"]})
    for e in ent.emails:
        indicators.append({"type": "email", "value": e})
    for a in ent.accounts:
        indicators.append({"type": "bank_account", "value": a})
    for t in ent.txn_ids:
        indicators.append({"type": "transaction_ref", "value": t})

    actions = []
    if result_core["money_lost"]:
        for u in f["upi"]:
            actions.append(f"Flag beneficiary UPI ID {u['upi_id']} as fraud and request a debit freeze / lien through CFCFRMS")
        for a in ent.accounts:
            actions.append(f"Request a lien on beneficiary account {a} with the beneficiary bank")
    for p in f["phones"]:
        if p["risk"] >= 0.3:
            actions.append(f"Report {p['number']} to DoT (Chakshu) for verification / disconnection")
    for u in f["urls"]:
        if u["verdict"] in {"dangerous", "suspicious"}:
            actions.append(f"Request blocking / takedown of {u['host']} (registrar abuse desk, CERT-In)")
    if indicators:
        actions.append("Add the indicators above to the I4C Suspect Registry")

    v = result_core["verdict"]
    tri = result_core.get("triage") or {}
    kc = result_core.get("killchain") or {}
    return {
        "schema": "satark.case/1.0",
        "case_id": result_core["case_id"],
        "generated_at": result_core["generated_at"],
        "risk": {"score": v["score"], "tier": v["tier"], "confidence": v["confidence"], "floor_reasons": v.get("floor_reasons", [])},
        "typology": result_core.get("typology_id"),
        "kill_chain_stage": kc.get("current_stage"),
        "evasion_techniques": [o["code"] for o in result_core.get("obfuscation", [])],
        "money": {
            "lost": result_core["money_lost"],
            "amount_inr": result_core.get("amount"),
            "mode": result_core.get("payment_mode"),
            "incident_at": tri.get("incident_at"),
            "minutes_elapsed": tri.get("elapsed_minutes"),
            "golden_hour": tri.get("status") == "golden",
            "authorisation": (result_core.get("liability") or {}).get("class"),
        },
        "indicators": indicators,
        "suggested_institutional_actions": actions,
        "evidence_sha256": result_core["fingerprint"],
    }
