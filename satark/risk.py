"""Risk Judge: an explainable scorecard that fuses tool evidence, playbook
matches and (optionally) the LLM's assessment.

Guardrail: hard 'floors' come from deterministic evidence (e.g. an APK link,
an OTP request, a digital-arrest script). An LLM — or a prompt-injection
attempt hidden inside the scam text — can never pull the score below them.
"""

from __future__ import annotations

from .tools.signals import SIGNAL_LABELS, SIGNAL_WEIGHTS, signal_risk

TIERS = [(75, "SCAM"), (50, "HIGH"), (25, "SUSPICIOUS"), (0, "SAFE")]
TIER_LABEL = {"SCAM": "Scam", "HIGH": "High risk", "SUSPICIOUS": "Suspicious", "SAFE": "Looks safe"}


def tier_for(score: int) -> str:
    for threshold, name in TIERS:
        if score >= threshold:
            return name
    return "SAFE"


def risky_links_pre(url_results: list[dict]) -> bool:
    return any(r["verdict"] in {"dangerous", "suspicious"} for r in url_results)


def _noisy_or(values: list[float]) -> float:
    p = 1.0
    for v in values:
        v = max(0.0, min(0.99, v))
        p *= 1 - v
    return 1 - p


def judge(
    signals: dict[str, list[str]],
    url_results: list[dict],
    upi_results: list[dict],
    phone_results: list[dict],
    sender_results: list[dict],
    playbooks: list[dict],
    money_lost: bool,
    llm_risk: int | None = None,
    llm_verdict: str | None = None,
    floor_signals: set[str] | None = None,
) -> dict:
    evidence: list[dict] = []
    floors: list[tuple[int, str]] = []
    sig_set = set(signals)
    # Hard floors only come from deterministic (rule-detected) signals.
    fs = set(floor_signals) if floor_signals is not None else sig_set

    # --- 1. Behavioural signals
    for sig, snippets in signals.items():
        w = SIGNAL_WEIGHTS.get(sig, 0.0)
        if w == 0:
            continue
        evidence.append({
            "source": "Signal detector",
            "label": SIGNAL_LABELS.get(sig, sig),
            "detail": " · ".join(f"“{s}”" for s in snippets[:2]),
            "weight": w,
        })

    # --- 2. Tool evidence
    def add_tool(source, item_key, results):
        for r in results:
            for s in r.get("signals", []):
                evidence.append({"source": source, "label": s["label"], "detail": s.get("detail") or r.get(item_key, ""), "weight": s["weight"]})
            for s in r.get("trust_signals", []):
                evidence.append({"source": source, "label": s["label"], "detail": s.get("detail") or r.get(item_key, ""), "weight": -s["weight"]})

    add_tool("Link forensics", "url", url_results)
    add_tool("UPI ID check", "upi_id", upi_results)
    add_tool("Phone check", "number", phone_results)
    add_tool("Sender-ID check", "sender", sender_results)

    top = playbooks[0] if playbooks and playbooks[0]["core_hit"] else None
    if top:
        evidence.append({
            "source": "Scam playbook matcher",
            "label": f"Matches the '{top['name_en']}' playbook",
            "detail": "Indicators: " + ", ".join(SIGNAL_LABELS.get(m, m) for m in top["matched"][:5]),
            "weight": round(top["score"], 2),
        })

    # --- 3. Combine
    comps = [
        (top["score"] * 0.9) if top else 0.0,
        signal_risk(signals) * 0.85,
        max((r["risk"] for r in url_results), default=0.0),
        max((r["risk"] for r in upi_results), default=0.0),
        max((r["risk"] for r in phone_results), default=0.0),
        max((r["risk"] for r in sender_results), default=0.0),
    ]
    combined = _noisy_or(comps)

    # --- 4. Trust adjustments
    trusts = []
    if url_results and all(r["verdict"] == "official" for r in url_results):
        trusts.append(0.5)
    if "otp_warning_legit" in sig_set and "otp_request" not in sig_set:
        trusts.append(0.35)
    if "bank_alert_format" in sig_set:
        trusts.append(0.15)
    if "official_channel_advice" in sig_set and not risky_links_pre(url_results):
        trusts.append(0.3)
    if any(t["code"] == "bank_1600" for r in phone_results for t in r.get("trust_signals", [])):
        trusts.append(0.3)
    if sender_results and not any(r["signals"] for r in sender_results):
        trusts.append(0.15)
    asks = {"payment_request", "otp_request", "remote_access", "apk_install", "pin_to_receive", "mule_recruit", "digital_arrest", "secrecy", "sextortion"}
    risky_links = [r for r in url_results if r["verdict"] in {"dangerous", "suspicious"}]
    if not (sig_set & asks) and not risky_links and not money_lost and not top:
        trusts.append(0.35)
    trust_total = min(0.85, _noisy_or(trusts)) if trusts else 0.0
    score = combined * (1 - trust_total)

    # --- 5. Hard floors from deterministic evidence
    if fs & {"apk_install", "remote_access"}:
        floors.append((85, "App-install / remote-access request"))
    if "pin_to_receive" in fs:
        floors.append((85, "UPI PIN / QR needed to 'receive' money"))
    if "otp_request" in fs:
        floors.append((80, "Asks for OTP / PIN / CVV"))
    if "mule_recruit" in fs:
        floors.append((80, "Bank-account renting (money mule)"))
    if "sextortion" in fs:
        floors.append((85, "Sextortion threat"))
    if "prompt_injection" in signals:
        floors.append((75, "Hidden instructions aimed at AI checkers"))
    if "bidi_spoof" in fs:
        floors.append((85, "Disguised file name (right-to-left trick)"))
    if "evasion_obfuscation" in fs and any(SIGNAL_WEIGHTS.get(x, 0) >= 0.15 for x in fs if x != "evasion_obfuscation"):
        floors.append((75, "Keywords deliberately disguised to evade filters"))
    if top and top["id"] == "digital_arrest" and top["score"] >= 0.6:
        floors.append((90, "Digital-arrest script"))
    if top and top["critical"] and top["score"] >= 0.55:
        floors.append((80, f"Critical playbook: {top['name_en']}"))
    for r in url_results:
        codes = {s["code"] for s in r["signals"]}
        if codes & {"brand_impersonation", "typosquat"}:
            floors.append((80, "Look-alike / impersonating link"))
        if "apk_download" in codes:
            floors.append((88, "APK download link"))
    for r in upi_results:
        if any(s["code"] == "official_fee_to_personal_upi" for s in r["signals"]):
            floors.append((80, "Official-sounding payment to a personal UPI ID"))
    for r in phone_results:
        if any(s["code"] == "foreign_claims_indian_authority" for s in r["signals"]):
            floors.append((80, "Foreign number posing as Indian bank/agency"))
    if money_lost and top and top["score"] >= 0.35:
        floors.append((85, "Money already lost in a known scam pattern"))

    rule_score = min(99, int(round(score * 100)))
    floor = max((f for f, _ in floors), default=0)
    blended = rule_score
    if llm_risk is not None:
        blended = int(round(0.65 * rule_score + 0.35 * max(0, min(100, llm_risk))))
    final = max(blended, floor)
    final = max(0, min(99, final))
    tier = tier_for(final)

    strong = [e for e in evidence if e["weight"] >= 0.4]
    if floors or len(strong) >= 3:
        confidence = "High"
    elif len(strong) >= 1 or len(evidence) >= 4:
        confidence = "Medium"
    else:
        confidence = "Low" if final >= 25 else "Medium"
    disagreement = None
    if llm_risk is not None and abs(llm_risk - rule_score) >= 45:
        disagreement = f"AI reviewer ({llm_risk}) and rule engine ({rule_score}) disagree — the higher-safety outcome is shown."
        if confidence == "High" and not floors:
            confidence = "Medium"

    evidence.sort(key=lambda e: e["weight"], reverse=True)
    return {
        "score": final,
        "tier": tier,
        "tier_label": TIER_LABEL[tier],
        "rule_score": rule_score,
        "llm_score": llm_risk,
        "llm_verdict": llm_verdict,
        "floor": floor,
        "floor_reasons": [r for f, r in sorted(floors, reverse=True)][:4],
        "trust_discount": round(trust_total, 2),
        "confidence": confidence,
        "disagreement": disagreement,
        "evidence": evidence,
        "top_playbook": top["id"] if top else None,
    }
