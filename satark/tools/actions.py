"""Recovery planner: turns verdict + triage into a prioritised action plan."""

from __future__ import annotations

from ..kb.i18n import ACTIONS, GOLDEN, t
from ..kb.playbooks import get_playbook

PRIORITY_ORDER = {"NOW": 0, "TODAY": 1, "NEXT 3 DAYS": 2, "LATER": 3}


def build_actions(tier: str, playbook_id: str | None, money_lost: bool, triage: dict | None, auth_class: str | None,
                  payment_mode: str | None, amount: float | None, state: str | None, has_contact_channel: bool, lang: str) -> list[dict]:
    plan: list[dict] = []
    seen: set[str] = set()

    def add(key: str, priority: str, due: str | None = None):
        if key in seen or key not in ACTIONS:
            return
        seen.add(key)
        plan.append({"key": key, "priority": priority, "due": due, "text": t(ACTIONS[key], lang), "text_en": ACTIONS[key]["en"]})

    pb = get_playbook(playbook_id)
    pm = (payment_mode or "").lower()

    if money_lost:
        if playbook_id == "digital_arrest":
            add("disconnect_call", "NOW")
        if playbook_id in {"malicious_apk", "refund_customer_care", "electricity_disconnection"}:
            add("uninstall_app", "NOW")
        add("call_1930", "NOW", "Immediately")
        add("call_bank_block", "NOW", "Immediately")
        add("file_ncrp", "NOW", "Within the hour")
        if "card" in pm:
            add("request_chargeback", "TODAY")
        if "upi" in pm:
            add("upi_app_dispute", "TODAY")
        due_zero = None
        for d in (triage or {}).get("deadlines", []):
            if d["key"] == "rbi_zero":
                due_zero = d["due"]
        add("bank_written_complaint", "TODAY", f"By {due_zero}" if due_zero and auth_class in {"unauthorised_third_party", "unknown"} else "Today")
        add("preserve_evidence", "TODAY")
        add("stop_contact", "TODAY")
        if has_contact_channel:
            add("report_chakshu", "TODAY")
        if playbook_id == "sextortion":
            add("do_not_pay_sextortion", "NOW")
        if playbook_id == "mule_recruitment":
            add("stop_mule", "NOW")
        if amount and amount > 10_00_000:
            if (state or "").strip().lower() == "delhi":
                add("ezero_fir", "NEXT 3 DAYS", "Within 3 days")
            else:
                add("file_fir", "TODAY")
        elif amount and amount >= 1_00_000:
            add("file_fir", "NEXT 3 DAYS")
        add("escalate_ombudsman", "LATER", "If unresolved after 30 days")
        add("warn_family", "LATER")
        return plan

    if tier == "SAFE":
        add("no_action_needed", "NOW")
        add("verify_official", "NOW")
        return plan

    for key in pb.get("actions", []):
        add(key, "NOW")
    add("never_share_otp", "NOW")
    if has_contact_channel:
        add("report_chakshu", "TODAY")
    add("check_suspect", "TODAY")
    add("preserve_evidence", "TODAY")
    if tier in {"SCAM", "HIGH"}:
        add("warn_family", "TODAY")
    plan.sort(key=lambda a: PRIORITY_ORDER.get(a["priority"], 9))
    return plan


def golden_message(triage: dict | None, lang: str) -> str | None:
    if not triage or triage.get("status") in {None, "not_applicable"}:
        return None
    status = triage["status"]
    key = {"golden": "golden", "urgent": "urgent", "late": "late", "unknown": "urgent"}.get(status, "urgent")
    return t(GOLDEN[key], lang)
