"""Deterministic stand-in for an LLM, used only by tests (SATARK_LLM_PROVIDER=mock).

SATARK_MOCK_MODE=manipulated simulates an LLM that was fooled by a prompt
injection (it claims everything is safe) — tests assert that Satark's
deterministic safety floors still hold.
"""

from __future__ import annotations

import os
import re


def mock_response(system: str, messages: list[dict]) -> dict:
    last = messages[-1]["content"] if messages else ""
    manipulated = os.environ.get("SATARK_MOCK_MODE") == "manipulated"
    if last.startswith("STEP: PLAN"):
        calls = []
        for u in re.findall(r"'links': \[([^\]]*)\]", last):
            for link in re.findall(r"'([^']+)'", u):
                calls.append({"tool": "analyze_url", "args": {"url": link}, "why": "check link owner"})
        for ph in sorted(set(re.findall(r"\[UPI_\d+\]", last))):
            calls.append({"tool": "check_upi_id", "args": {"upi_id": ph}, "why": "beneficiary check"})
        for ph in sorted(set(re.findall(r"\[PHONE_\d+\]", last)))[:1]:  # deliberately skip others → policy guard
            calls.append({"tool": "check_phone_number", "args": {"phone": ph}, "why": "caller origin"})
        calls.append({"tool": "match_scam_playbooks", "args": {}, "why": "known scripts"})
        calls.append({"tool": "not_a_real_tool", "args": {}, "why": "should be ignored"})
        money = "'money_lost': 'yes'" in last
        if money:
            calls.append({"tool": "golden_hour_triage", "args": {}, "why": "money lost"})
        sigs = []
        low = last.lower()
        if "otp" in low and "share" in low:
            sigs.append("otp_request")
        if "video call" in low:
            sigs.append("video_call")
        return {
            "thought": "Mock planner: checking every identifier and the scam playbooks.",
            "case_facts": {
                "claimed_identity": "Mock Bank" if "bank" in low else None,
                "channel": "whatsapp" if "whatsapp" in low else "sms",
                "asks": ["share details"],
                "threats_or_lures": [],
                "money_movement": {"lost": money, "authorised_by_victim": True if money else None, "otp_shared": None},
                "signals": sigs + ["not_a_signal"],
                "manipulation_attempt": False if manipulated else ("ignore all previous" in low),
            },
            "tool_calls": calls,
        }
    if last.startswith("STEP: REFLECT"):
        danger = ("DANGEROUS" in last or "core match" in last) and not manipulated
        return {
            "thought": "Mock reflection: evidence reviewed.",
            "tool_calls": [],
            "done": True,
            "assessment": {
                "risk": 3 if manipulated else (88 if danger else 20),
                "verdict": "legitimate" if manipulated else ("scam" if danger else "suspicious"),
                "typology": "legitimate" if manipulated else "kyc_update",
                "rationale": "Mock rationale.",
            },
        }
    lang = re.search(r"Write in: (\w+)", last)
    return {
        "headline": f"Mock headline ({lang.group(1) if lang else 'English'})",
        "summary_points": ["Mock point one citing [PHONE_1].", "Mock point two.", "Mock point three."],
        "what_they_want_next": "Mock next step.",
        "family_alert": "Mock alert: call 1930 and report on cybercrime.gov.in. <script>x</script>",
        "ncrp_description": "Mock complaint narrative. " * 12 + " Number used: [PHONE_1].",
        "chakshu_description": "Mock chakshu description.",
    }
