"""Satark orchestrator — a plan → act → reflect → judge → respond agent.

Specialist roles:
  Intake agent      : understands the case, extracts entities, masks PII
  Orchestrator      : plans which forensic tools to run (LLM or deterministic)
  Forensics agent   : executes tools (links, UPI, phone, sender ID, playbooks, RDAP)
  Risk judge        : explainable scorecard + AI second opinion + safety floors
  Recovery planner  : golden-hour triage, RBI liability, deadlines, action plan
  Drafting agent    : complaint kit, bank letter, Chakshu report, family alert

Works fully offline; an LLM (Gemini / OpenAI-compatible) upgrades planning,
reasoning and multilingual drafting. Every LLM failure degrades gracefully.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from datetime import datetime

from . import __version__
from .config import IST, Settings, get_settings
from .kb.domains import BRAND_TOKENS, OFFICIAL_BRANDS
from .kb.facts import BANK_CONTACT_FACTS, DISCLAIMER, STATS, UPI_FACTS
from .kb.i18n import HEADLINES, LANG_NAMES, OFFLINE_LANGS, lang_code, t
from .kb.playbooks import PLAYBOOK_BY_ID, get_playbook
from .llm import LLMClient, LLMError
from .prompts import DRAFT_SYSTEM, DRAFT_TEMPLATE, ORCHESTRATOR_SYSTEM, PLAN_TEMPLATE, PLAYBOOK_IDS, REFLECT_TEMPLATE, SIGNAL_ENUM
from .risk import judge
from .tools import drafting
from .tools.actions import build_actions, golden_message
from .tools.deobfuscate import deobfuscate
from .tools.extract import extract_entities
from .tools.console import build_case_file, build_console
from .tools.killchain import analyze_killchain
from .tools.identity_check import check_phone_number, check_sender_id, check_upi_id
from .tools.playbook_match import match_playbooks
from .tools.redact import Redactor
from .tools.signals import SIGNAL_LABELS, detect_signals
from .tools.triage import classify_authorisation, golden_hour_triage, liability_analysis
from .tools.url_check import analyze_url, rdap_domain_age_days, registrable_domain

ALLOWED_TOOLS = {
    "analyze_url", "check_domain_age", "check_upi_id", "check_phone_number", "check_sender_id",
    "match_scam_playbooks", "lookup_official_channel", "golden_hour_triage", "liability_check",
}


def _parse_amount(v) -> float | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v) if v > 0 else None
    s = str(v).lower().replace("₹", "").replace("rs.", "").replace("rs", "").replace("inr", "").strip()
    mult = 1.0
    if "crore" in s or s.endswith("cr"):
        mult = 1e7
    elif "lakh" in s or "lac" in s:
        mult = 1e5
    elif s.endswith("k"):
        mult = 1e3
    m = re.search(r"[\d,]+(\.\d+)?", s)
    if not m:
        return None
    try:
        val = float(m.group(0).replace(",", "")) * mult
    except ValueError:
        return None
    return val if val > 0 else None


@dataclass
class CaseInput:
    situation: str
    money_lost: str = "unspecified"  # yes | no | not_sure | unspecified
    amount: float | None = None
    when: str | None = None
    payment_mode: str | None = None
    language: str = "English"
    state: str | None = None
    victim_profile: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "CaseInput":
        d = d or {}

        def pick(*keys, default=None):
            for k in keys:
                if k in d and d[k] not in (None, ""):
                    return d[k]
            return default

        situation = pick("situation", "message", "text", "query", "input", "prompt", "description", default="") or ""
        ml_raw = pick("money_lost", "lost_money", "moneyLost", default="unspecified")
        if isinstance(ml_raw, bool):
            ml = "yes" if ml_raw else "no"
        else:
            low = str(ml_raw).strip().lower()
            if "sure" in low or "maybe" in low or "don't know" in low or "dont know" in low:
                ml = "not_sure"
            elif low.startswith(("yes", "y", "true", "हाँ", "హా", "అవును")):
                ml = "yes"
            elif low.startswith(("no", "n", "false", "नहीं", "లేదు")):
                ml = "no"
            else:
                ml = "unspecified"
        pm = pick("payment_mode", "payment_method", "paymentMode", default=None)
        if isinstance(pm, str) and pm.lower().startswith(("not applicable", "n/a", "none")):
            pm = None
        state = pick("state", "location", default=None)
        if isinstance(state, str) and state.lower().startswith(("prefer", "not ")):
            state = None
        return cls(
            situation=str(situation),
            money_lost=ml,
            amount=_parse_amount(pick("amount", "amount_lost", "amountLost", default=None)),
            when=pick("when", "incident_time", "time", "when_happened", default=None),
            payment_mode=pm,
            language=str(pick("language", "lang", default="English")),
            state=state,
            victim_profile=pick("victim_profile", "who", "profile", default=None),
        )


class SatarkAgent:
    def __init__(self, settings: Settings | None = None, now: datetime | None = None):
        self.s = settings or get_settings()
        self.now = now or datetime.now(IST)
        self.llm = LLMClient(self.s)
        self.t0 = time.monotonic()
        self.trace: list[dict] = []
        self.llm_errors: list[str] = []
        # tool results
        self.url_results: dict[str, dict] = {}
        self.upi_results: dict[str, dict] = {}
        self.phone_results: dict[str, dict] = {}
        self.sender_results: dict[str, dict] = {}
        self.domain_ages: dict[str, int | None] = {}
        self.official_lookups: dict[str, dict] = {}
        self.playbooks: list[dict] | None = None
        self.triage: dict | None = None
        self.liability: dict | None = None
        self.observations: list[str] = []

    # ------------------------------------------------------------------
    def remaining(self) -> float:
        return self.s.time_budget_s - (time.monotonic() - self.t0)

    def _step(self, agent: str, title: str, thought: str, calls: list[dict] | None = None, llm: bool = False, ms: int = 0, plan: list[str] | None = None) -> None:
        self.trace.append({"n": len(self.trace) + 1, "agent": agent, "title": title, "thought": thought, "calls": calls or [], "llm": llm, "ms": ms, "plan": plan or []})

    # ------------------------------------------------------------------
    def run(self, inp: CaseInput) -> dict:
        original = (inp.situation or "").strip()[:6000]
        lang = lang_code(inp.language)
        t_start = time.monotonic()

        # ---------------- 1. Intake -----------------------------------
        t1 = time.monotonic()
        self.fingerprint = hashlib.sha256(original.encode("utf-8")).hexdigest()
        text, obf = deobfuscate(original) if self.s.deobfuscate else (original, [])
        self.obfuscation = obf
        ent = extract_entities(text)
        sig_rule = detect_signals(text)
        for k, v in detect_signals(original).items():
            sig_rule.setdefault(k, v)
        if any(f["code"] == "bidi_override" for f in obf):
            sig_rule["bidi_spoof"] = [f["examples"][0] for f in obf if f["code"] == "bidi_override" and f["examples"]][:1] or ["(hidden control characters)"]
        if any(f["code"] != "bidi_override" for f in obf):
            sig_rule["evasion_obfuscation"] = [ex for f in obf if f["code"] != "bidi_override" for ex in f["examples"]][:3] or [f["label"] for f in obf][:1]
        red = Redactor()
        red.register(ent)
        masked = red.redact(text)
        self.ent, self.red = ent, red
        money_lost = inp.money_lost == "yes" or (
            inp.money_lost in {"not_sure", "unspecified"} and bool({"money_lost", "authorised_push"} & set(sig_rule))
        )
        inferred_loss = money_lost and inp.money_lost != "yes"
        inferred: list[str] = []
        amount = inp.amount
        if not amount and ent.amounts and money_lost:
            amount = max(ent.amounts)
            inferred.append(f"amount {drafting.inr(amount)}")
        if money_lost and not str(inp.when or "").strip():
            m = re.search(r"\b(\d+|an?|half an)\s*(minutes?|mins?|hours?|hrs?|days?)\s+ago\b|\b(yesterday|today)\b(\s+(at|around)?\s*\d{1,2}([:.]\d{2})?\s*(am|pm)?)?|\d+\s*(घंटे|मिनट)\s*पहले", text, re.I)
            if m:
                inp.when = m.group(0)
                inferred.append(f"time '{m.group(0)}'")
        if money_lost and not inp.payment_mode:
            pm = None
            if ent.upi_ids or re.search(r"\b(upi|gpay|google pay|phonepe|paytm|bhim|qr)\b", text, re.I):
                pm = "UPI"
            elif re.search(r"\b(card|cvv|atm)\b", text, re.I):
                pm = "Debit / Credit card"
            elif re.search(r"\b(net ?banking|neft|imps|rtgs|bank transfer)\b", text, re.I):
                pm = "Net banking / IMPS / NEFT"
            elif re.search(r"\b(crypto|usdt|bitcoin|gift card)\b", text, re.I):
                pm = "Crypto / gift card"
            if pm:
                inp.payment_mode = pm
                inferred.append(f"payment via {pm}")
        self.inp, self.amount, self.money_lost = inp, amount, money_lost
        calls = [
            {"tool": "deobfuscate", "args": {}, "summary": ("undid " + "; ".join(f"{f['label'].lower()}" + (f" ({f['examples'][0]})" if f["examples"] else "") for f in obf)) if obf else "no evasion tricks found", "ms": 0, "ok": True},
            {"tool": "extract_entities", "args": {"chars": len(text)}, "summary": self._ent_summary(ent), "ms": 0, "ok": True},
            {"tool": "detect_signals", "args": {"languages": ent.scripts}, "summary": ", ".join(SIGNAL_LABELS.get(k, k) for k in sig_rule) or "no red-flag phrases", "ms": 0, "ok": True},
            {"tool": "redact_pii", "args": {}, "summary": (", ".join(f"{v} {k.lower()}" for k, v in red.stats().items()) or "nothing to mask") + " masked before any AI reasoning", "ms": 0, "ok": True},
        ]
        thought = f"Read the case ({len(text)} characters, script: {', '.join(ent.scripts) or 'n/a'})."
        if inferred_loss:
            thought += " The text says money was already lost, so I'm switching to recovery mode."
        if inferred:
            thought += " Inferred from the text: " + ", ".join(inferred) + "."
        self._step("Intake agent", "Understand the case and protect privacy", thought, calls, ms=int((time.monotonic() - t1) * 1000))

        # ---------------- 2. Plan -------------------------------------
        llm_facts: dict = {}
        planned: list[dict] = []
        used_llm_plan = False
        if self.llm.available and self.remaining() > 45:
            t2 = time.monotonic()
            try:
                form = {
                    "money_lost": "yes" if money_lost else inp.money_lost,
                    "amount_inr": amount,
                    "when": inp.when,
                    "payment_mode": inp.payment_mode,
                    "state": inp.state,
                    "victim_profile": inp.victim_profile,
                    "reply_language": LANG_NAMES.get(lang, "English"),
                }
                user = PLAN_TEMPLATE.format(
                    form=form,
                    entities=self._masked_entities(),
                    text=masked,
                    signals=", ".join(SIGNAL_ENUM),
                )
                self.chat = [{"role": "user", "content": user}]
                resp = self.llm.chat_json(ORCHESTRATOR_SYSTEM, self.chat, timeout=min(self.s.llm_call_timeout_s, self.remaining() - 20))
                self.chat.append({"role": "assistant", "content": _short_json(resp)})
                llm_facts = resp.get("case_facts") if isinstance(resp.get("case_facts"), dict) else {}
                planned = self._validate_calls(resp.get("tool_calls"))
                used_llm_plan = True
                self._step(
                    "Orchestrator",
                    "Plan the investigation",
                    str(resp.get("thought") or "Planning tool calls.")[:500],
                    llm=True,
                    ms=int((time.monotonic() - t2) * 1000),
                    plan=[f"{c['tool']}({_fmt_args(c['args'])}) — {c.get('why', '')}".strip(" —") for c in planned],
                )
            except LLMError as exc:
                self.llm_errors.append(str(exc)[:200])
                self._step("Orchestrator", "Plan the investigation", "AI planner unavailable — switching to the deterministic planner.", ms=int((time.monotonic() - t2) * 1000))
        if not used_llm_plan:
            planned = self._deterministic_plan()
            self._step(
                "Orchestrator",
                "Plan the investigation",
                self._deterministic_thought(sig_rule),
                plan=[f"{c['tool']}({_fmt_args(c['args'])}) — {c['why']}" for c in planned],
            )

        # Merge AI-read signals (they may raise risk, never trigger hard floors)
        sig_all = {k: list(v) for k, v in sig_rule.items()}
        for s in llm_facts.get("signals") or []:
            if isinstance(s, str) and s in SIGNAL_ENUM and s not in sig_all:
                sig_all[s] = ["(AI reading of the message)"]
        if llm_facts.get("manipulation_attempt") is True and "prompt_injection" not in sig_all:
            sig_all["prompt_injection"] = ["(AI: text tries to manipulate automated checks)"]
        mm = llm_facts.get("money_movement") if isinstance(llm_facts.get("money_movement"), dict) else {}
        if mm.get("lost") is True and inp.money_lost in {"not_sure", "unspecified"} and not money_lost:
            money_lost = self.money_lost = True
        self.sig_all, self.llm_facts = sig_all, llm_facts

        # ---------------- 3. Act --------------------------------------
        self._execute(planned, agent="Forensics agent", title="Run forensic tools")

        # ---------------- 4. Reflect (LLM) ----------------------------
        assessment: dict = {}
        if used_llm_plan:
            for _ in range(max(0, self.s.max_react_steps - 1)):
                if self.remaining() < 50:
                    break
                t3 = time.monotonic()
                try:
                    user = REFLECT_TEMPLATE.format(observations="\n".join(self.observations[-25:]) or "(none)", playbooks=", ".join(PLAYBOOK_IDS))
                    self.chat.append({"role": "user", "content": user})
                    resp = self.llm.chat_json(ORCHESTRATOR_SYSTEM, self.chat, timeout=min(self.s.llm_call_timeout_s, self.remaining() - 20))
                    self.chat.append({"role": "assistant", "content": _short_json(resp)})
                except LLMError as exc:
                    self.llm_errors.append(str(exc)[:200])
                    break
                if isinstance(resp.get("assessment"), dict):
                    assessment = resp["assessment"]
                more = self._validate_calls(resp.get("tool_calls"), skip_done=True)
                self._step(
                    "Orchestrator",
                    "Reflect on the evidence" + (" and investigate further" if more else ""),
                    str(resp.get("thought") or "")[:500],
                    llm=True,
                    ms=int((time.monotonic() - t3) * 1000),
                    plan=[f"{c['tool']}({_fmt_args(c['args'])}) — {c.get('why', '')}".strip(" —") for c in more],
                )
                if more:
                    self._execute(more, agent="Forensics agent", title="Follow-up investigation")
                if resp.get("done") is True or not more:
                    break

        # ---------------- 5. Policy guard ------------------------------
        missing = self._coverage_gaps()
        if missing:
            self._execute(missing, agent="Policy guard", title="Mandatory checks the plan skipped", thought="Safety policy: every link, UPI ID, phone number and sender ID must be checked, playbooks always matched, and recovery triage run whenever money is lost.")

        # ---------------- 6. Judge -------------------------------------
        t4 = time.monotonic()
        llm_risk = None
        if assessment:
            try:
                llm_risk = int(float(assessment.get("risk")))
            except (TypeError, ValueError):
                llm_risk = None
        verdict = judge(
            signals=sig_all,
            url_results=list(self.url_results.values()),
            upi_results=list(self.upi_results.values()),
            phone_results=list(self.phone_results.values()),
            sender_results=list(self.sender_results.values()),
            playbooks=self.playbooks or [],
            money_lost=money_lost,
            llm_risk=llm_risk,
            llm_verdict=assessment.get("verdict") if assessment else None,
            floor_signals=set(sig_rule),
        )
        pb_id = verdict["top_playbook"]
        llm_typ = assessment.get("typology") if assessment else None
        if not pb_id and llm_typ in PLAYBOOK_BY_ID and verdict["tier"] != "SAFE":
            pb_id = llm_typ
        if not pb_id and verdict["tier"] != "SAFE":
            bank_link_abuse = any(
                s_["code"] in {"brand_impersonation", "typosquat", "bank_claim_wrong_domain"} for r_ in self.url_results.values() for s_ in r_["signals"]
            )
            claims_bank = any(OFFICIAL_BRANDS.get(b, {}).get("type") in {"bank", "fintech"} for b in ent.brands)
            if (bank_link_abuse or claims_bank) and ({"otp_request", "kyc_threat"} & set(sig_all) or bank_link_abuse):
                pb_id = "kyc_update"
            else:
                pb_id = "generic_suspicious"
        if verdict["tier"] == "SAFE":
            pb_id = None  # don't label a safe message with a scam type
        playbook = get_playbook(pb_id) if pb_id else None
        judge_thought = (
            f"Rule engine {verdict['rule_score']}/100"
            + (f", AI reviewer {llm_risk}/100" if llm_risk is not None else "")
            + (f", safety floor {verdict['floor']} ({'; '.join(verdict['floor_reasons'][:2])})" if verdict["floor"] else "")
            + f" → final {verdict['score']}/100: {verdict['tier_label']} (confidence {verdict['confidence']})."
        )
        if verdict.get("disagreement"):
            judge_thought += " " + verdict["disagreement"]
        if assessment.get("rationale"):
            judge_thought += " AI rationale: " + str(assessment["rationale"])[:300]
        self._step("Risk judge", "Score the risk", judge_thought, llm=llm_risk is not None, ms=int((time.monotonic() - t4) * 1000))

        # ---------------- 6b. Kill-chain analysis ----------------------
        kc = analyze_killchain(
            set(sig_all),
            [r["verdict"] for r in self.url_results.values()],
            bool(ent.brands or ent.agencies),
            money_lost,
            pb_id,
            verdict["tier"],
        )
        if verdict["tier"] != "SAFE":
            seen_names = [st["name"] for st in kc["stages"] if st["observed"]]
            self._step(
                "Kill-chain analyst",
                "Locate the victim in the scam lifecycle",
                f"Observed {kc['observed_count']}/7 stages ({' → '.join(seen_names)}); current stage: {kc['current_stage']}. Likely next move: {kc['next_move']}",
            )

        # ---------------- 7. Recovery plan -----------------------------
        t5 = time.monotonic()
        auth_class = None
        if money_lost:
            if self.triage is None:
                self.triage = golden_hour_triage(True, inp.when, amount, inp.payment_mode, inp.state, self.now)
            if self.liability is None:
                auth_class = classify_authorisation(set(sig_all), inp.payment_mode, llm_facts)
                self.liability = liability_analysis(auth_class, amount, self.triage)
            auth_class = self.liability["class"]
        has_channel = bool(ent.phones or ent.sender_ids or set(ent.channels) & {"call", "video_call", "whatsapp", "sms"})
        actions = build_actions(verdict["tier"], pb_id, money_lost, self.triage, auth_class, inp.payment_mode, amount, inp.state, has_channel, lang)
        gmsg = golden_message(self.triage, lang)
        rec_thought = (
            f"Money lost ({drafting.inr(amount)}): status '{self.triage['status']}'"
            + (f", {self.triage['elapsed_minutes']} min since the incident" if self.triage.get("elapsed_minutes") is not None else "")
            + f"; liability class: {self.liability['label']}."
            if money_lost
            else f"No money lost — prevention plan for a '{verdict['tier_label']}' case."
        ) + f" {len(actions)} prioritised actions."
        self._step("Recovery planner", "Plan the response", rec_thought, ms=int((time.monotonic() - t5) * 1000))

        # ---------------- 8. Drafting ----------------------------------
        t6 = time.monotonic()
        case = {
            "entities": ent,
            "playbook_id": pb_id,
            "money_lost": money_lost,
            "amount": amount,
            "payment_mode": inp.payment_mode,
            "when": inp.when,
            "triage": self.triage,
            "llm_facts": llm_facts,
        }
        drafts: dict = {"family_alert": None, "ncrp": None, "bank_letter": None, "chakshu": None, "police": None}
        if verdict["tier"] != "SAFE" or money_lost:
            drafts["ncrp"] = drafting.ncrp_kit(case)
            drafts["family_alert"] = drafting.family_alert(case, lang)
            drafts["chakshu"] = drafting.chakshu_report(case) if has_channel else None
            if money_lost:
                drafts["bank_letter"] = drafting.bank_letter(case, auth_class or "unknown")
                if amount and amount >= 1_00_000:
                    drafts["police"] = drafting.police_complaint(case)
        headline = t(HEADLINES[verdict["tier"]], lang)
        summary_points = self._fallback_points(verdict, playbook, lang)
        what_next = playbook["scammer_goal"] if playbook else None
        drafted_by_ai = False
        lang_note = None
        if lang not in OFFLINE_LANGS and not self.llm.available:
            lang_note = f"{LANG_NAMES.get(lang, lang)} drafting needs AI mode — showing English."
        if self.llm.available and self.remaining() > 30 and (verdict["tier"] != "SAFE" or money_lost):
            try:
                ev_lines = "\n".join(
                    f"- [{e['source']}] {e['label']}" + (f" ({red.redact(str(e['detail']))[:120]})" if e.get("detail") else "")
                    for e in verdict["evidence"][:8]
                )
                user = DRAFT_TEMPLATE.format(
                    language=LANG_NAMES.get(lang, "English"),
                    tier=verdict["tier_label"],
                    score=verdict["score"],
                    typology=playbook["name"]["en"] if playbook else "n/a",
                    truth=playbook["truth"]["en"] if playbook else "",
                    goal=playbook["scammer_goal"] if playbook else "",
                    evidence=ev_lines or "- none",
                    facts=_short_json({k: llm_facts.get(k) for k in ("claimed_identity", "channel", "asks", "threats_or_lures") if llm_facts.get(k)}),
                    money=(f"yes — {drafting.inr(amount)} via {inp.payment_mode or 'unknown mode'}, {self.triage.get('incident_display') or 'time unknown'}" if money_lost else "no"),
                    text=masked[:3000],
                )
                resp = self.llm.chat_json(DRAFT_SYSTEM, [{"role": "user", "content": user}], timeout=min(self.s.llm_call_timeout_s, self.remaining() - 10))
                headline = _clean(resp.get("headline"), 160) or headline
                pts = [red.rehydrate(_clean(p, 400)) for p in (resp.get("summary_points") or []) if _clean(p, 400)]
                if len(pts) >= 2:
                    summary_points = pts[:4]
                what_next = red.rehydrate(_clean(resp.get("what_they_want_next"), 300)) or what_next
                fa = red.rehydrate(_clean(resp.get("family_alert"), 900))
                if fa and drafts["family_alert"]:
                    drafts["family_alert"] = fa
                nd = red.rehydrate(_clean(resp.get("ncrp_description"), 2000))
                if nd and drafts["ncrp"] and len(nd) >= 200:
                    drafts["ncrp"]["description"] = nd
                cd = red.rehydrate(_clean(resp.get("chakshu_description"), 500))
                if cd and drafts["chakshu"]:
                    drafts["chakshu"] = re.sub(r"Description: .*", "Description: " + cd.replace("\\", ""), drafts["chakshu"], flags=re.S)
                drafted_by_ai = True
                lang_note = None
            except LLMError as exc:
                self.llm_errors.append(str(exc)[:200])
        n_docs = sum(1 for k in ("ncrp", "bank_letter", "chakshu", "police", "family_alert") if drafts.get(k))
        self._step(
            "Drafting agent",
            "Write the response pack",
            f"Prepared {n_docs} ready-to-use document(s) in {LANG_NAMES.get(lang, 'English')}"
            + (" (AI-personalised, placeholders re-filled locally)." if drafted_by_ai else " from verified templates."),
            llm=drafted_by_ai,
            ms=int((time.monotonic() - t6) * 1000),
        )

        # ---------------- 9. Assemble -----------------------------------
        official = [
            {"brand": b, "name": OFFICIAL_BRANDS[b]["name"], "domains": sorted(d for d in OFFICIAL_BRANDS[b]["domains"] if "." in d)}
            for b in ent.brands[:4]
            if b in OFFICIAL_BRANDS
        ]
        case_id = "STK-" + self.now.strftime("%y%m%d-%H%M") + "-" + self.fingerprint[:4].upper()
        mode = "ai" if (self.llm.calls and not (len(self.llm_errors) >= self.llm.calls)) else "offline"
        facts_used = []
        if pb_id == "upi_qr_receive" or ent.upi_ids:
            facts_used += UPI_FACTS
        if any(OFFICIAL_BRANDS.get(b, {}).get("type") == "bank" for b in ent.brands) or ent.urls:
            facts_used += BANK_CONTACT_FACTS[:2]
        result = {
            "agent": {"name": "Satark", "version": __version__},
            "case_id": case_id,
            "generated_at": self.now.strftime("%d %b %Y, %I:%M %p IST"),
            "mode": mode,
            "engine": self.llm.describe() if mode == "ai" else "Offline forensic engine (no data left the sandbox)",
            "llm_calls": self.llm.calls,
            "llm_errors": self.llm_errors,
            "language": lang,
            "language_name": LANG_NAMES.get(lang, "English"),
            "language_note": lang_note,
            "input": {
                "masked_text": masked,
                "chars": len(text),
                "money_lost": money_lost,
                "money_lost_inferred": inferred_loss,
                "amount": amount,
                "amount_display": drafting.inr(amount) if amount else None,
                "when": inp.when,
                "payment_mode": inp.payment_mode,
                "state": inp.state,
                "victim_profile": inp.victim_profile,
            },
            "privacy": {"masked": red.stats(), "llm_saw_only_masked": True},
            "verdict": {
                **{k: verdict[k] for k in ("score", "tier", "tier_label", "rule_score", "llm_score", "floor", "floor_reasons", "confidence", "disagreement", "trust_discount")},
                "headline": headline,
                "summary_points": summary_points,
                "what_they_want_next": what_next,
                "typology_id": pb_id,
                "typology": (playbook["name"].get(lang) or playbook["name"]["en"]) if playbook else None,
                "typology_en": playbook["name"]["en"] if playbook else None,
                "truth": t(playbook["truth"], lang) if playbook else None,
                "truth_en": playbook["truth"]["en"] if playbook else None,
            },
            "evidence": verdict["evidence"][:14],
            "forensics": {
                "urls": list(self.url_results.values()),
                "upi": list(self.upi_results.values()),
                "phones": list(self.phone_results.values()),
                "senders": list(self.sender_results.values()),
                "domain_ages": self.domain_ages,
            },
            "playbooks": self.playbooks or [],
            "triage": self.triage,
            "golden_message": gmsg,
            "liability": self.liability,
            "actions": actions,
            "killchain": kc,
            "obfuscation": self.obfuscation,
            "fingerprint": self.fingerprint,
            "console": build_console(money_lost, verdict["tier"], drafts, has_channel),
            "drafts": drafts,
            "official_channels": official,
            "facts_used": facts_used,
            "stats": STATS,
            "trace": self.trace,
            "timing_ms": int((time.monotonic() - t_start) * 1000),
            "disclaimer": DISCLAIMER,
        }
        result["case_file"] = build_case_file({
            "case_id": case_id,
            "generated_at": result["generated_at"],
            "verdict": result["verdict"],
            "typology_id": pb_id,
            "killchain": kc,
            "money_lost": money_lost,
            "amount": amount,
            "payment_mode": inp.payment_mode,
            "triage": self.triage,
            "liability": self.liability,
            "forensics": result["forensics"],
            "entities": ent,
            "fingerprint": self.fingerprint,
            "obfuscation": self.obfuscation,
        })
        return result

    # ------------------------------------------------------------------
    def _ent_summary(self, ent) -> str:
        parts = []
        for label, n in (("link", len(ent.urls)), ("UPI ID", len(ent.upi_ids)), ("phone number", len(ent.phones)), ("email", len(ent.emails)), ("sender ID", len(ent.sender_ids))):
            if n:
                parts.append(f"{n} {label}{'s' if n > 1 else ''}")
        if ent.brands or ent.agencies:
            parts.append("claims: " + ", ".join(ent.agencies + [OFFICIAL_BRANDS[b]["name"] for b in ent.brands if b in OFFICIAL_BRANDS][:4]))
        if ent.amounts:
            parts.append("amounts: " + ", ".join(drafting.inr(a) for a in ent.amounts[:3]))
        return "; ".join(parts) or "no identifiers found"

    def _masked_entities(self) -> dict:
        ent, red = self.ent, self.red
        return {
            "links": [red.reverse.get(u, u) for u in ent.urls],
            "upi_ids": [red.reverse.get(v, v) for v in ent.upi_ids],
            "phones": [red.reverse.get(p["raw"], "[PHONE]") + f" ({p['kind']}, +{p['cc']})" for p in ent.phones],
            "sender_ids": [s["raw"] for s in ent.sender_ids],
            "claimed_brands": ent.brands,
            "claimed_agencies": ent.agencies,
            "channels": ent.channels,
            "rule_signals": list(detect_signals(self.inp.situation).keys()),
        }

    def _deterministic_plan(self) -> list[dict]:
        ent = self.ent
        plan = []
        for u in ent.urls:
            plan.append({"tool": "analyze_url", "args": {"url": u}, "why": "verify the link's real owner"})
        for v in ent.upi_ids:
            plan.append({"tool": "check_upi_id", "args": {"upi_id": v}, "why": "who receives the money"})
        for p in ent.phones:
            plan.append({"tool": "check_phone_number", "args": {"phone": p["raw"]}, "why": "caller origin vs claimed identity"})
        for s in ent.sender_ids:
            plan.append({"tool": "check_sender_id", "args": {"sender": s["raw"]}, "why": "registered SMS header?"})
        plan.append({"tool": "match_scam_playbooks", "args": {}, "why": "compare with known Indian scam scripts"})
        for b in ent.brands[:2]:
            plan.append({"tool": "lookup_official_channel", "args": {"organisation": b}, "why": "get the genuine contact channel"})
        if self.money_lost:
            plan.append({"tool": "golden_hour_triage", "args": {}, "why": "money lost — time is critical"})
            plan.append({"tool": "liability_check", "args": {}, "why": "who bears the loss under RBI rules"})
        return plan

    def _deterministic_thought(self, sig: dict) -> str:
        ent = self.ent
        bits = []
        if ent.urls:
            bits.append(f"{len(ent.urls)} link(s) to verify")
        if ent.upi_ids:
            bits.append(f"{len(ent.upi_ids)} UPI ID(s) to check")
        if ent.phones:
            bits.append(f"{len(ent.phones)} phone number(s) to trace")
        if sig:
            bits.append("red flags: " + ", ".join(SIGNAL_LABELS.get(k, k).lower() for k in list(sig)[:3]))
        if self.money_lost:
            bits.append("money already lost → recovery triage")
        return "Deterministic planner: " + ("; ".join(bits) if bits else "no identifiers — rely on behavioural signals and playbooks") + "."

    def _validate_calls(self, calls, skip_done: bool = False) -> list[dict]:
        out = []
        if not isinstance(calls, list):
            return out
        for c in calls[:12]:
            if not isinstance(c, dict):
                continue
            name = c.get("tool") or c.get("name")
            if name not in ALLOWED_TOOLS:
                continue
            args = c.get("args") if isinstance(c.get("args"), dict) else {}
            out.append({"tool": name, "args": args, "why": str(c.get("why") or "")[:140]})
        return out

    def _coverage_gaps(self) -> list[dict]:
        ent = self.ent
        gaps = []
        for u in ent.urls:
            if u not in self.url_results:
                gaps.append({"tool": "analyze_url", "args": {"url": u}, "why": "policy: every link is checked"})
        for v in ent.upi_ids:
            if v not in self.upi_results:
                gaps.append({"tool": "check_upi_id", "args": {"upi_id": v}, "why": "policy: every UPI ID is checked"})
        for p in ent.phones:
            if p["raw"] not in self.phone_results:
                gaps.append({"tool": "check_phone_number", "args": {"phone": p["raw"]}, "why": "policy: every number is checked"})
        for s in ent.sender_ids:
            if s["raw"] not in self.sender_results:
                gaps.append({"tool": "check_sender_id", "args": {"sender": s["raw"]}, "why": "policy: every sender ID is checked"})
        if self.playbooks is None:
            gaps.append({"tool": "match_scam_playbooks", "args": {}, "why": "policy: playbooks are always matched"})
        if self.money_lost and self.triage is None:
            gaps.append({"tool": "golden_hour_triage", "args": {}, "why": "policy: money lost → triage"})
        if self.money_lost and self.liability is None:
            gaps.append({"tool": "liability_check", "args": {}, "why": "policy: money lost → liability"})
        return gaps

    # ------------------------------------------------------------------
    def _execute(self, calls: list[dict], agent: str, title: str, thought: str | None = None) -> None:
        if not calls:
            return
        t0 = time.monotonic()
        recorded = []
        seen = set()
        for c in calls:
            key = (c["tool"], tuple(sorted((k, str(v)) for k, v in c["args"].items())))
            if key in seen:
                continue
            seen.add(key)
            ts = time.monotonic()
            try:
                summary = self._run_tool(c["tool"], c["args"])
                ok = True
            except Exception as exc:  # noqa: BLE001 — a tool failure must never crash the run
                summary = f"tool error: {exc.__class__.__name__}"
                ok = False
            masked_summary = self.red.redact(summary)
            self.observations.append(f"- {c['tool']}({_fmt_args({k: self.red.redact(str(v)) for k, v in c['args'].items()})}) → {masked_summary}")
            recorded.append({
                "tool": c["tool"],
                "args": {k: self.red.redact(str(v)) for k, v in c["args"].items()},
                "why": c.get("why", ""),
                "summary": masked_summary,
                "ms": int((time.monotonic() - ts) * 1000),
                "ok": ok,
            })
        self._step(agent, title, thought or f"Executed {len(recorded)} tool call(s).", recorded, ms=int((time.monotonic() - t0) * 1000))

    def _run_tool(self, name: str, args: dict) -> str:
        ent, red = self.ent, self.red
        if name == "analyze_url":
            url = red.resolve(str(args.get("url", "")))
            if not url:
                return "no url given"
            match = next((u for u in ent.urls if u == url or url in u or u in url), url)
            res = analyze_url(match, ent.brands, use_rdap=False)
            if self.s.enable_rdap and res["verdict"] in {"dangerous", "suspicious", "unverified"} and not res.get("trust"):
                age = rdap_domain_age_days(res["registrable"], timeout=self.s.rdap_timeout) if self.remaining() > 40 else None
                self.domain_ages[res["registrable"]] = age
                if age is not None:
                    res = analyze_url(match, ent.brands, use_rdap=True, rdap_timeout=self.s.rdap_timeout)
            self.url_results[match] = res
            labels = [s["label"] for s in res["signals"]][:4] + [t_["label"] for t_ in res["trust_signals"]][:2]
            return f"{res['host']}: {res['verdict'].upper()} (risk {res['risk']:.2f})" + (" — " + "; ".join(labels) if labels else "")
        if name == "check_domain_age":
            dom = registrable_domain(str(args.get("domain", "")).replace("http://", "").replace("https://", "").split("/")[0])
            if not self.s.enable_rdap:
                return f"{dom}: domain-age lookup disabled (offline mode)"
            age = rdap_domain_age_days(dom, timeout=self.s.rdap_timeout)
            self.domain_ages[dom] = age
            if age is None:
                return f"{dom}: registration date unavailable (registry unreachable or not supported)"
            for u, r in self.url_results.items():
                if r.get("registrable") == dom:
                    self.url_results[u] = analyze_url(u, ent.brands, use_rdap=True, rdap_timeout=self.s.rdap_timeout)
            return f"{dom}: registered {age} days ago"
        if name == "check_upi_id":
            vpa = red.resolve(str(args.get("upi_id") or args.get("upi") or ""))
            if "@" not in vpa:
                return "not a UPI ID"
            claims_authority = bool(ent.agencies) or bool(set(self.sig_all) & {"digital_arrest", "courier_parcel", "challan", "electricity_cut", "kyc_threat", "govt_scheme_fee", "tax_refund", "authority_impersonation"}) or any(
                OFFICIAL_BRANDS.get(b, {}).get("type") in {"bank", "government", "regulator"} for b in ent.brands
            )
            demands_payment = bool(set(self.sig_all) & {"payment_request", "pin_to_receive", "digital_arrest"}) or self.money_lost
            official_claim = claims_authority and demands_payment
            res = check_upi_id(vpa, official_claim=official_claim, claimed_brands=ent.brands)
            self.upi_results[vpa] = res
            return f"{vpa}: " + "; ".join(res["info"][:2] + [s["label"] for s in res["signals"]])
        if name == "check_phone_number":
            raw = red.resolve(str(args.get("phone", "")))
            phone = next((p for p in ent.phones if p["raw"] == raw or p["e164"].endswith(re.sub(r"\D", "", raw)[-10:])), None)
            if phone is None:
                found = extract_entities(raw).phones
                if not found:
                    return "not a phone number"
                phone = found[0]
            res = check_phone_number(phone, ent.brands, ent.agencies, ent.channels)
            self.phone_results[phone["raw"]] = res
            return f"{phone['raw']}: {res['kind']}, {res['country']}" + ("; " + "; ".join(s["label"] for s in res["signals"] + res["trust_signals"]) if res["signals"] or res["trust_signals"] else "")
        if name == "check_sender_id":
            raw = str(args.get("sender", "")).strip().upper()
            sender = next((s for s in ent.sender_ids if s["raw"] == raw), None)
            if sender is None:
                m = re.match(r"([A-Z]{2})-([A-Z0-9]{3,9})(?:-([PSTG]))?$", raw)
                if not m:
                    return "not a TRAI-format header"
                sender = {"raw": raw, "entity": m.group(2), "suffix": m.group(3) or ""}
            res = check_sender_id(sender, ent.brands, asks_sensitive=bool(set(self.sig_all) & {"otp_request", "kyc_threat"}))
            self.sender_results[sender["raw"]] = res
            return f"{sender['raw']}: registered header" + (f" ({res['suffix_meaning']})" if res["suffix_meaning"] else "") + ("; " + "; ".join(s["label"] for s in res["signals"]) if res["signals"] else "")
        if name == "match_scam_playbooks":
            sigs = set(self.sig_all)
            if any(r["verdict"] in {"dangerous", "suspicious", "unverified"} for r in self.url_results.values()) or (self.ent.urls and not self.url_results):
                sigs.add("link_present")
            lang = lang_code(self.inp.language)
            self.playbooks = match_playbooks(sigs, lang=lang)
            if not self.playbooks:
                return "no known scam playbook matched"
            return "; ".join(f"{p['name_en']} {p['score']:.2f}{' (core match)' if p['core_hit'] else ''}" for p in self.playbooks)
        if name == "lookup_official_channel":
            org = str(args.get("organisation") or args.get("organization") or "").lower().replace(" ", "")
            key = org if org in OFFICIAL_BRANDS else BRAND_TOKENS.get(org)
            if not key:
                key = next((b for b, info in OFFICIAL_BRANDS.items() if org and org in info["name"].lower().replace(" ", "")), None)
            if not key:
                return f"'{org}': not in the verified directory"
            info = OFFICIAL_BRANDS[key]
            self.official_lookups[key] = info
            doms = sorted(d for d in info["domains"] if "." in d)
            extra = " Banks call from 1600xx numbers; websites end in .bank.in." if info["type"] == "bank" else ""
            return f"{info['name']}: official domains {', '.join(doms)}.{extra}"
        if name == "golden_hour_triage":
            self.triage = golden_hour_triage(self.money_lost, self.inp.when, self.amount, self.inp.payment_mode, self.inp.state, self.now)
            if not self.money_lost:
                return "no money lost — triage not needed"
            tri = self.triage
            el = tri.get("elapsed_minutes")
            return f"status={tri['status']}" + (f", {el} min since incident" if el is not None else ", time unknown") + f"; {len(tri['deadlines'])} deadlines computed"
        if name == "liability_check":
            if not self.money_lost:
                return "no money lost — liability not applicable"
            if self.triage is None:
                self.triage = golden_hour_triage(True, self.inp.when, self.amount, self.inp.payment_mode, self.inp.state, self.now)
            cls = str(args.get("authorisation") or "")
            if cls not in {"authorised_push", "unauthorised_negligence", "unauthorised_third_party"}:
                cls = classify_authorisation(set(self.sig_all), self.inp.payment_mode, self.llm_facts)
            self.liability = liability_analysis(cls, self.amount, self.triage)
            return self.liability["label"]
        return "unknown tool"

    def _fallback_points(self, verdict: dict, playbook: dict | None, lang: str) -> list[str]:
        pts = []
        if playbook and verdict["tier"] != "SAFE":
            pts.append(t(playbook["truth"], lang))
        for e in verdict["evidence"]:
            if e["weight"] <= 0 and verdict["tier"] != "SAFE":
                continue
            label = e["label"]
            detail = str(e.get("detail") or "")
            if detail and len(detail) < 110 and not detail.startswith("Indicators"):
                label += f" — {detail}"
            pts.append(label)
            if len(pts) >= 4:
                break
        if not pts:
            pts.append("No red flags found in the text, links or identifiers.")
        return pts


def _fmt_args(args: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in args.items())


def _short_json(obj) -> str:
    import json

    s = json.dumps(obj, ensure_ascii=False)
    return s[:4000]


def _clean(v, limit: int) -> str:
    if not isinstance(v, str):
        return ""
    v = v.strip()
    v = re.sub(r"<[^>]{0,200}>", "", v)  # no HTML from the model
    return v[:limit]


def analyze(payload: dict, settings: Settings | None = None, now: datetime | None = None) -> dict:
    """Convenience entry point: dict in → result dict out."""
    return SatarkAgent(settings, now).run(CaseInput.from_dict(payload))
