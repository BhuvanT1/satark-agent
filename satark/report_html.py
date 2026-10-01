"""Sandbox-safe HTML report (no JavaScript, no external assets).

aiKart renders `html` outputs in a sandbox without scripts/cookies, so the
report uses only inline CSS, inline SVG and native <details> elements.
All dynamic text is HTML-escaped.
"""

from __future__ import annotations

from html import escape

from .kb.facts import HELPLINES

TIER_COLORS = {
    "SCAM": ("#b42318", "#fef3f2", "#fecdca"),
    "HIGH": ("#c4320a", "#fff6ed", "#fddcab"),
    "SUSPICIOUS": ("#a15c07", "#fffaeb", "#fedf89"),
    "SAFE": ("#067647", "#ecfdf3", "#abefc6"),
}
PRIORITY_LABEL = {"NOW": "Do now", "TODAY": "Today", "NEXT 3 DAYS": "Next 3 days", "LATER": "Later"}

CSS = """
:root{--bg:#f6f7f9;--card:#ffffff;--ink:#101828;--muted:#475467;--soft:#667085;--line:#e4e7ec;--chip:#f2f4f7;--brand:#1d3d8f;--brand-soft:#eef2ff;--code:#f8fafc}
@media (prefers-color-scheme: dark){:root{--bg:#0c111d;--card:#161b26;--ink:#f5f5f6;--muted:#cecfd2;--soft:#94969c;--line:#2b3140;--chip:#1f242f;--brand:#8ea8ff;--brand-soft:#1b2440;--code:#11151f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans","Noto Sans Devanagari","Noto Sans Telugu",sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:16px}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.brand{display:flex;align-items:center;gap:10px}
.brand b{font-size:20px;letter-spacing:.06em}
.brand small{display:block;color:var(--soft);font-size:12px;letter-spacing:0}
.meta{display:flex;gap:6px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:6px;background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:12px;color:var(--muted);white-space:nowrap}
.chip.ai{background:var(--brand-soft);color:var(--brand);border-color:transparent}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin:12px 0}
.hero{display:grid;grid-template-columns:132px 1fr;gap:18px;align-items:center;border-width:2px}
.gauge{width:124px;height:124px;border-radius:50%;display:grid;place-items:center}
.gauge .inner{width:96px;height:96px;border-radius:50%;background:var(--card);display:grid;place-items:center;text-align:center}
.gauge .num{font-size:32px;font-weight:800;line-height:1}
.gauge .of{font-size:11px;color:var(--soft)}
.tier{display:inline-block;font-weight:800;font-size:13px;letter-spacing:.08em;padding:3px 10px;border-radius:6px;color:#fff}
h1{font-size:22px;line-height:1.3;margin:8px 0 6px}
h2{font-size:16px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
h3{font-size:14px;margin:14px 0 6px}
.sub{color:var(--muted);font-size:13px}
.golden{border-radius:14px;padding:14px 16px;margin:12px 0;color:#fff;background:linear-gradient(135deg,#b42318,#e04f16)}
.golden b{font-size:17px}
.golden .big{font-size:28px;font-weight:800;margin-top:4px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
ul.clean{list-style:none;padding:0;margin:0}
.act{display:grid;grid-template-columns:auto 1fr;gap:10px;padding:10px 0;border-top:1px solid var(--line)}
.act:first-child{border-top:0}
.pri{font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:6px;height:fit-content;white-space:nowrap}
.pri.NOW{background:#fee4e2;color:#b42318}.pri.TODAY{background:#fef0c7;color:#93370d}.pri.NEXT{background:#e0eaff;color:#2d31a6}.pri.LATER{background:var(--chip);color:var(--muted)}
.en{display:block;color:var(--soft);font-size:12px;margin-top:2px}
.due{display:inline-block;margin-top:4px;font-size:12px;color:var(--muted);background:var(--chip);border-radius:6px;padding:1px 8px}
.truth{background:var(--brand-soft);border-left:4px solid var(--brand);border-radius:8px;padding:10px 12px;margin:10px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 6px;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--soft);font-weight:600;font-size:12px;border-top:0}
.bar{height:6px;border-radius:4px;background:var(--chip);overflow:hidden;min-width:60px}
.bar span{display:block;height:100%}
.v{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;white-space:nowrap}
.v.dangerous{background:#fee4e2;color:#b42318}.v.suspicious{background:#fef0c7;color:#93370d}.v.official{background:#dcfae6;color:#067647}.v.unverified{background:var(--chip);color:var(--muted)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--code);border:1px solid var(--line);border-radius:10px;padding:12px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,"Noto Sans Mono",monospace;margin:6px 0 0}
details{border:1px solid var(--line);border-radius:12px;padding:10px 14px;margin:10px 0;background:var(--card)}
summary{cursor:pointer;font-weight:700;font-size:15px}
summary .sub{font-weight:400}
.kv{display:grid;grid-template-columns:170px 1fr;gap:4px 12px;font-size:13px;margin:8px 0}
.kv div:nth-child(odd){color:var(--soft)}
.step{display:grid;grid-template-columns:30px 1fr;gap:10px;padding:10px 0;border-top:1px dashed var(--line)}
.step:first-child{border-top:0}
.dot{width:26px;height:26px;border-radius:50%;background:var(--brand);color:#fff;font-size:12px;font-weight:700;display:grid;place-items:center}
.step .role{font-size:11px;font-weight:700;letter-spacing:.05em;color:var(--brand);text-transform:uppercase}
.step .ttl{font-weight:700}
.step .th{color:var(--muted);font-size:13px;margin:2px 0}
.call{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);border:1px solid var(--line);border-radius:8px;padding:6px 8px;margin:4px 0;word-break:break-word}
.call .tn{color:var(--brand);font-weight:700}
.ok{color:#067647}.err{color:#b42318}
.foot{color:var(--soft);font-size:12px;margin:16px 0 8px}
.help{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.help div{background:var(--chip);border-radius:10px;padding:8px 10px;font-size:12px}
.help b{display:block;font-size:13px;color:var(--ink)}
.console{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 14px;border-radius:10px;font-weight:700;font-size:14px;text-decoration:none;border:1px solid var(--line);color:var(--ink);background:var(--card)}
.btn.primary{background:#b42318;color:#fff;border-color:#b42318}
.defend{border:2px solid #1d3d8f;background:var(--brand-soft)}
.defend li{margin:4px 0}
.kc{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:6px;margin:8px 0 4px}
.kc .st{border:1px dashed var(--line);border-radius:10px;padding:8px 6px;font-size:12px;text-align:center;color:var(--soft);min-height:84px}
.kc .st b{display:block;font-size:13px;color:var(--soft)}
.kc .st.on{border-style:solid;color:var(--ink)}
.kc .st.on b{color:var(--ink)}
.kc .here{display:inline-block;margin-top:4px;font-size:10px;font-weight:800;letter-spacing:.04em;padding:1px 6px;border-radius:6px;color:#fff}
.next{border-left:4px solid #c4320a;background:var(--chip);border-radius:8px;padding:10px 12px;margin-top:10px}
.warn2{border-left:4px solid #b42318;background:#fef3f2;color:#7a271a;border-radius:8px;padding:10px 12px;margin-top:10px}
@media (prefers-color-scheme: dark){.warn2{background:#2a1515;color:#fecdca}}
.fp{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
@media (max-width:680px){.kc{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:680px){.hero{grid-template-columns:1fr;text-align:left}.grid2,.help{grid-template-columns:1fr}.kv{grid-template-columns:1fr}}
"""

SHIELD = (
    '<svg width="34" height="34" viewBox="0 0 48 48" aria-hidden="true"><path d="M24 3 6 10v12c0 11.2 7.7 20.6 18 23 10.3-2.4 18-11.8 18-23V10L24 3z" fill="#1d3d8f"/>'
    '<path d="M24 9 12 13.7V22c0 7.7 5 14.3 12 16.4 7-2.1 12-8.7 12-16.4v-8.3L24 9z" fill="#ff9933"/>'
    '<path d="m19.5 23.5 3.2 3.2 6.8-7.2" stroke="#fff" stroke-width="3.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def _e(x) -> str:
    return escape("" if x is None else str(x))


def _weight_bar(w: float) -> str:
    pct = int(min(1.0, abs(w)) * 100)
    color = "#d92d20" if w > 0 else "#17b26a"
    return f'<div class="bar" title="{w:+.2f}"><span style="width:{pct}%;background:{color}"></span></div>'


def render_html(r: dict) -> str:
    v = r["verdict"]
    tier = v["tier"]
    fg, bg, border = TIER_COLORS[tier]
    lang = r.get("language", "en")
    score = v["score"]
    out: list[str] = []
    a = out.append

    a("<!doctype html><html lang=\"" + _e(lang) + "\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    a(f"<title>Satark report {_e(r['case_id'])}</title><style>{CSS}</style></head><body><div class=\"wrap\">")

    # ---- Header
    engine_chip = f'<span class="chip ai">AI agent · {_e(r["engine"])}</span>' if r["mode"] == "ai" else '<span class="chip">Offline engine · data never left the sandbox</span>'
    a(
        f'<div class="top"><div class="brand">{SHIELD}<div><b>SATARK</b><small>Cyber-fraud first responder · Detect the scam. Act in the golden hour.</small></div></div>'
        f'<div class="meta"><span class="chip">Case {_e(r["case_id"])}</span><span class="chip">{_e(r["generated_at"])}</span>{engine_chip}'
        f'<span class="chip">{_e(r.get("language_name", "English"))}</span></div></div>'
    )

    # ---- Verdict hero
    deg = int(score * 3.6)
    floor_chips = "".join(f'<span class="chip">Safety floor: {_e(x)}</span> ' for x in v.get("floor_reasons", [])[:2])
    typ = f'<span class="chip">{_e(v["typology"])}</span> ' if v.get("typology") else ""
    a(
        f'<div class="card hero" style="border-color:{border};background:{bg}">'
        f'<div class="gauge" style="background:conic-gradient({fg} {deg}deg,{border} 0)"><div class="inner"><div><div class="num" style="color:{fg}">{score}</div><div class="of">risk / 100</div></div></div></div>'
        f'<div><span class="tier" style="background:{fg}">{_e(v["tier_label"].upper())}</span>'
        f'<h1 style="color:{fg}">{_e(v["headline"])}</h1>'
        f'<div>{typ}<span class="chip">Confidence: {_e(v["confidence"])}</span> {floor_chips}</div>'
        + (f'<p class="sub" style="margin:8px 0 0">{_e(v["disagreement"])}</p>' if v.get("disagreement") else "")
        + "</div></div>"
    )

    # ---- Golden hour banner
    tri = r.get("triage")
    if r["input"]["money_lost"] and tri:
        el = tri.get("elapsed_minutes")
        if el is None:
            when = "Time of incident unknown — act as if it just happened."
        elif el < 120:
            when = f"{el} minutes since the incident"
        elif el < 48 * 60:
            when = f"{el // 60} h {el % 60} min since the incident"
        else:
            when = f"{el // (24 * 60)} days since the incident"
        a(
            f'<div class="golden"><b>{_e(r.get("golden_message") or "")}</b>'
            f'<div class="big">Call 1930 · cybercrime.gov.in</div>'
            f'<div style="opacity:.9;font-size:13px">{_e(when)} · Loss: {_e(r["input"].get("amount_display") or "not stated")}'
            f'{" · via " + _e(r["input"].get("payment_mode")) if r["input"].get("payment_mode") else ""}</div></div>'
        )

    # ---- One-tap action console
    if r.get("console"):
        a('<div class="console">')
        for c in r["console"]:
            cls = "btn primary" if c.get("primary") else "btn"
            a(f'<a class="{cls}" href="{_e(c["href"])}" target="_blank" rel="noopener noreferrer">{_e(c["label"])}</a>')
        a("</div>")

    # ---- Scammer tricks defeated (adversarial robustness)
    obf = r.get("obfuscation") or []
    inj = [e for e in (r.get("evidence") or []) if e["label"].startswith("Text tries to manipulate")]
    if obf or inj:
        a('<div class="card defend"><h2>' + SHIELD.replace('width="34" height="34"', 'width="22" height="22"') + ' Scammer tricks Satark defeated</h2><ul>')
        if inj:
            a(f'<li><b>Prompt-injection attempt neutralised</b> — the message contains instructions aimed at AI scam-checkers ({_e(inj[0].get("detail") or "")}). Satark treats message text as untrusted data and its verdict cannot be lowered below the rule-based safety floor.</li>')
        for o in obf:
            ex = f' — {_e(", ".join(o["examples"]))}' if o.get("examples") else ""
            a(f'<li><b>{_e(o["label"])}</b>{ex}</li>')
        a('</ul><p class="sub">These tricks are built to slip past keyword filters and AI chatbots. Satark undoes them before analysis and counts them as evidence — genuine messages never need them.</p></div>')

    # ---- Scam kill-chain
    kc = r.get("killchain")
    if kc and tier != "SAFE" and kc.get("current_index", -1) >= 0:
        a('<div class="card"><h2>Where you are in the scam</h2><div class="kc">')
        for i, st in enumerate(kc["stages"]):
            on = st["observed"]
            style = f' style="border-color:{fg};background:{bg}"' if on else ""
            here = f'<span class="here" style="background:{fg}">YOU ARE HERE</span>' if i == kc["current_index"] else ""
            if i == kc.get("next_index"):
                here = '<span class="here" style="background:#475467">NEXT RISK</span>'
                style = f' style="border-color:{fg};border-style:dashed"'
            a(f'<div class="st{" on" if on else ""}"{style}><b>{i + 1}. {_e(st["name"])}</b>{_e(st["desc"])}<br>{here}</div>')
        a("</div>")
        if kc.get("next_move"):
            a(f'<div class="next"><b>Their likely next move:</b> {_e(kc["next_move"])}</div>')
        if kc.get("recovery_scam_warning"):
            a(f'<div class="warn2"><b>Second-scam alert:</b> {_e(kc["recovery_scam_warning"])}</div>')
        a("</div>")

    # ---- Action plan
    a('<div class="card"><h2>What to do — step by step</h2><ul class="clean">')
    for act in r["actions"]:
        pri = act["priority"]
        cls = pri.split()[0]
        en = f'<span class="en">{_e(act["text_en"])}</span>' if lang != "en" and act["text"] != act["text_en"] else ""
        due = f'<span class="due">{_e(act["due"])}</span>' if act.get("due") else ""
        a(f'<li class="act"><span class="pri {cls}">{_e(PRIORITY_LABEL.get(pri, pri))}</span><div>{_e(act["text"])}{en}{due}</div></li>')
    a("</ul></div>")

    # ---- Why
    a('<div class="card"><h2>Why Satark reached this verdict</h2><ul>')
    for p in v.get("summary_points", []):
        a(f"<li>{_e(p)}</li>")
    a("</ul>")
    if v.get("truth") and tier != "SAFE":
        en = f'<span class="en">{_e(v["truth_en"])}</span>' if lang != "en" and v.get("truth_en") != v.get("truth") else ""
        a(f'<div class="truth"><b>The truth:</b> {_e(v["truth"])}{en}</div>')
    if v.get("what_they_want_next") and tier != "SAFE":
        a(f'<p class="sub"><b>What the fraudster is after:</b> {_e(v["what_they_want_next"])}</p>')
    if r.get("language_note"):
        a(f'<p class="sub">{_e(r["language_note"])}</p>')
    a("</div>")

    # ---- Evidence board
    ev = r.get("evidence") or []
    if ev:
        a('<div class="card"><h2>Evidence board</h2><table><tr><th>Source</th><th>Finding</th><th style="width:90px">Weight</th></tr>')
        for e in ev[:12]:
            detail = f'<div class="sub">{_e(str(e.get("detail"))[:160])}</div>' if e.get("detail") else ""
            a(f'<tr><td class="sub">{_e(e["source"])}</td><td>{_e(e["label"])}{detail}</td><td>{_weight_bar(e["weight"])}</td></tr>')
        a("</table>")
        a(
            f'<p class="sub" style="margin-top:8px">Rule engine: {v["rule_score"]}/100'
            + (f" · AI reviewer: {v['llm_score']}/100" if v.get("llm_score") is not None else "")
            + (f" · Safety floor: {v['floor']}" if v.get("floor") else "")
            + (f" · Trust discount: {int(v['trust_discount'] * 100)}%" if v.get("trust_discount") else "")
            + "</p></div>"
        )

    # ---- Forensics detail
    f = r["forensics"]
    if f["urls"] or f["upi"] or f["phones"] or f["senders"]:
        a('<div class="card"><h2>Forensic checks</h2>')
        if f["urls"]:
            a("<h3>Links</h3><table><tr><th>Link</th><th>Verdict</th><th>Findings</th></tr>")
            for u in f["urls"]:
                finds = [s["label"] for s in u["signals"]] + [s["label"] for s in u.get("trust_signals", [])]
                age = f' · registered {u["domain_age_days"]} days ago' if u.get("domain_age_days") is not None else ""
                a(f'<tr><td><code>{_e(u["host"])}</code>{age}</td><td><span class="v {u["verdict"]}">{_e(u["verdict"].upper())}</span></td><td>{_e("; ".join(finds) or "No issues found")}</td></tr>')
            a("</table>")
        if f["upi"]:
            a("<h3>UPI IDs</h3><table><tr><th>UPI ID</th><th>Provider</th><th>Findings</th></tr>")
            for u in f["upi"]:
                finds = [s["label"] for s in u["signals"]] + u.get("info", [])[1:]
                a(f'<tr><td><code>{_e(u["upi_id"])}</code></td><td>{_e(u.get("psp") or "Unknown handle")}</td><td>{_e("; ".join(finds))}</td></tr>')
            a("</table>")
        if f["phones"]:
            a("<h3>Phone numbers</h3><table><tr><th>Number</th><th>Type</th><th>Findings</th></tr>")
            for p in f["phones"]:
                finds = [s["label"] for s in p["signals"]] + [s["label"] for s in p.get("trust_signals", [])] + p.get("info", [])
                a(f'<tr><td><code>{_e(p["number"])}</code></td><td>{_e(p["kind"])} · {_e(p["country"])}</td><td>{_e("; ".join(finds))}</td></tr>')
            a("</table>")
        if f["senders"]:
            a("<h3>SMS sender IDs</h3><table><tr><th>Header</th><th>Type</th><th>Findings</th></tr>")
            for s_ in f["senders"]:
                finds = [x["label"] for x in s_["signals"]] + [x["label"] for x in s_.get("trust_signals", [])]
                a(f'<tr><td><code>{_e(s_["sender"])}</code></td><td>{_e(s_.get("suffix_meaning") or "—")}</td><td>{_e("; ".join(finds))}</td></tr>')
            a("</table>")
        if r.get("official_channels"):
            a("<h3>Verified official channels</h3><ul>")
            for o in r["official_channels"]:
                a(f'<li><b>{_e(o["name"])}</b>: {_e(", ".join(o["domains"]))}</li>')
            a("</ul>")
        a("</div>")

    # ---- Recovery: deadlines + liability
    if r["input"]["money_lost"] and tri:
        a('<div class="card"><h2>Recovery clock &amp; your rights</h2>')
        if tri.get("incident_display"):
            a(f'<p class="sub">Incident time understood as: <b>{_e(tri["incident_display"])}</b></p>')
        a("<table><tr><th>Step</th><th>Deadline</th><th>Why</th></tr>")
        for d in tri.get("deadlines", []):
            a(f'<tr><td>{_e(d["label"])}</td><td><b>{_e(d["due"])}</b></td><td class="sub">{_e(d["note"])}</td></tr>')
        a("</table>")
        lia = r.get("liability")
        if lia:
            a(f'<h3>How the loss is treated: {_e(lia["label"])}</h3><ul>')
            for p in lia["points"]:
                a(f"<li>{_e(p)}</li>")
            a(f'</ul><p class="sub">Rule reference: {_e(lia["rule_ref"])}. Working days exclude Sundays and 2nd/4th Saturdays; state holidays may extend them.</p>')
        a("</div>")

    # ---- Document pack
    d = r["drafts"]
    if any(d.values()):
        a('<div class="card"><h2>Ready-to-send pack <span class="sub">— review, fill the [brackets], then submit</span></h2>')
        if d.get("family_alert"):
            a(f'<details open><summary>Family alert (WhatsApp) <span class="sub">· {_e(r.get("language_name"))}</span></summary><pre>{_e(d["family_alert"])}</pre></details>')
        if d.get("ncrp"):
            n = d["ncrp"]
            a('<details open><summary>Cyber-crime complaint kit <span class="sub">· cybercrime.gov.in → Report Cyber Crime</span></summary>')
            a('<div class="kv">')
            a(f"<div>Category</div><div><b>{_e(n['category'])}</b> → {_e(n['subcategory'])} <span class=\"sub\">(closest match — confirm on the portal)</span></div>")
            a(f"<div>Date &amp; time</div><div>{_e(n['incident_datetime'])}</div>")
            if n.get("amount"):
                a(f"<div>Amount lost</div><div>{_e(n['amount'])}</div>")
            for k, vals in n["identifiers"].items():
                if vals:
                    a(f"<div>{_e(k)}</div><div><code>{_e(', '.join(vals))}</code></div>")
            if n.get("delay_reason"):
                a(f"<div>Reason for delay</div><div>{_e(n['delay_reason'])}</div>")
            a("</div><div class=\"sub\">Incident description (paste into the complaint):</div>")
            a(f"<pre>{_e(n['description'])}</pre>")
            a("<div class=\"sub\" style=\"margin-top:8px\">Attach: " + _e("; ".join(n["evidence"])) + "</div></details>")
        if d.get("bank_letter"):
            a(f'<details><summary>Bank dispute letter <span class="sub">· email to your bank / give at branch</span></summary><pre>{_e(d["bank_letter"])}</pre></details>')
        if d.get("police"):
            a(f'<details><summary>Police complaint (FIR request)</summary><pre>{_e(d["police"])}</pre></details>')
        if d.get("chakshu"):
            a(f'<details><summary>Chakshu report <span class="sub">· sancharsaathi.gov.in → Chakshu</span></summary><pre>{_e(d["chakshu"])}</pre></details>')
        a("</div>")

    # ---- Agent trace
    a(f'<details><summary>How the agent worked <span class="sub">· {len(r["trace"])} steps · {r.get("llm_calls", 0)} AI calls · {r["timing_ms"] / 1000:.1f}s</span></summary>')
    for s in r["trace"]:
        badge = ' <span class="chip ai">AI</span>' if s.get("llm") else ""
        a(f'<div class="step"><div class="dot">{s["n"]}</div><div><div class="role">{_e(s["agent"])}{badge}</div><div class="ttl">{_e(s["title"])}</div><div class="th">{_e(s["thought"])}</div>')
        for p in s.get("plan", []):
            a(f'<div class="call">plan → {_e(p)}</div>')
        for c in s.get("calls", []):
            args = ", ".join(f"{k}={v}" for k, v in c.get("args", {}).items())
            status = '<span class="ok">✓</span>' if c.get("ok", True) else '<span class="err">✗</span>'
            a(f'<div class="call">{status} <span class="tn">{_e(c["tool"])}</span>({_e(args)}) → {_e(c["summary"])} <span class="sub">{c.get("ms", 0)} ms</span></div>')
        a("</div></div>")
    a("</details>")

    # ---- Machine-readable case file
    if r.get("case_file") and tier != "SAFE":
        import json as _json

        a('<details><summary>Case file for the bank fraud desk / 1930 <span class="sub">· machine-readable (satark.case/1.0)</span></summary>'
          '<p class="sub">Banks, fintechs and helplines can ingest this directly — indicators, risk, golden-hour status and suggested institutional actions.</p>'
          f'<pre>{_e(_json.dumps(r["case_file"], ensure_ascii=False, indent=2))}</pre></details>')

    # ---- Privacy & responsibility
    masked = r["privacy"]["masked"]
    masked_txt = ", ".join(f"{n} {k.lower()}" for k, n in masked.items()) or "nothing personal detected"
    a(
        '<details><summary>Privacy &amp; safety</summary><ul>'
        f"<li>Personal identifiers masked before any AI reasoning: <b>{_e(masked_txt)}</b>. Tools run on the real values locally; the AI only sees placeholders.</li>"
        "<li>Nothing is stored — the sandbox is destroyed after this report.</li>"
        f'<li>Evidence fingerprint (SHA-256 of the text you pasted): <span class="fp">{_e(r.get("fingerprint", ""))}</span> — note it with your complaint; it shows the message was not altered later. Keep the original phone/SMS: police may need it with a certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023.</li>'

        "<li>Legal rules, deadlines and helplines come from a verified knowledge base, not from the AI.</li>"
        "<li>Deterministic safety floors stop the AI (or text written to fool it) from downgrading clear scam evidence.</li>"
        f"<li>{_e(r['disclaimer'])}</li></ul></details>"
    )

    # ---- Helplines footer
    st = r["stats"]
    a('<div class="help">')
    for key in ("1930", "ncrp", "chakshu", "rbi_cms"):
        h = HELPLINES[key]
        a(f'<div><b>{_e(h["label"])}</b>{_e(h["detail"][:90])}…</div>')
    a("</div>")
    a(
        f'<p class="foot">India lost ₹{st["loss_2025_crore"]:,} crore to cyber fraud in 2025 across {st["complaints_2025"]:,} complaints ({_e(st["stat_source"])}). '
        f'Fast reporting through 1930 has helped save ₹{st["cfcfrms_saved_crore"]:,} crore ({_e(st["cfcfrms_source"])}). Satark v{_e(r["agent"]["version"])}.</p>'
    )
    a("</div></body></html>")
    return "".join(out)
