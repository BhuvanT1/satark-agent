"""Markdown report (for output.format=markdown and API consumers)."""

from __future__ import annotations

PRIORITY_LABEL = {"NOW": "Do now", "TODAY": "Today", "NEXT 3 DAYS": "Next 3 days", "LATER": "Later"}
TIER_ICON = {"SCAM": "🔴", "HIGH": "🟠", "SUSPICIOUS": "🟡", "SAFE": "🟢"}


def _md(s) -> str:
    return str(s or "").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def render_markdown(r: dict) -> str:
    v = r["verdict"]
    lang = r.get("language", "en")
    L: list[str] = []
    L.append(f"# 🛡️ Satark report — {TIER_ICON.get(v['tier'], '')} {v['tier_label'].upper()} ({v['score']}/100)")
    L.append(f"**{_md(v['headline'])}**  ")
    meta = f"Case `{r['case_id']}` · {r['generated_at']} · {r['engine']} · confidence {v['confidence']}"
    if v.get("typology"):
        meta = f"Type: **{_md(v['typology'])}** · " + meta
    L.append(meta)
    if v.get("floor_reasons"):
        L.append("Safety floor: " + "; ".join(_md(x) for x in v["floor_reasons"][:2]))
    tri = r.get("triage")
    if r["input"]["money_lost"] and tri:
        L.append("")
        L.append(f"> 🚨 **{_md(r.get('golden_message'))}** — **Call 1930 · cybercrime.gov.in**  ")
        el = tri.get("elapsed_minutes")
        L.append(f"> Loss: {r['input'].get('amount_display') or 'not stated'} · " + (f"{el} min since the incident" if el is not None else "time unknown"))
    if r.get("console"):
        L.append("")
        L.append(" · ".join(f"[{c['label']}]({c['href']})" for c in r["console"] if c["href"].startswith(("tel:", "https://cybercrime", "https://sanchar", "https://cms."))))
    obf = r.get("obfuscation") or []
    if obf or any(e["label"].startswith("Text tries to manipulate") for e in r.get("evidence", [])):
        L.append("\n## 🛡️ Scammer tricks Satark defeated")
        if any(e["label"].startswith("Text tries to manipulate") for e in r.get("evidence", [])):
            L.append("- **Prompt-injection attempt neutralised** — instructions aimed at AI checkers were ignored; the verdict cannot drop below the rule-based safety floor.")
        for o in obf:
            L.append(f"- **{_md(o['label'])}**" + (f" — {_md(', '.join(o['examples']))}" if o.get("examples") else ""))
    kc = r.get("killchain")
    if kc and v["tier"] != "SAFE" and kc.get("current_index", -1) >= 0:
        chain = " → ".join((f"**[{st['name']}]**" if i == kc["current_index"] else (st["name"] if st["observed"] else f"~~{st['name']}~~")) for i, st in enumerate(kc["stages"]))
        L.append(f"\n## Where you are in the scam\n{chain}")
        if kc.get("next_move"):
            L.append(f"\n> **Their likely next move:** {_md(kc['next_move'])}")
        if kc.get("recovery_scam_warning"):
            L.append(f"\n> ⚠️ **Second-scam alert:** {_md(kc['recovery_scam_warning'])}")
    L.append("\n## What to do — step by step")
    for a in r["actions"]:
        line = f"- **{PRIORITY_LABEL.get(a['priority'], a['priority'])}:** {_md(a['text'])}"
        if lang != "en" and a["text"] != a["text_en"]:
            line += f"  \n  _{_md(a['text_en'])}_"
        if a.get("due"):
            line += f" _(due: {_md(a['due'])})_"
        L.append(line)
    L.append("\n## Why")
    for p in v.get("summary_points", []):
        L.append(f"- {_md(p)}")
    if v.get("truth") and v["tier"] != "SAFE":
        L.append(f"\n> **The truth:** {_md(v['truth'])}")
    if r.get("evidence"):
        L.append("\n## Evidence board\n| Source | Finding | Weight |\n|---|---|---|")
        for e in r["evidence"][:10]:
            L.append(f"| {_md(e['source'])} | {_md(e['label'])} | {e['weight']:+.2f} |")
    f = r["forensics"]
    if f["urls"]:
        L.append("\n### Links")
        for u in f["urls"]:
            finds = [s["label"] for s in u["signals"]] + [s["label"] for s in u.get("trust_signals", [])]
            L.append(f"- `{_md(u['host'])}` — **{u['verdict'].upper()}**: {_md('; '.join(finds) or 'no issues found')}")
    if f["upi"]:
        L.append("\n### UPI IDs")
        for u in f["upi"]:
            L.append(f"- `{_md(u['upi_id'])}` ({_md(u.get('psp') or 'unknown handle')}): " + _md("; ".join([s["label"] for s in u["signals"]] + u.get("info", [])[1:])))
    if f["phones"]:
        L.append("\n### Phone numbers")
        for p in f["phones"]:
            L.append(f"- `{_md(p['number'])}` ({p['kind']}, {p['country']}): " + _md("; ".join([s["label"] for s in p["signals"]] + p.get("info", []))))
    if r["input"]["money_lost"] and tri:
        L.append("\n## Recovery clock\n| Step | Deadline |\n|---|---|")
        for d in tri.get("deadlines", []):
            L.append(f"| {_md(d['label'])} | **{_md(d['due'])}** |")
        if r.get("liability"):
            L.append(f"\n**{_md(r['liability']['label'])}**")
            for p in r["liability"]["points"]:
                L.append(f"- {_md(p)}")
    d = r["drafts"]
    if d.get("family_alert"):
        L.append("\n## Family alert (WhatsApp)\n```\n" + d["family_alert"] + "\n```")
    if d.get("ncrp"):
        n = d["ncrp"]
        L.append(f"\n## Cyber-crime complaint kit\nCategory: **{_md(n['category'])} → {_md(n['subcategory'])}** · Date/time: {_md(n['incident_datetime'])}")
        L.append("```\n" + n["description"] + "\n```")
    if d.get("bank_letter"):
        L.append("\n## Bank dispute letter\n```\n" + d["bank_letter"] + "\n```")
    if d.get("police"):
        L.append("\n## Police complaint (FIR request)\n```\n" + d["police"] + "\n```")
    if d.get("chakshu"):
        L.append("\n## Chakshu report\n```\n" + d["chakshu"] + "\n```")
    L.append("\n## How the agent worked")
    for s in r["trace"]:
        L.append(f"{s['n']}. **{_md(s['agent'])} — {_md(s['title'])}**{' (AI)' if s.get('llm') else ''}: {_md(s['thought'])}")
        for c in s.get("calls", []):
            L.append(f"   - `{c['tool']}` → {_md(c['summary'])}")
    masked = ", ".join(f"{n} {k.lower()}" for k, n in r["privacy"]["masked"].items()) or "nothing personal detected"
    L.append(f"\n---\n_Privacy: masked before AI — {masked}. Nothing stored. Evidence fingerprint (SHA-256): `{r.get('fingerprint', '')}`. {_md(r['disclaimer'])}_")
    return "\n".join(L)
