#!/usr/bin/env python3
"""Evaluate Satark on the labelled case set.

Metrics
- Detection rate  : scam cases scored HIGH or SCAM (>= 50)
- False-alarm rate: legitimate cases scored SUSPICIOUS or worse (>= 25)
- Typology accuracy: scam cases whose top playbook matches the label

Usage: python eval/run_eval.py [--llm]   (offline by default)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from satark.agent import analyze  # noqa: E402
from satark.config import IST, Settings  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="use the configured LLM instead of offline mode")
    args = ap.parse_args()
    settings = Settings() if args.llm else Settings(llm_provider="none", enable_rdap=False)
    now = datetime(2026, 10, 1, 15, 0, tzinfo=IST)
    rows, t0 = [], time.monotonic()
    for line in (ROOT / "eval" / "cases.jsonl").read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        r = analyze(case["input"], settings, now)
        v = r["verdict"]
        exp = case["expected_typology"]
        ok_typ = None if not exp else (v["typology_id"] in exp.split("|"))
        rows.append({"id": case["id"], "label": case["label"], "lang": case["lang"], "score": v["score"], "tier": v["tier"],
                     "typology": v["typology_id"], "expected": exp, "typology_ok": ok_typ, "text": case["input"]["situation"][:70]})
    scams = [r for r in rows if r["label"] == "scam"]
    legit = [r for r in rows if r["label"] == "legit"]
    detected = [r for r in scams if r["score"] >= 50]
    false_alarms = [r for r in legit if r["score"] >= 25]
    typ_ok = [r for r in scams if r["typology_ok"]]
    summary = {
        "cases": len(rows),
        "scam_cases": len(scams),
        "legit_cases": len(legit),
        "detection_rate": round(len(detected) / max(1, len(scams)), 3),
        "false_alarm_rate": round(len(false_alarms) / max(1, len(legit)), 3),
        "typology_accuracy": round(len(typ_ok) / max(1, len(scams)), 3),
        "mode": "llm" if args.llm else "offline",
        "seconds": round(time.monotonic() - t0, 2),
    }
    out = ["# Satark evaluation", "", f"Mode: **{summary['mode']}** · {summary['cases']} labelled cases ({summary['scam_cases']} scam / {summary['legit_cases']} legitimate; English, Hinglish, Hindi, Telugu)", "",
           f"- Detection rate (scam → High/Scam): **{summary['detection_rate']*100:.0f}%**",
           f"- False-alarm rate (legit → Suspicious or worse): **{summary['false_alarm_rate']*100:.0f}%**",
           f"- Scam-type accuracy: **{summary['typology_accuracy']*100:.0f}%**",
           f"- Total time: {summary['seconds']} s ({summary['seconds']/max(1,len(rows))*1000:.0f} ms per case)", "",
           "| # | Label | Lang | Score | Tier | Type found | Expected | Text |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        mark = "" if r["label"] == "legit" else (" ✓" if r["typology_ok"] else " ✗")
        out.append(f"| {r['id']} | {r['label']} | {r['lang']} | {r['score']} | {r['tier']} | {r['typology'] or '—'}{mark} | {r['expected'] or '—'} | {r['text'].replace('|','/')}… |")
    (ROOT / "eval" / "RESULTS.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    for r in rows:
        bad = (r["label"] == "scam" and (r["score"] < 50 or not r["typology_ok"])) or (r["label"] == "legit" and r["score"] >= 25)
        if bad:
            print("MISS:", r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
