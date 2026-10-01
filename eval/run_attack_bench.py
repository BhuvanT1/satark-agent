#!/usr/bin/env python3
"""Attack bench: can scammers slip past Satark?

Each case is a scam disguised with a technique aimed at keyword filters or
AI checkers. We report:
  1. Satark (full)                      — robustness layer + safety floors
  2. Ablation: robustness layer OFF     — same engine, no de-obfuscation
  3. Fooled-AI test                     — the AI reviewer is FORCED to answer
                                          "legitimate, risk 3/100"; does the
                                          final verdict still flag the scam?
A case counts as caught when the final score is >= 50 (High risk or Scam).
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from satark.agent import analyze  # noqa: E402
from satark.config import IST, Settings  # noqa: E402

NOW = datetime(2026, 10, 1, 15, 0, tzinfo=IST)


def run(text: str, **kw) -> dict:
    s = Settings(llm_provider=kw.pop("provider", "none"), enable_rdap=False)
    s.deobfuscate = kw.pop("deobfuscate", True)
    return analyze({"situation": text, "money_lost": "No"}, s, NOW)


def main() -> int:
    cases = [json.loads(l) for l in (ROOT / "eval" / "attack_cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = []
    for c in cases:
        full = run(c["text"])
        abl = run(c["text"], deobfuscate=False)
        os.environ["SATARK_MOCK_MODE"] = "manipulated"
        fooled = run(c["text"], provider="mock")
        os.environ.pop("SATARK_MOCK_MODE", None)
        rows.append({
            "id": c["id"], "technique": c["technique"],
            "full": full["verdict"]["score"], "full_tier": full["verdict"]["tier"],
            "ablation": abl["verdict"]["score"],
            "fooled_ai_said": fooled["verdict"]["llm_score"], "fooled_final": fooled["verdict"]["score"],
            "tricks": [o["code"] for o in full["obfuscation"]],
        })
    n = len(rows)
    caught = sum(r["full"] >= 50 for r in rows)
    caught_abl = sum(r["ablation"] >= 50 for r in rows)
    caught_fooled = sum(r["fooled_final"] >= 50 for r in rows)
    lines = [
        "# Satark attack bench", "",
        f"{n} disguised scams (leetspeak, spaced letters, Cyrillic look-alikes, full-width text, zero-width characters, right-to-left file spoofing, prompt injection in English/Hindi/Telugu).", "",
        f"- **Satark (full): {caught}/{n} caught**",
        f"- Ablation — robustness layer switched off: {caught_abl}/{n} caught",
        f"- Fooled-AI test — AI reviewer forced to say 'legitimate, 3/100': final verdict still caught **{caught_fooled}/{n}**", "",
        "| # | Technique | Satark | Without robustness layer | Forced-wrong AI said | Final with forced-wrong AI | Tricks undone |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r['id']} | {r['technique']} | {r['full']} ({r['full_tier']}) | {r['ablation']} | {r['fooled_ai_said']} | {r['fooled_final']} | {', '.join(r['tricks']) or '—'} |")
    (ROOT / "eval" / "ATTACK_RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:7]))
    for r in rows:
        if r["full"] < 50 or r["fooled_final"] < 50:
            print("MISS", r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
