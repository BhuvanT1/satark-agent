"""Match observed red-flag signals against the Indian scam playbook library."""

from __future__ import annotations

from ..kb.playbooks import PLAYBOOKS

MECHANISMS = {"malicious_apk"}


def match_playbooks(signals: set[str], lang: str = "en", top_k: int = 3) -> list[dict]:
    results = []
    for pb in PLAYBOOKS:
        weights = pb["weights"]
        present = [s for s in weights if s in signals]
        if not present:
            continue
        core_hits = [s for s in pb["core"] if s in signals]
        prod = 1.0
        for s in present:
            prod *= 1 - weights[s]
        score = 1 - prod
        if len(core_hits) < pb.get("min_core", 1):
            score *= 0.35
        results.append(
            {
                "id": pb["id"],
                "name": pb["name"].get(lang) or pb["name"]["en"],
                "name_en": pb["name"]["en"],
                "score": round(score, 3),
                "matched": present,
                "core_hit": bool(core_hits),
                "critical": pb.get("critical", False),
            }
        )
    # A delivery mechanism (APK / remote access) usually serves a lure (loan, challan,
    # refund...). When another playbook also has a core match, prefer the lure.
    lures_with_core = [r for r in results if r["core_hit"] and r["id"] not in MECHANISMS]
    if lures_with_core:
        for r in results:
            if r["id"] in MECHANISMS:
                r["score"] = round(r["score"] * 0.85, 3)
    results.sort(key=lambda r: (r["core_hit"], r["score"]), reverse=True)
    return results[:top_k]
