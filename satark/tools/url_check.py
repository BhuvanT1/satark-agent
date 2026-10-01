"""Link forensics: look-alike / brand-impersonation detection, risky TLDs,
shorteners, APK downloads, free hosting, and optional domain-age (RDAP)."""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..kb.domains import (
    BRAND_TOKENS,
    FREE_HOSTING_SUFFIXES,
    MESSAGING_LINK_HOSTS,
    MULTI_SUFFIXES,
    OFFICIAL_BRANDS,
    RDAP_SERVERS,
    RISKY_PATH_WORDS,
    SHORT_TOKEN_MAX,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

_ALL_OFFICIAL = {d: b for b, info in OFFICIAL_BRANDS.items() for d in info["domains"]}
_RDAP_CACHE: dict[str, int | None] = {}
_RDAP_STATE = {"down": False}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 3:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 4 and ".".join(labels[-3:]) in MULTI_SUFFIXES:
        return ".".join(labels[-4:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _sig(code: str, label: str, weight: float, detail: str = "") -> dict:
    return {"code": code, "label": label, "weight": round(weight, 2), "detail": detail}


def rdap_domain_age_days(domain: str, timeout: float = 3.5) -> int | None:
    """Days since registration via RDAP; None when unknown/offline."""
    if domain in _RDAP_CACHE:
        return _RDAP_CACHE[domain]
    tld = domain.rsplit(".", 1)[-1]
    base = RDAP_SERVERS.get(tld)
    if not base or _RDAP_STATE["down"] or domain.endswith((".gov.in", ".nic.in", ".bank.in", ".fin.in")):
        _RDAP_CACHE[domain] = None
        return None
    try:
        req = urllib.request.Request(base + "domain/" + domain, headers={"Accept": "application/rdap+json", "User-Agent": "Satark/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                when = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                days = (datetime.now(timezone.utc) - when).days
                _RDAP_CACHE[domain] = days
                return days
    except urllib.error.HTTPError:
        pass  # registry answered (e.g. 404) — network is fine
    except (OSError, socket.timeout):
        _RDAP_STATE["down"] = True  # no egress: skip further lookups this run
    except (ValueError, json.JSONDecodeError):
        pass
    _RDAP_CACHE[domain] = None
    return None


def analyze_url(url: str, claimed_brands: list[str] | None = None, use_rdap: bool = False, rdap_timeout: float = 3.5) -> dict:
    claimed_brands = claimed_brands or []
    raw = url.strip()
    parts = urlsplit(raw if "://" in raw else "http://" + raw)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme if "://" in raw else ""
    path = (parts.path or "") + ("?" + parts.query if parts.query else "")
    signals: list[dict] = []
    trust: list[dict] = []

    if not host:
        return {"url": raw, "host": "", "risk": 0.0, "trust": 0.0, "signals": [], "verdict": "unparsed"}

    is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))
    reg = host if is_ip else registrable_domain(host)
    tld = host.rsplit(".", 1)[-1]
    official_brand = _ALL_OFFICIAL.get(reg) or _ALL_OFFICIAL.get(host)

    if host.endswith(".gov.in") or host.endswith(".nic.in"):
        trust.append(_sig("gov_domain", "Government-reserved domain (.gov.in / .nic.in)", 0.6, host))
    if host.endswith(".bank.in"):
        trust.append(_sig("bank_in", "RBI-mandated bank domain (.bank.in) — only regulated banks can register it", 0.6, host))
    if host.endswith(".fin.in"):
        trust.append(_sig("fin_in", "Regulated financial-entity domain (.fin.in)", 0.45, host))
    if official_brand:
        trust.append(_sig("official_domain", f"Verified official domain of {OFFICIAL_BRANDS[official_brand]['name']}", 0.6, reg))

    # Brand impersonation: a brand token inside a non-official domain
    if not trust and not is_ip:
        name_part = reg.rsplit(".", 1)[0] if "." in reg else reg
        sub_part = host[: -len(reg)].strip(".") if host != reg else ""
        hay_labels = re.split(r"[.\-_]", (sub_part + "." + name_part).strip("."))
        joined = (sub_part + name_part).replace("-", "").replace(".", "")
        hits = set()
        for token, brand in BRAND_TOKENS.items():
            if len(token) <= SHORT_TOKEN_MAX:
                if token in hay_labels:
                    hits.add(brand)
            elif token in joined:
                hits.add(brand)
        for brand in sorted(hits):
            bname = OFFICIAL_BRANDS.get(brand, {}).get("name", brand.upper())
            signals.append(_sig(
                "brand_impersonation",
                f"Uses the name '{bname}' but is NOT its official website",
                0.6,
                f"{host} — official: {', '.join(sorted(OFFICIAL_BRANDS.get(brand, {}).get('domains', [])))[:120]}",
            ))
        # Typosquatting: close to an official registrable domain
        if not hits:
            best = None
            for off in _ALL_OFFICIAL:
                if "." not in off:
                    continue
                d = levenshtein(reg, off)
                if 0 < d <= 2 and len(off) >= 7 and (best is None or d < best[1]):
                    best = (off, d)
            if best:
                bname = OFFICIAL_BRANDS[_ALL_OFFICIAL[best[0]]]["name"]
                signals.append(_sig("typosquat", f"Look-alike of {bname}'s domain {best[0]}", 0.55, f"{reg} differs by {best[1]} character(s)"))

    # A bank is mentioned but the link is not on a bank domain
    bank_claims = [b for b in claimed_brands if OFFICIAL_BRANDS.get(b, {}).get("type") == "bank"]
    if bank_claims and not trust:
        signals.append(_sig(
            "bank_claim_wrong_domain",
            "Message claims to be from a bank, but the link is not on a '.bank.in' or official bank domain",
            0.35,
            host,
        ))

    if tld in SUSPICIOUS_TLDS and not trust:
        signals.append(_sig("suspicious_tld", f"High-abuse top-level domain '.{tld}'", SUSPICIOUS_TLDS[tld], host))
    if host in URL_SHORTENERS or reg in URL_SHORTENERS:
        signals.append(_sig("shortener", "Link shortener hides the real destination", 0.3, host))
    if host in MESSAGING_LINK_HOSTS or reg in MESSAGING_LINK_HOSTS:
        signals.append(_sig("messaging_link", "Moves the conversation to WhatsApp/Telegram (unmonitored)", 0.2, host))
    if any(host.endswith(s) or reg.endswith(s) for s in FREE_HOSTING_SUFFIXES):
        signals.append(_sig("free_hosting", "Hosted on a free website/app builder — common for phishing kits", 0.3, host))
    if is_ip:
        signals.append(_sig("ip_host", "Uses a raw IP address instead of a domain name", 0.45, host))
    if "xn--" in host:
        signals.append(_sig("punycode", "Internationalised (punycode) domain — can imitate real letters", 0.4, host))
    if "@" in (parts.netloc or ""):
        signals.append(_sig("at_trick", "'@' in the link hides the real destination", 0.35, raw))
    if scheme == "http" and not trust:
        signals.append(_sig("no_https", "Not encrypted (http://)", 0.1, raw))
    if host.count("-") >= 2 and not trust:
        signals.append(_sig("many_hyphens", "Hyphen-stuffed domain name", 0.12, host))
    if host.count(".") >= 4 and not trust:
        signals.append(_sig("deep_subdomains", "Unusually deep sub-domain chain", 0.15, host))
    if re.search(r"\.apk(\b|$)", path.lower()) or host.endswith(".apk"):
        signals.append(_sig("apk_download", "Downloads an Android APK — banks/government never send apps by link", 0.7, raw))
    bait = [w for w in RISKY_PATH_WORDS if w in (host + path).lower()]
    if bait and not trust:
        signals.append(_sig("bait_words", "Bait words in the link: " + ", ".join(bait[:5]), 0.15, raw))

    age = None
    if use_rdap and not trust and not is_ip:
        age = rdap_domain_age_days(reg, timeout=rdap_timeout)
        if age is not None:
            if age < 30:
                signals.append(_sig("young_domain", f"Domain registered only {age} day(s) ago", 0.45, reg))
            elif age < 180:
                signals.append(_sig("young_domain", f"Domain registered {age} days ago (< 6 months)", 0.2, reg))
            elif age > 3 * 365:
                trust.append(_sig("old_domain", f"Domain is {age // 365}+ years old", 0.1, reg))

    risk = 1.0
    for s in signals:
        risk *= 1 - s["weight"]
    risk = 1 - risk
    trust_score = max([t["weight"] for t in trust], default=0.0)
    if trust_score >= 0.45:
        risk *= 0.2
    risk = round(min(risk, 0.99), 3)

    if trust_score >= 0.45 and risk < 0.3:
        verdict = "official"
    elif risk >= 0.6:
        verdict = "dangerous"
    elif risk >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "unverified"

    return {
        "url": raw,
        "host": host,
        "registrable": reg,
        "tld": tld,
        "official_for": OFFICIAL_BRANDS[official_brand]["name"] if official_brand else None,
        "domain_age_days": age,
        "risk": risk,
        "trust": round(trust_score, 2),
        "signals": signals,
        "trust_signals": trust,
        "verdict": verdict,
    }
