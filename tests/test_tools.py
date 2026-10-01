from datetime import datetime

from satark.config import IST
from satark.tools.deobfuscate import deobfuscate
from satark.tools.extract import extract_entities
from satark.tools.identity_check import check_phone_number, check_upi_id
from satark.tools.redact import Redactor
from satark.tools.signals import detect_signals
from satark.tools.triage import add_working_days, golden_hour_triage, parse_when
from satark.tools.url_check import analyze_url

NOW = datetime(2026, 10, 1, 15, 0, tzinfo=IST)


def test_entities_extracted():
    e = extract_entities("Pay Rs 2,50,000 to ramesh.kumar@okaxis, call +92 301 2345678 or 9876543210, visit https://sbi-kyc.xyz/login, mail a@b.com")
    assert "ramesh.kumar@okaxis" in e.upi_ids
    assert "a@b.com" in e.emails and "a@b.com" not in e.upi_ids
    assert any(p["cc"] == "92" for p in e.phones) and any(p["e164"] == "+919876543210" for p in e.phones)
    assert e.urls == ["https://sbi-kyc.xyz/login"]
    assert 250000.0 in e.amounts


def test_otp_warning_is_not_a_request():
    sig = detect_signals("Your OTP is 482913. Do not share it with anyone. -HDFC Bank")
    assert "otp_request" not in sig and "otp_warning_legit" in sig
    assert "otp_request" in detect_signals("Please share the OTP sent to your phone to unblock your account")


def test_multilingual_signals():
    assert "electricity_cut" in detect_signals("आपका बिजली कनेक्शन आज रात काट दिया जाएगा")
    assert "reward_lure" in detect_signals("మీకు లాటరీలో 25 లక్షలు బహుమతి వచ్చింది")
    assert "payment_request" in detect_signals("Urgent hai, 20000 bhej do is UPI pe")


def test_lookalike_vs_official_domains():
    bad = analyze_url("https://sbi-kyc-update.xyz/login", ["sbi"])
    assert bad["verdict"] == "dangerous"
    assert {"brand_impersonation", "suspicious_tld"} <= {s["code"] for s in bad["signals"]}
    good = analyze_url("https://onlinesbi.sbi/", ["sbi"])
    assert good["verdict"] == "official"
    assert analyze_url("https://sbi.bank.in/", ["sbi"])["verdict"] == "official"
    assert analyze_url("https://echallan.parivahan.gov.in/")["verdict"] == "official"
    assert any(s["code"] == "apk_download" for s in analyze_url("http://bit.ly/x/RTO.apk")["signals"])


def test_upi_and_phone_checks():
    u = check_upi_id("ramesh.kumar@okaxis", official_claim=True)
    assert any(s["code"] == "official_fee_to_personal_upi" for s in u["signals"])
    assert check_upi_id("shop@unknownhandle")["signals"][0]["code"] == "unknown_handle"
    ph = check_phone_number({"raw": "+92 301 2345678", "e164": "+923012345678", "kind": "international", "cc": "92"}, [], ["CBI"])
    assert any(s["code"] == "foreign_claims_indian_authority" for s in ph["signals"])
    bank = check_phone_number({"raw": "1600123456", "e164": "1600123456", "kind": "1600-series", "cc": "91"}, ["hdfc"], [])
    assert bank["trust_signals"] and bank["risk"] == 0


def test_redaction_roundtrip():
    e = extract_entities("Send to ramesh@okaxis or call 9876543210")
    r = Redactor()
    r.register(e)
    masked = r.redact("Send to ramesh@okaxis or call 9876543210")
    assert "ramesh@okaxis" not in masked and "9876543210" not in masked
    assert r.rehydrate(masked) == "Send to ramesh@okaxis or call 9876543210"


def test_deobfuscation_layer():
    for raw, needle, code in [
        ("Share your 0TP now", "otp", "leetspeak"),
        ("share O T P for K-Y-C", "otp", "spaced_letters"),
        ("Your ЅВІ account", "sbi", "homoglyph"),
        ("Your ＯＴＰ", "otp", "fullwidth"),
        ("O​T​P", "otp", "invisible_chars"),
        ("photo‮gpj.apk", "apk", "bidi_override"),
    ]:
        clean, found = deobfuscate(raw)
        assert needle in clean.lower(), raw
        assert code in {f["code"] for f in found}, raw
    clean, found = deobfuscate("Rs 500 credited to a/c XX1234. Avl bal Rs 10,000.")
    assert found == [] and "Rs 500" in clean
    # Indic joiners must survive
    clean, _ = deobfuscate("ఆర్‌బీఐ")
    assert "‌" in clean


def test_time_parsing_and_deadlines():
    assert parse_when("40 minutes ago", NOW)[0].minute == 20
    assert parse_when("kal raat 10 baje", NOW)[0].hour == 22
    assert parse_when("10:30 am", NOW)[0] <= NOW
    # Thu 1 Oct 2026 + 3 working days (skip Sun 4 Oct) -> Mon 5 Oct
    assert add_working_days(NOW, 3).strftime("%a %d") == "Mon 05"
    tri = golden_hour_triage(True, "40 minutes ago", 250000, "UPI", "Telangana", NOW)
    assert tri["status"] == "golden" and tri["elapsed_minutes"] == 40
    assert golden_hour_triage(True, "3 days ago", 1000, "UPI", None, NOW)["status"] == "late"
