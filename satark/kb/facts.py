"""Grounded regulatory facts, helplines and statistics.

The LLM is never allowed to invent legal facts: every rule, deadline and
statistic shown to the user comes from this file, with its source.
Last verified: 1 Oct 2026.
"""

from __future__ import annotations

HELPLINES = {
    "1930": {
        "label": "National Cyber Crime Helpline 1930",
        "detail": "Report financial cyber fraud immediately so the money trail can be frozen through I4C's Citizen Financial Cyber Fraud Reporting & Management System (CFCFRMS).",
    },
    "ncrp": {
        "label": "cybercrime.gov.in (NCRP)",
        "detail": "National Cyber Crime Reporting Portal — file a complaint and get an acknowledgement number; also 'Report & Check Suspect' for phone numbers, UPI IDs, bank accounts and URLs.",
    },
    "chakshu": {
        "label": "Sanchar Saathi → Chakshu (sancharsaathi.gov.in)",
        "detail": "DoT facility to report suspected fraud calls, SMS and WhatsApp messages so numbers can be disconnected.",
    },
    "rbi_cms": {
        "label": "RBI Ombudsman — cms.rbi.org.in / 14448",
        "detail": "Escalate if your bank/payment company does not resolve your complaint within 30 days or you are unhappy with its reply.",
    },
}

RBI_LIABILITY_2017 = {
    "title": "RBI: Limiting liability of customers in unauthorised electronic banking transactions",
    "ref": "RBI circular DBR.No.Leg.BC.78/09.07.005/2017-18, 6 July 2017",
    "zero_liability_working_days": 3,
    "limited_liability_working_days": 7,
    "limited_caps": [
        ("Basic Savings Bank Deposit (BSBD) account", 5000),
        ("Other savings accounts; current accounts/cash credit/overdraft of MSMEs and individuals with limit up to ₹25 lakh; credit cards with limit up to ₹5 lakh; prepaid instruments/gift cards", 10000),
        ("Other current/cash credit/overdraft accounts; credit cards with limit above ₹5 lakh", 25000),
    ],
    "shadow_credit_working_days": 10,
    "resolution_days": 90,
    "points": [
        "Zero liability if the fraud was due to the bank's negligence, or due to a third-party breach (neither you nor the bank at fault) and you inform the bank within 3 working days of receiving the transaction alert.",
        "Limited liability (capped at ₹5,000 / ₹10,000 / ₹25,000 depending on account type) if you inform the bank within 4–7 working days in a third-party breach.",
        "If the loss is due to your negligence (e.g., you shared OTP/PIN/password), you bear the loss until you report it to the bank; any loss after reporting is borne by the bank.",
        "The bank must credit (shadow-reverse) the amount within 10 working days of your notification and resolve the complaint within 90 days.",
    ],
}

RBI_COMPENSATION_PROPOSAL_2026 = {
    "title": "RBI proposed compensation framework for small-value digital frauds (Feb 2026)",
    "status": "Proposed (draft for public consultation, announced Feb 2026). Ask your bank whether it is in force and whether your case qualifies.",
    "points": [
        "Compensation of up to ₹25,000 or 85% of the fraud amount, whichever is lower, for small-value digital frauds where the transaction is not mala fide.",
        "RBI indicated customers may be eligible even in some cases where an OTP was shared.",
        "RBI noted that about 65% of fraud cases involve amounts below ₹55,000.",
    ],
    "source": "RBI Governor's statement, 6 Feb 2026 (reported by Business Today / Business Standard)",
}

E_ZERO_FIR = {
    "title": "e-Zero FIR (I4C, launched 21 May 2025 as a Delhi pilot)",
    "threshold": 10_00_000,
    "points": [
        "Financial cyber-fraud complaints above ₹10 lakh filed on NCRP or via 1930 are automatically converted into Zero FIRs (pilot started in Delhi).",
        "The complainant must visit the concerned police station within 3 days to convert the Zero FIR into a regular FIR.",
        "Enabled under Section 173(1) and 1(ii) of the BNSS.",
    ],
}

UPI_FACTS = [
    "You never need to enter your UPI PIN or scan a QR code to receive money — the PIN is only for paying.",
    "NPCI discontinued person-to-person (P2P) 'collect requests' on UPI from 1 Oct 2025 to curb fraud.",
]

BANK_CONTACT_FACTS = [
    "RBI has directed banks to use the '1600xx' number series for service/transactional calls and '140xx' for promotional calls.",
    "Indian banks have moved to the exclusive '.bank.in' web domain (RBI deadline 31 Oct 2025); other regulated financial entities use '.fin.in'.",
    "Commercial SMS headers must end in -T (transactional), -S (service), -P (promotional) or -G (government) under TRAI's TCCCPR 2025.",
]

STATS = {
    "loss_2025_crore": 22495,
    "complaints_2025": 2402579,
    "loss_2024_crore": 22848,
    "complaints_2024": 1918835,
    "stat_source": "MHA reply in Parliament (Unstarred Q. 1341), 11 Feb 2026",
    "cfcfrms_saved_crore": 11158,
    "cfcfrms_complaints_lakh": 32.80,
    "cfcfrms_source": "I4C / PIB (CFCFRMS 2.0), figures up to June 2026",
    "suspect_registry_declined_crore": 25698,
}

LEGAL_SECTIONS = (
    "relevant provisions of the Bharatiya Nyaya Sanhita, 2023 (e.g., Section 318 – cheating, Section 319 – cheating by personation) "
    "and the Information Technology Act, 2000 (e.g., Section 66C – identity theft, Section 66D – cheating by personation using a computer resource)"
)

DISCLAIMER = (
    "Satark gives safety guidance and drafts documents for you to review — it is not legal advice and it never contacts anyone on your behalf. "
    "Satark will never ask for your OTP, UPI PIN, card details or passwords."
)
