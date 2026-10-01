"""Reference data for the forensic tools: official domains, brand tokens,
risky TLDs, URL shorteners, free-hosting platforms, UPI PSP handles and
telephone country codes.

Sources / rules encoded here (verified Oct 2026):
- RBI mandated the exclusive ".bank.in" domain for Indian banks (migration
  deadline 31 Oct 2025) and ".fin.in" for other regulated financial entities.
- ".gov.in" / ".nic.in" are reserved for Indian government bodies.
- RBI directed banks to use the "1600xx" number series for service/transactional
  calls and "140xx" for promotional calls.
- TRAI (TCCCPR 2025) requires commercial SMS headers to carry suffixes
  -T (transactional), -S (service), -P (promotional), -G (government).
"""

from __future__ import annotations

# Multi-label public suffixes we need to know about to find the registrable domain.
MULTI_SUFFIXES = {
    "co.in", "org.in", "net.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in",
    "bank.in", "fin.in", "firm.in", "gen.in", "ind.in", "mil.in",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "com.sg", "com.my", "co.za", "com.br", "com.cn", "com.pk", "com.bd", "com.np",
    "blogspot.com", "github.io", "web.app", "firebaseapp.com", "vercel.app",
    "netlify.app", "pages.dev", "glitch.me", "herokuapp.com", "wixsite.com",
    "weebly.com", "000webhostapp.com", "onrender.com", "repl.co", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "azurewebsites.net", "appspot.com",
}

# Brand -> (display name, official registrable domains). Only domains we are
# confident about are listed; any *.bank.in domain is also treated as a bank.
OFFICIAL_BRANDS: dict[str, dict] = {
    "sbi": {"name": "State Bank of India", "domains": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "yonobusiness.sbi"}, "type": "bank"},
    "hdfc": {"name": "HDFC Bank", "domains": {"hdfcbank.com", "hdfc.bank.in", "hdfcbank.bank.in", "hdfc.com", "hdfclife.com", "hdfcergo.com"}, "type": "bank"},
    "icici": {"name": "ICICI Bank", "domains": {"icicibank.com", "icici.bank.in", "icicibank.bank.in", "icicidirect.com", "iciciprulife.com", "icicilombard.com"}, "type": "bank"},
    "axis": {"name": "Axis Bank", "domains": {"axisbank.com", "axis.bank.in", "axisbank.bank.in"}, "type": "bank"},
    "kotak": {"name": "Kotak Mahindra Bank", "domains": {"kotak.com", "kotak.bank.in", "kotakbank.bank.in"}, "type": "bank"},
    "pnb": {"name": "Punjab National Bank", "domains": {"pnbindia.in", "pnb.bank.in", "pnbindia.bank.in", "netpnb.com"}, "type": "bank"},
    "bankofbaroda": {"name": "Bank of Baroda", "domains": {"bankofbaroda.in", "bankofbaroda.com", "bankofbaroda.bank.in", "bobcard.co.in"}, "type": "bank"},
    "canara": {"name": "Canara Bank", "domains": {"canarabank.com", "canarabank.in", "canarabank.bank.in"}, "type": "bank"},
    "unionbank": {"name": "Union Bank of India", "domains": {"unionbankofindia.co.in", "unionbankofindia.bank.in"}, "type": "bank"},
    "idfc": {"name": "IDFC FIRST Bank", "domains": {"idfcfirstbank.com", "idfcfirst.bank.in", "idfcfirstbank.bank.in"}, "type": "bank"},
    "yesbank": {"name": "Yes Bank", "domains": {"yesbank.in", "yesbank.bank.in"}, "type": "bank"},
    "indusind": {"name": "IndusInd Bank", "domains": {"indusind.com", "indusind.bank.in"}, "type": "bank"},
    "federal": {"name": "Federal Bank", "domains": {"federalbank.co.in", "federalbank.bank.in"}, "type": "bank"},
    "bankofindia": {"name": "Bank of India", "domains": {"bankofindia.co.in", "bankofindia.bank.in"}, "type": "bank"},
    "indianbank": {"name": "Indian Bank", "domains": {"indianbank.in", "indianbank.bank.in"}, "type": "bank"},
    "paytm": {"name": "Paytm", "domains": {"paytm.com", "paytm.in", "paytmbank.com", "paytmpayments.com"}, "type": "fintech"},
    "phonepe": {"name": "PhonePe", "domains": {"phonepe.com"}, "type": "fintech"},
    "googlepay": {"name": "Google Pay", "domains": {"google.com", "pay.google.com", "gpay.app.goo.gl"}, "type": "fintech"},
    "bhim": {"name": "BHIM / NPCI", "domains": {"bhimupi.org.in", "npci.org.in"}, "type": "fintech"},
    "npci": {"name": "NPCI", "domains": {"npci.org.in", "bhimupi.org.in"}, "type": "fintech"},
    "rbi": {"name": "Reserve Bank of India", "domains": {"rbi.org.in"}, "type": "regulator"},
    "sebi": {"name": "SEBI", "domains": {"sebi.gov.in"}, "type": "regulator"},
    "uidai": {"name": "UIDAI (Aadhaar)", "domains": {"uidai.gov.in"}, "type": "government"},
    "aadhaar": {"name": "UIDAI (Aadhaar)", "domains": {"uidai.gov.in"}, "type": "government"},
    "incometax": {"name": "Income Tax Department", "domains": {"incometax.gov.in", "incometaxindia.gov.in"}, "type": "government"},
    "gst": {"name": "GST Network", "domains": {"gst.gov.in"}, "type": "government"},
    "epfo": {"name": "EPFO", "domains": {"epfindia.gov.in"}, "type": "government"},
    "parivahan": {"name": "Parivahan / e-Challan", "domains": {"parivahan.gov.in"}, "type": "government"},
    "echallan": {"name": "Parivahan e-Challan", "domains": {"parivahan.gov.in"}, "type": "government"},
    "indiapost": {"name": "India Post", "domains": {"indiapost.gov.in", "ippbonline.com"}, "type": "government"},
    "irctc": {"name": "IRCTC", "domains": {"irctc.co.in"}, "type": "government"},
    "lic": {"name": "LIC of India", "domains": {"licindia.in", "lic.co.in"}, "type": "insurer"},
    "fedex": {"name": "FedEx", "domains": {"fedex.com"}, "type": "courier"},
    "dhl": {"name": "DHL", "domains": {"dhl.com", "dhl.co.in"}, "type": "courier"},
    "bluedart": {"name": "Blue Dart", "domains": {"bluedart.com"}, "type": "courier"},
    "delhivery": {"name": "Delhivery", "domains": {"delhivery.com"}, "type": "courier"},
    "dtdc": {"name": "DTDC", "domains": {"dtdc.com", "dtdc.in"}, "type": "courier"},
    "amazon": {"name": "Amazon", "domains": {"amazon.in", "amazon.com", "amazonpay.in"}, "type": "ecommerce"},
    "flipkart": {"name": "Flipkart", "domains": {"flipkart.com"}, "type": "ecommerce"},
    "myntra": {"name": "Myntra", "domains": {"myntra.com"}, "type": "ecommerce"},
    "meesho": {"name": "Meesho", "domains": {"meesho.com"}, "type": "ecommerce"},
    "airtel": {"name": "Airtel", "domains": {"airtel.in", "airtel.com"}, "type": "telecom"},
    "jio": {"name": "Jio", "domains": {"jio.com"}, "type": "telecom"},
    "bsnl": {"name": "BSNL", "domains": {"bsnl.co.in", "bsnl.in"}, "type": "telecom"},
    "vodafone": {"name": "Vi (Vodafone Idea)", "domains": {"myvi.in"}, "type": "telecom"},
    "trai": {"name": "TRAI", "domains": {"trai.gov.in"}, "type": "regulator"},
    "kbc": {"name": "Kaun Banega Crorepati (Sony)", "domains": {"sonyliv.com", "setindia.com"}, "type": "media"},
    "zerodha": {"name": "Zerodha", "domains": {"zerodha.com"}, "type": "broker"},
    "groww": {"name": "Groww", "domains": {"groww.in"}, "type": "broker"},
    "upstox": {"name": "Upstox", "domains": {"upstox.com"}, "type": "broker"},
    "whatsapp": {"name": "WhatsApp", "domains": {"whatsapp.com", "wa.me"}, "type": "platform"},
    "pmkisan": {"name": "PM-KISAN", "domains": {"pmkisan.gov.in"}, "type": "government"},
    "cybercrime": {"name": "National Cyber Crime Reporting Portal", "domains": {"cybercrime.gov.in"}, "type": "government"},
}

# Tokens that, when found inside a domain, indicate the domain is *claiming* a
# brand. Short tokens are only matched as whole labels/hyphen-parts.
BRAND_TOKENS: dict[str, str] = {
    "sbi": "sbi", "onlinesbi": "sbi", "yono": "sbi", "statebank": "sbi",
    "hdfc": "hdfc", "icici": "icici", "axis": "axis", "axisbank": "axis", "kotak": "kotak",
    "pnb": "pnb", "bankofbaroda": "bankofbaroda", "bob": "bankofbaroda", "canara": "canara",
    "unionbank": "unionbank", "idfc": "idfc", "yesbank": "yesbank", "indusind": "indusind",
    "federal": "federal", "paytm": "paytm", "phonepe": "phonepe", "gpay": "googlepay", "googlepay": "googlepay",
    "bhim": "bhim", "npci": "npci", "rbi": "rbi", "reservebank": "rbi", "sebi": "sebi",
    "uidai": "uidai", "aadhaar": "aadhaar", "aadhar": "aadhaar", "incometax": "incometax", "itrefund": "incometax",
    "gst": "gst", "epfo": "epfo", "epf": "epfo", "parivahan": "parivahan", "echallan": "echallan",
    "challan": "echallan", "vahan": "parivahan", "indiapost": "indiapost", "irctc": "irctc", "lic": "lic",
    "fedex": "fedex", "dhl": "dhl", "bluedart": "bluedart", "delhivery": "delhivery", "dtdc": "dtdc",
    "amazon": "amazon", "flipkart": "flipkart", "myntra": "myntra", "meesho": "meesho",
    "airtel": "airtel", "jio": "jio", "bsnl": "bsnl", "trai": "trai", "kbc": "kbc",
    "zerodha": "zerodha", "groww": "groww", "upstox": "upstox", "pmkisan": "pmkisan", "kisan": "pmkisan",
    "cybercrime": "cybercrime",
}

SHORT_TOKEN_MAX = 4  # tokens of this length or shorter must match a whole label part

SUSPICIOUS_TLDS: dict[str, float] = {
    # High abuse-rate TLDs in phishing feeds; weights are risk contributions.
    "xyz": 0.3, "top": 0.3, "club": 0.2, "online": 0.25, "site": 0.25, "live": 0.2, "buzz": 0.3,
    "icu": 0.3, "shop": 0.2, "vip": 0.3, "work": 0.25, "click": 0.3, "link": 0.25, "rest": 0.3,
    "fit": 0.25, "cfd": 0.35, "sbs": 0.35, "monster": 0.3, "quest": 0.3, "cam": 0.3, "tk": 0.35,
    "ml": 0.35, "ga": 0.35, "cf": 0.35, "gq": 0.35, "zip": 0.35, "mov": 0.3, "lol": 0.3, "pw": 0.3,
    "cyou": 0.35, "bond": 0.3, "today": 0.2, "support": 0.2, "help": 0.2, "website": 0.2,
    "store": 0.15, "space": 0.2, "fun": 0.2, "life": 0.15, "world": 0.15, "ink": 0.2, "win": 0.3,
    "bid": 0.3, "loan": 0.3, "men": 0.3, "date": 0.3, "racing": 0.3, "download": 0.3, "stream": 0.25,
    "info": 0.1, "biz": 0.1, "cc": 0.15, "ws": 0.15, "su": 0.2,
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly",
    "ow.ly", "s.id", "v.gd", "tiny.cc", "bit.do", "shorte.st", "goo.gl", "t.co", "lnkd.in",
    "surl.li", "u.to", "clck.ru", "qr.ae", "short.gy", "tny.im", "bl.ink", "dub.sh", "linktr.ee",
    "i8.ae", "urlz.fr", "x.gd", "shrtco.de", "zws.im", "1url.com", "rb.gy", "tinu.be",
}

MESSAGING_LINK_HOSTS = {"t.me", "telegram.me", "wa.me", "chat.whatsapp.com", "api.whatsapp.com", "whatsapp.com"}

FREE_HOSTING_SUFFIXES = {
    "blogspot.com", "github.io", "web.app", "firebaseapp.com", "vercel.app", "netlify.app",
    "pages.dev", "glitch.me", "herokuapp.com", "wixsite.com", "weebly.com", "000webhostapp.com",
    "onrender.com", "repl.co", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "azurewebsites.net", "appspot.com", "sites.google.com", "forms.gle", "carrd.co", "godaddysites.com",
}

RISKY_PATH_WORDS = [
    "kyc", "update", "verify", "verification", "secure", "login", "signin", "reward", "refund", "bonus",
    "gift", "claim", "challan", "pay", "unblock", "block", "suspend", "otp", "aadhaar", "pan", "prize",
    "lottery", "win", "offer", "free", "redeem", "points", "account", "bank", "customs", "parcel",
]

# Known UPI PSP handles (suffix after @). Not exhaustive; unknown != fake.
UPI_HANDLES: dict[str, str] = {
    "okaxis": "Google Pay (Axis)", "okhdfcbank": "Google Pay (HDFC)", "okicici": "Google Pay (ICICI)",
    "oksbi": "Google Pay (SBI)", "ybl": "PhonePe (Yes Bank)", "ibl": "PhonePe (ICICI)", "axl": "PhonePe (Axis)",
    "paytm": "Paytm", "ptyes": "Paytm (Yes)", "ptaxis": "Paytm (Axis)", "pthdfc": "Paytm (HDFC)", "ptsbi": "Paytm (SBI)",
    "apl": "Amazon Pay", "yapl": "Amazon Pay", "rapl": "Amazon Pay", "upi": "BHIM", "icici": "ICICI Bank",
    "sbi": "SBI", "hdfcbank": "HDFC Bank", "axisbank": "Axis Bank", "kotak": "Kotak", "kmbl": "Kotak",
    "idfcbank": "IDFC FIRST", "idfcfirst": "IDFC FIRST", "yesbank": "Yes Bank", "yesbankltd": "Yes Bank",
    "pnb": "PNB", "barodampay": "Bank of Baroda", "cnrb": "Canara Bank", "unionbank": "Union Bank",
    "indus": "IndusInd", "federal": "Federal Bank", "fbl": "Federal Bank", "freecharge": "Freecharge",
    "jupiteraxis": "Jupiter", "airtel": "Airtel Payments Bank", "jio": "Jio Payments Bank", "postbank": "India Post Payments Bank",
    "waaxis": "WhatsApp Pay (Axis)", "wahdfcbank": "WhatsApp Pay (HDFC)", "waicici": "WhatsApp Pay (ICICI)",
    "wasbi": "WhatsApp Pay (SBI)", "mbk": "MobiKwik", "ikwik": "MobiKwik", "slc": "slice", "sliceaxis": "slice",
    "naviaxis": "Navi", "superyes": "super.money", "abfspay": "Aditya Birla", "dlb": "Dhanlaxmi Bank",
    "rbl": "RBL Bank", "aubank": "AU Bank", "equitas": "Equitas", "dbs": "DBS", "hsbc": "HSBC", "sc": "Standard Chartered",
    "citi": "Citi", "boi": "Bank of India", "centralbank": "Central Bank", "indianbank": "Indian Bank", "iob": "IOB",
    "uco": "UCO Bank", "kvb": "Karur Vysya", "tmb": "TMB", "kbl": "Karnataka Bank", "cub": "City Union Bank",
    "pingpay": "Samsung Pay", "timecosmos": "Cred", "axisb": "Cred (Axis)", "yescred": "Cred (Yes)", "pockets": "ICICI Pockets",
}

# Country calling codes. "risk" marks origins frequently reported in India-targeted scams
# (incl. South-East Asian scam compounds flagged by I4C / MEA advisories).
COUNTRY_CODES: dict[str, dict] = {
    "91": {"country": "India", "risk": 0.0},
    "92": {"country": "Pakistan", "risk": 0.45},
    "880": {"country": "Bangladesh", "risk": 0.25},
    "977": {"country": "Nepal", "risk": 0.2},
    "94": {"country": "Sri Lanka", "risk": 0.2},
    "84": {"country": "Vietnam", "risk": 0.4},
    "855": {"country": "Cambodia", "risk": 0.45},
    "856": {"country": "Laos", "risk": 0.45},
    "95": {"country": "Myanmar", "risk": 0.45},
    "66": {"country": "Thailand", "risk": 0.3},
    "62": {"country": "Indonesia", "risk": 0.35},
    "63": {"country": "Philippines", "risk": 0.3},
    "60": {"country": "Malaysia", "risk": 0.3},
    "65": {"country": "Singapore", "risk": 0.2},
    "86": {"country": "China", "risk": 0.3},
    "852": {"country": "Hong Kong", "risk": 0.3},
    "971": {"country": "UAE", "risk": 0.25},
    "966": {"country": "Saudi Arabia", "risk": 0.2},
    "974": {"country": "Qatar", "risk": 0.2},
    "968": {"country": "Oman", "risk": 0.2},
    "965": {"country": "Kuwait", "risk": 0.2},
    "973": {"country": "Bahrain", "risk": 0.2},
    "1": {"country": "USA/Canada", "risk": 0.25},
    "44": {"country": "United Kingdom", "risk": 0.25},
    "234": {"country": "Nigeria", "risk": 0.4},
    "254": {"country": "Kenya", "risk": 0.3},
    "27": {"country": "South Africa", "risk": 0.25},
    "7": {"country": "Russia/Kazakhstan", "risk": 0.3},
    "998": {"country": "Uzbekistan", "risk": 0.3},
    "61": {"country": "Australia", "risk": 0.2},
    "49": {"country": "Germany", "risk": 0.2},
    "33": {"country": "France", "risk": 0.2},
    "81": {"country": "Japan", "risk": 0.2},
    "82": {"country": "South Korea", "risk": 0.2},
}

# Minimal RDAP bootstrap for domain-age lookups (registration date).
RDAP_SERVERS: dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "in": "https://rdap.registry.in/",
    "xyz": "https://rdap.centralnic.com/xyz/",
    "online": "https://rdap.centralnic.com/online/",
    "site": "https://rdap.centralnic.com/site/",
    "store": "https://rdap.centralnic.com/store/",
    "website": "https://rdap.centralnic.com/website/",
    "space": "https://rdap.centralnic.com/space/",
    "fun": "https://rdap.centralnic.com/fun/",
    "top": "https://rdap.nic.top/",
    "live": "https://rdap.identitydigital.services/rdap/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "life": "https://rdap.identitydigital.services/rdap/",
    "world": "https://rdap.identitydigital.services/rdap/",
    "today": "https://rdap.identitydigital.services/rdap/",
    "support": "https://rdap.identitydigital.services/rdap/",
}
