"""Localised strings for offline mode (English, Hindi, Telugu).

With an LLM configured, Satark can answer in any of the 11 listed languages;
offline, it uses these hand-written strings and falls back to English.
"""

from __future__ import annotations

LANGUAGES = {
    "English": "en",
    "Hindi": "hi",
    "Telugu": "te",
    "Tamil": "ta",
    "Bengali": "bn",
    "Marathi": "mr",
    "Kannada": "kn",
    "Malayalam": "ml",
    "Gujarati": "gu",
    "Odia": "or",
    "Punjabi": "pa",
}
OFFLINE_LANGS = {"en", "hi", "te"}
LANG_NAMES = {v: k for k, v in LANGUAGES.items()}


def lang_code(value: str | None) -> str:
    if not value:
        return "en"
    v = value.strip()
    if v in LANGUAGES:
        return LANGUAGES[v]
    low = v.lower()
    for name, code in LANGUAGES.items():
        if low.startswith(name.lower()) or low == code:
            return code
    # Accept native-script labels such as "हिन्दी (Hindi)"
    for name, code in LANGUAGES.items():
        if name.lower() in low:
            return code
    return "en"


ACTIONS: dict[str, dict[str, str]] = {
    "call_1930": {
        "en": "Call 1930 (National Cyber Crime Helpline) right now and give them the transaction details.",
        "hi": "अभी 1930 (राष्ट्रीय साइबर क्राइम हेल्पलाइन) पर कॉल करें और लेन-देन का पूरा विवरण बताएं।",
        "te": "వెంటనే 1930 (జాతీయ సైబర్ క్రైమ్ హెల్ప్‌లైన్) కు కాల్ చేసి, లావాదేవీ వివరాలు చెప్పండి.",
    },
    "file_ncrp": {
        "en": "File a complaint on cybercrime.gov.in ('Report Cyber Crime') and save the acknowledgement number.",
        "hi": "cybercrime.gov.in पर शिकायत दर्ज करें ('Report Cyber Crime') और पावती संख्या सहेज लें।",
        "te": "cybercrime.gov.in లో ('Report Cyber Crime') ఫిర్యాదు చేసి, అక్నాలెడ్జ్‌మెంట్ నంబర్‌ను భద్రపరచుకోండి.",
    },
    "call_bank_block": {
        "en": "Call your bank on the number printed on your card or in its official app: block the card/UPI/net-banking and report the fraud.",
        "hi": "कार्ड पर छपे नंबर या बैंक के आधिकारिक ऐप से बैंक को कॉल करें: कार्ड/UPI/नेट-बैंकिंग ब्लॉक करवाएं और धोखाधड़ी की सूचना दें।",
        "te": "మీ కార్డ్‌పై ఉన్న నంబర్ లేదా బ్యాంక్ అధికారిక యాప్ ద్వారా బ్యాంక్‌కు కాల్ చేయండి: కార్డ్/UPI/నెట్-బ్యాంకింగ్ బ్లాక్ చేయించి, మోసం గురించి తెలియజేయండి.",
    },
    "stop_contact": {
        "en": "Stop all contact. Do not reply, click links, call back, or pay anything.",
        "hi": "सारा संपर्क बंद करें। जवाब न दें, लिंक न खोलें, वापस कॉल न करें और कोई भुगतान न करें।",
        "te": "అన్ని సంబంధాలు ఆపేయండి. జవాబు ఇవ్వవద్దు, లింక్‌లు తెరవవద్దు, తిరిగి కాల్ చేయవద్దు, ఏమీ చెల్లించవద్దు.",
    },
    "never_share_otp": {
        "en": "Never share OTP, UPI PIN, CVV or passwords — no genuine bank or officer will ask for them.",
        "hi": "OTP, UPI पिन, CVV या पासवर्ड कभी किसी को न बताएं — कोई असली बैंक या अधिकारी इन्हें नहीं मांगता।",
        "te": "OTP, UPI పిన్, CVV లేదా పాస్‌వర్డ్‌లను ఎవరికీ చెప్పవద్దు — ఏ నిజమైన బ్యాంక్ లేదా అధికారి వీటిని అడగరు.",
    },
    "disconnect_call": {
        "en": "Disconnect the call now. Real police or CBI never keep anyone on a video call or 'digitally arrest' them.",
        "hi": "अभी कॉल काट दें। असली पुलिस या सीबीआई किसी को वीडियो कॉल पर रोककर 'डिजिटल अरेस्ट' नहीं करती।",
        "te": "ఇప్పుడే కాల్ కట్ చేయండి. నిజమైన పోలీసులు లేదా సీబీఐ ఎవరినీ వీడియో కాల్‌లో ఉంచి 'డిజిటల్ అరెస్ట్' చేయరు.",
    },
    "report_chakshu": {
        "en": "Report the number/message on Sanchar Saathi → Chakshu (sancharsaathi.gov.in) so it can be blocked.",
        "hi": "नंबर/संदेश की शिकायत संचार साथी → चक्षु (sancharsaathi.gov.in) पर करें ताकि उसे ब्लॉक किया जा सके।",
        "te": "నంబర్/సందేశాన్ని సంచార్ సాథీ → చక్షు (sancharsaathi.gov.in) లో రిపోర్ట్ చేయండి, తద్వారా దాన్ని బ్లాక్ చేయవచ్చు.",
    },
    "check_suspect": {
        "en": "Check the phone number, UPI ID or link on cybercrime.gov.in → 'Report & Check Suspect'.",
        "hi": "फ़ोन नंबर, UPI ID या लिंक की जांच cybercrime.gov.in → 'Report & Check Suspect' पर करें।",
        "te": "ఫోన్ నంబర్, UPI ID లేదా లింక్‌ను cybercrime.gov.in → 'Report & Check Suspect' లో తనిఖీ చేయండి.",
    },
    "preserve_evidence": {
        "en": "Save evidence: screenshots of chats, caller numbers, UPI/transaction IDs and bank SMS. Don't delete anything.",
        "hi": "सबूत संभालें: चैट के स्क्रीनशॉट, कॉल करने वाले नंबर, UPI/ट्रांज़ैक्शन ID और बैंक SMS। कुछ भी डिलीट न करें।",
        "te": "సాక్ష్యాలు భద్రపరచండి: చాట్ స్క్రీన్‌షాట్‌లు, కాల్ చేసిన నంబర్లు, UPI/లావాదేవీ IDలు, బ్యాంక్ SMSలు. ఏదీ డిలీట్ చేయవద్దు.",
    },
    "uninstall_app": {
        "en": "If you installed any app or screen-sharing tool they sent: switch on airplane mode, uninstall it, and change banking passwords from another device.",
        "hi": "अगर आपने उनका भेजा कोई ऐप या स्क्रीन-शेयरिंग टूल इंस्टॉल किया है: एयरप्लेन मोड चालू करें, उसे हटाएं और किसी दूसरे डिवाइस से बैंकिंग पासवर्ड बदलें।",
        "te": "వారు పంపిన ఏదైనా యాప్ లేదా స్క్రీన్-షేరింగ్ టూల్ ఇన్‌స్టాల్ చేసి ఉంటే: ఎయిర్‌ప్లేన్ మోడ్ ఆన్ చేసి, దాన్ని తొలగించి, వేరే పరికరం నుండి బ్యాంకింగ్ పాస్‌వర్డ్‌లు మార్చండి.",
    },
    "verify_official": {
        "en": "Verify only through the official app or website you already use — never via links or numbers given in the message.",
        "hi": "केवल उसी आधिकारिक ऐप या वेबसाइट से जांच करें जिसे आप पहले से इस्तेमाल करते हैं — संदेश में दिए लिंक या नंबर से कभी नहीं।",
        "te": "మీరు ఇప్పటికే వాడుతున్న అధికారిక యాప్ లేదా వెబ్‌సైట్ ద్వారానే తనిఖీ చేయండి — సందేశంలోని లింక్‌లు లేదా నంబర్ల ద్వారా ఎప్పుడూ కాదు.",
    },
    "call_relative_back": {
        "en": "Hang up and call your family member back on their known number before doing anything.",
        "hi": "कुछ भी करने से पहले फ़ोन काटें और परिवार के सदस्य को उनके जाने-पहचाने नंबर पर वापस कॉल करें।",
        "te": "ఏదైనా చేసే ముందు కాల్ కట్ చేసి, మీ కుటుంబ సభ్యుడికి వారి తెలిసిన నంబర్‌కు తిరిగి కాల్ చేయండి.",
    },
    "warn_family": {
        "en": "Warn your family — especially elders — using the ready-made alert below.",
        "hi": "नीचे दिए तैयार संदेश से अपने परिवार — खासकर बुज़ुर्गों — को सावधान करें।",
        "te": "క్రింద ఉన్న సిద్ధమైన సందేశంతో మీ కుటుంబాన్ని — ముఖ్యంగా పెద్దలను — హెచ్చరించండి.",
    },
    "bank_written_complaint": {
        "en": "Send the written dispute letter below to your bank (email or branch) and keep the complaint reference number.",
        "hi": "नीचे दिया लिखित शिकायत-पत्र बैंक को (ईमेल या शाखा) भेजें और शिकायत संदर्भ संख्या रखें।",
        "te": "క్రింద ఉన్న లిఖిత ఫిర్యాదు లేఖను మీ బ్యాంక్‌కు (ఈమెయిల్ లేదా శాఖ) పంపి, ఫిర్యాదు రిఫరెన్స్ నంబర్‌ను ఉంచుకోండి.",
    },
    "escalate_ombudsman": {
        "en": "If the bank doesn't resolve it within 30 days, escalate to the RBI Ombudsman at cms.rbi.org.in (helpline 14448).",
        "hi": "अगर बैंक 30 दिनों में समाधान न करे, तो cms.rbi.org.in पर RBI लोकपाल से शिकायत करें (हेल्पलाइन 14448)।",
        "te": "బ్యాంక్ 30 రోజుల్లో పరిష్కరించకపోతే, cms.rbi.org.in లో ఆర్‌బీఐ అంబుడ్స్‌మన్‌కు ఫిర్యాదు చేయండి (హెల్ప్‌లైన్ 14448).",
    },
    "file_fir": {
        "en": "File an FIR at the nearest (cyber) police station, quoting your NCRP acknowledgement number.",
        "hi": "अपनी NCRP पावती संख्या के साथ नज़दीकी (साइबर) पुलिस स्टेशन में FIR दर्ज कराएं।",
        "te": "మీ NCRP అక్నాలెడ్జ్‌మెంట్ నంబర్‌తో సమీపంలోని (సైబర్) పోలీస్ స్టేషన్‌లో FIR నమోదు చేయించండి.",
    },
    "ezero_fir": {
        "en": "Loss above ₹10 lakh: in Delhi your NCRP/1930 complaint is auto-converted to an e-Zero FIR — visit the police station within 3 days to make it a regular FIR.",
        "hi": "₹10 लाख से अधिक का नुकसान: दिल्ली में आपकी NCRP/1930 शिकायत अपने-आप e-Zero FIR बन जाती है — 3 दिनों के भीतर पुलिस स्टेशन जाकर उसे नियमित FIR में बदलवाएं।",
        "te": "₹10 లక్షలకు పైగా నష్టం: ఢిల్లీలో మీ NCRP/1930 ఫిర్యాదు ఆటోమేటిక్‌గా e-Zero FIR గా మారుతుంది — 3 రోజుల్లో పోలీస్ స్టేషన్‌కు వెళ్లి దాన్ని సాధారణ FIR గా మార్చించండి.",
    },
    "do_not_pay_sextortion": {
        "en": "Do not pay or negotiate. Block the account, report the profile on the platform, and file a complaint on cybercrime.gov.in.",
        "hi": "पैसे न दें और बातचीत न करें। अकाउंट ब्लॉक करें, प्लेटफ़ॉर्म पर प्रोफ़ाइल रिपोर्ट करें और cybercrime.gov.in पर शिकायत करें।",
        "te": "డబ్బు చెల్లించవద్దు, చర్చలు జరపవద్దు. ఖాతాను బ్లాక్ చేసి, ప్లాట్‌ఫామ్‌లో ప్రొఫైల్‌ను రిపోర్ట్ చేసి, cybercrime.gov.in లో ఫిర్యాదు చేయండి.",
    },
    "stop_mule": {
        "en": "Never let anyone use your bank account, UPI or SIM. If you already did, inform your bank and the police immediately — it protects you legally.",
        "hi": "किसी को भी अपना बैंक खाता, UPI या सिम इस्तेमाल न करने दें। अगर पहले ही दे दिया है, तो तुरंत बैंक और पुलिस को बताएं — इससे आप कानूनी रूप से सुरक्षित रहेंगे।",
        "te": "మీ బ్యాంక్ ఖాతా, UPI లేదా సిమ్‌ను ఎవరినీ వాడనివ్వవద్దు. ఇప్పటికే ఇచ్చి ఉంటే, వెంటనే బ్యాంక్‌కు మరియు పోలీసులకు తెలియజేయండి — ఇది మిమ్మల్ని చట్టపరంగా కాపాడుతుంది.",
    },
    "verify_sebi": {
        "en": "Verify any adviser or platform on sebi.gov.in before investing, and never pay 'fees' or 'tax' to withdraw profits.",
        "hi": "निवेश से पहले किसी भी सलाहकार या प्लेटफ़ॉर्म की जांच sebi.gov.in पर करें, और मुनाफ़ा निकालने के लिए कभी 'फ़ीस' या 'टैक्स' न दें।",
        "te": "పెట్టుబడి పెట్టే ముందు ఏ సలహాదారు లేదా ప్లాట్‌ఫామ్‌నైనా sebi.gov.in లో తనిఖీ చేయండి; లాభాలు విత్‌డ్రా చేయడానికి 'ఫీజు' లేదా 'ట్యాక్స్' ఎప్పుడూ చెల్లించవద్దు.",
    },
    "no_action_needed": {
        "en": "No scam signals found. Still, verify through official channels before paying or sharing any details.",
        "hi": "कोई धोखाधड़ी संकेत नहीं मिला। फिर भी भुगतान करने या कोई जानकारी देने से पहले आधिकारिक माध्यम से जांच लें।",
        "te": "మోసం సంకేతాలు ఏవీ కనిపించలేదు. అయినా చెల్లించే ముందు లేదా వివరాలు ఇచ్చే ముందు అధికారిక మార్గాల్లో తనిఖీ చేయండి.",
    },
    "request_chargeback": {
        "en": "For card transactions, ask the bank to raise a chargeback dispute and to hot-list (block) the card.",
        "hi": "कार्ड लेन-देन के लिए बैंक से चार्जबैक विवाद दर्ज करने और कार्ड को हॉट-लिस्ट (ब्लॉक) करने को कहें।",
        "te": "కార్డ్ లావాదేవీల కోసం, ఛార్జ్‌బ్యాక్ వివాదం నమోదు చేసి, కార్డ్‌ను హాట్-లిస్ట్ (బ్లాక్) చేయమని బ్యాంక్‌ను అడగండి.",
    },
    "upi_app_dispute": {
        "en": "Also raise a dispute inside your UPI app (Help → Report a problem / Raise dispute) for the transaction.",
        "hi": "उस लेन-देन के लिए अपने UPI ऐप में भी शिकायत दर्ज करें (Help → Report a problem / Raise dispute)।",
        "te": "ఆ లావాదేవీ కోసం మీ UPI యాప్‌లో కూడా వివాదం నమోదు చేయండి (Help → Report a problem / Raise dispute).",
    },
}

HEADLINES = {
    "SCAM": {
        "en": "This is very likely a SCAM.",
        "hi": "यह लगभग निश्चित रूप से एक धोखाधड़ी (स्कैम) है।",
        "te": "ఇది దాదాపు ఖచ్చితంగా మోసం (స్కామ్).",
    },
    "HIGH": {
        "en": "High risk — treat this as a scam until verified.",
        "hi": "उच्च जोखिम — जांच होने तक इसे धोखाधड़ी ही मानें।",
        "te": "అధిక ప్రమాదం — నిర్ధారణ అయ్యే వరకు దీన్ని మోసంగానే భావించండి.",
    },
    "SUSPICIOUS": {
        "en": "Suspicious — verify through official channels before acting.",
        "hi": "संदिग्ध — कुछ भी करने से पहले आधिकारिक माध्यम से जांच करें।",
        "te": "అనుమానాస్పదం — ఏదైనా చేసే ముందు అధికారిక మార్గాల్లో తనిఖీ చేయండి.",
    },
    "SAFE": {
        "en": "No scam signals found — this looks legitimate.",
        "hi": "कोई धोखाधड़ी संकेत नहीं मिला — यह असली लगता है।",
        "te": "మోసం సంకేతాలు కనిపించలేదు — ఇది నిజమైనదిగా అనిపిస్తోంది.",
    },
}

GOLDEN = {
    "golden": {
        "en": "You are still inside the golden hour — every minute matters. Call 1930 now.",
        "hi": "आप अभी 'गोल्डन आवर' के भीतर हैं — हर मिनट कीमती है। अभी 1930 पर कॉल करें।",
        "te": "మీరు ఇంకా 'గోల్డెన్ అవర్' లోపలే ఉన్నారు — ప్రతి నిమిషం విలువైనది. ఇప్పుడే 1930 కు కాల్ చేయండి.",
    },
    "urgent": {
        "en": "The golden hour has passed, but reporting today can still freeze money that hasn't moved yet. Call 1930 now.",
        "hi": "गोल्डन आवर निकल गया है, लेकिन आज शिकायत करने से वह पैसा अब भी फ़्रीज़ हो सकता है जो आगे नहीं गया। अभी 1930 पर कॉल करें।",
        "te": "గోల్డెన్ అవర్ దాటిపోయింది, కానీ ఈ రోజే ఫిర్యాదు చేస్తే ఇంకా ముందుకు వెళ్లని డబ్బును ఫ్రీజ్ చేయవచ్చు. ఇప్పుడే 1930 కు కాల్ చేయండి.",
    },
    "late": {
        "en": "Some time has passed — still report it today. Complaints help trace mule accounts and support any refund claim.",
        "hi": "कुछ समय बीत चुका है — फिर भी आज ही शिकायत करें। शिकायत से म्यूल खातों का पता चलता है और रिफंड दावे में मदद मिलती है।",
        "te": "కొంత సమయం గడిచిపోయింది — అయినా ఈ రోజే ఫిర్యాదు చేయండి. ఫిర్యాదులు మ్యూల్ ఖాతాలను గుర్తించడానికి, రీఫండ్ క్లెయిమ్‌కు సహాయపడతాయి.",
    },
}

FAMILY_ALERT = {
    "en": "⚠ Scam alert: I just received a \"{typology}\" {channel}. It is a FRAUD. {truth} Never share OTP or UPI PIN, never open such links, and never pay. If anyone loses money, call 1930 immediately or report on cybercrime.gov.in.",
    "hi": "⚠ सावधान: मुझे अभी एक \"{typology}\" वाला {channel} मिला। यह धोखाधड़ी है। {truth} OTP या UPI पिन कभी न बताएं, ऐसे लिंक न खोलें और कोई भुगतान न करें। अगर किसी के पैसे कट जाएं तो तुरंत 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत करें।",
    "te": "⚠ జాగ్రత్త: నాకు ఇప్పుడే \"{typology}\" అనే {channel} వచ్చింది. ఇది మోసం. {truth} OTP లేదా UPI పిన్ ఎవరికీ చెప్పవద్దు, అలాంటి లింక్‌లు తెరవవద్దు, ఏమీ చెల్లించవద్దు. ఎవరైనా డబ్బు పోగొట్టుకుంటే వెంటనే 1930 కు కాల్ చేయండి లేదా cybercrime.gov.in లో ఫిర్యాదు చేయండి.",
}

CHANNEL_WORDS = {
    "call": {"en": "phone call", "hi": "फ़ोन कॉल", "te": "ఫోన్ కాల్"},
    "video_call": {"en": "video call", "hi": "वीडियो कॉल", "te": "వీడియో కాల్"},
    "whatsapp": {"en": "WhatsApp message", "hi": "WhatsApp संदेश", "te": "WhatsApp సందేశం"},
    "sms": {"en": "SMS", "hi": "SMS", "te": "SMS"},
    "email": {"en": "email", "hi": "ईमेल", "te": "ఈమెయిల్"},
    "telegram": {"en": "Telegram message", "hi": "Telegram संदेश", "te": "Telegram సందేశం"},
    "social": {"en": "social-media message", "hi": "सोशल मीडिया संदेश", "te": "సోషల్ మీడియా సందేశం"},
    "message": {"en": "message", "hi": "संदेश", "te": "సందేశం"},
}


def t(table: dict[str, str], lang: str) -> str:
    """Pick a localised string, falling back to English."""
    return table.get(lang) or table.get("en", "")
