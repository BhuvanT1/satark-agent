"""Behavioural red-flag detection (English, Hinglish, Hindi, Telugu).

Each signal = a social-engineering tactic or scam ingredient. Detection is
sentence-aware so that warnings like "Do not share your OTP" are recognised as
*legitimate* advice rather than an OTP request.
"""

from __future__ import annotations

import re

# --- Pattern tables -------------------------------------------------------
# English/Hinglish patterns are regexes (word-bounded). Indic-script patterns
# are plain substrings (word boundaries are unreliable with combining marks).

P: dict[str, dict[str, list[str]]] = {
    "otp_request": {
        "re": [
            r"\b(share|send|tell|give|forward|provide|read out|enter|type|confirm)\b[^.\n]{0,25}\b(otp|one[- ]time password|verification code|upi pin|mpin|atm pin|cvv|card pin|password)\b",
            r"\b(otp|upi pin|mpin|cvv|pin)\b[^.\n]{0,20}\b(share|send|tell|forward|batao|bata do|bhejo|bhej do|de do|dijiye|batayein|bataiye)\b",
            r"\b(what is|whats|what's)\b[^.\n]{0,15}\b(the |your )?(otp|pin|cvv)\b",
            r"\botp\b[^.\n]{0,10}\b(aaya|aya hoga|received)\b[^.\n]{0,20}\b(batao|bata|share|tell)\b",
            r"(?i)\b(otp|pin|cvv)\s*(చెప్ప|పంప|ఇవ్వ|बत|भेज|शेयर|सांगा|पाठवा|বল|পাঠা|சொல்|அனுப்ப|ಹೇಳ|ಕಳುಹಿಸ|જણાવ|મોકલ|പറയ|അയക്ക)",
            r"\b(otp|upi pin|mpin|cvv|password)\b[^.\n]{0,15}\b(is |are )?(required|needed|mandatory|necessary)\b",
            r"\breply (back )?with (the |your |that )?(otp|code|pin)\b",
        ],
        "sub": ["ओटीपी बत", "ओटीपी भेज", "ओटीपी शेयर", "ओटीपी दे", "पिन बत", "ఓటీపీ చెప్ప", "ఓటీపీ పంప", "ఓటిపి చెప్ప", "ఓటీపీ ఇవ్వ", "ওটিপি বল", "ওটিপি পাঠা", "ওটিপি শেয়ার", "ஓடிபி சொல்", "ஓடிபி அனுப்ப", "ஓடிபி பகிர", "ओटीपी सांगा", "ओटीपी पाठवा", "ಒಟಿಪಿ ಹೇಳ", "ಒಟಿಪಿ ಕಳುಹಿಸ", "ઓટીપી જણાવ", "ઓટીપી મોકલ", "ഒടിപി പറയ", "ഒടിപി അയക്ക"],
    },
    "pin_to_receive": {
        "re": [
            r"\b(enter|put|type)\b[^.\n]{0,20}\b(upi )?pin\b[^.\n]{0,40}\b(receive|get|credit|claim|accept|refund)",
            r"\b(scan|scanning)\b[^.\n]{0,30}\b(qr|q\.r\.|code)\b[^.\n]{0,40}\b(receive|get|credit|claim|refund|payment will (come|be credited))",
            r"\b(receive|get|claim)\b[^.\n]{0,30}\b(money|payment|amount|refund)\b[^.\n]{0,30}\b(scan|enter (your )?(upi )?pin)\b",
            r"\bapprove (the )?(collect )?request\b[^.\n]{0,30}\b(receive|get|refund)",
            r"\bpaise (lene|receive karne|paane) ke liye\b",
        ],
        "sub": ["पैसे प्राप्त करने के लिए", "पैसे पाने के लिए", "డబ్బు పొందడానికి", "డబ్బు రావడానికి"],
    },
    "remote_access": {
        "re": [
            r"\b(any ?desk|team ?viewer|quick ?support|rust ?desk|airdroid|ammyy|ultra ?viewer|zoho assist|screen ?share|screen ?sharing|share (your )?screen|remote (access|control|app))\b",
        ],
        "sub": ["स्क्रीन शेयर", "ఎనీడెస్క్", "స్క్రీన్ షేర్"],
    },
    "apk_install": {
        "re": [
            r"\.apk\b",
            r"\bapk\b",
            r"\b(install|download)\b[^.\n]{0,30}\b(this|the|attached|below|our|given)\b[^.\n]{0,20}\b(app|application|file|software)\b",
        ],
        "sub": ["ऐप डाउनलोड कर", "ऐप इंस्टॉल", "యాప్ డౌన్‌లోడ్", "యాప్ ఇన్‌స్టాల్"],
    },
    "kyc_threat": {
        "re": [
            r"\b(kyc|e-?kyc|re-?kyc)\b[^.\n]{0,40}\b(update|expired?|expiry|pending|incomplete|suspen\w*|block\w*|not (done|updated|completed))\b",
            r"\b(update|complete|verify|link)\b[^.\n]{0,12}\b(your|the|ur)\b[^.\n]{0,10}\b(kyc|pan|aadhaar|aadhar)\b",
            r"\b(account|a/c|acct|card|wallet|paytm|yono|net ?banking|bank account)\b[^.\n]{0,40}\b(will be |has been |is |be |got )?(blocked|suspended|deactivated|freezed|frozen|closed|disabled|locked|blocked today)\b",
            r"\b(pan|aadhaar|aadhar)\b[^.\n]{0,30}\b(not (linked|updated)|expired|expir\w+|deactivat\w*|suspen\w*|block\w*|pending)\b",
            r"\b(account|khata|khaata)\b[^.\n]{0,20}\b(band|block)\b[^.\n]{0,15}\b(ho jayega|hoga|kar diya|ho jaega)\b",
        ],
        "sub": ["केवाईसी", "खाता बंद", "खाता ब्लॉक", "अकाउंट बंद", "अकाउंट ब्लॉक", "కేవైసీ", "ఖాతా బ్లాక్", "అకౌంట్ బ్లాక్", "ఖాతా నిలిపి", "ఖాతా మూసివే", "কেওয়াইসি", "অ্যাকাউন্ট বন্ধ", "অ্যাকাউন্ট ব্লক", "একাউন্ট বন্ধ", "கேஒய்சி", "கணக்கு முடக்க", "கணக்கு மூட", "கணக்கு தடை", "खाते बंद", "खाते ब्लॉक", "ಕೆವೈಸಿ", "ಖಾತೆ ಬ್ಲಾಕ್", "ಖಾತೆ ಸ್ಥಗಿತ", "કેવાયસી", "ખાતું બંધ", "കെവൈസി", "അക്കൗണ്ട് ബ്ലോക്ക്"],
    },
    "authority_impersonation": {
        "re": [
            r"\b(cbi|c\.b\.i\.?|enforcement directorate|ed officer|narcotics|ncb|customs (officer|department|dept|official)|cyber ?(crime|cell)( (department|branch|police|officer))?|crime branch|police (officer|station|department|inspector|commissioner)|mumbai police|delhi police|ips officer|dcp|inspector|trai|department of telecom(munications)?|rbi officer|reserve bank (officer|official)|income tax (officer|department)|supreme court|high court|court notice|arrest warrant|warrant against|fir (has been |is )?(registered|lodged|filed) against|interpol|nia officer|judge)\b",
            r"\b(police wale|giraftar|giraftari)\b",
        ],
        "sub": ["सीबीआई", "पुलिस", "क्राइम ब्रांच", "कस्टम अधिकारी", "नारकोटिक्स", "गिरफ्तारी", "वारंट", "पोलिस", "పోలీస", "పోలీసు", "సీబీఐ", "కస్టమ్స్ అధికారి", "అరెస్ట్ వారెంట్", "ఎఫ్ఐఆర్", "సైబర్ క్రైమ్", "পুলিশ", "সিবিআই", "কাস্টমস", "காவல்துறை", "போலீஸ்", "சிபிஐ", "சுங்க", "पोलीस", "सीबीआय", "ಪೊಲೀಸ್", "ಸಿಬಿಐ", "પોલીસ", "പോലീസ്"],
    },
    "digital_arrest": {
        "re": [
            r"\bdigital(ly)?[- ]arrest(ed)?\b",
            r"\b(video|skype|whatsapp) (call )?(verification|interrogation|statement|enquiry|inquiry|investigation|hearing)\b",
            r"\b(stay|remain|be|keep) on (the )?(video )?call\b",
            r"\b(do not|don't|dont)\b[^.\n]{0,10}\b(disconnect|cut|end) (the )?call\b",
            r"\bmoney[- ]laundering\b",
            r"\b(your )?(aadhaar|aadhar|sim|mobile number|number|bank account|account|pan)\b[^.\n]{0,50}\b(used|involved|linked|misused|found)\b[^.\n]{0,50}\b(crime|laundering|drugs|trafficking|terror\w*|illegal|scam|case|smuggling)\b",
            r"\b(drugs?|mdma|ganja|cocaine|heroin)\b[^.\n]{0,40}\b(parcel|package|courier|consignment)\b",
            r"\b(parcel|package|courier|consignment)\b[^.\n]{0,50}\b(drugs?|mdma|illegal (items|goods)|contraband|fake passports?|passports)\b",
            r"\bsafe (account|custody)\b",
            r"\b(rbi|government|secret|supervision|escrow)[- ](verified |safe |secure )?account\b",
            r"\bverification (amount|deposit|transfer|fund)\b",
            r"\bhouse arrest\b",
            r"\bunder (surveillance|investigation|digital custody)\b",
            r"\bnon[- ]bailable\b",
            r"\bvideo call (pe|par) (raho|rahiye|rahna)\b",
            r"\b(inquiry|enquiry|investigation|interrogation|questioning|statement|verification)\b[^.\n]{0,30}\b(on|over|via)\s+(a\s+)?(camera|cam|video|skype|whatsapp)\b",
            r"\b(on|over) (the )?camera\b[^.\n]{0,30}\b(inquiry|enquiry|investigation|until|statement)\b",
            r"\b(package|parcel|consignment|courier|shipment)\b[^.\n]{0,40}\b(intercepted|seized|confiscated|held by (customs|police))\b",
            r"\bcooperate (with|in) (the |our )?(inquiry|enquiry|investigation|verification)\b",
            r"\bcall (mat|na) (katna|kaatna|kaatiye)\b",
        ],
        "sub": ["डिजिटल अरेस्ट", "डिजिटल गिरफ्तारी", "मनी लॉन्ड्रिंग", "वीडियो कॉल पर रह", "కాల్ కట్ చేయవద్దు", "డిజిటల్ అరెస్ట్", "మనీ లాండరింగ్", "ডিজিটাল অ্যারেস্ট", "মানি লন্ডারিং", "டிஜிட்டல் கைது", "பணமோசடி", "डिजिटल अटक", "ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್"],
    },
    "secrecy": {
        "re": [
            r"\b(don't|do not|dont|never|not to|must not|should not|not)\b[^.\n]{0,15}\b(tell|inform|share (this )?with|disclose (this )?to|discuss (this )?with|talk to)\b[^.\n]{0,25}\b(anyone|anybody|family|relatives|friends|bank|police|husband|wife|parents|children|son|daughter|others)\b",
            r"\b(keep (this|it) (secret|confidential)|strictly confidential|national secret|secrecy|confidential (matter|investigation|case))\b",
            r"\bkisi (ko|se) (mat|na|nahi) (batana|batayen|bataiye|bolna|batao)\b",
            r"\bghar (walon|waalon|par) ko (mat|na)\b",
        ],
        "sub": ["किसी को मत बता", "किसी को न बता", "किसी को भी न", "गोपनीय", "ఎవరికీ చెప్పవద్దు", "ఎవరికి చెప్పకండి", "ఎవరికీ చెప్పకండి", "రహస్యం", "কাউকে বলবেন না", "কাউকে জানাবেন না", "யாரிடமும் சொல்ல வேண்டாம்", "யாரிடமும் கூற வேண்டாம்", "कोणालाही सांगू नका", "ಯಾರಿಗೂ ಹೇಳಬೇಡಿ"],
    },
    "urgency": {
        "re": [
            r"\b(immediately|urgent(ly)?|right now|asap|within (\d+|one|two|24|48) ?(hours?|hrs?|minutes?|mins?)|today (itself|only)|before (midnight|tonight)|tonight|last (chance|warning|reminder|date|day)|expires? (today|tonight|soon|in)|final (notice|warning|reminder)|act now|hurry|at the earliest)\b",
            r"\b(turant|jaldi|abhi ke abhi|aaj raat)\b",
        ],
        "sub": ["तुरंत", "आज रात", "अंतिम चेतावनी", "जल्दी", "వెంటనే", "ఈ రోజు రాత్రి", "చివరి హెచ్చరిక", "త్వరగా", "এখনই", "অবিলম্বে", "আজই", "உடனே", "உடனடியாக", "இன்றே", "ताबडतोब", "लगेच", "ತಕ್ಷಣ", "ಈಗಲೇ", "તાત્કાલિક", "ഉടൻ"],
    },
    "payment_request": {
        "re": [
            r"\b(pay|transfer|send|deposit|remit)\b[^.\n]{0,30}(\brs\b\.?|₹|\binr\b|rupees|\bamount\b|\bmoney\b|\bfees?\b|\bcharges?\b|\bpayment\b)",
            r"\b(processing|registration|security|verification|clearance|customs|delivery|activation|unlock|withdrawal|release|gst|tax|insurance|handling|legal|settlement|refundable|penalty|fine)\s+(fee|fees|charges?|amount|deposit)\b",
            r"(\brs\b\.?|₹|\binr\b)\s?[\d,]+(\.\d+)?\s?(/-)?\s?(only)?[^.\n]{0,30}\b(pay|transfer|send|deposit)\b",
            r"\bpaise (bhejo|bhej do|transfer karo|transfer kijiye|jama karo|dalo|daaliye)\b",
            r"\b(fees?|charge|amount) (bharo|bhar do|jama karo|pay karo)\b",
            r"\b[\d,]+\s*(rs|rupaye|rupees|rupay)?\s*(bhej do|bhejo|bhej dijiye|transfer kar do|transfer karo|daal do)\b",
            r"\b(bhej do|bhejo|bhej dijiye|transfer kar do|transfer karo)\b[^.\n]{0,30}\b(upi|account|number|pe|par|gpay|phonepe|paytm)\b",
        ],
        "sub": ["पैसे भेज", "भुगतान कर", "शुल्क जमा", "रुपये ट्रांसफर", "पेमेंट कर", "డబ్బు పంప", "చెల్లించండి", "ఫీజు చెల్లించ", "జమ చేయండి", "ట్రాన్స్‌ఫర్ చేయండి", "ట్రాన్స్ఫర్ చేయండి", "টাকা পাঠান", "ফি পাঠান", "প্রসেসিং ফি", "পেমেন্ট করুন", "জমা দিন", "பணம் அனுப்ப", "கட்டணம் செலுத்த", "செலுத்துங்கள்", "पैसे पाठवा", "शुल्क भरा", "पेमेंट करा", "ಹಣ ಕಳುಹಿಸಿ", "ಶುಲ್ಕ ಪಾವತಿಸಿ", "ಪಾವತಿಸಿ", "પૈસા મોકલો", "ફી ભરો", "പണം അയക്ക"],
    },
    "reward_lure": {
        "re": [
            r"\b(you (have )?won|you are (the )?(lucky )?winner|winner of|congratulations|lottery|lucky draw|lucky winner|jackpot|kbc|kaun banega crorepati|prize money|cash prize|claim (your )?(prize|reward|gift)|free (gift|iphone|laptop|scooty|recharge|data|smartphone|mobile)|cashback of|bumper prize)\b",
        ],
        "sub": ["इनाम", "लॉटरी", "बधाई हो", "जीत लिया", "जीत गए", "బహుమతి", "లాటరీ", "అభినందనలు", "గెలుచుకున్నారు", "লটারি", "জিতেছেন", "অভিনন্দন", "পুরস্কার", "லாட்டரி", "பரிசு", "வாழ்த்துக்கள்", "வென்றுள்ளீர்கள்", "बक्षीस", "अभिनंदन", "जिंकले", "ಲಾಟರಿ", "ಬಹುಮಾನ", "ಅಭಿನಂದನೆ", "લોટરી", "ઇનામ", "ലോട്ടറി", "സമ്മാനം"],
    },
    "job_task": {
        "re": [
            r"\b(part[- ]?time (job|work|income)|work from home|home[- ]based (job|work)|data entry (job|work)|earn (rs\.?|₹|inr)?\s?[\d,]+\s?(daily|per day|/day|a day|per task|weekly|per hour)|daily (income|earning|payout|salary)|like (youtube )?videos?|subscribe (to )?(youtube )?channels?|rate (hotels?|products?|restaurants?|movies?)|(google )?(map|maps) reviews?|telegram (task|group|job)|prepaid tasks?|merchant tasks?|task[- ]based|commission (per|on each|for every) task|hr (manager|team) from)\b",
            r"\bghar baithe\b",
            r"\broz(ana)? (ke )?[\d,]+ (kamao|kamaye|kamaiye)\b",
        ],
        "sub": ["घर बैठे", "पार्ट टाइम", "रोज़ाना कमाई", "रोजाना कमाई", "పార్ట్ టైమ్", "పార్ట్‌టైమ్", "ఇంటి నుండి పని", "రోజుకు సంపాద", "পার্ট টাইম", "বাড়ি থেকে কাজ", "প্রতিদিন আয়", "பகுதி நேர வேலை", "வீட்டிலிருந்து வேலை", "घरबसल्या", "ಮನೆಯಿಂದ ಕೆಲಸ", "ಪಾರ್ಟ್ ಟೈಮ್"],
    },
    "investment_lure": {
        "re": [
            r"\b(guaranteed (returns?|profits?|income)|assured returns?|double (your )?money|\d{1,3}\s?% (daily|weekly|monthly|per day|per month) (returns?|profits?)|stock (market )?tips|intraday tips|ipo (allotment|shares?)|institutional (account|trading|quota)|block trade|vip (group|trading|plan)|trading (app|platform|group)|crypto(currency)?|usdt|bitcoin|forex|binary options|high returns?|sebi[- ]registered (advisor|adviser|expert|analyst)|investment (plan|opportunity|scheme|group)|withdrawal (fee|tax|charges?))\b",
        ],
        "sub": ["दोगुना", "गारंटीड रिटर्न", "शेयर टिप्स", "రెట్టింపు", "గ్యారంటీ లాభం", "షేర్ టిప్స్"],
    },
    "courier_parcel": {
        "re": [
            r"\b(fedex|dhl|blue ?dart|dtdc|courier|parcel|consignment|shipment|package)\b[^.\n]{0,60}\b(held|seized|returned|stuck|on hold|pending|undeliverable|customs|illegal|suspicious|confiscated|address (is )?(incomplete|incorrect|invalid)|update (your )?address|could not be delivered)\b",
            r"\bcustoms (duty|clearance|fee|charges|department|officer)\b",
        ],
        "sub": ["पार्सल", "कूरियर", "कस्टम", "పార్సెల్", "కొరియర్", "కస్టమ్స్"],
    },
    "electricity_cut": {
        "re": [
            r"\b(electricity|power|bijli|current|light|electric)\b[^.\n]{0,40}\b(connection )?(will be |would be |is going to be )?(cut|disconnected|discontinued|disconnect|kat)\b",
            r"\b(previous|last) month('?s)? bill (was |is )?(not )?(updated|paid|pending)\b",
            r"\belectricity (officer|department|board) (number|contact|call)\b",
        ],
        "sub": ["बिजली कनेक्शन", "बिजली काट", "बिजली बिल", "లైట్ కట్", "కరెంట్ కట్", "విద్యుత్ కనెక్షన్", "కరెంటు బిల్లు", "కరెంట్ బిల్లు", "বিদ্যুৎ সংযোগ", "বিদ্যুৎ বিল", "மின் இணைப்பு", "மின்சார இணைப்பு", "மின் கட்டணம்", "वीज कनेक्शन", "वीज बिल", "ವಿದ್ಯುತ್ ಸಂಪರ್ಕ", "ಕರೆಂಟ್ ಕಟ್"],
    },
    "challan": {
        "re": [r"\b(e-?challan|traffic (fine|violation|challan|penalty)|rto (fine|challan|notice)|vahan|parivahan|overspeeding|speed violation|challan)\b"],
        "sub": ["चालान", "చలాన్"],
    },
    "loan_lure": {
        "re": [r"\b(pre-?approved (personal )?loan|instant loan|loan (is |has been )?(approved|sanctioned)|loan without (cibil|documents|credit check)|low interest loan|loan app|loan offer)\b"],
        "sub": ["लोन मंजूर", "तुरंत लोन", "లోన్ మంజూరు", "తక్షణ లోన్"],
    },
    "loan_harassment": {
        "re": [
            r"\b(morphed|obscene|edited) (photos?|pictures?|images?)\b",
            r"\b(send|share|message|call)\b[^.\n]{0,20}\b(all )?(your )?(contacts|contact list|relatives)\b[^.\n]{0,30}\b(defaulter|fraud|loan)\b",
            r"\bloan (recovery|agent)\b[^.\n]{0,30}\b(threat|abuse|harass)\w*\b",
        ],
        "sub": ["फोटो वायरल", "కాంటాక్ట్‌లకు పంప"],
    },
    "sextortion": {
        "re": [
            r"\b(nude|naked|obscene|intimate|private|sexual|explicit|objectionable) (video|photos?|pictures?|images?|call|recording|clip)\b",
            r"\b(video|recording|screen ?shots?|clip)\b[^.\n]{0,40}\b(viral|leak|upload|send to (your )?(family|contacts|friends|relatives))\b",
            r"\b(will )?(make|go) (it )?viral\b",
            r"\bdefame\b",
        ],
        "sub": ["अश्लील", "वायरल कर", "न्यूड", "అశ్లీల", "వైరల్ చేస"],
    },
    "relative_emergency": {
        "re": [
            r"\b(your|ur) (son|daughter|husband|wife|father|mother|brother|sister|child|nephew|niece|relative|grandson|granddaughter)\b[^.\n]{0,40}\b(arrested|detained|caught|in (police )?custody|accident|hospital(ized|ised)?|injured|kidnapped|in trouble|rape case)\b",
            r"\b(mom|mum|mummy|maa|dad|papa|uncle|aunty|bhaiya|didi)\b[^.\n]{0,30}\b(urgent|emergency|help|trouble|accident|send money|need money)\b",
            r"\b(this is my new number|my new number|new number,? (save|please save))\b",
            r"\b(i am|i'm) in (trouble|an emergency|hospital|police custody)\b",
            r"\b(beta|beti|papa|mummy|bhai)\b[^.\n]{0,30}\b(pakda|pakad liya|giraftar|accident|hospital|musibat)\b",
            r"\bmera naya number\b",
        ],
        "sub": ["मेरा नया नंबर", "बेटा पकड़", "बेटे को पुलिस", "నా కొత్త నంబర్", "మీ అబ్బాయిని అరెస్ట్", "మీ కొడుకు"],
    },
    "refund_customer_care": {
        "re": [
            r"\b(refund|reversal|cashback)\b[^.\n]{0,40}\b(process|initiat|credit|claim|receive|pending|failed)\w*",
            r"\bcustomer (care|support|service) (executive|number|helpline|agent)\b",
            r"\b(helpline|toll[- ]free) number\b",
        ],
        "sub": ["रिफंड", "ग्राहक सेवा", "రీఫండ్", "కస్టమర్ కేర్"],
    },
    "sim_swap": {
        "re": [
            r"\b(e-?sim|sim (card )?(upgrade|swap|replacement|block|deactivat\w*|verification)|4g to 5g|5g upgrade|network upgrade|port (your )?number)\b",
            r"\bsim\b[^.\n]{0,30}\b(will be )?(blocked|deactivated|suspended|discontinued)\b",
        ],
        "sub": ["सिम बंद", "सिम ब्लॉक", "సిమ్ బ్లాక్", "సిమ్ డీయాక్టివేట్"],
    },
    "mule_recruit": {
        "re": [
            r"\b(rent|lend|sell|give|provide) (out )?(your |us your |me your )?(bank )?(account|a/c|current account|savings account|upi|sim)( details)?\b",
            r"\bcommission\b[^.\n]{0,40}\b(transactions?|transfer|deposits?|receiving|payments?|per lakh)\b",
            r"\b(receive|accept) (payments?|money|funds) (in|into|on|through) your (account|upi|bank)\b",
            r"\baccount (holders?|providers?) (needed|wanted|required)\b",
            r"\baccount (de do|kiraye par)\b",
        ],
        "sub": ["खाता किराए", "అకౌంట్ అద్దెకు"],
    },
    "wrong_transfer": {
        "re": [
            r"\b(sent|transferred|credited|paid)\b[^.\n]{0,25}\b(by mistake|wrongly|accidentally|in error|galti se)\b",
            r"\b(please )?(return|send back|refund) (the |my )?(money|amount|payment)\b",
        ],
        "sub": ["गलती से", "పొరపాటున"],
    },
    "govt_scheme_fee": {
        "re": [r"\b(pm[- ]?kisan|pm[- ]?awas|ayushman|ujjwala|mudra loan|yojana|govt\.? scheme|government scheme|subsidy|free laptop|free scooty|free solar|berojgari bhatta|pm[- ]?(scheme|yojana))\b"],
        "sub": ["योजना", "सब्सिडी", "పథకం", "సబ్సిడీ"],
    },
    "tax_refund": {
        "re": [r"\b(income ?tax|it|gst|tds) refund\b", r"\brefund (of|for) (income ?tax|it|tds)\b"],
        "sub": ["आयकर रिफंड", "ఆదాయపు పన్ను రీఫండ్"],
    },
    "pension_life_cert": {
        "re": [r"\b(pension|pensioner|life certificate|jeevan pramaan|ppo number)\b"],
        "sub": ["पेंशन", "जीवन प्रमाण", "పెన్షన్"],
    },
    "card_reward": {
        "re": [
            r"\b(credit card|debit card|card)\b[^.\n]{0,40}\b(reward points?|limit (increase|enhancement|upgrade)|annual (fee|charges) (waiver|reversal)|points (will )?expire)\b",
            r"\breward points?\b[^.\n]{0,30}\b(expir\w*|redeem|worth)\b",
        ],
        "sub": ["रिवॉर्ड पॉइंट", "రివార్డ్ పాయింట్"],
    },
    "call_instruction": {
        "re": [
            r"\b(call|contact|whatsapp|ring)\b[^.\n]{0,25}\b(officer|executive|agent|department|immediately|urgently|now|on|at)\b[^.\n]{0,20}(\+?\d[\d\s\-]{8,})",
            r"\b(call|contact)\s+(\+?91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}\b",
        ],
        "sub": ["कॉल करें", "संपर्क करें", "కాల్ చేయండి"],
    },
    "video_call": {"re": [r"\b(video call|skype|whatsapp video|zoom call|google meet)\b"], "sub": ["वीडियो कॉल", "వీడియో కాల్"]},
    "telegram_whatsapp_move": {
        "re": [r"\b(telegram|t\.me|whatsapp (me|us|group|number)|wa\.me|join (our|the|my) (group|channel)|chat\.whatsapp\.com)\b"],
        "sub": [],
    },
    "marketplace_buyer": {
        "re": [r"\b(olx|quikr|facebook marketplace|army (officer|man|person|personnel)|cisf|crpf|jawan|transfer(red)? (posting|order))\b"],
        "sub": ["आर्मी", "ఆర్మీ"],
    },
    "money_lost": {
        "re": [
            r"\b(made|forced|convinced|pressured|got) (me|us|him|her|my \w+) (to )?(transfer|pay|send|deposit)\b",
            r"\b(i|we|my (father|mother|dad|mom|parents?|grandfather|grandmother|husband|wife|son|daughter|uncle|aunt))\b[^.\n]{0,25}\b(paid|transferred|sent|lost|deposited|gave)\b",
            r"\b(money|amount|rs\.?|₹|rupees)\b[^.\n]{0,30}\b(debited|deducted|withdrawn|gone|lost|transferred|stolen)\b",
            r"\b(got|been|was|were) (debited|deducted|scammed|cheated|duped|defrauded)\b",
            r"\b(paise|rupaye|rupees) (kat gaye|kat gye|chale gaye|bhej diye|transfer kar diye|de diye)\b",
        ],
        "sub": ["पैसे कट", "पैसे चले गए", "ट्रांसफर कर दिए", "भेज दिए", "డబ్బులు కట్", "డబ్బు పంపాను", "పోగొట్టుకున్నా", "డబ్బులు పోయాయి", "টাকা কেটে", "টাকা চলে গেছে", "টাকা পাঠিয়েছি", "பணம் போய்விட்டது", "பணம் அனுப்பினேன்", "पैसे गेले", "पैसे कापले", "ಹಣ ಹೋಯಿತು"],
    },
    "otp_shared": {
        "re": [
            r"\b(i|he|she|we|my \w+)\b[^.\n]{0,20}\b(shared|gave|told|provided|entered|read out)\b[^.\n]{0,20}\b(the |my |an |him |her |them |his )?(otp|pin|cvv|password)\b",
            r"\b(otp|pin|cvv)\b[^.\n]{0,15}\b(shared|given|told|bata diya|de diya)\b",
        ],
        "sub": ["ओटीपी बता दिया", "ओटीपी दे दिया", "ఓటీపీ చెప్పాను", "ఓటీపీ ఇచ్చాను"],
    },
    "no_otp_shared": {
        "re": [
            r"\b(didn't|did not|never|haven't|have not|without)\b[^.\n]{0,15}\b(share|sharing|give|giving|tell|telling|shared|given)\b[^.\n]{0,15}\b(any |the |my )?(otp|pin|cvv|password|details)\b",
            r"\bwithout my (knowledge|consent|permission)\b",
            r"\b(not done by me|i didn't do|i did not do|i never did|unknown transactions?|unauthori[sz]ed transactions?|i did not make|i didn't make)\b",
            r"\botp (share )?nahi (kiya|diya|bataya)\b",
        ],
        "sub": ["ओटीपी नहीं बताया", "मेरी जानकारी के बिना", "నాకు తెలియకుండా"],
    },
    "authorised_push": {
        "re": [
            r"\b(i|we|he|she|my \w+)\b[^.\n]{0,20}\b(transferred|paid|sent|scanned|deposited)\b",
            r"\b(made|asked|forced|told|instructed|convinced|pressured|got) (me|us|him|her|my \w+) (to )?(transfer|pay|send|deposit)\b",
            r"\b(i|we) (had to|was made to|were made to) (transfer|pay|send)\b",
            r"\bscanned (the |their )?(qr|code)\b",
            r"\bentered (my )?(upi )?pin\b",
        ],
        "sub": ["ट्रांसफर कर दिए", "भेज दिए", "పంపాను", "ట్రాన్స్‌ఫర్ చేశాను"],
    },
    "repeat_demand": {
        "re": [
            r"\b(again|another|one more|second|additional|more)\b[^.\n]{0,20}\b(fee|fees|payment|charges?|tax|deposit|amount|transfer)\b",
            r"\b(now|then) (they|he|she) (asked|asking|demanded|demanding|want|wants) (for )?(more|another)\b",
        ],
        "sub": ["फिर से पैसे", "और पैसे", "మళ్ళీ డబ్బు", "ఇంకా డబ్బు"],
    },
    "prompt_injection": {
        "re": [
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,20}\b(all |any |the |your )?(previous|prior|above|earlier|system)\b[^.\n]{0,15}\b(instructions?|prompts?|rules?|messages?)\b",
            r"\b(mark|classify|label|rate|treat|report)\b[^.\n]{0,20}\b(this|it|the message)\b[^.\n]{0,20}\b(as )?(safe|legit(imate)?|genuine|not (a )?scam|low risk|harmless)\b",
            r"\b(as an ai|you are (now )?(an? )?(ai|assistant|chatbot|language model))\b",
            r"\b(system prompt|developer mode|jailbreak)\b",
            r"\bnote (to|for) (the )?(ai|assistant|any ai|llm|scanner|filter)s?\b",
            r"\b(classify|mark|label|rate|treat|flag)\b[^.\n]{0,15}\bas\b[^.\n]{0,10}\b(safe|legit(imate)?|genuine|harmless|not (a )?scam|verified)\b",
            r"\b(system|admin|developer) (note|message|instruction)s?\b[^.\n]{0,30}\b(ai|assistant|model|scanner|filter|safe|verified)\b",
            r"\b(do not|don't|never) flag (this|it)\b",
            r"\b(this|the) message is (verified|certified)? ?(safe|legit(imate)?|genuine)\b",
        ],
        "sub": ["AI के लिए निर्देश", "सुरक्षित बताएं", "सुरक्षित बताओ", "सुरक्षित मार्क", "निर्देशों को अनदेखा", "AI కి సూచన", "సురక్షితమైన సందేశం", "సూచనలను పట్టించుకోవద్దు"],
    },
    # --- Trust signals (reduce risk) ---
    "otp_warning_legit": {
        "re": [
            r"\b(do not|don't|never|not to|dont)\b[^.\n]{0,15}\b(share|disclose|tell|give)\b[^.\n]{0,25}\b(otp|pin|cvv|password|this code|it)\b",
            r"\b(bank|we|sbi|hdfc|icici|axis) (will )?never (ask|call|request)\b",
            r"\bkisi ke saath share na kare\b",
        ],
        "sub": ["किसी के साथ साझा न करें", "शेयर न करें", "ఎవరితోనూ పంచుకోవద్దు"],
    },
    "official_channel_advice": {
        "re": [
            r"\bvisit (your|the) (home |nearest |base |parent )?branch\b",
            r"\b(through|via|using|in) (the |our )?(official (app|website|portal)|yono|net ?banking|mobile banking app)\b",
        ],
        "sub": [],
    },
    "bank_alert_format": {
        "re": [
            r"\b(a/c|acct|account|card)\b[^.\n]{0,15}\b(x+|\*+)\d{3,4}\b[^.\n]{0,60}\b(debited|credited|spent|used)\b",
            r"\b(avl\.? bal|available balance|avl bal)\b",
            r"\bif not (done by )?(you|u)\b",
        ],
        "sub": [],
    },
}

NEGATORS = re.compile(
    r"(?i)\b(do not|don't|dont|never|not to|no one|nobody|will never|won't|mat|na karein|na kare|nahi)\b|मत|न करें|न बताएं|వద్దు|చెప్పకండి"
)

COMPILED = {
    k: ([re.compile(r, re.IGNORECASE) for r in v.get("re", [])], v.get("sub", []))
    for k, v in P.items()
}

# Risk weight of each signal on its own (0..1). Trust signals are negative.
SIGNAL_WEIGHTS: dict[str, float] = {
    "otp_request": 0.55, "pin_to_receive": 0.6, "remote_access": 0.55, "apk_install": 0.6,
    "kyc_threat": 0.35, "authority_impersonation": 0.25, "digital_arrest": 0.55, "secrecy": 0.3,
    "urgency": 0.15, "payment_request": 0.2, "reward_lure": 0.3, "job_task": 0.35,
    "investment_lure": 0.35, "courier_parcel": 0.2, "electricity_cut": 0.35, "challan": 0.15,
    "loan_lure": 0.25, "loan_harassment": 0.4, "sextortion": 0.5, "relative_emergency": 0.35,
    "refund_customer_care": 0.15, "sim_swap": 0.35, "mule_recruit": 0.55, "wrong_transfer": 0.3,
    "govt_scheme_fee": 0.1, "tax_refund": 0.2, "pension_life_cert": 0.08, "card_reward": 0.25,
    "video_call": 0.08, "telegram_whatsapp_move": 0.2, "marketplace_buyer": 0.12, "call_instruction": 0.12,
    "prompt_injection": 0.45, "evasion_obfuscation": 0.4, "bidi_spoof": 0.6,
    # context-only signals (no direct risk)
    "repeat_demand": 0.2, "money_lost": 0.0, "otp_shared": 0.0, "no_otp_shared": 0.0, "authorised_push": 0.0,
    # trust
    "otp_warning_legit": -0.35, "bank_alert_format": -0.15, "official_channel_advice": -0.3,
}

SIGNAL_LABELS: dict[str, str] = {
    "otp_request": "Asks for OTP / PIN / CVV / password",
    "pin_to_receive": "Asks you to scan a QR or enter UPI PIN to 'receive' money",
    "remote_access": "Asks you to install a screen-sharing / remote-access app",
    "apk_install": "Pushes an APK file or app install from a link",
    "kyc_threat": "Threatens account/KYC/PAN block",
    "authority_impersonation": "Claims to be police / CBI / customs / regulator",
    "digital_arrest": "'Digital arrest' / money-laundering / drugs-parcel script",
    "secrecy": "Demands secrecy — 'don't tell anyone'",
    "urgency": "Creates artificial urgency / deadline",
    "payment_request": "Demands a payment, fee or transfer",
    "reward_lure": "Lottery / prize / free-gift lure",
    "job_task": "Part-time job / task-earning lure",
    "investment_lure": "Guaranteed-return investment / trading lure",
    "courier_parcel": "Courier / customs parcel story",
    "electricity_cut": "Electricity disconnection threat",
    "challan": "Traffic e-challan notice",
    "loan_lure": "Instant / pre-approved loan lure",
    "loan_harassment": "Loan-recovery harassment / morphed photos",
    "sextortion": "Intimate-content blackmail",
    "relative_emergency": "Family emergency / 'new number' story",
    "refund_customer_care": "Refund / customer-care story",
    "sim_swap": "SIM / eSIM upgrade or block story",
    "mule_recruit": "Asks to rent/use your bank account or UPI",
    "wrong_transfer": "'Sent by mistake, please return' story",
    "govt_scheme_fee": "Mentions a government scheme / subsidy",
    "tax_refund": "Income-tax / GST refund story",
    "pension_life_cert": "Pension / life-certificate story",
    "card_reward": "Card reward points / limit story",
    "video_call": "Moves you onto a video call",
    "call_instruction": "Pushes you to call a number given in the message",
    "telegram_whatsapp_move": "Moves you to Telegram/WhatsApp groups",
    "marketplace_buyer": "Marketplace 'army officer' buyer pattern",
    "prompt_injection": "Text tries to manipulate AI scam-checkers",
    "evasion_obfuscation": "Disguised keywords / look-alike characters to evade scam filters",
    "bidi_spoof": "Hidden right-to-left characters disguising a file name",
    "repeat_demand": "Keeps demanding more fees / payments",
    "money_lost": "Money already lost",
    "otp_shared": "Credentials/OTP were shared",
    "no_otp_shared": "No OTP/credentials were shared",
    "authorised_push": "Victim made/approved the payment",
    "otp_warning_legit": "Contains standard 'never share OTP' safety advice",
    "bank_alert_format": "Matches a standard bank transaction-alert format",
    "official_channel_advice": "Points you to the branch / official app rather than a link or caller",
}

_SENT_SPLIT = re.compile(r"(?<=[.!?।\n])\s+")


def split_sentences(text: str) -> list[str]:
    parts = [s.strip() for s in _SENT_SPLIT.split(text or "") if s.strip()]
    return parts or ([text.strip()] if text and text.strip() else [])


def detect_signals(text: str) -> dict[str, list[str]]:
    """Return {signal: [evidence snippets]} for the given text."""
    found: dict[str, list[str]] = {}
    if not text:
        return found

    def add(sig: str, snippet: str):
        snippet = snippet.strip()
        if len(snippet) > 90:
            snippet = snippet[:87] + "…"
        lst = found.setdefault(sig, [])
        if snippet and snippet not in lst and len(lst) < 3:
            lst.append(snippet)

    for sentence in split_sentences(text):
        low = sentence.lower()
        for sig, (regexes, subs) in COMPILED.items():
            hit = None
            for rx in regexes:
                m = rx.search(sentence)
                if m:
                    hit = m.group(0)
                    break
            if not hit:
                for s in subs:
                    if s.lower() in low:
                        hit = s
                        break
            if not hit:
                continue
            if sig == "otp_request":
                # "Do not share OTP" is advice, not a request.
                idx = low.find(hit.lower())
                window = low[max(0, idx - 35): idx + len(hit) + 15]
                if NEGATORS.search(window):
                    add("otp_warning_legit", hit)
                    continue
            if sig == "secrecy" and "otp" in low and re.search(r"(?i)\b(do not|don't|never)\b[^.]{0,15}\bshare\b", sentence):
                # "Never share OTP with anyone" is not a secrecy demand.
                continue
            add(sig, hit)
    # A message that contains BOTH a warning and an explicit request keeps both.
    return found


def signal_risk(signals: dict[str, list[str]]) -> float:
    """Noisy-OR combination of positive signal weights (0..1)."""
    prod = 1.0
    for sig in signals:
        w = SIGNAL_WEIGHTS.get(sig, 0.0)
        if w > 0:
            prod *= 1 - w
    return 1 - prod
