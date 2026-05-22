"""
Configuration for AI Service
"""

import os
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional during lightweight test runs
    def load_dotenv() -> bool:
        return False

load_dotenv()

# Server Configuration
HOST = os.getenv("AI_SERVICE_HOST", "0.0.0.0")
PORT = int(os.getenv("AI_SERVICE_PORT", "8000"))
DEBUG = os.getenv("AI_SERVICE_DEBUG", "false").lower() == "true"

# Authentication Configuration
# API Keys for authentication (comma-separated in env var)
# In production, set AI_SERVICE_API_KEYS env var with secure keys
_raw_keys = os.getenv("AI_SERVICE_API_KEYS", "")
API_KEYS = {k.strip() for k in _raw_keys.split(",") if k.strip()}
REQUIRE_AUTH = os.getenv("AI_SERVICE_REQUIRE_AUTH", "true").lower() == "true"

# Model Configuration
# Model Configuration (Hybrid Pipeline)
# 1. English Model (High Accuracy)
MODEL_EN = os.getenv(
    "MODEL_EN", 
    "MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli"
)

# 2. Multilingual Model (Thai Support)
MODEL_MULTI = os.getenv(
    "MODEL_MULTI", 
    "MoritzLaurer/bge-m3-zeroshot-v2.0"
)

# Use CPU by default (no CUDA)
DEVICE = os.getenv("DEVICE", "cpu")
MAX_CLASSIFIER_INPUT_CHARS = int(os.getenv("MAX_CLASSIFIER_INPUT_CHARS", "0") or "0")

# Threat Categories (Used for Zero-shot Classification)
# NOTE: Lowercase for model input, mapped to Title Case for scoring
# using a mapping to preserve acronyms like DDoS, APT
LABEL_MAPPING = {
    "ransomware": "Ransomware",
    "phishing": "Phishing",
    "DDoS": "DDoS",
    "data breach": "Data Breach",
    "supply chain attack": "Supply Chain Attack",
    "zero-day exploit": "Zero-day Exploit",
    "APT": "APT"
}

THREAT_LABELS = list(LABEL_MAPPING.keys())

# Sector Classification Labels (Zero-shot NLP)
# Natural-language hypotheses for the zero-shot model — run in the same
# inference pass as THREAT_LABELS with multi_label=True.
SECTOR_LABELS = [
    "targeting banking or financial services",
    "targeting government or public services",
    "targeting healthcare or public health",
    "targeting national security or defense",
    "targeting energy or public utilities",
    "targeting technology or telecommunications",
    "targeting transportation or logistics",
]

SECTOR_LABEL_MAPPING = {
    "targeting banking or financial services": "financial",
    "targeting government or public services": "government",
    "targeting healthcare or public health": "healthcare",
    "targeting national security or defense": "government",
    "targeting energy or public utilities": "critical_infrastructure",
    "targeting technology or telecommunications": "technology",
    "targeting transportation or logistics": "critical_infrastructure",
}

SECTOR_CONFIDENCE_THRESHOLD = 0.35

# ============================================
# ENHANCED SCORING CONFIGURATION
# ============================================

# Risk Scoring Weights (sum = 1.0)
# Unified 6-factor scoring — applies equally to all IOC types
# (sha256, domain, url, ip, etc.). domain_age and entropy factors
# were dropped: domain_age coverage is only 3-4% even after WHOIS
# enrichment, and entropy is a weak DGA signal with high false-positives.
# Their 15% combined weight was redistributed to the 6 universal factors.
SCORING_WEIGHTS = {
    "cross_source":         0.20,  # พบจากหลายแหล่ง (+5% from 0.15)
    "threat_intel_source":  0.25,  # แหล่งน่าเชื่อถือ (+5% from 0.20)
    "high_risk_keywords":   0.10,  # คำสำคัญอันตราย
    "threat_type_severity": 0.30,  # AI: ประเภทภัยคุกคาม (+5% from 0.25)
    "threat_actor":         0.10,  # AI: กลุ่มผู้โจมตี
    "mitre_techniques":     0.05,  # AI: MITRE ATT&CK
}
# Total: 1.00 — applies uniformly to all IOC types

# Threat Type Severity Levels
# Level 1 (Critical): Maximum impact, nation-state or destructive
# Level 2 (High): Significant impact, common attack vectors
# Level 3 (Medium): Moderate impact, less targeted
# NOTE: Scores are now normalized to 0-100 scale for direct weighting
THREAT_TYPE_SEVERITY = {
    # Level 1 - Critical (Max 100)
    "Ransomware": {"level": 1, "score": 80, "description": "การเข้ารหัสเรียกค่าไถ่"},
    "APT": {"level": 1, "score": 80, "description": "การโจมตีแบบ Advanced Persistent Threat"},
    "C2": {"level": 1, "score": 80, "description": "เซิร์ฟเวอร์ Command & Control"},
    "Botnet": {"level": 1, "score": 75, "description": "เครือข่ายบอท"},
    "Wiper": {"level": 1, "score": 80, "description": "มัลแวร์ลบข้อมูล"},
    "Supply Chain Attack": {"level": 1, "score": 90, "description": "การโจมตีผ่านห่วงโซ่อุปทาน"},
    "Zero-day Exploit": {"level": 1, "score": 90, "description": "การโจมตีช่องโหว่ใหม่ที่ไม่เคยพบมาก่อน"},
    "Exploited Vulnerability": {"level": 1, "score": 75, "description": "ช่องโหว่ที่ถูกนำไปใช้โจมตีจริง"},
    "Remote Code Execution": {"level": 1, "score": 75, "description": "ช่องโหว่ที่ทำให้รันคำสั่งระยะไกลได้"},
    
    # Level 2 - High (Max 70)
    "Malware": {"level": 2, "score": 60, "description": "มัลแวร์ทั่วไป"},
    "Credential Theft": {"level": 2, "score": 60, "description": "การขโมย credentials"},
    "Trojan": {"level": 2, "score": 55, "description": "โทรจัน"},
    "Backdoor": {"level": 2, "score": 60, "description": "ช่องทางลับ"},
    "Exploit": {"level": 2, "score": 55, "description": "โค้ดโจมตีช่องโหว่"},
    "Data Breach": {"level": 2, "score": 50, "description": "การรั่วไหลของข้อมูล"},
    
    # Level 3 - Medium (Max 40)
    "Phishing": {"level": 3, "score": 40, "description": "การหลอกลวง"},
    "DDoS": {"level": 3, "score": 35, "description": "การโจมตี Distributed DoS"},
    "Spam": {"level": 3, "score": 25, "description": "สแปม"},
    "Scanning": {"level": 3, "score": 20, "description": "การสแกนหาช่องโหว่"},
    
    # Level 4 - Low (Max 20)
    "Vulnerability": {"level": 4, "score": 20, "description": "ช่องโหว่ที่รู้จัก"},
    "Defacement": {"level": 4, "score": 15, "description": "การเปลี่ยนแปลงหน้าเว็บ"},
    "Other": {"level": 4, "score": 10, "description": "อื่นๆ"}
}

# Known Threat Actors Database
# Score based on sophistication and impact (Scale 0-100)
# activity_status: active (1.0x), dormant (0.7x), disbanded (0.4x)
KNOWN_THREAT_ACTORS = {
    # Nation-State APT Groups (80-100 points)
    "Lazarus": {"score": 100, "origin": "KP", "aliases": ["Hidden Cobra", "ZINC"], "targets": ["Finance", "Crypto"], "activity_status": "active", "last_known_activity": "2025"},
    "APT28": {"score": 100, "origin": "RU", "aliases": ["Fancy Bear", "Sofacy"], "targets": ["Government", "Military"], "activity_status": "active", "last_known_activity": "2025"},
    "APT29": {"score": 100, "origin": "RU", "aliases": ["Cozy Bear", "Nobelium"], "targets": ["Government", "Think Tanks"], "activity_status": "active", "last_known_activity": "2025"},
    "APT41": {"score": 100, "origin": "CN", "aliases": ["Winnti", "Barium"], "targets": ["Gaming", "Tech"], "activity_status": "active", "last_known_activity": "2025"},
    "Sandworm": {"score": 100, "origin": "RU", "aliases": ["Voodoo Bear"], "targets": ["Energy", "Government"], "activity_status": "active", "last_known_activity": "2025"},
    "Equation Group": {"score": 100, "origin": "US", "aliases": ["EQGRP"], "targets": ["Government"], "activity_status": "dormant", "last_known_activity": "2017"},
    "Charming Kitten": {"score": 90, "origin": "IR", "aliases": ["APT35", "Phosphorus"], "targets": ["Journalists", "Academics"], "activity_status": "active", "last_known_activity": "2025"},
    "MuddyWater": {"score": 90, "origin": "IR", "aliases": ["MERCURY"], "targets": ["Government", "Telco"], "activity_status": "active", "last_known_activity": "2025"},
    
    # Ransomware Groups (70-90 points)
    "LockBit": {"score": 90, "origin": "RU", "aliases": ["ABCD"], "targets": ["Enterprise"], "activity_status": "active", "last_known_activity": "2025"},
    "BlackCat": {"score": 90, "origin": "RU", "aliases": ["ALPHV"], "targets": ["Enterprise"], "activity_status": "disbanded", "last_known_activity": "2024"},
    "Conti": {"score": 90, "origin": "RU", "aliases": ["Wizard Spider"], "targets": ["Healthcare", "Enterprise"], "activity_status": "disbanded", "last_known_activity": "2022"},
    "REvil": {"score": 90, "origin": "RU", "aliases": ["Sodinokibi"], "targets": ["Enterprise"], "activity_status": "disbanded", "last_known_activity": "2022"},
    "Cl0p": {"score": 85, "origin": "RU", "aliases": ["TA505"], "targets": ["Enterprise"], "activity_status": "active", "last_known_activity": "2025"},
    "Play": {"score": 80, "origin": "Unknown", "aliases": [], "targets": ["Enterprise"], "activity_status": "active", "last_known_activity": "2025"},
    "Royal": {"score": 80, "origin": "Unknown", "aliases": [], "targets": ["Healthcare"], "activity_status": "dormant", "last_known_activity": "2023"},
    
    # Cybercrime Groups (60-80 points)
    "FIN7": {"score": 75, "origin": "RU", "aliases": ["Carbanak"], "targets": ["Finance", "Retail"], "activity_status": "active", "last_known_activity": "2025"},
    "FIN8": {"score": 70, "origin": "Unknown", "aliases": [], "targets": ["Retail", "Hospitality"], "activity_status": "dormant", "last_known_activity": "2023"},
    "Qakbot": {"score": 70, "origin": "Unknown", "aliases": ["QBot", "Quakbot"], "targets": ["Banking"], "activity_status": "disbanded", "last_known_activity": "2023"},
    "Emotet": {"score": 70, "origin": "Unknown", "aliases": ["Heodo"], "targets": ["All"], "activity_status": "active", "last_known_activity": "2025"},
    "TrickBot": {"score": 70, "origin": "RU", "aliases": ["Trickster"], "targets": ["Banking"], "activity_status": "disbanded", "last_known_activity": "2022"},
    "IcedID": {"score": 65, "origin": "Unknown", "aliases": ["BokBot"], "targets": ["Banking"], "activity_status": "dormant", "last_known_activity": "2023"},
    
    # Hacktivists (40-60 points)
    "Anonymous": {"score": 50, "origin": "Global", "aliases": [], "targets": ["Various"], "activity_status": "active", "last_known_activity": "2025"},
    "LulzSec": {"score": 50, "origin": "Global", "aliases": [], "targets": ["Various"], "activity_status": "disbanded", "last_known_activity": "2014"},
    "GhostSec": {"score": 45, "origin": "Global", "aliases": [], "targets": ["Various"], "activity_status": "active", "last_known_activity": "2025"},
    
    # Regional (10 points)
    "Cobalt Group": {"score": 18, "origin": "Unknown", "aliases": [], "targets": ["Finance"], "activity_status": "dormant", "last_known_activity": "2020"},
    "OilRig": {"score": 20, "origin": "IR", "aliases": ["APT34", "Helix Kitten"], "targets": ["Telco", "Government"], "activity_status": "active", "last_known_activity": "2025"}
}

# MITRE ATT&CK Tactics (for bonus scoring)
MITRE_TACTICS = {
    "Initial Access": {"id": "TA0001", "score": 5},
    "Execution": {"id": "TA0002", "score": 5},
    "Persistence": {"id": "TA0003", "score": 6},
    "Privilege Escalation": {"id": "TA0004", "score": 6},
    "Defense Evasion": {"id": "TA0005", "score": 6},
    "Credential Access": {"id": "TA0006", "score": 7},
    "Discovery": {"id": "TA0007", "score": 4},
    "Lateral Movement": {"id": "TA0008", "score": 7},
    "Collection": {"id": "TA0009", "score": 5},
    "Command and Control": {"id": "TA0011", "score": 8},
    "Exfiltration": {"id": "TA0010", "score": 8},
    "Impact": {"id": "TA0040", "score": 8}
}

# High Risk Keywords
# NOTE: Removed 'critical' and 'encryption' - too generic, causes false positives
HIGH_RISK_KEYWORDS_TIERED = {
    "critical": {  # 30 คะแนน/คำ - ภัยร้ายแรงสูงสุด
        "score": 30,
        "keywords": [
            "ransomware", "zero-day", "0day", "wiper", "supply chain",
            "cobalt strike", "command and control", "c&c", "exfiltration"
        ]
    },
    "high": {      # 20 คะแนน/คำ - ภัยร้ายแรงสูง
        "score": 20,
        "keywords": [
            "exploit", "backdoor", "c2", "cnc", "apt", "credential",
            "rootkit", "keylogger", "lateral movement", "privilege escalation",
            "persistence", "obfuscated"
        ]
    },
    "medium": {    # 10 คะแนน/คำ - ภัยระดับกลาง
        "score": 10,
        "keywords": [
            "malware", "trojan", "phishing", "botnet", "active",
            "lazarus", "lockbit", "conti", "revil", "emotet", "trickbot",
            "stealer", "banker", "infostealer", "loader", "dropper"
        ]
    }
}

# High Risk Countries (ISO Alpha-2)
HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "IR", "BY", "SY", "VE"]

# Trusted Threat Intel Sources
TRUSTED_SOURCES = [
    "VirusTotal", "AbuseIPDB", "MITRE", "AlienVault",
    "ThreatFox", "URLhaus", "MalwareBazaar", "PhishTank",
    "Suricata", "Snort", "Zeek", "YARA", "Cyberint", "Recorded Future",
    "Sandbox",  # Internal malware analysis platform
    "Cyble",    # Cyble Threat Intelligence Feed
    "Zone-H",   # Defacement archive
    "MISP",
    "Cyble Threat Intelligence Feed",
]

# News Sources (lower weight)
NEWS_SOURCES = [
    "BleepingComputer", "DarkReading", "TheHackerNews", "The Hacker News",
    "Cyber News", "SecurityWeek", "KrebsOnSecurity"
]

# Confidence Thresholds
CONFIDENCE_THRESHOLDS = {
    "very_high": 0.93,  # +8 bonus
    "high": 0.85,       # +5 bonus
    "medium": 0.70,     # +2 bonus
    "low": 0.40         # no bonus
}

# ============================================
# SECTOR CLASSIFICATION
# ============================================
# Maps IOCs to target sectors based on keywords, domains, and threat actors

SECTORS = {
    "financial": {
        "name": "Banking and Finance",
        "name_th": "ด้านการเงินการธนาคาร",
        "icon": "🏦",
        "weight": 1.3,  # Higher impact multiplier
        "keywords": [
            # English
            "bank", "banking", "financial", "payment", "credit", "fintech",
            "trading", "cryptocurrency", "crypto", "wallet", "swift", "atm",
            "pos", "point of sale", "merchant", "insurance", "investment",
            "stock", "exchange", "fund", "loan", "mortgage",
            # Thai context (Phase 1.17)
            "ธนาคาร", "การเงิน", "การธนาคาร", "หลักทรัพย์", "ลงทุน",
            "ตลาดหลักทรัพย์", "บัตรเครดิต", "พร้อมเพย์", "promptpay",
            # Thai bank brand tokens — only words >=4 chars to avoid substring false positives.
            # Short codes (scb/ktb/bbl/uob/etc.) live in domains[] where token-level
            # matching prevents 3-letter substring traps like "rtadlnacz".
            "kasikorn", "kbank", "bangkokbank",
            "krungsri", "krungthai", "ttbbank", "tmbthanachart",
            "cimbthai", "thanachart", "ghbank", "lhbank",
            "kiatnakin", "kkpfg",
            # International brands often phished (Phase 1.17)
            "paypal", "venmo", "zelle", "cashapp", "wise", "revolut", "n26",
            "stripe", "square", "klarna", "afterpay",
            # Crypto exchanges & wallets (very common phishing target)
            "binance", "coinbase", "kraken", "bitfinex", "huobi", "okx",
            "metamask", "trustwallet", "tokenpocket", "imtoken", "phantom",
            "ledger", "trezor", "exodus", "uniswap", "pancakeswap",
            # Major international banks
            "hsbc", "citi", "citibank", "chase", "wellsfargo", "bofa",
            "bankofamerica", "barclays", "santander", "bbva", "garanti",
            "natwest", "rbs", "lloyds", "deutsche", "credit-suisse",
        ],
        "domains": [
            ".bank.", ".finance.", "pay.", "crypto.",
            # Thai bank domains — full domain substring (safe)
            "scb.co.th", "scbeasy", "kasikornbank", "kbank.co.th",
            "ktb.co.th", "bangkokbank.com", "krungsri.com",
            "krungthai.com", "ttbbank.com", "uob.co.th",
            "cimbthai.com", "thanachart.co.th", "ghbank.co.th",
            "gsb.or.th", "lhbank.co.th", "kkpfg.com",
            "bot.or.th", "set.or.th", "sec.or.th",
            # Thai bank bare tokens — token-level match (split by . _ -) prevents false positives
            "scb", "ktb", "bbl", "uob", "ghb", "gsb", "exim",
            # International payment / crypto domains (full substring)
            "paypal.com", "venmo.com", "cashapp.com", "stripe.com",
            "binance.com", "coinbase.com", "kraken.com", "metamask.io",
            "trustwallet.com", "tokenpocket.pro", "imtoken.io",
            "hsbc.com", "chase.com", "wellsfargo.com", "barclays.com",
            # International payment / crypto bare tokens (token-level match)
            "paypal", "venmo", "stripe", "binance", "coinbase", "kraken",
            "metamask", "trustwallet", "tokenpocket", "imtoken",
            "hsbc", "chase", "barclays", "santander", "bbva", "garanti",
        ],
        "threat_actors": ["Lazarus", "FIN7", "FIN8", "Carbanak", "Cobalt Group",
                          "Qakbot", "TrickBot", "IcedID", "Emotet"]
    },
    "government": {
        "name": "Substantive Public Services",
        "name_th": "ด้านบริการภาครัฐที่สำคัญ",
        "icon": "🏛️",
        "weight": 1.4,  # Highest impact multiplier
        "keywords": [
            # English
            "government", "ministry", "agency", "federal", "state", "municipal",
            "embassy", "diplomatic", "military", "defense",
            "parliament", "senate", "congress", "election", "voting",
            "public sector", "civil service", "national security",
            # Thai context (Phase 1.17)
            "รัฐบาล", "กระทรวง", "กรม", "สำนัก", "หน่วยงานรัฐ",
            "ภาครัฐ", "ราชการ", "ความมั่นคง", "กลาโหม",
            # Thai gov agency tokens — only longer words (>=4 chars) safe for substring.
            # Short 3-char codes (mof, mfa, moi, moe, moj, mol, nia, rta, rtn) moved to
            # domains[] where token-level matching avoids false positives.
            "ncsa", "etda", "depa", "moph", "moac", "rtaf", "rtarf", "isoc",
        ],
        "domains": [
            ".gov.", ".go.th", ".mil.", ".mod.", ".mfa.",
            # Thai government domains (full substring — safe)
            "etda.or.th", "depa.or.th", "ncsa.or.th",
            "moph.go.th", "mof.go.th", "mfa.go.th", "moe.go.th",
            "moac.go.th", "moj.go.th", "mol.go.th", "moi.go.th",
            "rtaf.mi.th", "navy.mi.th", "rta.mi.th",
            # Short Thai gov agency tokens (token-level match avoids false positives)
            "mof", "mfa", "moi", "moe", "moj", "mol", "nia", "rta", "rtn",
        ],
        "threat_actors": ["APT28", "APT29", "APT41", "Sandworm", "Turla",
                          "Equation Group", "Charming Kitten", "MuddyWater", "OilRig"]
    },
    "healthcare": {
        "name": "Public Health",
        "name_th": "ด้านสาธารณสุข",
        "icon": "🏥",
        "weight": 1.3,
        "keywords": [
            # English
            "hospital", "health", "medical", "pharmaceutical", "clinic", "patient",
            "doctor", "nurse", "medicine", "drug", "vaccine", "laboratory",
            "diagnostic", "treatment", "surgery", "emergency", "ambulance",
            "healthcare", "public health", "epidem",
            # Thai context (Phase 1.17)
            "สาธารณสุข", "โรงพยาบาล", "คลินิก", "การแพทย์",
            "ยา", "วัคซีน", "อนามัย", "ผู้ป่วย", "แพทย์", "พยาบาล",
            # Thai hospital brands
            "siriraj", "ramathibodi", "chulalongkorn", "phyathai",
            "bumrungrad", "samitivej", "bangkokhospital", "bdms",
            "siphhospital", "rajavithi", "vichaiyut", "siphhospital",
            "ku.ac.th", "mahidol", "phramongkutklao",
        ],
        "domains": [
            ".health.", ".hospital.", ".med.", ".clinic.",
            # Thai healthcare (Phase 1.17)
            ".hosp.go.th", "moph.go.th",
            "siriraj.go.th", "rama.mahidol.ac.th", "chula.ac.th",
            "bangkokhospital.com", "samitivejhospitals.com",
            "bumrungrad.com", "phyathai.com", "bdms.co.th",
        ],
        "threat_actors": ["Conti", "Royal", "Ryuk", "Maze", "BlackCat"]
    },
    "education": {
        "name": "Education",
        "name_th": "ภาคการศึกษา",
        "icon": "🎓",
        "weight": 1.0,
        "keywords": [
            # English
            "university", "school", "college", "education", "academic", "research",
            "student", "professor", "faculty", "campus", "library", "scholar",
            "institute", "academy", "learning", "course", "curriculum",
            # Thai context (Phase 1.17)
            "มหาวิทยาลัย", "โรงเรียน", "การศึกษา", "นิสิต", "นักศึกษา",
            "ครู", "อาจารย์", "วิทยาลัย", "สถาบัน",
            # Thai universities
            "chula", "mahidol", "thammasat", "kasetsart", "chiangmai",
            "khonkaen", "ku.ac.th", "kmutt", "kmitl", "kmutnb",
            "ait.ac.th", "mu.ac.th", "psu.ac.th",
        ],
        "domains": [
            ".edu.", ".ac.th", ".edu.th", ".ac.", ".university.",
            # Thai universities (Phase 1.17)
            "chula.ac.th", "mahidol.ac.th", "tu.ac.th", "ku.ac.th",
            "cmu.ac.th", "kku.ac.th", "kmutt.ac.th", "kmitl.ac.th",
            "kmutnb.ac.th", "psu.ac.th", "swu.ac.th", "mu.ac.th",
        ],
        "threat_actors": ["Charming Kitten"]  # Known to target academics
    },
    "critical_infrastructure": {
        "name": "Energy and Public Utilities",
        "name_th": "ด้านพลังงานและสาธารณูปโภค",
        "icon": "⚡",
        "weight": 1.5,  # Highest impact
        "keywords": [
            # English
            "power", "energy", "electricity", "water", "utility", "grid", "pipeline",
            "transportation", "rail", "airport", "port", "logistics",
            "oil", "gas", "refinery", "nuclear", "dam", "scada", "ics", "ot",
            # Thai context (Phase 1.17)
            "พลังงาน", "ไฟฟ้า", "น้ำมัน", "ก๊าซ", "ประปา",
            "การไฟฟ้า", "การประปา", "สาธารณูปโภค", "โรงไฟฟ้า",
            # Thai utilities — only longer brand words safe for substring keyword match
            "pttep", "pttgc", "irpc", "esso", "metropolitan",
            "thai-airways", "airportthai", "thairailway",
        ],
        "domains": [
            ".energy.", ".power.", ".utility.",
            # Thai utilities full domain (safe substring)
            "egat.co.th", "pea.co.th", "mea.or.th",
            "pttplc.com", "pttep.com", "pttgc.com",
            "bangchak.co.th", "irpc.co.th",
            "airportthai.co.th", "aot.co.th",
            "srt.or.th", "mrta.co.th", "bts.co.th",
            # Short Thai utility tokens (token-level match)
            "egat", "pea", "mea", "ptt", "aot", "srt", "mrta", "bts", "bcp",
        ],
        "threat_actors": ["Sandworm", "Xenotime", "Triton", "Havex"]
    },
    "technology": {
        "name": "Information Technology and Telecommunications",
        "name_th": "ด้านเทคโนโลยีสารสนเทศและโทรคมนาคม",
        "icon": "💻",
        "weight": 1.1,
        "keywords": [
            # English
            "software", "hardware", "tech", "technology", "saas", "cloud",
            "data center", "hosting", "developer", "programming", "code",
            "api", "platform", "startup", "vendor", "supplier", "mssp",
            # Telecom (moved from critical_infrastructure to align with dashboard taxonomy)
            "telecom", "telecommunications", "network", "internet", "isp",
            "mobile", "cellular", "broadband", "fiber", "5g",
            # Thai context (Phase 1.17)
            "เทคโนโลยี", "โทรคมนาคม", "อินเทอร์เน็ต", "ไอที", "ซอฟต์แวร์",
            "ผู้ให้บริการอินเทอร์เน็ต", "เครือข่าย",
            # Thai telecom + IT brands — only longer words safe for substring
            "advanced-info", "truemove", "truemoveh", "true-corp",
            "totalaccess", "cat-telecom", "samartcorp", "sammart", "interlink",
            # Global cloud / CDN
            "aws", "amazon-aws", "azure", "gcp", "cloudflare", "akamai",
            "fastly", "github", "gitlab", "digitalocean", "linode",
            # Major SaaS / social tech often phished (Phase 1.17)
            "google", "gmail", "microsoft", "office365", "outlook",
            "apple", "icloud", "yahoo", "dropbox",
            "facebook", "instagram", "whatsapp", "messenger",
            "twitter", "tiktok", "snapchat", "linkedin", "discord",
            "telegram", "signal", "zoom", "teams", "slack",
            "spotify", "netflix", "youtube", "amazon",
            "airbnb", "uber", "lyft", "doordash",
            "shopify", "wordpress", "wix", "squarespace",
        ],
        "domains": [
            ".tech.", ".io", ".dev", ".cloud.",
            # Thai telecom full domains (safe substring)
            "ais.co.th", "truecorp.co.th", "truemoveh.com",
            "dtac.co.th", "dtac.com", "nt.co.th", "nt-tv.co.th",
            "tot.co.th", "cattelecom.com",
            # Short Thai telecom tokens (token-level match)
            "ais", "dtac", "tot",
            # Global IT brand full domains
            "amazonaws.com", "azure.com", "microsoft.com",
            "cloudflare.com", "github.com", "githubusercontent.com",
        ],
        "threat_actors": ["APT41", "Winnti", "Barium"]
    },
    "state_security": {
        # NCSA: ด้านความมั่นคงของรัฐ (military, police, intelligence, DSI, NSC)
        "name": "National Security",
        "name_th": "ด้านความมั่นคงของรัฐ",
        "icon": "🛡️",
        "weight": 1.5,  # Highest impact alongside critical_infrastructure
        "keywords": [
            # English
            "national security", "military", "armed forces", "defense", "defence",
            "police", "law enforcement", "intelligence", "counterintelligence",
            "border patrol", "dsi", "nsc",
            # Thai (from NCSA agency CSV)
            "ความมั่นคงของรัฐ", "ด้านความมั่นคงของรัฐ",
            "กองทัพ", "กองทัพบก", "กองทัพเรือ", "กองทัพอากาศ",
            "กองทัพไทย", "ทหาร", "กลาโหม",
            "ตำรวจ", "ตำรวจแห่งชาติ", "ตำรวจภูธร",
            "สอบสวนคดีพิเศษ", "ข่าวกรอง", "ข่าวกรองแห่งชาติ",
            "สภาความมั่นคงแห่งชาติ", "รักษาความมั่นคง",
            "ตำรวจตระเวนชายแดน", "ศาลปกครอง",
        ],
        "domains": [
            # Distinctive Thai gov/military domains for state security
            ".mi.th", ".mil.th",
            "police.go.th", "royalthaipolice.go.th",
            "dsi.go.th", "nia.go.th",
            "rta.mi.th", "navy.mi.th", "rtaf.mi.th",
            "isoc.go.th", "mod.go.th",
            "admincourt.go.th",
            "police", "rtp", "dsi", "isoc",
        ],
        "threat_actors": ["APT28", "APT29", "Sandworm", "Turla",
                          "Equation Group", "MuddyWater", "Mustang Panda"]
    },
    "transportation": {
        # NCSA: ด้านการขนส่งและโลจิสติกส์ (airlines, rail, port, road, aviation)
        "name": "Transportation and Logistics",
        "name_th": "ด้านการขนส่งและโลจิสติกส์",
        "icon": "🚆",
        "weight": 1.2,
        "keywords": [
            # English
            "transportation", "transport", "logistics", "airline", "airport",
            "aviation", "railway", "rail", "metro", "port", "shipping",
            "freight", "cargo", "airways",
            # Thai (from NCSA agency CSV)
            "การขนส่งและโลจิสติกส์", "ด้านการขนส่งและโลจิสติกส์",
            "ขนส่ง", "คมนาคม", "การบิน", "การบินพลเรือน",
            "การรถไฟ", "การท่าเรือ", "การท่าอากาศยาน",
            "การบินไทย", "ไทยแอร์เอเชีย", "ไทยเวียตเจ็ท",
            "นกแอร์", "การบินกรุงเทพ", "วิทยุการบิน",
            "รถไฟฟ้า", "ระบบขนส่งมวลชน",
            "อุตุนิยมวิทยา",
            # Brand tokens >= 4 chars
            "airasia", "vietjet", "nokair", "thaiairways", "bangkokair",
        ],
        "domains": [
            # Full domain substrings
            "thaiairways.com", "airasia.com", "bangkokair.com",
            "nokair.com", "vietjetair.com",
            "airportthai.co.th", "aot.co.th",
            "srt.or.th", "mrta.co.th", "bts.co.th",
            "dlt.go.th", "drr.go.th", "doh.go.th",
            "caat.or.th", "md.go.th", "port.co.th",
            # Bare tokens
            "thai-airways", "aot", "srt", "mrta", "bts",
            "dlt", "doh", "caat",
        ],
        "threat_actors": ["APT41", "Lazarus", "Carbanak"]
    },
    "general": {
        "name": "Other",
        "name_th": "อื่นๆ",
        "icon": "🌐",
        "weight": 1.0,
        "keywords": [],
        "domains": [],
        "threat_actors": []
    }
}

# Sector impact on scoring
SECTOR_RISK_BONUS = {
    "state_security": 15,
    "government": 12,
    "critical_infrastructure": 15,
    "healthcare": 10,
    "financial": 10,
    "transportation": 10,
    "technology": 5,
    "education": 0,
    "general": 0
}
