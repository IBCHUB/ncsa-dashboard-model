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
THREAT_CATEGORIES = list(LABEL_MAPPING.values())

# ============================================
# ENHANCED SCORING CONFIGURATION
# ============================================

# Risk Scoring Weights (sum = 1.0)
# NOTE: geo_risk removed - data source not auditable
SCORING_WEIGHTS = {
    "cross_source": 0.25,      # พบจากหลายแหล่ง
    "threat_intel_source": 0.15,  # แหล่งน่าเชื่อถือ
    "high_risk_keywords": 0.10,   # คำสำคัญอันตราย
    "domain_age": 0.10,        # อายุโดเมน
    "entropy": 0.05,           # ความสุ่ม (DGA)
    "threat_type_severity": 0.20,  # AI: ประเภทภัยคุกคาม
    "threat_actor": 0.10,          # AI: กลุ่มผู้โจมตี
    "mitre_techniques": 0.05       # AI: MITRE ATT&CK
}

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

# Backward-compatible flat list (auto-generated from tiered)
HIGH_RISK_KEYWORDS = []
for tier_info in HIGH_RISK_KEYWORDS_TIERED.values():
    HIGH_RISK_KEYWORDS.extend(tier_info["keywords"])

# High Risk Countries (ISO Alpha-2)
HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "IR", "BY", "SY", "VE"]

# Trusted Threat Intel Sources
TRUSTED_SOURCES = [
    "VirusTotal", "AbuseIPDB", "MITRE", "AlienVault",
    "ThreatFox", "URLhaus", "MalwareBazaar", "PhishTank",
    "Suricata", "Snort", "Zeek", "YARA", "Cyberint", "Recorded Future",
    "Sandbox"  # Internal malware analysis platform
]

# News Sources (lower weight)
NEWS_SOURCES = [
    "BleepingComputer", "DarkReading", "TheHackerNews",
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
        "name": "Financial Services",
        "name_th": "ภาคการเงิน",
        "icon": "🏦",
        "weight": 1.3,  # Higher impact multiplier
        "keywords": [
            "bank", "banking", "financial", "payment", "credit", "fintech",
            "trading", "cryptocurrency", "crypto", "wallet", "swift", "atm",
            "pos", "point of sale", "merchant", "insurance", "investment",
            "stock", "exchange", "fund", "loan", "mortgage"
        ],
        "domains": [".bank.", ".finance.", "pay.", "crypto."],
        "threat_actors": ["Lazarus", "FIN7", "FIN8", "Carbanak", "Cobalt Group", 
                          "Qakbot", "TrickBot", "IcedID", "Emotet"]
    },
    "government": {
        "name": "Government",
        "name_th": "ภาครัฐ",
        "icon": "🏛️",
        "weight": 1.4,  # Highest impact multiplier
        "keywords": [
            "government", "ministry", "agency", "federal", "state", "municipal",
            "embassy", "diplomatic", "military", "defense", "intelligence",
            "parliament", "senate", "congress", "election", "voting",
            "public sector", "civil service", "national security"
        ],
        "domains": [".gov.", ".go.th", ".mil.", ".mod.", ".mfa."],
        "threat_actors": ["APT28", "APT29", "APT41", "Sandworm", "Turla", 
                          "Equation Group", "Charming Kitten", "MuddyWater", "OilRig"]
    },
    "healthcare": {
        "name": "Healthcare",
        "name_th": "ภาคสาธารณสุข",
        "icon": "🏥",
        "weight": 1.3,
        "keywords": [
            "hospital", "health", "medical", "pharmaceutical", "clinic", "patient",
            "doctor", "nurse", "medicine", "drug", "vaccine", "laboratory",
            "diagnostic", "treatment", "surgery", "emergency", "ambulance",
            "healthcare", "public health", "epidem"
        ],
        "domains": [".health.", ".hospital.", ".med.", ".clinic."],
        "threat_actors": ["Conti", "Royal", "Ryuk", "Maze", "BlackCat"]
    },
    "education": {
        "name": "Education",
        "name_th": "ภาคการศึกษา",
        "icon": "🎓",
        "weight": 1.0,
        "keywords": [
            "university", "school", "college", "education", "academic", "research",
            "student", "professor", "faculty", "campus", "library", "scholar",
            "institute", "academy", "learning", "course", "curriculum"
        ],
        "domains": [".edu.", ".ac.th", ".edu.th", ".ac.", ".university."],
        "threat_actors": ["Charming Kitten"]  # Known to target academics
    },
    "critical_infrastructure": {
        "name": "Critical Infrastructure",
        "name_th": "โครงสร้างพื้นฐาน",
        "icon": "⚡",
        "weight": 1.5,  # Highest impact
        "keywords": [
            "power", "energy", "electricity", "water", "utility", "grid", "pipeline",
            "telecom", "telecommunications", "network", "internet", "isp",
            "transportation", "rail", "airport", "port", "logistics",
            "oil", "gas", "refinery", "nuclear", "dam", "scada", "ics", "ot"
        ],
        "domains": [".energy.", ".power.", ".utility."],
        "threat_actors": ["Sandworm", "Xenotime", "Triton", "Havex"]
    },
    "technology": {
        "name": "Technology",
        "name_th": "ภาคเทคโนโลยี",
        "icon": "💻",
        "weight": 1.1,
        "keywords": [
            "software", "hardware", "tech", "technology", "saas", "cloud",
            "data center", "hosting", "developer", "programming", "code",
            "api", "platform", "startup", "vendor", "supplier", "mssp"
        ],
        "domains": [".tech.", ".io", ".dev", ".cloud."],
        "threat_actors": ["APT41", "Winnti", "Barium"]
    },
    "general": {
        "name": "General/Multiple",
        "name_th": "ทั่วไป",
        "icon": "🌐",
        "weight": 1.0,
        "keywords": [],
        "domains": [],
        "threat_actors": []
    }
}

# Sector impact on scoring
SECTOR_RISK_BONUS = {
    "government": 12,
    "critical_infrastructure": 15,
    "healthcare": 10,
    "financial": 10,
    "technology": 5,
    "education": 0,
    "general": 0
}
