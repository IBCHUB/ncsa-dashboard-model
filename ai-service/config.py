"""
Configuration for AI Service
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Server Configuration
HOST = os.getenv("AI_SERVICE_HOST", "0.0.0.0")
PORT = int(os.getenv("AI_SERVICE_PORT", "8000"))
DEBUG = os.getenv("AI_SERVICE_DEBUG", "false").lower() == "true"

# Authentication Configuration
# API Keys for authentication (comma-separated in env var)
# In production, set AI_SERVICE_API_KEYS env var with secure keys
_default_keys = "tcti-dev-key-2024,tcti-dashboard-key"
API_KEYS = set(os.getenv("AI_SERVICE_API_KEYS", _default_keys).split(","))
REQUIRE_AUTH = os.getenv("AI_SERVICE_REQUIRE_AUTH", "true").lower() == "true"

# Model Configuration
# Using a lighter model for CPU compatibility
CLASSIFIER_MODEL = os.getenv(
    "CLASSIFIER_MODEL", 
    "typeform/distilbert-base-uncased-mnli"  # Lighter zero-shot model
)

# Use CPU by default (no CUDA)
DEVICE = os.getenv("DEVICE", "cpu")

# Threat Categories for Classification
THREAT_CATEGORIES = [
    "Ransomware",
    "Phishing",
    "Malware",
    "Data Breach",
    "DDoS",
    "APT",
    "Defacement",
    "Vulnerability",
    "Botnet",
    "C2",
    "Credential Theft",
    "Other"
]

# ============================================
# ENHANCED SCORING CONFIGURATION
# ============================================

# Risk Scoring Weights (sum = 1.0)
# NOTE: geo_risk removed - data source not auditable
SCORING_WEIGHTS = {
    "cross_source": 0.25,      # พบจากหลายแหล่ง (เพิ่มจาก 0.20)
    "threat_intel_source": 0.15,  # แหล่งน่าเชื่อถือ
    "high_risk_keywords": 0.10,   # คำสำคัญอันตราย
    "domain_age": 0.10,        # อายุโดเมน
    "entropy": 0.05,           # ความสุ่ม (DGA)
    # geo_risk removed - ไม่มีแหล่งข้อมูลที่ตรวจสอบได้
    # New NLP-based factors
    "threat_type_severity": 0.15,  # AI: ประเภทภัยคุกคาม
    "threat_actor": 0.10,          # AI: กลุ่มผู้โจมตี
    "mitre_techniques": 0.05,      # AI: MITRE ATT&CK
    "ai_confidence": 0.05          # AI: ความมั่นใจในการจำแนก
}

# Threat Type Severity Levels
# Level 1 (Critical): Maximum impact, nation-state or destructive
# Level 2 (High): Significant impact, common attack vectors
# Level 3 (Medium): Moderate impact, less targeted
THREAT_TYPE_SEVERITY = {
    # Level 1 - Critical (25 points)
    "Ransomware": {"level": 1, "score": 25, "description": "การเข้ารหัสเรียกค่าไถ่"},
    "APT": {"level": 1, "score": 25, "description": "การโจมตีแบบ Advanced Persistent Threat"},
    "C2": {"level": 1, "score": 25, "description": "เซิร์ฟเวอร์ Command & Control"},
    "Botnet": {"level": 1, "score": 22, "description": "เครือข่ายบอท"},
    "Wiper": {"level": 1, "score": 25, "description": "มัลแวร์ลบข้อมูล"},
    
    # Level 2 - High (15-20 points)
    "Malware": {"level": 2, "score": 18, "description": "มัลแวร์ทั่วไป"},
    "Credential Theft": {"level": 2, "score": 18, "description": "การขโมย credentials"},
    "Trojan": {"level": 2, "score": 16, "description": "โทรจัน"},
    "Backdoor": {"level": 2, "score": 18, "description": "ช่องทางลับ"},
    "Exploit": {"level": 2, "score": 17, "description": "โค้ดโจมตีช่องโหว่"},
    "Data Breach": {"level": 2, "score": 15, "description": "การรั่วไหลของข้อมูล"},
    
    # Level 3 - Medium (10-15 points)
    "Phishing": {"level": 3, "score": 12, "description": "การหลอกลวง"},
    "DDoS": {"level": 3, "score": 10, "description": "การโจมตี Distributed DoS"},
    "Spam": {"level": 3, "score": 8, "description": "สแปม"},
    "Scanning": {"level": 3, "score": 6, "description": "การสแกนหาช่องโหว่"},
    
    # Level 4 - Low (5-10 points)
    "Vulnerability": {"level": 4, "score": 8, "description": "ช่องโหว่ที่รู้จัก"},
    "Defacement": {"level": 4, "score": 5, "description": "การเปลี่ยนแปลงหน้าเว็บ"},
    "Other": {"level": 4, "score": 3, "description": "อื่นๆ"}
}

# Known Threat Actors Database
# Score based on sophistication and impact
KNOWN_THREAT_ACTORS = {
    # Nation-State APT Groups (30 points)
    "Lazarus": {"score": 30, "origin": "KP", "aliases": ["Hidden Cobra", "ZINC"], "targets": ["Finance", "Crypto"]},
    "APT28": {"score": 30, "origin": "RU", "aliases": ["Fancy Bear", "Sofacy"], "targets": ["Government", "Military"]},
    "APT29": {"score": 30, "origin": "RU", "aliases": ["Cozy Bear", "Nobelium"], "targets": ["Government", "Think Tanks"]},
    "APT41": {"score": 30, "origin": "CN", "aliases": ["Winnti", "Barium"], "targets": ["Gaming", "Tech"]},
    "Sandworm": {"score": 30, "origin": "RU", "aliases": ["Voodoo Bear"], "targets": ["Energy", "Government"]},
    "Equation Group": {"score": 30, "origin": "US", "aliases": ["EQGRP"], "targets": ["Government"]},
    "Charming Kitten": {"score": 28, "origin": "IR", "aliases": ["APT35", "Phosphorus"], "targets": ["Journalists", "Academics"]},
    "MuddyWater": {"score": 28, "origin": "IR", "aliases": ["MERCURY"], "targets": ["Government", "Telco"]},
    
    # Ransomware Groups (25 points)
    "LockBit": {"score": 25, "origin": "RU", "aliases": ["ABCD"], "targets": ["Enterprise"]},
    "BlackCat": {"score": 25, "origin": "RU", "aliases": ["ALPHV"], "targets": ["Enterprise"]},
    "Conti": {"score": 25, "origin": "RU", "aliases": ["Wizard Spider"], "targets": ["Healthcare", "Enterprise"]},
    "REvil": {"score": 25, "origin": "RU", "aliases": ["Sodinokibi"], "targets": ["Enterprise"]},
    "Cl0p": {"score": 24, "origin": "RU", "aliases": ["TA505"], "targets": ["Enterprise"]},
    "Play": {"score": 22, "origin": "Unknown", "aliases": [], "targets": ["Enterprise"]},
    "Royal": {"score": 22, "origin": "Unknown", "aliases": [], "targets": ["Healthcare"]},
    
    # Cybercrime Groups (20 points)
    "FIN7": {"score": 22, "origin": "RU", "aliases": ["Carbanak"], "targets": ["Finance", "Retail"]},
    "FIN8": {"score": 20, "origin": "Unknown", "aliases": [], "targets": ["Retail", "Hospitality"]},
    "Qakbot": {"score": 20, "origin": "Unknown", "aliases": ["QBot", "Quakbot"], "targets": ["Banking"]},
    "Emotet": {"score": 20, "origin": "Unknown", "aliases": ["Heodo"], "targets": ["All"]},
    "TrickBot": {"score": 20, "origin": "RU", "aliases": ["Trickster"], "targets": ["Banking"]},
    "IcedID": {"score": 18, "origin": "Unknown", "aliases": ["BokBot"], "targets": ["Banking"]},
    
    # Hacktivists (15 points)
    "Anonymous": {"score": 15, "origin": "Global", "aliases": [], "targets": ["Various"]},
    "LulzSec": {"score": 15, "origin": "Global", "aliases": [], "targets": ["Various"]},
    "GhostSec": {"score": 14, "origin": "Global", "aliases": [], "targets": ["Various"]},
    
    # Regional (10 points)
    "Cobalt Group": {"score": 18, "origin": "Unknown", "aliases": [], "targets": ["Finance"]},
    "OilRig": {"score": 20, "origin": "IR", "aliases": ["APT34", "Helix Kitten"], "targets": ["Telco", "Government"]}
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
HIGH_RISK_KEYWORDS = [
    "ransomware", "zero-day", "0day", "exploit", "active",
    "lazarus", "apt", "backdoor", "c2", "cnc", "botnet", "credential",
    "phishing", "malware", "trojan", "wiper", "lockbit",
    "conti", "revil", "emotet", "trickbot", "cobalt strike",
    # Additional keywords
    "obfuscated", "c&c", "command and control", "exfiltration",
    "lateral movement", "privilege escalation", "persistence", "rootkit",
    "keylogger", "stealer", "banker", "infostealer", "loader", "dropper"
]

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
    "very_high": 0.90,  # +10 bonus
    "high": 0.80,       # +7 bonus
    "medium": 0.60,     # +3 bonus
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
    "critical_infrastructure": 15,
    "government": 12,
    "healthcare": 10,
    "financial": 10,
    "technology": 5,
    "education": 3,
    "general": 0
}

