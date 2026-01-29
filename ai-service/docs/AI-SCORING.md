# AI Scoring System Documentation

> **Last Updated:** 2026-01-29  
> **Source:** [scorer.py](file:///Users/mm/Desktop/Cyber/ai-service/models/scorer.py), [config.py](file:///Users/mm/Desktop/Cyber/ai-service/config.py)

## ภาพรวม

ระบบ AI Scoring ใช้ **10 ปัจจัย** ในการคำนวณคะแนนความเสี่ยง (0-100) พร้อม **Decay Factor** สำหรับ IOC ที่เก่า

---

## สูตรการคำนวณ

```
Total Score = Σ(Factor Scores) × Decay Multiplier
```

**Decay Multiplier:**
- IOC < 7 วัน → 1.0 (ไม่ลด)
- IOC 7-30 วัน → 0.9
- IOC 30-90 วัน → 0.75
- IOC 90-180 วัน → 0.6
- IOC > 180 วัน → 0.5

---

## ปัจจัยการให้คะแนน (10 ปัจจัย)

### 1. Cross-Source Validation (Max: 25 คะแนน)
**น้ำหนัก:** 25%

| จำนวนแหล่งที่พบ | คะแนน |
|----------------|-------|
| 1 แหล่ง | 5 |
| 2 แหล่ง | 12 |
| 3 แหล่ง | 18 |
| 4+ แหล่ง | 25 |

**หลักการ:** IOC ที่พบจากหลายแหล่งมีความน่าเชื่อถือสูง

---

### 2. Source Quality (Max: 15 คะแนน)
**น้ำหนัก:** 15%

**Trusted Sources (15 คะแนน/แหล่ง):**
- VirusTotal, AbuseIPDB, MITRE, AlienVault
- ThreatFox, URLhaus, MalwareBazaar, PhishTank
- Suricata, Snort, Zeek, YARA
- Cyberint, Recorded Future, **Sandbox**

**News Sources (5 คะแนน/แหล่ง):**
- BleepingComputer, DarkReading, TheHackerNews
- Cyber News, SecurityWeek, KrebsOnSecurity

---

### 3. Threat Type Severity (Max: 35 คะแนน)
**น้ำหนัก:** 15%

#### Level 1 - Critical (ร้ายแรงมาก)
| ประเภท | คะแนน | คำอธิบาย |
|--------|-------|----------|
| Ransomware | 25 | การเข้ารหัสเรียกค่าไถ่ |
| APT | 25 | Advanced Persistent Threat |
| C2 | 25 | Command & Control Server |
| Wiper | 25 | มัลแวร์ลบข้อมูล |
| Botnet | 22 | เครือข่ายบอท |

#### Level 2 - High (ร้ายแรง)
| ประเภท | คะแนน | คำอธิบาย |
|--------|-------|----------|
| Malware | 18 | มัลแวร์ทั่วไป |
| Credential Theft | 18 | การขโมย credentials |
| Backdoor | 18 | ช่องทางลับ |
| Exploit | 17 | โค้ดโจมตีช่องโหว่ |
| Trojan | 16 | โทรจัน |
| Data Breach | 15 | การรั่วไหลของข้อมูล |

#### Level 3 - Medium (ปานกลาง)
| ประเภท | คะแนน | คำอธิบาย |
|--------|-------|----------|
| Phishing | 12 | การหลอกลวง |
| DDoS | 10 | Distributed DoS |
| Spam | 8 | สแปม |
| Scanning | 6 | การสแกนหาช่องโหว่ |

#### Level 4 - Low (ต่ำ)
| ประเภท | คะแนน | คำอธิบาย |
|--------|-------|----------|
| Vulnerability | 8 | ช่องโหว่ที่รู้จัก |
| Defacement | 5 | การเปลี่ยนแปลงหน้าเว็บ |
| Other | 3 | อื่นๆ |

---

### 4. Threat Actor Attribution (Max: 30 คะแนน)
**น้ำหนัก:** 10%

#### Nation-State APT Groups (30 คะแนน)
| กลุ่ม | ประเทศ | เป้าหมาย |
|-------|--------|----------|
| Lazarus (Hidden Cobra) | 🇰🇵 | Finance, Crypto |
| APT28 (Fancy Bear) | 🇷🇺 | Government, Military |
| APT29 (Cozy Bear) | 🇷🇺 | Government, Think Tanks |
| APT41 (Winnti) | 🇨🇳 | Gaming, Tech |
| Sandworm | 🇷🇺 | Energy, Government |

#### Ransomware Groups (25 คะแนน)
| กลุ่ม | เป้าหมาย |
|-------|----------|
| LockBit | Enterprise |
| BlackCat (ALPHV) | Enterprise |
| Conti | Healthcare, Enterprise |
| REvil | Enterprise |

#### Cybercrime Groups (20 คะแนน)
FIN7, FIN8, Qakbot, Emotet, TrickBot, IcedID

---

### 5. MITRE ATT&CK Techniques (Max: 20 คะแนน)
**น้ำหนัก:** 5%

| Technique | ID | คะแนน |
|-----------|-----|-------|
| Command and Control | TA0011 | 8 |
| Exfiltration | TA0010 | 8 |
| Impact | TA0040 | 8 |
| Lateral Movement | TA0008 | 7 |
| Credential Access | TA0006 | 7 |
| Persistence | TA0003 | 6 |
| Privilege Escalation | TA0004 | 6 |
| Defense Evasion | TA0005 | 6 |

---

### 6. High-Risk Keywords (Max: 20 คะแนน)
**น้ำหนัก:** 10%

**Keyword List:**
```
ransomware, zero-day, 0day, exploit, active,
lazarus, apt, backdoor, c2, cnc, botnet, credential,
phishing, malware, trojan, wiper, lockbit,
conti, revil, emotet, trickbot, cobalt strike,
obfuscated, c&c, command and control, exfiltration,
lateral movement, privilege escalation, persistence, rootkit,
keylogger, stealer, banker, infostealer, loader, dropper
```

**หมายเหตุ:** ลบ `critical`, `encryption`, `encrypted` ออกแล้ว (False Positive สูง)

---

### 7. Domain Age (Max: 20 คะแนน)
**น้ำหนัก:** 10%

| อายุโดเมน | คะแนน |
|-----------|-------|
| < 7 วัน | 20 |
| 7-30 วัน | 15 |
| 30-90 วัน | 10 |
| 90-365 วัน | 5 |
| > 1 ปี | 0 |

---

### 8. Entropy (DGA Detection) (Max: 15 คะแนน)
**น้ำหนัก:** 5%

**Shannon Entropy** ใช้ตรวจจับ Domain Generated Algorithm (DGA)

| ค่า Entropy | คะแนน | ความหมาย |
|-------------|-------|----------|
| > 4.0 | 15 | สูงมาก (อาจเป็น DGA) |
| 3.5-4.0 | 10 | สูง (น่าสงสัย) |
| 3.0-3.5 | 5 | ปานกลาง |
| < 3.0 | 0 | ปกติ |

---

### 9. AI Confidence Bonus (Max: 10 คะแนน)
**น้ำหนัก:** 5%

| ระดับความมั่นใจ | Threshold | คะแนนโบนัส |
|----------------|-----------|------------|
| Very High | ≥ 90% | +10 |
| High | ≥ 80% | +7 |
| Medium | ≥ 60% | +3 |
| Low | < 60% | 0 |

---

### 10. Geo-Risk (ปิดใช้งาน)
**สถานะ:** ❌ Disabled

**เหตุผล:** ข้อมูลประเทศต้นทางจากแหล่ง feed ไม่สามารถ audit ได้

---

## ระดับความรุนแรง (Severity Levels)

| คะแนน | ระดับ | สี |
|-------|-------|-----|
| 75-100 | Critical | 🔴 |
| 50-74 | High | 🟠 |
| 25-49 | Medium | 🟡 |
| 0-24 | Low | 🟢 |

---

## ตัวอย่างการคำนวณ

**IOC:** `45.155.205[.]233`  
**แหล่งที่พบ:** VirusTotal, Sandbox (2 แหล่ง)  
**ประเภท:** APT, C2  
**Threat Actor:** Lazarus  
**Keywords:** apt, c2, backdoor  

```
Cross-Source:     12 (2 แหล่ง)
Source Quality:   15 (VirusTotal=Trusted) + 15 (Sandbox=Trusted) = 30 → max 15
Threat Type:      25 (APT) + 25 (C2) = 50 → max 35
Threat Actor:     30 (Lazarus)
Keywords:         15 (3 keywords)
------------------------------------------------
Raw Total:        107 → Normalized: 85

Decay Factor:     1.0 (IOC อายุ 2 วัน)
------------------------------------------------
Final Score:      85 (Critical)
```

---

## การปรับปรุงเกณฑ์

หากต้องการปรับเกณฑ์ ให้แก้ไขไฟล์:
- **น้ำหนักปัจจัย:** `config.py` → `SCORING_WEIGHTS`
- **คะแนนประเภทภัย:** `config.py` → `THREAT_TYPE_SEVERITY`
- **กลุ่มผู้โจมตี:** `config.py` → `KNOWN_THREAT_ACTORS`
- **MITRE Tactics:** `config.py` → `MITRE_TACTICS`
- **Keywords:** `config.py` → `HIGH_RISK_KEYWORDS`
