"""
Risk Scoring Model - Enhanced with NLP Classification

Calculate risk scores for IOCs based on multiple factors:
- Cross-source validation
- Source reliability
- High-risk keywords
- Domain age
- Entropy (DGA detection)
- Geolocation risk
- AI Classification (Threat Types, Actors, MITRE)
"""

from typing import List, Dict, Any, Optional
import math
import re
import logging

from config import (
    SCORING_WEIGHTS,
    HIGH_RISK_KEYWORDS,
    HIGH_RISK_COUNTRIES,
    TRUSTED_SOURCES,
    NEWS_SOURCES,
    THREAT_TYPE_SEVERITY,
    KNOWN_THREAT_ACTORS,
    MITRE_TACTICS,
    CONFIDENCE_THRESHOLDS,
    SECTOR_RISK_BONUS
)
from models.sector_classifier import classify_sector

logger = logging.getLogger(__name__)


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy suggests DGA-generated domains.
    
    Returns:
        Entropy value (0-4+ for ASCII, higher = more random)
    """
    if not text:
        return 0.0
    
    # Remove TLD for domain analysis
    text = text.split('.')[0] if '.' in text else text
    
    # Count character frequencies
    freq = {}
    for char in text.lower():
        if char.isalnum():
            freq[char] = freq.get(char, 0) + 1
    
    if not freq:
        return 0.0
    
    # Calculate entropy
    length = sum(freq.values())
    entropy = 0.0
    
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return round(entropy, 3)


def calculate_keyword_score(text: str) -> Dict[str, Any]:
    """
    Calculate score based on high-risk keyword presence.
    
    Returns:
        Dict with score and matched keywords
    """
    if not text:
        return {"score": 0, "keywords": []}
    
    text_lower = text.lower()
    matched = []
    
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword.lower() in text_lower:
            matched.append(keyword)
    
    # Score: max 25 points (5 keywords = max)
    score = min(len(matched) * 5, 25)
    
    return {
        "score": score,
        "keywords": matched
    }


def calculate_source_score(sources: List[str]) -> Dict[str, Any]:
    """
    Calculate score based on data sources.
    
    Returns:
        Dict with score and source breakdown
    """
    if not sources:
        return {"score": 0, "trusted": 0, "news": 0, "other": 0}
    
    trusted_count = 0
    news_count = 0
    other_count = 0
    
    for source in sources:
        source_upper = source.upper()
        
        if any(t.upper() in source_upper for t in TRUSTED_SOURCES):
            trusted_count += 1
        elif any(n.upper() in source_upper for n in NEWS_SOURCES):
            news_count += 1
        else:
            other_count += 1
    
    # Trusted sources worth more
    score = (trusted_count * 15) + (news_count * 8) + (other_count * 5)
    score = min(score, 40)  # Cap at 40
    
    return {
        "score": score,
        "trusted": trusted_count,
        "news": news_count,
        "other": other_count
    }


def calculate_cross_source_score(source_count: int) -> int:
    """
    Calculate score based on how many sources reported this IOC.
    """
    if source_count <= 0:
        return 0
    elif source_count == 1:
        return 5
    elif source_count == 2:
        return 15
    elif source_count == 3:
        return 25
    else:
        return min(30 + (source_count - 3) * 5, 40)


def calculate_geo_risk(country_code: Optional[str]) -> Dict[str, Any]:
    """
    Calculate risk based on geolocation.
    """
    if not country_code:
        return {"score": 0, "country": None, "is_high_risk": False}
    
    is_high_risk = country_code.upper() in HIGH_RISK_COUNTRIES
    score = 15 if is_high_risk else 0
    
    return {
        "score": score,
        "country": country_code.upper(),
        "is_high_risk": is_high_risk
    }


def calculate_domain_age_score(
    age_days: Optional[int],
    is_new_domain: bool = False
) -> Dict[str, Any]:
    """
    Calculate risk score based on domain age.
    Newer domains are riskier.
    """
    score = 0
    description = "Unknown age"
    
    if is_new_domain or (age_days is not None and age_days < 30):
        score = 20  # Very new domain
        description = "Very new (<30 days)"
    elif age_days is not None and age_days < 90:
        score = 15
        description = "New (30-90 days)"
    elif age_days is not None and age_days < 180:
        score = 10
        description = "Recent (90-180 days)"
    elif age_days is not None and age_days < 365:
        score = 5
        description = "Less than 1 year"
    elif age_days is not None:
        score = 0
        description = f"Established ({age_days} days)"
    
    return {
        "score": score,
        "days": age_days,
        "description": description
    }


def calculate_decay_factor(ioc_age_days: Optional[int]) -> Dict[str, Any]:
    """
    Calculate decay factor based on IOC age.
    Older IOCs are less relevant and should have reduced scores.
    
    Args:
        ioc_age_days: Age of IOC in days since first seen
        
    Returns:
        Dict with decay multiplier and description
    """
    if ioc_age_days is None:
        return {
            "multiplier": 1.0,
            "reduction_percent": 0,
            "description": "ไม่ทราบอายุ IOC",
            "descriptionEn": "IOC age unknown"
        }
    
    if ioc_age_days <= 7:
        # Fresh IOC - full score
        multiplier = 1.0
        description = "IOC ใหม่ (<=7 วัน) - คะแนนเต็ม"
    elif ioc_age_days <= 30:
        # Recent IOC - slight reduction
        multiplier = 0.90
        description = "IOC ล่าสุด (8-30 วัน) - ลด 10%"
    elif ioc_age_days <= 90:
        # Older IOC - moderate reduction
        multiplier = 0.75
        description = "IOC เก่า (31-90 วัน) - ลด 25%"
    elif ioc_age_days <= 180:
        # Old IOC - significant reduction
        multiplier = 0.60
        description = "IOC เก่ามาก (91-180 วัน) - ลด 40%"
    else:
        # Very old IOC - major reduction
        multiplier = 0.50
        description = "IOC เก่ามากกว่า 6 เดือน - ลด 50%"
    
    reduction_percent = int((1 - multiplier) * 100)
    
    return {
        "multiplier": multiplier,
        "reduction_percent": reduction_percent,
        "ioc_age_days": ioc_age_days,
        "description": description,
        "descriptionEn": f"IOC age: {ioc_age_days} days - {reduction_percent}% reduction"
    }


# ============================================
# NEW: AI CLASSIFICATION SCORING FUNCTIONS
# ============================================

def calculate_threat_type_score(threat_types: List[str]) -> Dict[str, Any]:
    """
    Calculate score based on AI-detected threat types.
    Uses severity levels from config.
    
    Returns:
        Dict with total score, matched types, and severity levels
    """
    if not threat_types:
        return {
            "score": 0,
            "types": [],
            "max_severity_level": None,
            "details": []
        }
    
    details = []
    total_score = 0
    max_level = 5  # Lower is worse
    
    for threat_type in threat_types:
        severity_info = THREAT_TYPE_SEVERITY.get(threat_type)
        
        if severity_info:
            type_score = severity_info["score"]
            level = severity_info["level"]
            description = severity_info["description"]
            
            details.append({
                "type": threat_type,
                "score": type_score,
                "level": level,
                "description": description
            })
            
            # Only count top 2 threat types to avoid over-scoring
            if len(details) <= 2:
                total_score += type_score
            
            if level < max_level:
                max_level = level
        else:
            # Unknown threat type gets minimal score
            details.append({
                "type": threat_type,
                "score": 3,
                "level": 4,
                "description": "Unknown category"
            })
            if len(details) <= 2:
                total_score += 3
    
    # Cap at 30 max
    total_score = min(total_score, 30)
    
    # Multi-threat bonus (3+ different types = complex attack)
    if len(threat_types) >= 3:
        total_score += 5
        logger.info(f"Multi-threat bonus applied: {len(threat_types)} threat types")
    
    total_score = min(total_score, 35)  # Final cap
    
    return {
        "score": total_score,
        "types": threat_types,
        "max_severity_level": max_level if details else None,
        "details": details
    }


def calculate_threat_actor_score(threat_actors: List[str]) -> Dict[str, Any]:
    """
    Calculate score based on known threat actors.
    Named threat actors indicate attributed attacks.
    
    Returns:
        Dict with score, matched actors, and their details
    """
    if not threat_actors:
        return {
            "score": 0,
            "actors": [],
            "matched": [],
            "attribution_level": "none"
        }
    
    matched_actors = []
    max_score = 0
    
    for actor in threat_actors:
        actor_normalized = actor.strip()
        
        # Check direct match
        if actor_normalized in KNOWN_THREAT_ACTORS:
            actor_info = KNOWN_THREAT_ACTORS[actor_normalized]
            matched_actors.append({
                "name": actor_normalized,
                "score": actor_info["score"],
                "origin": actor_info.get("origin", "Unknown"),
                "aliases": actor_info.get("aliases", []),
                "targets": actor_info.get("targets", [])
            })
            if actor_info["score"] > max_score:
                max_score = actor_info["score"]
        else:
            # Check aliases
            for known_actor, info in KNOWN_THREAT_ACTORS.items():
                if actor_normalized in info.get("aliases", []):
                    matched_actors.append({
                        "name": known_actor,
                        "alias_matched": actor_normalized,
                        "score": info["score"],
                        "origin": info.get("origin", "Unknown"),
                        "aliases": info.get("aliases", []),
                        "targets": info.get("targets", [])
                    })
                    if info["score"] > max_score:
                        max_score = info["score"]
                    break
            else:
                # Unknown actor still gets some score
                matched_actors.append({
                    "name": actor_normalized,
                    "score": 15,  # Unknown but named = medium score
                    "origin": "Unknown",
                    "aliases": [],
                    "targets": []
                })
                if 15 > max_score:
                    max_score = 15
    
    # Determine attribution level
    if max_score >= 25:
        attribution = "confirmed"
    elif max_score >= 15:
        attribution = "suspected"
    elif max_score > 0:
        attribution = "possible"
    else:
        attribution = "none"
    
    return {
        "score": min(max_score, 30),  # Cap at 30
        "actors": threat_actors,
        "matched": matched_actors,
        "attribution_level": attribution
    }


def calculate_mitre_score(mitre_techniques: List[str]) -> Dict[str, Any]:
    """
    Calculate score based on MITRE ATT&CK techniques.
    More techniques = more sophisticated attack.
    
    Returns:
        Dict with score, matched techniques
    """
    if not mitre_techniques:
        return {
            "score": 0,
            "techniques": [],
            "matched_tactics": [],
            "sophistication": "none"
        }
    
    matched_tactics = []
    total_score = 0
    
    for technique in mitre_techniques:
        # Check if it matches any known tactic
        for tactic_name, tactic_info in MITRE_TACTICS.items():
            if tactic_name.lower() in technique.lower() or tactic_info["id"].lower() in technique.lower():
                if tactic_name not in [m["name"] for m in matched_tactics]:
                    matched_tactics.append({
                        "name": tactic_name,
                        "id": tactic_info["id"],
                        "score": tactic_info["score"]
                    })
                    total_score += tactic_info["score"]
                break
        else:
            # Generic technique score
            total_score += 3
    
    # Cap at 20
    total_score = min(total_score, 20)
    
    # Determine sophistication level
    tactic_count = len(matched_tactics)
    if tactic_count >= 5:
        sophistication = "advanced"
    elif tactic_count >= 3:
        sophistication = "intermediate"
    elif tactic_count >= 1:
        sophistication = "basic"
    else:
        sophistication = "none"
    
    return {
        "score": total_score,
        "techniques": mitre_techniques,
        "matched_tactics": matched_tactics,
        "sophistication": sophistication
    }


def calculate_confidence_bonus(confidence: float) -> Dict[str, Any]:
    """
    Calculate bonus score based on AI classification confidence.
    Higher confidence = more reliable classification.
    
    Returns:
        Dict with bonus score and confidence level
    """
    if confidence >= CONFIDENCE_THRESHOLDS["very_high"]:
        bonus = 10
        level = "very_high"
    elif confidence >= CONFIDENCE_THRESHOLDS["high"]:
        bonus = 7
        level = "high"
    elif confidence >= CONFIDENCE_THRESHOLDS["medium"]:
        bonus = 3
        level = "medium"
    else:
        bonus = 0
        level = "low"
    
    return {
        "score": bonus,
        "confidence": round(confidence, 3),
        "level": level
    }


# ============================================
# MAIN SCORING FUNCTION
# ============================================

def calculate_risk_score(
    ioc_value: str,
    ioc_type: str,
    description: str = "",
    sources: Optional[List[str]] = None,
    country_code: Optional[str] = None,
    domain_age_days: Optional[int] = None,
    threat_classification: Optional[Dict] = None,
    ioc_age_days: Optional[int] = None  # For decay factor
) -> Dict[str, Any]:
    """
    Calculate comprehensive risk score for an IOC.
    
    Args:
        ioc_value: The IOC (IP, domain, hash, etc.)
        ioc_type: Type of IOC (ip, domain, hash, url, etc.)
        description: Text description of the threat
        sources: List of source names
        country_code: Country code (ISO Alpha-2)
        domain_age_days: Age of domain in days
        threat_classification: Result from classifier with:
            - threat_types: List[str]
            - threat_actors: List[str]
            - mitre_techniques: List[str]
            - confidence: float
        ioc_age_days: Age of IOC in days (for decay factor)
    
    Returns:
        Dict with total score, severity, and detailed breakdown
    """
    sources = sources or []
    threat_classification = threat_classification or {}
    breakdown = {}
    
    # ==========================================
    # TRADITIONAL FACTORS
    # ==========================================
    
    # 1. Cross-source validation score
    unique_sources = list(set(sources))
    source_count = len(unique_sources)
    cross_source = calculate_cross_source_score(source_count)
    breakdown["cross_source"] = {
        "score": cross_source,
        "maxScore": 40,
        "count": source_count,
        "sources_found": unique_sources,
        "description": f"พบจาก {source_count} แหล่งข้อมูล",
        "reason": f"พบใน {source_count} แหล่ง: {', '.join(unique_sources)}" if unique_sources else "ไม่พบในแหล่งใด",
        "reasonEn": f"Found in {source_count} source(s): {', '.join(unique_sources)}" if unique_sources else "Not found in any source",
        "methodology": "นับจำนวนแหล่งข่าวกรองที่รายงาน IOC นี้ ยิ่งพบหลายแหล่งยิ่งน่าเชื่อถือ",
        "methodologyEn": "Count unique threat intelligence sources reporting this IOC. More sources = higher confidence.",
        "scoringRules": "1 แหล่ง = 5 คะแนน, 2 แหล่ง = 15 คะแนน, 3 แหล่ง = 25 คะแนน, 4+ แหล่ง = สูงสุด 40 คะแนน"
    }
    
    # 2. Source reliability score
    source_quality = calculate_source_score(sources)
    trusted_list = [s for s in sources if any(t.upper() in s.upper() for t in TRUSTED_SOURCES)]
    news_list = [s for s in sources if any(n.upper() in s.upper() for n in NEWS_SOURCES) and s not in trusted_list]
    other_list = [s for s in sources if s not in trusted_list and s not in news_list]
    
    # Build reason based on what types of sources were found
    reason_parts = []
    reason_parts_en = []
    if trusted_list:
        reason_parts.append(f"แหล่งเชื่อถือ: {', '.join(trusted_list)}")
        reason_parts_en.append(f"Trusted: {', '.join(trusted_list)}")
    if news_list:
        reason_parts.append(f"แหล่งข่าว: {', '.join(news_list)}")
        reason_parts_en.append(f"News: {', '.join(news_list)}")
    if other_list:
        reason_parts.append(f"แหล่งอื่นๆ: {', '.join(other_list)} (5 คะแนน/แหล่ง)")
        reason_parts_en.append(f"Other: {', '.join(other_list)} (5 pts each)")
    
    source_reason = " | ".join(reason_parts) if reason_parts else "ไม่มีแหล่งข้อมูล"
    source_reason_en = " | ".join(reason_parts_en) if reason_parts_en else "No sources"
    
    breakdown["source_quality"] = {
        **source_quality,
        "maxScore": 40,
        "trusted_sources": trusted_list,
        "news_sources": news_list,
        "other_sources": other_list,
        "description": f"แหล่งน่าเชื่อถือ {source_quality['trusted']} แห่ง",
        "reason": source_reason,
        "reasonEn": source_reason_en,
        "methodology": "ตรวจสอบว่าแหล่งข้อมูลอยู่ในรายการที่เชื่อถือได้หรือไม่ (เช่น VirusTotal, AbuseIPDB, MISP)",
        "methodologyEn": "Check if sources are in trusted list (e.g., VirusTotal, AbuseIPDB, MISP)",
        "scoringRules": "แหล่งเชื่อถือ = 15 คะแนน, แหล่งข่าว = 8 คะแนน, อื่นๆ = 5 คะแนน (สูงสุด 40)"
    }
    
    # 3. Keyword analysis
    keyword_result = calculate_keyword_score(description)
    matched_keywords = keyword_result.get('keywords', [])
    breakdown["keywords"] = {
        **keyword_result,
        "maxScore": 25,
        "description": f"พบ {len(matched_keywords)} คำสำคัญ",
        "reason": f"พบคำสำคัญ: {', '.join(matched_keywords)}" if matched_keywords else "ไม่พบคำสำคัญที่น่าสงสัย",
        "reasonEn": f"Keywords found: {', '.join(matched_keywords)}" if matched_keywords else "No high-risk keywords found",
        "methodology": "ค้นหาคำสำคัญที่บ่งชี้ภัยคุกคาม เช่น ransomware, zero-day, exploit, APT, backdoor",
        "methodologyEn": "Search for keywords indicating threats like ransomware, zero-day, exploit, APT, backdoor",
        "scoringRules": "คำสำคัญละ 5 คะแนน สูงสุด 25 คะแนน"
    }
    
    # 4. Entropy (for domains/URLs)
    entropy = 0.0
    entropy_score = 0
    entropy_description = "ไม่ได้วิเคราะห์"
    entropy_reason = "ไม่ได้วิเคราะห์ (ไม่ใช่โดเมน/URL)"
    
    if ioc_type in ["domain", "url", "hostname"]:
        entropy = calculate_entropy(ioc_value)
        if entropy > 4.0:
            entropy_score = 15
            entropy_description = "สูงมาก (น่าสงสัย DGA)"
            entropy_reason = f"Entropy = {entropy:.2f} (สูงมาก) บ่งชี้ว่าอาจเป็นโดเมนที่สร้างจาก DGA"
        elif entropy > 3.5:
            entropy_score = 10
            entropy_description = "สูง (อาจเป็น DGA)"
            entropy_reason = f"Entropy = {entropy:.2f} (สูง) อาจเป็นโดเมน DGA"
        elif entropy > 3.0:
            entropy_score = 5
            entropy_description = "ปานกลาง"
            entropy_reason = f"Entropy = {entropy:.2f} (ปานกลาง)"
        else:
            entropy_description = "ปกติ"
            entropy_reason = f"Entropy = {entropy:.2f} (ปกติ) ดูเหมือนชื่อโดเมนปกติ"
    
    breakdown["entropy"] = {
        "value": entropy,
        "score": entropy_score,
        "maxScore": 15,
        "description": entropy_description,
        "reason": entropy_reason,
        "reasonEn": f"Entropy value = {entropy:.2f}" if ioc_type in ["domain", "url", "hostname"] else "Not analyzed (not a domain/URL)",
        "methodology": "คำนวณค่า Shannon Entropy ของชื่อโดเมน ค่าสูง = สุ่มมาก = อาจเป็น DGA (Domain Generation Algorithm)",
        "methodologyEn": "Calculate Shannon Entropy of domain name. High entropy = more random = likely DGA",
        "scoringRules": "Entropy > 4.0 = 15 คะแนน, > 3.5 = 10 คะแนน, > 3.0 = 5 คะแนน"
    }
    
    # 5. Geolocation risk - DISABLED (data source not auditable)
    # ไม่นับคะแนน geo_risk เพราะไม่มี data source ที่ตรวจสอบได้
    geo_result = {"score": 0, "country": country_code, "is_high_risk": False}
    breakdown["geo_risk"] = {
        **geo_result,
        "maxScore": 15,
        "disabled": True,  # Flag to indicate this factor is disabled
        "description": "ปิดใช้งาน - ไม่มีแหล่งข้อมูลที่ตรวจสอบได้",
        "reason": "ปัจจัยนี้ถูกปิดใช้งานเพราะข้อมูลประเทศต้นทางไม่สามารถ audit ได้",
        "reasonEn": "This factor is disabled - country data source is not auditable",
        "methodology": "ปิดใช้งานเพื่อความโปร่งใสและสามารถตรวจสอบได้",
        "methodologyEn": "Disabled for transparency and auditability",
        "scoringRules": "ปิดใช้งาน"
    }
    
    # 6. Domain age (if applicable)
    age_result = {"score": 0, "days": None, "description": "ไม่ใช่โดเมน"}
    if ioc_type in ["domain", "url", "hostname"]:
        age_result = calculate_domain_age_score(domain_age_days)
    
    age_reason = age_result.get("description", "ไม่ทราบ")
    if domain_age_days is not None:
        age_reason = f"อายุโดเมน {domain_age_days} วัน - {age_result.get('description', '')}"
    
    breakdown["domain_age"] = {
        **age_result,
        "maxScore": 20,
        "reason": age_reason,
        "reasonEn": f"Domain age: {domain_age_days} days" if domain_age_days else "Domain age unknown",
        "methodology": "วิเคราะห์อายุโดเมนจาก WHOIS โดเมนใหม่มากมีความเสี่ยงสูงกว่า",
        "methodologyEn": "Analyze domain age from WHOIS. Newer domains are riskier.",
        "scoringRules": "< 30 วัน = 20 คะแนน, < 90 วัน = 15 คะแนน, < 180 วัน = 10 คะแนน, < 365 วัน = 5 คะแนน"
    }
    
    # ==========================================
    # AI CLASSIFICATION FACTORS (NEW)
    # ==========================================
    
    # 7. Threat Type Severity
    threat_types = threat_classification.get("threat_types", [])
    threat_type_result = calculate_threat_type_score(threat_types)
    breakdown["threat_type_severity"] = {
        **threat_type_result,
        "maxScore": 35,
        "description": f"ตรวจพบ {len(threat_types)} ประเภทภัยคุกคาม",
        "reason": f"ประเภทที่พบ: {', '.join(threat_types)}" if threat_types else "ไม่พบประเภทภัยคุกคามที่รู้จัก",
        "reasonEn": f"Types detected: {', '.join(threat_types)}" if threat_types else "No known threat types detected",
        "methodology": "วิเคราะห์ด้วย AI (NLP) เพื่อจัดประเภทภัยคุกคาม เช่น Ransomware, APT, Phishing, Malware",
        "methodologyEn": "AI (NLP) analysis to classify threat types like Ransomware, APT, Phishing, Malware",
        "scoringRules": "Ransomware/APT = 15 คะแนน, Botnet/C2 = 12 คะแนน, Phishing/Malware = 10 คะแนน ฯลฯ"
    }
    
    # 8. Threat Actor Attribution
    threat_actors = threat_classification.get("threat_actors", [])
    threat_actor_result = calculate_threat_actor_score(threat_actors)
    actor_names = [a.get('name', a) if isinstance(a, dict) else a for a in threat_actors]
    breakdown["threat_actor"] = {
        **threat_actor_result,
        "maxScore": 30,
        "actors_found": actor_names,
        "description": f"กลุ่มผู้โจมตี: {', '.join(actor_names) if actor_names else 'ไม่ระบุ'}",
        "reason": f"ตรวจพบกลุ่มผู้โจมตี: {', '.join(actor_names)}" if actor_names else "ไม่พบการระบุกลุ่มผู้โจมตี",
        "reasonEn": f"Threat actors detected: {', '.join(actor_names)}" if actor_names else "No threat actor attribution found",
        "methodology": "ค้นหาชื่อกลุ่มผู้โจมตีที่รู้จัก เช่น Lazarus, APT28, FIN7, Conti",
        "methodologyEn": "Search for known threat actor names like Lazarus, APT28, FIN7, Conti",
        "scoringRules": "กลุ่มระดับชาติ (APT) = 25 คะแนน, กลุ่มอาชญากรรม = 20 คะแนน, Hacktivist = 15 คะแนน"
    }
    
    # 9. MITRE ATT&CK Techniques
    mitre_techniques = threat_classification.get("mitre_techniques", [])
    mitre_result = calculate_mitre_score(mitre_techniques)
    breakdown["mitre_techniques"] = {
        **mitre_result,
        "maxScore": 20,
        "techniques_found": mitre_techniques,
        "description": f"MITRE tactics: {mitre_result['sophistication']}",
        "reason": f"พบ {len(mitre_techniques)} tactics: {', '.join(mitre_techniques[:3])}{'...' if len(mitre_techniques) > 3 else ''}" if mitre_techniques else "ไม่พบ MITRE ATT&CK tactics",
        "reasonEn": f"Found {len(mitre_techniques)} tactics: {', '.join(mitre_techniques[:3])}{'...' if len(mitre_techniques) > 3 else ''}" if mitre_techniques else "No MITRE ATT&CK tactics found",
        "methodology": "วิเคราะห์เทคนิคการโจมตีตาม MITRE ATT&CK Framework (Initial Access, Execution, Persistence ฯลฯ)",
        "methodologyEn": "Analyze attack techniques per MITRE ATT&CK Framework",
        "scoringRules": "1-2 tactics = 5 คะแนน, 3-4 tactics = 10 คะแนน, 5+ tactics = 20 คะแนน"
    }
    
    # 10. AI Confidence Bonus
    confidence = threat_classification.get("confidence", 0.5)
    confidence_result = calculate_confidence_bonus(confidence)
    confidence_pct = round(confidence * 100, 1)
    breakdown["ai_confidence"] = {
        **confidence_result,
        "maxScore": 10,
        "confidence_value": confidence,
        "description": f"ความมั่นใจ AI: {confidence_pct}%",
        "reason": f"AI classification confidence = {confidence_pct}%",
        "reasonEn": f"AI classification confidence = {confidence_pct}%",
        "methodology": "คะแนนโบนัสตามระดับความมั่นใจของการจัดประเภท AI",
        "methodologyEn": "Bonus score based on AI classification confidence level",
        "scoringRules": "≥90% = 10 คะแนน, ≥80% = 8 คะแนน, ≥70% = 5 คะแนน, ≥60% = 3 คะแนน"
    }
    
    # ==========================================
    # CALCULATE TOTAL SCORE
    # ==========================================
    
    total = (
        cross_source +                              # Max 40
        source_quality["score"] +                   # Max 40
        keyword_result["score"] +                   # Max 25
        entropy_score +                             # Max 15
        geo_result["score"] +                       # Max 15
        age_result["score"] +                       # Max 20
        threat_type_result["score"] +               # Max 35
        threat_actor_result["score"] +              # Max 30
        mitre_result["score"] +                     # Max 20
        confidence_result["score"]                  # Max 10
    )
    
    # Normalize to 0-100
    # Max possible = 250, but typical max is ~150
    # Use logarithmic scaling for better distribution
    if total > 100:
        total = min(100, 70 + (total - 100) * 0.3)
    
    total = min(max(int(total), 0), 100)
    
    # Apply decay factor for older IOCs
    decay_result = calculate_decay_factor(ioc_age_days)
    original_score = total
    total = int(total * decay_result["multiplier"])
    
    # Add decay factor to breakdown
    breakdown["decay_factor"] = {
        **decay_result,
        "original_score": original_score,
        "final_score": total,
        "maxScore": 0,  # This is a modifier, not a score
        "reason": decay_result["description"],
        "reasonEn": decay_result["descriptionEn"],
        "methodology": "ลดคะแนน IOC ที่เก่าเพราะความเกี่ยวข้องลดลงตามเวลา",
        "methodologyEn": "Reduce score for older IOCs as relevance decreases over time",
        "scoringRules": "<=7 วัน = 100%, 8-30 วัน = 90%, 31-90 วัน = 75%, 91-180 วัน = 60%, >180 วัน = 50%"
    }
    
    # Determine severity
    if total >= 75:
        severity = "critical"
        severity_th = "วิกฤต"
    elif total >= 50:
        severity = "high"
        severity_th = "สูง"
    elif total >= 25:
        severity = "medium"
        severity_th = "ปานกลาง"
    elif total > 0:
        severity = "low"
        severity_th = "ต่ำ"
    else:
        severity = "clean"
        severity_th = "ปลอดภัย"
    
    # Get top contributing factors
    factor_scores = [
        ("cross_source", cross_source, "การยืนยันข้ามแหล่ง"),
        ("source_quality", source_quality["score"], "คุณภาพแหล่งข้อมูล"),
        ("keywords", keyword_result["score"], "คำสำคัญอันตราย"),
        ("entropy", entropy_score, "การวิเคราะห์ Entropy"),
        ("geo_risk", geo_result["score"], "ความเสี่ยงตามภูมิศาสตร์"),
        ("domain_age", age_result["score"], "อายุโดเมน"),
        ("threat_type_severity", threat_type_result["score"], "ประเภทภัยคุกคาม (AI)"),
        ("threat_actor", threat_actor_result["score"], "กลุ่มผู้โจมตี (AI)"),
        ("mitre_techniques", mitre_result["score"], "MITRE ATT&CK (AI)"),
        ("ai_confidence", confidence_result["score"], "ความมั่นใจ AI")
    ]
    
    top_factors = sorted(factor_scores, key=lambda x: x[1], reverse=True)[:5]
    top_factors = [
        {"factor": f, "score": s, "label": label} 
        for f, s, label in top_factors if s > 0
    ]
    
    # ==========================================
    # SECTOR CLASSIFICATION (NEW)
    # ==========================================
    
    sector_result = classify_sector(
        description=description,
        title="",  # Title passed separately if available
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        threat_actors=threat_actors,
        tags=[]
    )
    
    # Add sector to breakdown
    breakdown["target_sector"] = {
        "sector": sector_result["sector"],
        "sector_name": sector_result["sector_name"],
        "sector_name_th": sector_result["sector_name_th"],
        "icon": sector_result["icon"],
        "confidence": sector_result["confidence"],
        "matched_keywords": sector_result["matched_keywords"],
        "matched_actors": sector_result["matched_actors"],
        "risk_bonus": sector_result["risk_bonus"],
        "score": sector_result["risk_bonus"],
        "maxScore": 15,
        "reason": f"เป้าหมาย: {sector_result['sector_name_th']}" if sector_result["confidence"] > 0 else "ไม่ระบุเซกเตอร์เป้าหมาย",
        "reasonEn": f"Target: {sector_result['sector_name']}" if sector_result["confidence"] > 0 else "No specific sector identified",
        "methodology": "วิเคราะห์จากคำสำคัญ โดเมน และกลุ่มผู้โจมตีที่เกี่ยวข้อง",
        "methodologyEn": "Analyzed from keywords, domain patterns, and associated threat actors"
    }
    
    # Apply sector bonus to final score
    sector_bonus = sector_result["risk_bonus"]
    total = min(total + sector_bonus, 100)
    
    # Recalculate severity after sector bonus
    if total >= 75:
        severity = "critical"
        severity_th = "วิกฤต"
    elif total >= 50:
        severity = "high"
        severity_th = "สูง"
    elif total >= 25:
        severity = "medium"
        severity_th = "ปานกลาง"
    elif total > 0:
        severity = "low"
        severity_th = "ต่ำ"
    else:
        severity = "clean"
        severity_th = "ปลอดภัย"
    
    return {
        "risk_score": total,
        "severity": severity,
        "severity_th": severity_th,
        "breakdown": breakdown,
        "top_factors": top_factors,
        "target_sector": sector_result,  # NEW: Include full sector info
        "summary": {
            "traditional_score": cross_source + source_quality["score"] + keyword_result["score"] + entropy_score + geo_result["score"] + age_result["score"],
            "ai_score": threat_type_result["score"] + threat_actor_result["score"] + mitre_result["score"] + confidence_result["score"],
            "has_threat_actor": len(threat_actors) > 0,
            "has_mitre": len(mitre_techniques) > 0,
            "primary_threat": threat_types[0] if threat_types else None,
            "target_sector": sector_result["sector"]  # NEW
        }
    }


def get_severity_level(score: int) -> str:
    """Convert numeric score to severity level."""
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    elif score > 0:
        return "low"
    return "clean"


# For testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test case 1: Domain with full classification
    result = calculate_risk_score(
        ioc_value="malicious-domain-xyz123.com",
        ioc_type="domain",
        description="Lazarus Group ransomware campaign targeting banks using Cobalt Strike",
        sources=["VirusTotal", "BleepingComputer", "AbuseIPDB"],
        country_code="KP",
        domain_age_days=15,
        threat_classification={
            "threat_types": ["Ransomware", "APT", "C2"],
            "threat_actors": ["Lazarus"],
            "mitre_techniques": ["Initial Access", "Execution", "Persistence", "Command and Control"],
            "confidence": 0.92
        }
    )
    
    print("=" * 60)
    print("TEST CASE 1: High-risk domain with full classification")
    print("=" * 60)
    print(f"Risk Score: {result['risk_score']}")
    print(f"Severity: {result['severity']} ({result['severity_th']})")
    print(f"\nTop Factors:")
    for factor in result['top_factors']:
        print(f"  - {factor['label']}: {factor['score']} pts")
    print(f"\nSummary:")
    print(f"  Traditional Score: {result['summary']['traditional_score']}")
    print(f"  AI Score: {result['summary']['ai_score']}")
    print(f"  Primary Threat: {result['summary']['primary_threat']}")
    
    # Test case 2: Simple IOC with minimal data
    result2 = calculate_risk_score(
        ioc_value="192.168.1.1",
        ioc_type="ip",
        description="Unknown IP",
        sources=["Internal"],
    )
    
    print("\n" + "=" * 60)
    print("TEST CASE 2: Simple IOC with minimal data")
    print("=" * 60)
    print(f"Risk Score: {result2['risk_score']}")
    print(f"Severity: {result2['severity']}")
