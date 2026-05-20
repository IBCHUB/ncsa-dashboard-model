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
import os
import logging

from config import (
    SCORING_WEIGHTS,
    HIGH_RISK_KEYWORDS_TIERED,
    TRUSTED_SOURCES,
    NEWS_SOURCES,
    THREAT_TYPE_SEVERITY,
    KNOWN_THREAT_ACTORS,
    MITRE_TACTICS,
    SECTOR_RISK_BONUS,
    SECTORS,
)
from models.sector_classifier import classify_sector as classify_sector_keywords

logger = logging.getLogger(__name__)

SCORE_MODEL_VERSION = os.getenv("SCORE_MODEL_VERSION", "scoring-v3.0.0")
SCORE_CONFIG_VERSION = os.getenv("SCORE_CONFIG_VERSION", "weights-v2-ioc-aware")

# Mapping between breakdown factors and configurable scoring weights.
WEIGHT_KEY_BY_FACTOR = {
    "cross_source": "cross_source",
    "source_quality": "threat_intel_source",
    "keywords": "high_risk_keywords",
    "domain_age": "domain_age",
    "entropy": "entropy",
    "threat_type_severity": "threat_type_severity",
    "threat_actor": "threat_actor",
    "mitre_techniques": "mitre_techniques"
}

# IOC types where domain_age and entropy factors are NOT applicable.
_NON_DOMAIN_IOC_TYPES = frozenset({
    "hash", "sha256", "sha1", "md5", "ip", "ipv4", "ipv6",
    "email", "filename", "filepath", "registry", "mutex",
    "certificate", "ja3", "jarm", "ssdeep",
})

# Patterns in description that imply malware for hash IOCs from trusted sources.
_MALICIOUS_INDICATORS = re.compile(
    r"malicious|malware|trojan|ransomware|backdoor|exploit|botnet|"
    r"payload|infect|weaponized|dropper|stealer|keylogger|rat\b|"
    r"remote.access|command.and.control|c2\b|cnc",
    re.IGNORECASE,
)


def _effective_weights(ioc_type: str) -> Dict[str, float]:
    """Return scoring weights adjusted for IOC type.

    For non-domain IOC types (hash, IP, etc.), domain_age and entropy
    weights are redistributed proportionally to the remaining factors.
    This ensures hash IOCs are not penalized for inapplicable factors.
    """
    base = dict(SCORING_WEIGHTS)
    ioc_lower = (ioc_type or "").strip().lower().replace("-", "").replace("_", "")

    if ioc_lower in _NON_DOMAIN_IOC_TYPES:
        # Collect weight from inapplicable factors
        reclaimed = base.pop("domain_age", 0.0) + base.pop("entropy", 0.0)
        if reclaimed > 0:
            remaining_sum = sum(base.values())
            if remaining_sum > 0:
                scale = (remaining_sum + reclaimed) / remaining_sum
                base = {k: round(v * scale, 4) for k, v in base.items()}
    return base


def _infer_threat_types_for_hash(
    ioc_type: str,
    description: str,
    sources: List[Any],
    existing_types: List[str],
) -> List[str]:
    """Infer threat types for hash IOCs from trusted sources.

    When a trusted source (e.g. Cyberint) marks a hash as malicious but
    the NLP classifier couldn't extract specific threat types, we infer
    "Malware" automatically.  This prevents hash IOCs from scoring 0 on
    the threat_type factor just because the description is sparse.
    """
    if existing_types:
        return existing_types  # Already has types from classifier

    ioc_lower = (ioc_type or "").strip().lower().replace("-", "").replace("_", "")
    if ioc_lower not in {"hash", "sha256", "sha1", "md5", "ssdeep"}:
        return existing_types

    # Check if any source is trusted
    has_trusted = False
    for s in (sources or []):
        name = str(s.get("name", s) if isinstance(s, dict) else s).upper()
        if any(t.upper() in name for t in TRUSTED_SOURCES):
            has_trusted = True
            break

    if not has_trusted:
        return existing_types

    # Check description for malicious indicators
    if _MALICIOUS_INDICATORS.search(description or ""):
        return ["Malware"]

    return existing_types


def _raw_to_score100(raw_score: float, raw_max: float) -> float:
    """
    Normalize a factor's internal raw score (0..raw_max) to a 0..100 scale.

    The final risk score is based on normalized ratios, so moving factor maxScore
    to 100 keeps the overall score behavior identical (same ratios, same weights).
    """
    if raw_max <= 0:
        return 0.0
    clamped = min(max(float(raw_score), 0.0), float(raw_max))
    return (clamped / float(raw_max)) * 100.0


def _weighted_points(
    factor: str,
    raw_score: float,
    max_score: float,
    weights: Optional[Dict[str, float]] = None,
) -> float:
    """
    Convert raw factor score into weighted contribution.

    When *weights* is provided (IOC-type-aware effective weights), those
    values are used instead of the global SCORING_WEIGHTS.
    """
    if max_score <= 0:
        return 0.0
    normalized = min(max(raw_score, 0.0), max_score) / max_score
    w = weights if weights is not None else SCORING_WEIGHTS
    weight_key = WEIGHT_KEY_BY_FACTOR.get(factor)
    weight = w.get(weight_key, 0.0) if weight_key else 0.0
    return round(normalized * weight * 100, 3)


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy suggests DGA-generated domains.
    
    Returns:
        Entropy score (0-100)
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
    
    # Scoring (Normalized to 0-100)
    # Average English word entropy ~3.5
    # Random strings usually > 4.0
    val = round(entropy, 3)
    if val > 4.2:
        return 100.0
    elif val > 3.8:
        return 60.0
    else:
        return 0.0


def calculate_keyword_score(text: str) -> Dict[str, Any]:
    """
    Calculate score based on high-risk keyword presence.
    Uses tiered scoring: critical=30, high=20, medium=10 per keyword.
    
    Returns:
        Dict with score, matched keywords, and tier details
    """
    if not text:
        return {"score": 0, "keywords": [], "tier_breakdown": {}}
    
    text_lower = text.lower()
    matched = []
    tier_breakdown = {"critical": [], "high": [], "medium": []}
    score = 0

    # Use tiered keywords for contextual scoring
    for tier_name, tier_info in HIGH_RISK_KEYWORDS_TIERED.items():
        tier_score = tier_info["score"]
        for keyword in tier_info["keywords"]:
            keyword_lower = keyword.lower().strip()
            if not keyword_lower:
                continue
            pattern = r"(?<![a-z0-9])" + re.escape(keyword_lower) + r"(?![a-z0-9])"
            if re.search(pattern, text_lower):
                matched.append(keyword)
                tier_breakdown[tier_name].append(keyword)
                score += tier_score

    # Cap at 100
    score = min(score, 100)
    
    return {
        "score": score,
        "keywords": matched,
        "tier_breakdown": tier_breakdown
    }


def calculate_source_score(sources: List[Any]) -> Dict[str, Any]:
    """
    Calculate score based on data sources and their confidence.
    Accepts list of strings (names) or dicts ({'name': str, 'confidence': int}).
    
    Returns:
        Dict with score and source breakdown
    """
    if not sources:
        return {"score": 0, "trusted": 0, "news": 0, "other": 0}
    
    trusted_count = 0
    news_count = 0
    other_count = 0
    total_confidence_bonus = 0
    
    for source in sources:
        # Handle both string and dict inputs
        if isinstance(source, dict):
            name = str(source.get("name", "")).upper()
            confidence = float(source.get("confidence", 0))
        else:
            name = str(source).upper()
            confidence = 0.0
            
        # Confidence bonus: 20% of source confidence (0-100 scale → 0-20 bonus points)
        if confidence > 0:
            total_confidence_bonus += (confidence * 0.2)
        
        if any(t.upper() in name for t in TRUSTED_SOURCES):
            trusted_count += 1
        elif any(n.upper() in name for n in NEWS_SOURCES):
            news_count += 1
        else:
            other_count += 1
    
    # Base score from source types (Normalized to ~100)
    # Trusted: 30 points
    # News: 16 points
    # Other: 10 points
    base_score = (trusted_count * 30) + (news_count * 16) + (other_count * 10)
    
    # Combined score with cap at 100
    final_score = min(base_score + total_confidence_bonus, 100)
    
    return {
        "score": round(final_score, 2),
        "trusted": trusted_count,
        "news": news_count,
        "other": other_count,
        "confidence_bonus": round(total_confidence_bonus, 2)
    }


def _calculate_source_independence(source_diversity: int, source_count: int) -> float:
    """
    Calculate independence factor (0.5 - 1.0) based on source class diversity.
    
    Penalizes "echo chamber" sources where multiple sources are from the
    same class (e.g., 5 news sites copying each other).
    
    Args:
        source_diversity: Number of distinct source classes (1-3: trusted/news/other)
        source_count: Total number of unique sources
    
    Returns:
        Independence factor (0.5 = single class, 1.0 = all classes represented)
    """
    if source_count <= 1:
        return 1.0  # Single source, no echo chamber possible
    
    # Max diversity = 3 classes (trusted, news, other)
    # 1 class = 0.5 (heavy penalty for echo chamber)
    # 2 classes = 0.8 (moderate confidence)
    # 3 classes = 1.0 (full confidence, independent corroboration)
    independence_map = {1: 0.5, 2: 0.8, 3: 1.0}
    return independence_map.get(min(source_diversity, 3), 0.5)


def calculate_cross_source_score(source_count: int, source_diversity: int = 1) -> int:
    """
    Calculate score based on source corroboration + diversity.
    Applies independence factor to penalize echo chamber sources.
    """
    if source_count <= 0:
        return 0
    
    # Normalized scoring (Target: 100 for 5+ sources)
    if source_count == 1:
        points = 20
    elif source_count == 2:
        points = 40
    elif source_count == 3:
        points = 60
    elif source_count == 4:
        points = 80
    else:
        points = 100  # 5+ sources
    
    # Apply independence factor (penalizes single-class echo chamber).
    # PDF 01 defines corroboration as base step score multiplied by source-class independence.
    independence = _calculate_source_independence(source_diversity, source_count)
    return min(int(points * independence), 100)


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
        score = 100  # Very new domain
        description = "Very new (<30 days)"
    elif age_days is not None and age_days < 90:
        score = 75
        description = "New (30-90 days)"
    elif age_days is not None and age_days < 180:
        score = 50
        description = "Recent (90-180 days)"
    elif age_days is not None and age_days < 365:
        score = 25
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
        multiplier = 0.95
        description = "IOC ล่าสุด (8-30 วัน) - ลด 5%"
    elif ioc_age_days <= 90:
        # Older IOC - moderate reduction
        multiplier = 0.85
        description = "IOC เก่า (31-90 วัน) - ลด 15%"
    elif ioc_age_days <= 180:
        # Old IOC - significant reduction
        multiplier = 0.78
        description = "IOC เก่ามาก (91-180 วัน) - ลด 22%"
    elif ioc_age_days <= 365:
        multiplier = 0.72
        description = "IOC เก่ามากกว่า 6 เดือน (181-365 วัน) - ลด 28%"
    else:
        # Very old IOC - floor at 0.65 (was 0.50) — datalake holds historical
        # IOCs intentionally; a 1-year-old C2 server is still actionable.
        multiplier = 0.65
        description = "IOC เก่ามากกว่า 1 ปี - ลด 35% (floor)"
    
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

_THREAT_TYPE_ALIASES: Dict[str, str] = {
    "malware_payload": "Malware",
    "malware": "Malware",
    "command_and_control": "C2",
    "cnc_server": "C2",
    "c2": "C2",
    "c&c": "C2",
    "phishing": "Phishing",
    "phishing_website": "Phishing",
    "ransomware": "Ransomware",
    "botnet": "Botnet",
    "trojan": "Trojan",
    "backdoor": "Backdoor",
    "exploit": "Exploit",
    "ddos": "DDoS",
    "spam": "Spam",
    "scanning": "Scanning",
    "vulnerability": "Vulnerability",
    "defacement": "Defacement",
    "data_breach": "Data Breach",
    "credential_theft": "Credential Theft",
    "credential_stealing": "Credential Theft",
    "apt": "APT",
    "wiper": "Wiper",
    "supply_chain_attack": "Supply Chain Attack",
    "zero_day": "Zero-day Exploit",
    "remote_code_execution": "Remote Code Execution",
    "rce": "Remote Code Execution",
    "exploited_vulnerability": "Exploited Vulnerability",
    "infecting_url": "Malware",
    "infected_machine": "Malware",
    "infection_source": "Malware",
    "payload_delivery": "Malware",
    "anonymization": "Other",
}


def _normalize_threat_type(raw: str) -> str:
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    return _THREAT_TYPE_ALIASES.get(key, raw)


def calculate_threat_type_score(threat_types: List[str], threat_details: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """
    Calculate score based on AI-detected threat types.
    
    If threat_details is provided (List of {type, confidence}), 
    it calculates weighted score: sum(severity * specific_confidence).
    
    Returns:
        Dict with total score, matched types, and severity levels
    """
    if not threat_types:
        return {
            "score": 0,
            "types": [],
            "max_severity_level": None,
            "details": [],
            "using_granular_confidence": False
        }
    
    details = []
    total_score = 0
    max_level = 5  # Lower is worse
    
    # Use threat_details if available to get confidence mapping
    conf_map = {}
    if threat_details:
        for item in threat_details:
            conf_map[item.get("type")] = float(item.get("confidence", 1.0))

    for threat_type in threat_types:
        normalized = _normalize_threat_type(threat_type)
        severity_info = THREAT_TYPE_SEVERITY.get(normalized)
        confidence = conf_map.get(threat_type, 1.0) if threat_details else 1.0
        
        if severity_info:
            base_score = severity_info["score"]
            # Apply confidence immediately if using per-threat logic
            weighted_score = base_score * confidence if threat_details else base_score
            
            level = severity_info["level"]
            description = severity_info["description"]
            
            details.append({
                "type": threat_type,
                "score": base_score,
                "confidence": confidence,
                "weighted_score": weighted_score,
                "level": level,
                "description": description
            })
            
            # Only count top 2 threat types to avoid over-scoring
            if len(details) <= 2:
                total_score += weighted_score
            
            if level < max_level:
                max_level = level
        else:
            # Unknown threat type
            base_score = 40
            weighted_score = base_score * confidence if threat_details else base_score
            
            details.append({
                "type": threat_type,
                "score": base_score,
                "confidence": confidence,
                "weighted_score": weighted_score,
                "level": 4,
                "description": "Unknown category"
            })
            if len(details) <= 2:
                total_score += weighted_score
    
    # Cap at 100 max (Base raw score cap)
    total_score = min(total_score, 100)
    
    # Multi-threat bonus (3+ different types = complex attack)
    if len(threat_types) >= 3:
        total_score += 10
        logger.info(f"Multi-threat bonus applied: {len(threat_types)} threat types")
    
    total_score = min(total_score, 100)  # Final cap
    
    return {
        "score": total_score,
        "types": threat_types,
        "max_severity_level": max_level if details else None,
        "details": details,
        "using_granular_confidence": bool(threat_details)
    }


def calculate_threat_actor_score(threat_actors: List[str]) -> Dict[str, Any]:
    """
    Calculate score based on known threat actors.
    Named threat actors indicate attributed attacks.
    Applies activity_status multiplier: active=1.0, dormant=0.7, disbanded=0.4
    
    Returns:
        Dict with score, matched actors, and their details
    """
    ACTIVITY_MULTIPLIER = {"active": 1.0, "dormant": 0.7, "disbanded": 0.4}
    
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
            activity = actor_info.get("activity_status", "active")
            multiplier = ACTIVITY_MULTIPLIER.get(activity, 1.0)
            adjusted_score = int(actor_info["score"] * multiplier)
            
            matched_actors.append({
                "name": actor_normalized,
                "base_score": actor_info["score"],
                "score": adjusted_score,
                "activity_status": activity,
                "activity_multiplier": multiplier,
                "last_known_activity": actor_info.get("last_known_activity", "Unknown"),
                "origin": actor_info.get("origin", "Unknown"),
                "aliases": actor_info.get("aliases", []),
                "targets": actor_info.get("targets", [])
            })
            if adjusted_score > max_score:
                max_score = adjusted_score
        else:
            # Check aliases
            for known_actor, info in KNOWN_THREAT_ACTORS.items():
                if actor_normalized in info.get("aliases", []):
                    activity = info.get("activity_status", "active")
                    multiplier = ACTIVITY_MULTIPLIER.get(activity, 1.0)
                    adjusted_score = int(info["score"] * multiplier)
                    
                    matched_actors.append({
                        "name": known_actor,
                        "alias_matched": actor_normalized,
                        "base_score": info["score"],
                        "score": adjusted_score,
                        "activity_status": activity,
                        "activity_multiplier": multiplier,
                        "last_known_activity": info.get("last_known_activity", "Unknown"),
                        "origin": info.get("origin", "Unknown"),
                        "aliases": info.get("aliases", []),
                        "targets": info.get("targets", [])
                    })
                    if adjusted_score > max_score:
                        max_score = adjusted_score
                    break
            else:
                # Unknown actor still gets some score
                matched_actors.append({
                    "name": actor_normalized,
                    "base_score": 50,
                    "score": 50,  # Unknown but named = medium score
                    "activity_status": "unknown",
                    "activity_multiplier": 1.0,
                    "origin": "Unknown",
                    "aliases": [],
                    "targets": []
                })
                if 50 > max_score:
                    max_score = 50
    
    # Determine attribution level
    if max_score >= 80:
        attribution = "confirmed"
    elif max_score >= 50:
        attribution = "suspected"
    elif max_score > 0:
        attribution = "possible"
    else:
        attribution = "none"
    
    return {
        "score": min(max_score, 100),  # Cap at 100
        "actors": threat_actors,
        "matched": matched_actors,
        "attribution_level": attribution
    }


def calculate_mitre_score(mitre_techniques: List[str]) -> Dict[str, Any]:
    """
    Calculate score based on MITRE ATT&CK techniques.
    More techniques = more sophisticated attack.
    PDF spec assigns 20 raw points per confirmed technique, capped at 100.
    
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
    normalized_techniques: List[str] = []

    for technique in mitre_techniques:
        normalized = str(technique).strip()
        if not normalized or normalized in normalized_techniques:
            continue
        normalized_techniques.append(normalized)

        # Check if it matches any known tactic
        for tactic_name, tactic_info in MITRE_TACTICS.items():
            if tactic_name.lower() in normalized.lower() or tactic_info["id"].lower() in normalized.lower():
                if tactic_name not in [m["name"] for m in matched_tactics]:
                    matched_tactics.append({
                        "name": tactic_name,
                        "id": tactic_info["id"],
                        "score": 20
                    })
                break
    
    total_score = min(len(normalized_techniques) * 20, 100)
    
    # Determine sophistication level
    tactic_count = len(normalized_techniques)
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
        "techniques": normalized_techniques,
        "matched_tactics": matched_tactics,
        "sophistication": sophistication
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

    # IOC-type-aware weight redistribution:
    # For hash/IP/email IOCs, domain_age and entropy weights are
    # redistributed proportionally to the remaining applicable factors.
    eff_weights = _effective_weights(ioc_type)
    is_redistributed = eff_weights != dict(SCORING_WEIGHTS)

    # ==========================================
    # TRADITIONAL FACTORS
    # ==========================================
    
    # Normalize sources: extract names for display/counts, keep objects for scoring
    source_names = []
    for s in sources:
        if isinstance(s, dict):
            source_names.append(str(s.get("name", "")).strip())
        else:
            source_names.append(str(s).strip())

    # 1. Source quality score (used for source diversity in cross-source factor)
    # calculate_source_score handles both str and dict
    source_quality = calculate_source_score(sources)
    source_diversity = sum(
        1 for n in [source_quality["trusted"], source_quality["news"], source_quality["other"]] if n > 0
    )

    # 2. Cross-source validation score
    unique_sources = list(set([n for n in source_names if n]))  # Filter empty strings
    source_count = len(unique_sources)
    cross_source_raw = calculate_cross_source_score(source_count, source_diversity)
    independence_factor = _calculate_source_independence(source_diversity, source_count)
    cross_source_score = _raw_to_score100(cross_source_raw, 100)
    breakdown["cross_source"] = {
        "raw_score": cross_source_raw,
        "raw_max": 100,
        "score": round(cross_source_score, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("cross_source", cross_source_score, 100, eff_weights),
        "count": source_count,
        "source_diversity": source_diversity,
        "independence_factor": independence_factor,
        "sources_found": unique_sources,
        "description": f"พบจาก {source_count} แหล่งข้อมูล (independence: {independence_factor})",
        "reason": f"พบใน {source_count} แหล่ง: {', '.join(unique_sources)} (diversity: {source_diversity}/3)" if unique_sources else "ไม่พบในแหล่งใด",
        "reasonEn": f"Found in {source_count} source(s): {', '.join(unique_sources)} (diversity: {source_diversity}/3)" if unique_sources else "Not found in any source",
        "methodology": "นับจำนวนแหล่งข้อมูลที่ไม่ซ้ำ แล้วคูณ independence factor ตามความหลากหลายของประเภทแหล่ง",
        "methodologyEn": "Count unique sources, then multiply by an independence factor based on source class diversity.",
        "scoringRules": "Raw: 1=20, 2=40, 3=60, 4=80, 5+=100 × independence(1class=0.5, 2class=0.8, 3class=1.0)"
    }

    # 3. Source reliability score
    # Use source_names for categorization logic
    trusted_list = [s for s in source_names if any(t.upper() in s.upper() for t in TRUSTED_SOURCES)]
    news_list = [s for s in source_names if any(n.upper() in s.upper() for n in NEWS_SOURCES) and s not in trusted_list]
    news_list = list(set(news_list)) # Deduplicate news list for display

    other_list = [s for s in source_names if s not in trusted_list and s not in news_list]
    
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
    
    source_quality_raw = source_quality["score"]
    source_quality_score = _raw_to_score100(source_quality_raw, 100)
    breakdown["source_quality"] = {
        **source_quality,
        "raw_score": source_quality_raw,
        "raw_max": 100,
        "score": round(source_quality_score, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("source_quality", source_quality_score, 100, eff_weights),
        "trusted_sources": trusted_list,
        "news_sources": news_list,
        "other_sources": other_list,
        "description": f"แหล่งน่าเชื่อถือ {source_quality['trusted']} แห่ง",
        "reason": source_reason,
        "reasonEn": source_reason_en,
        "methodology": "ตรวจสอบว่าแหล่งข้อมูลอยู่ในรายการที่เชื่อถือได้หรือไม่ (เช่น VirusTotal, AbuseIPDB, MISP)",
        "methodologyEn": "Check if sources are in trusted list (e.g., VirusTotal, AbuseIPDB, MISP)",
        "scoringRules": "Raw: trusted=30, news=16, other=10 ต่อแหล่ง (cap 100)"
    }

    # 4. Keyword analysis
    keyword_result = calculate_keyword_score(description)
    matched_keywords = keyword_result.get('keywords', [])
    keyword_raw = keyword_result["score"]
    keyword_score = _raw_to_score100(keyword_raw, 100)
    breakdown["keywords"] = {
        **keyword_result,
        "raw_score": keyword_raw,
        "raw_max": 100,
        "score": round(keyword_score, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("keywords", keyword_score, 100, eff_weights),
        "description": f"พบ {len(matched_keywords)} คำสำคัญ",
        "reason": f"พบคำสำคัญ: {', '.join(matched_keywords)}" if matched_keywords else "ไม่พบคำสำคัญที่น่าสงสัย",
        "reasonEn": f"Keywords found: {', '.join(matched_keywords)}" if matched_keywords else "No high-risk keywords found",
        "methodology": "ค้นหาคำสำคัญที่บ่งชี้ภัยคุกคาม เช่น ransomware, zero-day, exploit, APT, backdoor",
        "methodologyEn": "Search for keywords indicating threats like ransomware, zero-day, exploit, APT, backdoor",
        "scoringRules": "Tiered: Critical=30, High=20, Medium=10 คะแนน/คำ (cap 100)"
    }
    
    # 4. Entropy (for domains/URLs)
    entropy = 0.0
    entropy_score = 0
    entropy_description = "ไม่ได้วิเคราะห์"
    entropy_reason = "ไม่ได้วิเคราะห์ (ไม่ใช่โดเมน/URL)"
    
    if ioc_type in ["domain", "url", "hostname"]:
        entropy = calculate_entropy(ioc_value)
        if entropy > 4.2:
            entropy_score = 100
            entropy_description = "สูงมาก (น่าสงสัย DGA)"
            entropy_reason = f"Entropy = {entropy:.2f} (สูงมาก > 4.2) บ่งชี้ว่าอาจเป็นโดเมนที่สร้างจาก DGA"
        elif entropy > 3.8:
            entropy_score = 60
            entropy_description = "สูง (อาจเป็น DGA)"
            entropy_reason = f"Entropy = {entropy:.2f} (สูง > 3.8) อาจเป็นโดเมน DGA"
        else:
            entropy_score = 0
            entropy_description = "ปกติ"
            entropy_reason = f"Entropy = {entropy:.2f} (ปกติ)"
    
    entropy_norm = _raw_to_score100(entropy_score, 100)
    breakdown["entropy"] = {
        "value": entropy,
        "raw_score": entropy_score,
        "raw_max": 100,
        "score": round(entropy_norm, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("entropy", entropy_norm, 100, eff_weights),
        "description": entropy_description,
        "reason": entropy_reason,
        "reasonEn": f"Entropy value = {entropy:.2f}" if ioc_type in ["domain", "url", "hostname"] else "Not analyzed (not a domain/URL)",
        "methodology": "คำนวณค่า Shannon Entropy ของชื่อโดเมน ค่าสูง = สุ่มมาก = อาจเป็น DGA (Domain Generation Algorithm)",
        "methodologyEn": "Calculate Shannon Entropy of domain name. High entropy = more random = likely DGA",
        "scoringRules": "Raw: Entropy > 4.2 = 100, > 3.8 = 60 (cap 100)"
    }
    
    # 5. Geolocation risk - DISABLED (data source not auditable)
    # ไม่นับคะแนน geo_risk เพราะไม่มี data source ที่ตรวจสอบได้
    geo_result = {"score": 0, "country": country_code, "is_high_risk": False}
    breakdown["geo_risk"] = {
        **geo_result,
        "raw_score": 0,
        "raw_max": 100,
        "score": 0,
        "maxScore": 100,
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
    
    domain_age_raw = age_result["score"]
    domain_age_score = _raw_to_score100(domain_age_raw, 100)
    breakdown["domain_age"] = {
        **age_result,
        "raw_score": domain_age_raw,
        "raw_max": 100,
        "score": round(domain_age_score, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("domain_age", domain_age_score, 100, eff_weights),
        "reason": age_reason,
        "reasonEn": f"Domain age: {domain_age_days} days" if domain_age_days else "Domain age unknown",
        "methodology": "วิเคราะห์อายุโดเมนจาก WHOIS โดเมนใหม่มากมีความเสี่ยงสูงกว่า",
        "methodologyEn": "Analyze domain age from WHOIS. Newer domains are riskier.",
        "scoringRules": "Raw: <30=100, <90=75, <180=50, <365=25 (cap 100)"
    }
    
    # ==========================================
    # AI CLASSIFICATION FACTORS (NEW)
    # ==========================================
    
    # Get AI Confidence (Default 1.0 if not provided, to avoid zeroing out score)
    ai_confidence = threat_classification.get("confidence", 1.0)
    
    # 7. Threat Type Severity
    threat_types = threat_classification.get("threat_types", [])
    threat_details = threat_classification.get("threat_details", [])

    # For hash IOCs from trusted sources, infer "Malware" if no threat type
    # was extracted by the NLP classifier (prevents 0-score on this factor).
    threat_types = _infer_threat_types_for_hash(
        ioc_type, description, sources, threat_types,
    )

    threat_type_result = calculate_threat_type_score(threat_types, threat_details)
    
    if threat_type_result.get("using_granular_confidence"):
        # Score is already weighted by individual confidences
        threat_type_raw = float(threat_type_result["score"])
        scoring_rule_text = "Sum(Severity * Specific Confidence)"
        
        # Format reason string for granular details
        details_text = []
        if threat_type_result.get('details'):
            for d in threat_type_result['details']:
                d_conf = int(d.get('confidence', 1.0) * 100)
                details_text.append(f"{d['type']} ({d_conf}%)")
        
        reason_str = f"AI พบ: {', '.join(details_text)}" if details_text else "ไม่พบประเภทภัยคุกคาม"
        reason_en_str = f"AI Found: {', '.join(details_text)}" if details_text else "No threats detected"
        
    else:
        # Fallback: Apply Global Confidence Multiplier
        # Logic: Risk = Severity * Global Confidence
        threat_type_raw = float(threat_type_result["score"]) * ai_confidence
        scoring_rule_text = "Raw: (Severity Score) * (Global AI Confidence %)"
        
        reason_str = f"AI มั่นใจ {int(ai_confidence*100)}% ว่าเป็น: {', '.join(threat_types)}" if threat_types else "ไม่พบประเภทภัยคุกคาม"
        reason_en_str = f"AI Confidence {int(ai_confidence*100)}%: {', '.join(threat_types)}" if threat_types else "No threats detected"

    threat_type_score = _raw_to_score100(threat_type_raw, 100)
    
    breakdown["threat_type_severity"] = {
        **threat_type_result,
        "raw_score": round(threat_type_raw, 2),
        "raw_max": 100,
        "score": round(threat_type_score, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("threat_type_severity", threat_type_score, 100, eff_weights),
        "confidence_used": ai_confidence,
        "description": f"ตรวจพบ {len(threat_types)} ประเภทภัยคุกคาม",
        "reason": reason_str,
        "reasonEn": reason_en_str,
        "methodology": "AI (NLP) Threat Classification",
        "methodologyEn": "AI (NLP) Threat Classification",
        "scoringRules": scoring_rule_text
    }
    
    # 8. Threat Actor Attribution
    threat_actors = threat_classification.get("threat_actors", [])
    threat_actor_result = calculate_threat_actor_score(threat_actors)
    
    # Apply Confidence Multiplier
    threat_actor_raw = threat_actor_result["score"] * ai_confidence
    threat_actor_score = _raw_to_score100(threat_actor_raw, 100)
    
    actor_names = [a.get('name', a) if isinstance(a, dict) else a for a in threat_actors]
    breakdown["threat_actor"] = {
        **threat_actor_result,
        "raw_score": round(threat_actor_raw, 2),
        "raw_max": 100,
        "score": round(threat_actor_score, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("threat_actor", threat_actor_score, 100, eff_weights),
        "confidence_used": ai_confidence,
        "actors_found": actor_names,
        "description": f"กลุ่มผู้โจมตี: {', '.join(actor_names) if actor_names else 'ไม่ระบุ'} (Conf: {int(ai_confidence*100)}%)",
        "reason": f"AI มั่นใจ {int(ai_confidence*100)}% พบกลุ่ม: {', '.join(actor_names)}" if actor_names else "ไม่พบกลุ่มผู้โจมตี",
        "reasonEn": f"AI Conf {int(ai_confidence*100)}% found: {', '.join(actor_names)}" if actor_names else "No threat actors found",
        "methodology": "Attribution Score x AI Confidence",
        "methodologyEn": "Attribution Score x AI Confidence",
        "scoringRules": "Raw: (Actor Score) * (AI Confidence %)"
    }
    
    # 9. MITRE ATT&CK Techniques
    mitre_techniques = threat_classification.get("mitre_techniques", [])
    mitre_result = calculate_mitre_score(mitre_techniques)
    
    # Apply Confidence Multiplier
    mitre_raw = mitre_result["score"] * ai_confidence
    mitre_score = _raw_to_score100(mitre_raw, 100)
    
    breakdown["mitre_techniques"] = {
        **mitre_result,
        "raw_score": round(mitre_raw, 2),
        "raw_max": 100,
        "score": round(mitre_score, 2),
        "maxScore": 100,
        "weighted_score": _weighted_points("mitre_techniques", mitre_score, 100, eff_weights),
        "confidence_used": ai_confidence,
        "techniques_found": mitre_techniques,
        "description": f"MITRE tactics: {mitre_result['sophistication']} (Conf: {int(ai_confidence*100)}%)",
        "reason": f"AI มั่นใจ {int(ai_confidence*100)}% พบ {len(mitre_techniques)} tactics" if mitre_techniques else "ไม่พบ MITRE tactics",
        "reasonEn": f"AI Conf {int(ai_confidence*100)}% found {len(mitre_techniques)} tactics" if mitre_techniques else "No MITRE tactics found",
        "methodology": "MITRE Score x AI Confidence",
        "methodologyEn": "MITRE Score x AI Confidence",
        "scoringRules": "Raw: 20 points per confirmed technique × AI Confidence % (cap 100)"
    }
    
    # REMOVED: Separate AI Confidence Bonus (now integrated as multiplier)
    
    # ==========================================
    # CALCULATE TOTAL SCORE
    # ==========================================

    weighted_components = {
        "cross_source": breakdown["cross_source"]["weighted_score"],
        "source_quality": breakdown["source_quality"]["weighted_score"],
        "keywords": breakdown["keywords"]["weighted_score"],
        "entropy": breakdown["entropy"]["weighted_score"],
        "domain_age": breakdown["domain_age"]["weighted_score"],
        "threat_type_severity": breakdown["threat_type_severity"]["weighted_score"],
        "threat_actor": breakdown["threat_actor"]["weighted_score"],
        "mitre_techniques": breakdown["mitre_techniques"]["weighted_score"]
        # ai_confidence is removed from weighted sum (already applied)
    }

    weighted_total = round(sum(weighted_components.values()), 3)
    weighted_total = min(max(weighted_total, 0.0), 100.0)
    total = int(round(weighted_total))

    credibility_score = int(round(
        weighted_components["cross_source"] +
        weighted_components["source_quality"]
        # AI Confidence is implicit in AI scores now
    ))
    impact_score = int(round(max(weighted_total - credibility_score, 0)))

    breakdown["score_governance"] = {
        "model_version": SCORE_MODEL_VERSION,
        "config_version": SCORE_CONFIG_VERSION,
        "weights": SCORING_WEIGHTS,
        "effective_weights": eff_weights,
        "weights_redistributed": is_redistributed,
        "ioc_type": ioc_type,
        "weighted_total_before_decay": weighted_total,
        "credibility_score": credibility_score,
        "impact_score": impact_score,
    }

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
    
    # ==========================================
    # SECTOR CLASSIFICATION (NLP zero-shot + keyword fallback)
    # ==========================================

    nlp_sectors = threat_classification.get("sector_classifications", [])
    classification_method = "nlp"

    if nlp_sectors:
        top = nlp_sectors[0]
        sector_key = top["sector"]
        sector_config = SECTORS.get(sector_key, SECTORS["general"])
        nlp_confidence = top["confidence"]

        # Scale risk_bonus by confidence tier
        base_bonus = SECTOR_RISK_BONUS.get(sector_key, 0)
        if nlp_confidence >= 0.70:
            scaled_bonus = base_bonus
        elif nlp_confidence >= 0.50:
            scaled_bonus = int(base_bonus * 0.7)
        else:
            scaled_bonus = min(base_bonus, 5)

        sector_result = {
            "sector": sector_key,
            "sector_name": sector_config["name"],
            "sector_name_th": sector_config["name_th"],
            "icon": sector_config["icon"],
            "confidence": nlp_confidence,
            "matched_keywords": [],
            "matched_actors": [],
            "risk_bonus": scaled_bonus,
            "weight": sector_config.get("weight", 1.0),
        }

        # Hybrid boost: if NLP confidence is moderate, check keyword agreement
        if nlp_confidence < 0.50:
            kw_result = classify_sector_keywords(
                description=description, title="",
                ioc_value=ioc_value, ioc_type=ioc_type,
                threat_actors=threat_actors, tags=[],
            )
            if kw_result["sector"] == sector_key and kw_result["confidence"] > 0:
                sector_result["confidence"] = min(nlp_confidence + 0.15, 1.0)
                sector_result["matched_keywords"] = kw_result["matched_keywords"]
                sector_result["matched_actors"] = kw_result["matched_actors"]
                classification_method = "nlp+keyword"
    else:
        # Fallback to keyword-based classification
        sector_result = classify_sector_keywords(
            description=description, title="",
            ioc_value=ioc_value, ioc_type=ioc_type,
            threat_actors=threat_actors, tags=[],
        )
        classification_method = "keyword_fallback"

    # Add sector to breakdown
    methodology_map = {
        "nlp": ("วิเคราะห์ด้วย AI zero-shot classification", "Classified by AI zero-shot NLP model"),
        "nlp+keyword": ("AI zero-shot ร่วมกับ keyword matching", "AI zero-shot corroborated by keyword matching"),
        "keyword_fallback": ("วิเคราะห์จากคำสำคัญ โดเมน และกลุ่มผู้โจมตี", "Analyzed from keywords, domain patterns, and threat actors"),
    }
    meth_th, meth_en = methodology_map.get(classification_method, methodology_map["nlp"])

    breakdown["target_sector"] = {
        "sector": sector_result["sector"],
        "sector_name": sector_result["sector_name"],
        "sector_name_th": sector_result["sector_name_th"],
        "icon": sector_result["icon"],
        "confidence": sector_result["confidence"],
        "matched_keywords": sector_result.get("matched_keywords", []),
        "matched_actors": sector_result.get("matched_actors", []),
        "risk_bonus": sector_result["risk_bonus"],
        "score": sector_result["risk_bonus"],
        "maxScore": max(SECTOR_RISK_BONUS.values()) if SECTOR_RISK_BONUS else 0,
        "reason": f"เป้าหมาย: {sector_result['sector_name_th']}" if sector_result["confidence"] > 0 else "ไม่ระบุเซกเตอร์เป้าหมาย",
        "reasonEn": f"Target: {sector_result['sector_name']}" if sector_result["confidence"] > 0 else "No specific sector identified",
        "classification_method": classification_method,
        "methodology": meth_th,
        "methodologyEn": meth_en,
        "scoringRules": "Multiplier: critical_infrastructure=1.15, government=1.12, healthcare=1.10, financial=1.10, technology=1.05",
    }
    
    # Apply sector bonus as MULTIPLIER (not additive) to prevent threshold jumps
    # e.g. Base 60 + additive 15 = 75 (jumps severity) vs 60 × 1.15 = 69 (stays same)
    sector_bonus = sector_result["risk_bonus"]
    if sector_result["confidence"] < 0.45:
        sector_bonus = min(sector_bonus, 5)
    if source_quality["trusted"] == 0 and source_quality["news"] > 0 and source_quality["other"] == 0:
        sector_bonus = min(sector_bonus, 3)

    pre_sector_total = total
    sector_multiplier = 1.0 + (sector_bonus / 100.0)
    total = min(int(total * sector_multiplier), 100)
    sector_total_before_policy = total

    # Update breakdown with actual capped sector bonus (after policy guardrails)
    breakdown["target_sector"]["score_before_policy"] = sector_total_before_policy - pre_sector_total
    breakdown["target_sector"]["score"] = sector_total_before_policy - pre_sector_total
    breakdown["target_sector"]["risk_bonus_original"] = sector_result["risk_bonus"]
    breakdown["target_sector"]["multiplier_used"] = round(sector_multiplier, 3)

    policy_adjustments = []
    # Prevent Critical escalation without strong trusted corroboration.
    if total >= 80 and source_quality["trusted"] < 2:
        total = min(total, 74)
        policy_adjustments.append(
            "Critical requires at least 2 trusted corroborating sources; capped to High."
        )

    # Reliability Gate: If evidence comes ONLY from unverified sources (News, Social, Blogs, etc.)
    # without any Trusted Source corroboration (Technical Evidence), risk score must not exceed High.
    # This prevents Panic/False Positives from rumors or fake news.
    if source_quality["trusted"] == 0 and total >= 50:
        total = min(total, 49)
        policy_adjustments.append(
            "Unverified sources (No Trusted Source) capped to Medium to prevent false positives."
        )

    breakdown["policy_gate"] = {
        "triggered": len(policy_adjustments) > 0,
        "adjustments": policy_adjustments
    }

    breakdown["target_sector"]["score"] = total - pre_sector_total

    # Recalculate severity after sector bonus and policy gates
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

    # Build factor list with RAW scores (matching methodology/scoringRules text)
    # and WEIGHTED scores (for the calculation summary to add up)
    actual_sector_points = total - pre_sector_total  # Actual points added by multiplier
    factor_entries = [
        ("cross_source", breakdown["cross_source"]["score"], weighted_components["cross_source"], "การยืนยันข้ามแหล่ง"),
        ("source_quality", breakdown["source_quality"]["score"], weighted_components["source_quality"], "คุณภาพแหล่งข้อมูล"),
        ("keywords", breakdown["keywords"]["score"], weighted_components["keywords"], "คำสำคัญอันตราย"),
        ("entropy", breakdown["entropy"]["score"], weighted_components["entropy"], "การวิเคราะห์ Entropy"),
        ("domain_age", breakdown["domain_age"]["score"], weighted_components["domain_age"], "อายุโดเมน"),
        ("threat_type_severity", breakdown["threat_type_severity"]["score"], weighted_components["threat_type_severity"], "ประเภทภัยคุกคาม (AI)"),
        ("threat_actor", breakdown["threat_actor"]["score"], weighted_components["threat_actor"], "กลุ่มผู้โจมตี (AI)"),
        ("mitre_techniques", breakdown["mitre_techniques"]["score"], weighted_components["mitre_techniques"], "MITRE ATT&CK (AI)"),
        ("target_sector", float(actual_sector_points), float(actual_sector_points), "ผลกระทบต่อโครงสร้างพื้นฐานสำคัญ")
    ]

    # Send ALL factors with score > 0 for full transparency
    # Sort by weighted_score for ranking, but display raw_score in UI
    all_factors = sorted(factor_entries, key=lambda x: x[2], reverse=True)
    top_factors = [
        {
            "factor": f,
            "score": round(float(raw), 2),       # RAW score (matches methodology text)
            "weighted_score": round(float(w), 2),  # WEIGHTED score (for calculation summary)
            "label": label
        }
        for f, raw, w, label in all_factors if raw > 0
    ]
    
    # ==========================================
    # UNCERTAINTY SCORE (Separate dimension from Risk)
    # ==========================================
    # Measures "how confident are we in this risk assessment?"
    # NOT the same as risk — high risk + high uncertainty = "investigate more"
    
    confidence_component = ai_confidence * 40  # AI confidence contributes 40%
    source_component = min(source_count, 5) / 5 * 30  # Source count contributes 30%
    diversity_component = min(source_diversity, 3) / 3 * 30  # Diversity contributes 30%
    
    certainty = int(confidence_component + source_component + diversity_component)
    uncertainty = max(0, min(100 - certainty, 100))
    
    # Interpretation for SOC analysts
    if total >= 50 and uncertainty <= 30:
        interpretation = "Risk สูง + Uncertainty ต่ำ → ควร Act ทันที"
        interpretation_en = "High Risk + Low Uncertainty → Act immediately"
    elif total >= 50 and uncertainty > 30:
        interpretation = "Risk สูง + Uncertainty สูง → ต้องสืบเพิ่มก่อน Act"
        interpretation_en = "High Risk + High Uncertainty → Investigate before acting"
    elif total < 50 and uncertainty <= 30:
        interpretation = "Risk ต่ำ + Uncertainty ต่ำ → มอนิเตอร์ปกติ"
        interpretation_en = "Low Risk + Low Uncertainty → Normal monitoring"
    else:
        interpretation = "Risk ต่ำ + Uncertainty สูง → ยังไม่มั่นใจ ควรติดตาม"
        interpretation_en = "Low Risk + High Uncertainty → Not confident, keep watching"

    return {
        "risk_score": total,
        "operational_risk_score": total,
        "credibility_score": credibility_score,
        "impact_score": impact_score,
        "uncertainty": uncertainty,
        "interpretation": interpretation,
        "interpretation_en": interpretation_en,
        "severity": severity,
        "severity_th": severity_th,
        "score_model_version": SCORE_MODEL_VERSION,
        "score_config_version": SCORE_CONFIG_VERSION,
        "breakdown": breakdown,
        "top_factors": top_factors,
        "target_sector": sector_result,  # NEW: Include full sector info
        "summary": {
            "traditional_score": cross_source_raw + source_quality["score"] + keyword_result["score"] + entropy_score + geo_result["score"] + age_result["score"],
            "ai_score": threat_type_result["score"] + threat_actor_result["score"] + mitre_result["score"],
            "weighted_total_before_decay": weighted_total,
            "has_threat_actor": len(threat_actors) > 0,
            "has_mitre": len(mitre_techniques) > 0,
            "primary_threat": threat_types[0] if threat_types else None,
            "target_sector": sector_result["sector"]  # NEW
        }
    }


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
