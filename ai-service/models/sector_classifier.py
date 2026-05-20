"""
Sector Classification Module for Thailand Cyber Threat Intelligence (Keyword-based)

DEPRECATED: Primary sector classification now uses NLP zero-shot in classifier.py.
This module is retained as a keyword fallback when NLP confidence is low.
The scorer calls classify_sector() as a fallback via classify_sector_keywords().

Classifies IOCs into target sectors based on:
- Keywords in description/title
- Domain patterns
- Associated threat actors
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import logging
import re

from config import SECTORS, SECTOR_RISK_BONUS

logger = logging.getLogger(__name__)


# Thai TLD heuristics: registrable suffix → sector
# These run before keyword matching so government-domain IOCs always classify.
TLD_SECTOR_HINTS = (
    (".go.th", "government", "tld_go_th"),
    (".gov.th", "government", "tld_gov_th"),
    (".mil.th", "defense", "tld_mil_th"),
    (".ac.th", "education", "tld_ac_th"),
    (".edu", "education", "tld_edu"),
    (".gov", "government", "tld_gov"),
    (".mil", "defense", "tld_mil"),
    (".bank", "financial", "tld_bank"),
)


def _extract_url_components(ioc_value: str, ioc_type: str) -> tuple[str, str]:
    """
    Return (hostname_lower, path_lower) for a URL or domain IOC.
    Empty strings if ioc_type doesn't match or parsing fails.
    """
    cleaned = (ioc_value or "").strip()
    if not cleaned:
        return "", ""
    ioc_type_l = (ioc_type or "").lower()
    if ioc_type_l in ("url", "uri"):
        try:
            # Ensure parseable URL — add scheme if missing
            parsed = urlparse(cleaned if "://" in cleaned else "http://" + cleaned)
            return (parsed.hostname or "").lower(), (parsed.path or "").lower()
        except Exception:
            return cleaned.lower(), ""
    if ioc_type_l in ("domain", "hostname", "fqdn"):
        # Strip any leading scheme/path the upstream feed may have leaked in
        if "://" in cleaned:
            try:
                parsed = urlparse(cleaned)
                return (parsed.hostname or "").lower(), (parsed.path or "").lower()
            except Exception:
                pass
        # Strip trailing slash/path manually for bare domains
        return cleaned.lower().split("/", 1)[0], ""
    return "", ""


def _tld_sector_hint(hostname: str) -> Optional[tuple[str, str]]:
    """Return (sector_key, matched_pattern) if hostname matches a TLD heuristic."""
    if not hostname:
        return None
    host = hostname.lower().rstrip(".")
    for suffix, sector, pattern in TLD_SECTOR_HINTS:
        if host.endswith(suffix):
            return sector, pattern
    return None


def classify_sector(
    description: str = "",
    title: str = "",
    ioc_value: str = "",
    ioc_type: str = "",
    threat_actors: Optional[List[str]] = None,
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Classify target sector from IOC context.
    
    Args:
        description: Threat description text
        title: Event title
        ioc_value: The IOC value (domain, IP, etc.)
        ioc_type: Type of IOC (domain, ip, hash, etc.)
        threat_actors: List of detected threat actors
        tags: List of tags associated with the event
    
    Returns:
        Dict with:
            - sector: sector key (e.g., "financial")
            - sector_name: display name
            - sector_name_th: Thai display name
            - icon: emoji icon
            - confidence: 0.0-1.0
            - matched_keywords: keywords that matched
            - matched_actors: actors that matched
            - matched_domains: domain patterns that matched
            - risk_bonus: additional risk score for this sector
    """
    threat_actors = threat_actors or []
    tags = tags or []

    # Parse URL/domain into hostname + path so we can match keywords on path tokens
    hostname, url_path = _extract_url_components(ioc_value, ioc_type)
    path_tokens = " ".join(re.split(r"[/_\-.?=&]+", url_path)) if url_path else ""

    # TLD-based shortcut for high-confidence government / .ac.th / .mil / .bank domains
    tld_hint = _tld_sector_hint(hostname)
    if tld_hint:
        forced_sector, forced_pattern = tld_hint
        sector_config = SECTORS.get(forced_sector, SECTORS["general"])
        return {
            "sector": forced_sector,
            "sector_name": sector_config["name"],
            "sector_name_th": sector_config["name_th"],
            "icon": sector_config["icon"],
            "confidence": 0.85,
            "matched_keywords": [forced_pattern],
            "matched_actors": [],
            "matched_domains": [forced_pattern],
            "risk_bonus": SECTOR_RISK_BONUS.get(forced_sector, 0),
            "weight": sector_config["weight"],
        }

    # Combine all text for analysis — include URL path tokens so e.g.
    # https://attacker/bank/login matches the financial sector keywords.
    combined_text = f"{title} {description} {' '.join(tags)} {hostname} {path_tokens}".lower()

    sector_scores: Dict[str, Dict[str, Any]] = {}

    for sector_key, sector_config in SECTORS.items():
        if sector_key == "general":
            continue  # Skip general, use as fallback

        score = 0.0
        matched_keywords: List[str] = []
        matched_actors: List[str] = []
        matched_domains: List[str] = []

        # 1. Keyword matching (weight: 0.4)
        for keyword in sector_config["keywords"]:
            if keyword.lower() in combined_text:
                matched_keywords.append(keyword)
                score += 0.1  # Each keyword adds 0.1

        # Cap keyword contribution
        keyword_score = min(len(matched_keywords) * 0.1, 0.4)
        score = keyword_score

        # 2. Domain pattern matching (weight: 0.3)
        if ioc_type in ["domain", "url", "hostname", "fqdn", "uri"] and hostname:
            for pattern in sector_config["domains"]:
                if pattern.lower() in hostname:
                    matched_domains.append(pattern)
                    score += 0.15

        # Cap domain contribution
        domain_score = min(len(matched_domains) * 0.15, 0.3)
        score = keyword_score + domain_score
        
        # 3. Threat actor matching (weight: 0.3)
        for actor in threat_actors:
            actor_normalized = actor.strip()
            if actor_normalized in sector_config["threat_actors"]:
                matched_actors.append(actor_normalized)
                score += 0.15
        
        # Cap actor contribution
        actor_score = min(len(matched_actors) * 0.15, 0.3)
        score = keyword_score + domain_score + actor_score
        
        # Store if any matches found
        if score > 0:
            sector_scores[sector_key] = {
                "score": score,
                "matched_keywords": matched_keywords,
                "matched_actors": matched_actors,
                "matched_domains": matched_domains
            }
    
    # Determine best sector
    if sector_scores:
        best_sector = max(sector_scores.keys(), key=lambda k: sector_scores[k]["score"])
        best_data = sector_scores[best_sector]
        sector_config = SECTORS[best_sector]
        
        return {
            "sector": best_sector,
            "sector_name": sector_config["name"],
            "sector_name_th": sector_config["name_th"],
            "icon": sector_config["icon"],
            "confidence": round(min(best_data["score"], 1.0), 2),
            "matched_keywords": best_data["matched_keywords"],
            "matched_actors": best_data["matched_actors"],
            "matched_domains": best_data["matched_domains"],
            "risk_bonus": SECTOR_RISK_BONUS.get(best_sector, 0),
            "weight": sector_config["weight"]
        }
    
    # Default to general
    general_config = SECTORS["general"]
    return {
        "sector": "general",
        "sector_name": general_config["name"],
        "sector_name_th": general_config["name_th"],
        "icon": general_config["icon"],
        "confidence": 0.0,
        "matched_keywords": [],
        "matched_actors": [],
        "matched_domains": [],
        "risk_bonus": 0,
        "weight": 1.0
    }


# Test function
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_cases = [
        {
            "description": "Ransomware attack targeting Thai banks and financial institutions",
            "title": "Lazarus Group targets SWIFT networks",
            "ioc_value": "malware.payment-gateway.com",
            "ioc_type": "domain",
            "threat_actors": ["Lazarus"],
            "tags": ["banking", "cryptocurrency"]
        },
        {
            "description": "APT28 targets government ministry email servers",
            "title": "Russian hackers breach Thai government",
            "ioc_value": "update.go.th.malicious.com",
            "ioc_type": "domain",
            "threat_actors": ["APT28"],
            "tags": ["government", "espionage"]
        },
        {
            "description": "Generic phishing campaign",
            "title": "Phishing emails detected",
            "ioc_value": "192.168.1.1",
            "ioc_type": "ip",
            "threat_actors": [],
            "tags": ["phishing"]
        }
    ]
    
    print("=== Sector Classification Tests ===\n")
    for i, tc in enumerate(test_cases, 1):
        result = classify_sector(**tc)
        print(f"Test {i}: {tc['title'][:40]}...")
        print(f"  Sector: {result['icon']} {result['sector_name']} ({result['sector']})")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Matched Keywords: {result['matched_keywords']}")
        print(f"  Matched Actors: {result['matched_actors']}")
        print(f"  Risk Bonus: +{result['risk_bonus']} points")
        print()
