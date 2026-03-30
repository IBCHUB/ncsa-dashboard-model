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
import logging

from config import SECTORS, SECTOR_RISK_BONUS

logger = logging.getLogger(__name__)


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
    
    # Combine all text for analysis
    combined_text = f"{title} {description} {' '.join(tags)}".lower()
    
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
        if ioc_type in ["domain", "url", "hostname"]:
            ioc_lower = ioc_value.lower()
            for pattern in sector_config["domains"]:
                if pattern.lower() in ioc_lower:
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
