"""
Sector Classification Module for Thailand Cyber Threat Intelligence

Classifies IOCs into target sectors based on:
- Keywords in description/title
- Domain patterns
- Associated threat actors
"""

from typing import List, Dict, Any, Optional, Tuple
import re
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


def classify_sector_batch(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Classify sectors for multiple items.
    
    Args:
        items: List of dicts with keys: description, title, ioc_value, ioc_type, 
               threat_actors, tags
    
    Returns:
        List of sector classification results
    """
    results = []
    for item in items:
        result = classify_sector(
            description=item.get("description", ""),
            title=item.get("title", ""),
            ioc_value=item.get("ioc_value", ""),
            ioc_type=item.get("ioc_type", ""),
            threat_actors=item.get("threat_actors", []),
            tags=item.get("tags", [])
        )
        results.append(result)
    return results


def get_sector_summary(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Generate sector-level threat summary from a list of events.
    
    Args:
        events: List of threat events with sector classifications
    
    Returns:
        Dict with per-sector statistics
    """
    from collections import defaultdict
    
    sector_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "threat_types": defaultdict(int),
        "threat_actors": set()
    })
    
    for event in events:
        sector = event.get("sector", "general")
        severity = event.get("aiSeverity", event.get("severity", "low"))
        threat_types = event.get("aiThreatTypes", [])
        actors = event.get("aiThreatActors", [])
        
        stats = sector_stats[sector]
        stats["count"] += 1
        
        if severity in ["critical", "high", "medium", "low"]:
            stats[severity] += 1
        
        for tt in threat_types:
            stats["threat_types"][tt] += 1
        
        for actor in actors:
            stats["threat_actors"].add(actor)
    
    # Convert to JSON-serializable format
    result = {}
    for sector, stats in sector_stats.items():
        sector_config = SECTORS.get(sector, SECTORS["general"])
        
        # Calculate sector threat level
        weighted_score = (
            stats["critical"] * 4 +
            stats["high"] * 3 +
            stats["medium"] * 2 +
            stats["low"] * 1
        )
        
        if stats["count"] > 0:
            avg_level = weighted_score / stats["count"]
        else:
            avg_level = 0
        
        # Determine sector threat level
        if avg_level >= 3.5:
            threat_level = "critical"
            threat_level_th = "วิกฤต"
        elif avg_level >= 2.5:
            threat_level = "high"
            threat_level_th = "สูง"
        elif avg_level >= 1.5:
            threat_level = "medium"
            threat_level_th = "ปานกลาง"
        elif avg_level > 0:
            threat_level = "low"
            threat_level_th = "ต่ำ"
        else:
            threat_level = "clean"
            threat_level_th = "ปลอดภัย"
        
        result[sector] = {
            "name": sector_config["name"],
            "name_th": sector_config["name_th"],
            "icon": sector_config["icon"],
            "count": stats["count"],
            "by_severity": {
                "critical": stats["critical"],
                "high": stats["high"],
                "medium": stats["medium"],
                "low": stats["low"]
            },
            "threat_level": threat_level,
            "threat_level_th": threat_level_th,
            "top_threat_types": dict(sorted(
                stats["threat_types"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            "threat_actors": list(stats["threat_actors"])
        }
    
    return result


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
