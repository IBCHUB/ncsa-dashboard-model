
import sys
import logging
from pathlib import Path

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.append(str(AI_SERVICE_ROOT))

from models.scorer import calculate_risk_score

logging.basicConfig(level=logging.ERROR)

def test_fake_news_score():
    print("=== Simulation: High-Impact Fake News (No Trusted Source) ===")
    
    # Scenario: Rumor about a massive bank hack by Lazarus
    # Content is SCARY (High Risk), but Source is WEAK (Social Media)
    
    result = calculate_risk_score(
        ioc_value="1.1.1.1",
        ioc_type="ip",
        description="Rumor: Lazarus Group hacked Central Bank and leaked 10M records. Ransomware deployed.",
        sources=["Twitter", "Facebook_Post", "RandomBlog"], # None are TRUSTED_SOURCES
        threat_classification={
            "threat_types": ["Ransomware", "APT", "Data Breach"], # High Severity
            "threat_actors": ["Lazarus"], # High Score (30)
            "mitre_techniques": ["Initial Access", "Impact"],
            "confidence": 0.85
        }
    )

    print(f"\n[Inputs]")
    print(f"Sources: {result['breakdown']['source_quality']['reason']}")
    print(f"Threat: {result['summary']['primary_threat']} (Actor: {result['summary']['has_threat_actor']})")
    print(f"Sector: {result['breakdown']['target_sector']['sector_name']} (Bonus: +{result['breakdown']['target_sector']['score']})")

    print(f"\n[Scoring Breakdown]")
    # We want to see the score BEFORE the Gate
    # The 'breakdown' might show the final score, so we look at weighted components
    
    breakdown = result['breakdown']
    
    print(f"1. Threat Type Score: {breakdown['threat_type_severity']['score']} (Raw: {breakdown['threat_type_severity']['raw_score']})")
    print(f"2. Threat Actor Score: {breakdown['threat_actor']['score']} (Conf used: {breakdown['threat_actor'].get('confidence_used', 1.0)})")
    print(f"3. Sector Bonus: {breakdown['target_sector']['score']}")
    print(f"4. Source Quality: {breakdown['source_quality']['score']}")
    # print(f"5. AI Confidence Bonus: {breakdown['ai_confidence']['score']}")  <-- REMOVED
    
    raw_total = result['summary']['weighted_total_before_decay']
    # Wait, weighted_total_before_decay includes sector bonus? 
    # Let's check scorer.py logic... 
    # Yes, total = min(total + sector_bonus, 100) happened before policy gate.
    
    print(f"\n>>> Total Score (Before Gate): {raw_total}")
    print(f">>> Final Score (After Gate):  {result['risk_score']}")
    print(f">>> Severity: {result['severity']}")
    
    if result['breakdown']['policy_gate']['triggered']:
        print(f"\n[Policy Gate Triggered]")
        for adj in result['breakdown']['policy_gate']['adjustments']:
            print(f"- {adj}")
    else:
        print("\n[No Gate Triggered]")

if __name__ == "__main__":
    test_fake_news_score()
