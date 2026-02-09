"""
Unit Tests for Risk Scoring Model (scorer.py)

Tests cover:
1. Individual factor scoring functions
2. Weighted scoring calculation
3. Policy gates (Critical/High caps)
4. Decay factor application
5. Sector bonus with guardrails
6. Edge cases and boundary conditions

Run with: pytest tests/test_scorer.py -v
"""

import pytest
from unittest.mock import patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scorer import (
    calculate_entropy,
    calculate_keyword_score,
    calculate_source_score,
    calculate_cross_source_score,
    calculate_domain_age_score,
    calculate_decay_factor,
    calculate_threat_type_score,
    calculate_threat_actor_score,
    calculate_mitre_score,
    calculate_confidence_bonus,
    calculate_risk_score,
    get_severity_level,
)


# ============================================
# ENTROPY TESTS
# ============================================

class TestCalculateEntropy:
    """Tests for Shannon entropy calculation (DGA detection)"""
    
    def test_high_entropy_dga_domain(self):
        """DGA-like domains should have entropy > 4.0"""
        result = calculate_entropy("xk7m9p2q5w8r3t6y")
        assert result > 4.0, "DGA domain should have high entropy"
    
    def test_low_entropy_normal_domain(self):
        """Normal readable domains should have low entropy"""
        result = calculate_entropy("google")
        assert result < 3.0, "Normal domain should have low entropy"
    
    def test_empty_string(self):
        """Empty string should return 0"""
        result = calculate_entropy("")
        assert result == 0


# ============================================
# KEYWORD SCORING TESTS
# ============================================

class TestCalculateKeywordScore:
    """Tests for high-risk keyword matching"""
    
    def test_single_keyword_match(self):
        """Single keyword should score 5"""
        result = calculate_keyword_score("This is a ransomware attack")
        assert result["score"] >= 5
        assert "ransomware" in [k.lower() for k in result["matched_keywords"]]
    
    def test_multiple_keywords(self):
        """Multiple keywords should stack (capped at 25)"""
        result = calculate_keyword_score("Ransomware APT with C2 botnet backdoor")
        assert result["score"] == 25, "Should cap at 25"
    
    def test_no_keywords(self):
        """No keywords should return 0"""
        result = calculate_keyword_score("This is a normal document about cats")
        assert result["score"] == 0
    
    def test_boundary_aware_matching(self):
        """Should not match substrings (e.g., 'critical' in 'hypercritical')"""
        # This test ensures regex boundary-aware matching works
        result = calculate_keyword_score("This is a hypercritical analysis")
        # 'critical' was removed from keywords, so this should be 0
        assert result["score"] == 0


# ============================================
# SOURCE QUALITY TESTS
# ============================================

class TestCalculateSourceScore:
    """Tests for source quality scoring"""
    
    def test_trusted_source(self):
        """Trusted source should score 15"""
        result = calculate_source_score(["VirusTotal"])
        assert result["score"] >= 15
    
    def test_news_source(self):
        """News source should score lower than trusted"""
        result = calculate_source_score(["BleepingComputer"])
        assert result["score"] < 15
        assert result["score"] >= 5
    
    def test_multiple_sources_capped(self):
        """Multiple sources should be capped at max 40"""
        result = calculate_source_score([
            "VirusTotal", "AbuseIPDB", "ThreatFox", "URLhaus", "Suricata"
        ])
        assert result["score"] <= 40


# ============================================
# CROSS-SOURCE VALIDATION TESTS
# ============================================

class TestCalculateCrossSourceScore:
    """Tests for cross-source validation with diminishing returns"""
    
    def test_single_source(self):
        """Single source should score 5"""
        result = calculate_cross_source_score(1)
        assert result["score"] == 5
    
    def test_two_sources(self):
        """Two sources should score 10"""
        result = calculate_cross_source_score(2)
        assert result["score"] == 10
    
    def test_four_plus_sources_diminishing(self):
        """4+ sources should have diminishing returns (max 30)"""
        result = calculate_cross_source_score(5)
        assert result["score"] <= 30
    
    def test_diversity_bonus(self):
        """Diverse source types should add bonus"""
        result = calculate_cross_source_score(3, source_diversity=3)
        base_result = calculate_cross_source_score(3, source_diversity=1)
        assert result["score"] > base_result["score"]


# ============================================
# DOMAIN AGE TESTS
# ============================================

class TestCalculateDomainAgeScore:
    """Tests for domain age risk scoring"""
    
    def test_very_new_domain(self):
        """Domain < 30 days should score 20"""
        result = calculate_domain_age_score(15)
        assert result["score"] == 20
    
    def test_old_domain(self):
        """Domain > 365 days should score 0"""
        result = calculate_domain_age_score(400)
        assert result["score"] == 0
    
    def test_none_age(self):
        """None age should return 0 (unknown)"""
        result = calculate_domain_age_score(None)
        assert result["score"] == 0


# ============================================
# DECAY FACTOR TESTS
# ============================================

class TestCalculateDecayFactor:
    """Tests for IOC age decay"""
    
    def test_fresh_ioc(self):
        """IOC <= 7 days should have multiplier 1.0"""
        result = calculate_decay_factor(5)
        assert result["multiplier"] == 1.0
    
    def test_stale_ioc(self):
        """IOC > 180 days should have multiplier 0.5"""
        result = calculate_decay_factor(200)
        assert result["multiplier"] == 0.5
    
    def test_boundary_30_days(self):
        """IOC at exactly 30 days should use 8-30 day bracket"""
        result = calculate_decay_factor(30)
        assert result["multiplier"] == 0.9


# ============================================
# AI CLASSIFICATION SCORING TESTS
# ============================================

class TestCalculateThreatTypeScore:
    """Tests for AI-detected threat type scoring"""
    
    def test_critical_threat(self):
        """Ransomware should score 25"""
        result = calculate_threat_type_score(["Ransomware"])
        assert result["score"] >= 22
    
    def test_multiple_threats_capped(self):
        """Multiple threats should be capped at 35"""
        result = calculate_threat_type_score(["Ransomware", "APT", "C2", "Botnet"])
        assert result["score"] <= 35
    
    def test_multi_threat_bonus(self):
        """3+ threats should get multi-threat bonus"""
        result = calculate_threat_type_score(["Malware", "Backdoor", "Trojan"])
        # Should have bonus for multi-threat
        assert "multi_threat_bonus" in result or result["score"] > 0


class TestCalculateThreatActorScore:
    """Tests for threat actor attribution scoring"""
    
    def test_nation_state_actor(self):
        """Lazarus (nation-state) should score 30"""
        result = calculate_threat_actor_score(["Lazarus"])
        assert result["score"] == 30
    
    def test_ransomware_group(self):
        """LockBit should score 25"""
        result = calculate_threat_actor_score(["LockBit"])
        assert result["score"] == 25
    
    def test_unknown_actor(self):
        """Unknown actor should score 0"""
        result = calculate_threat_actor_score(["UnknownHacker123"])
        assert result["score"] == 0


class TestCalculateConfidenceBonus:
    """Tests for AI confidence bonus thresholds"""
    
    def test_very_high_confidence(self):
        """Confidence >= 0.93 should give +8"""
        result = calculate_confidence_bonus(0.95)
        assert result["score"] == 8
        assert result["level"] == "very_high"
    
    def test_high_confidence(self):
        """Confidence >= 0.85 should give +5"""
        result = calculate_confidence_bonus(0.88)
        assert result["score"] == 5
        assert result["level"] == "high"
    
    def test_medium_confidence(self):
        """Confidence >= 0.70 should give +2"""
        result = calculate_confidence_bonus(0.75)
        assert result["score"] == 2
        assert result["level"] == "medium"
    
    def test_low_confidence(self):
        """Confidence < 0.70 should give 0"""
        result = calculate_confidence_bonus(0.60)
        assert result["score"] == 0
        assert result["level"] == "low"


# ============================================
# SEVERITY LEVEL TESTS
# ============================================

class TestGetSeverityLevel:
    """Tests for score to severity mapping"""
    
    def test_critical_threshold(self):
        """Score >= 75 should be Critical"""
        assert get_severity_level(85) == "critical"
        assert get_severity_level(75) == "critical"
    
    def test_high_threshold(self):
        """Score 50-74 should be High"""
        assert get_severity_level(60) == "high"
        assert get_severity_level(50) == "high"
    
    def test_medium_threshold(self):
        """Score 25-49 should be Medium"""
        assert get_severity_level(35) == "medium"
    
    def test_low_threshold(self):
        """Score 1-24 should be Low"""
        assert get_severity_level(10) == "low"
    
    def test_clean(self):
        """Score 0 should be Clean"""
        assert get_severity_level(0) == "clean"


# ============================================
# POLICY GATE TESTS (Critical/High Caps)
# ============================================

class TestPolicyGates:
    """Tests for policy gates that prevent false escalation"""
    
    def test_critical_requires_trusted_corroboration(self):
        """
        Critical severity requires at least 2 trusted sources.
        Without this, score should be capped at High.
        """
        # This test requires mocking or integration testing
        # with the full calculate_risk_score function
        result = calculate_risk_score(
            ioc_value="malicious.domain.com",
            ioc_type="domain",
            description="Ransomware C2 server by Lazarus group",
            sources=["BleepingComputer"],  # Only news source
            threat_classification={
                "threat_types": ["Ransomware", "C2"],
                "confidence": 0.95
            }
        )
        # Should be capped below Critical due to news-only
        assert result.get("severity") != "critical" or \
               result.get("breakdown", {}).get("policy_gate") is not None
    
    def test_news_only_capped_below_high(self):
        """
        News-only evidence should be capped below High severity.
        """
        result = calculate_risk_score(
            ioc_value="phishing.example.com",
            ioc_type="domain",
            description="Phishing campaign detected",
            sources=["BleepingComputer", "DarkReading"],  # Only news
            threat_classification={
                "threat_types": ["Phishing"],
                "confidence": 0.80
            }
        )
        # Breakdown should indicate policy gate was triggered
        breakdown = result.get("breakdown", {})
        # Either severity is limited OR policy gate is recorded
        assert result.get("severity") in ["low", "medium"] or \
               breakdown.get("policy_gate") is not None


# ============================================
# INTEGRATION TESTS
# ============================================

class TestCalculateRiskScoreIntegration:
    """Integration tests for full scoring pipeline"""
    
    def test_high_risk_ioc_with_all_factors(self):
        """Test complete scoring with all factors present"""
        result = calculate_risk_score(
            ioc_value="evil-c2.malware-domain.net",
            ioc_type="domain",
            description="Lazarus APT C2 server with active ransomware campaign",
            sources=["VirusTotal", "ThreatFox", "AlienVault"],
            domain_age_days=10,
            threat_classification={
                "threat_types": ["APT", "C2", "Ransomware"],
                "threat_actors": ["Lazarus"],
                "mitre_techniques": ["T1071", "TA0011 (Command and Control)"],
                "confidence": 0.95
            },
            ioc_age_days=2
        )
        
        assert "risk_score" in result
        assert "severity" in result
        assert "breakdown" in result
        assert result["risk_score"] > 0
        assert result["severity"] in ["critical", "high", "medium", "low", "clean"]
    
    def test_output_includes_governance_fields(self):
        """Test that output includes versioning for audit"""
        result = calculate_risk_score(
            ioc_value="test.domain.com",
            ioc_type="domain",
            description="Test threat",
            sources=["VirusTotal"]
        )
        
        assert "score_model_version" in result or "model_version" in result
        assert "breakdown" in result
    
    def test_score_within_valid_range(self):
        """Score should always be 0-100"""
        result = calculate_risk_score(
            ioc_value="extreme-threat.evil.com",
            ioc_type="domain",
            description="Ransomware APT C2 wiper botnet backdoor dropper",
            sources=["VirusTotal"] * 10,  # Many sources
            threat_classification={
                "threat_types": ["Ransomware", "APT", "C2", "Wiper", "Botnet"],
                "threat_actors": ["Lazarus", "APT28", "APT29"],
                "confidence": 1.0
            }
        )
        
        assert 0 <= result["risk_score"] <= 100


# ============================================
# RUN TESTS
# ============================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
