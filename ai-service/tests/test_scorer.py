"""
Unit tests for the AI scoring model.

Focused on the PDF-aligned scoring rules:
1. 8 core factors
2. sector multiplier
3. reliability gates
4. decay handling
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scorer import (  # noqa: E402
    calculate_cross_source_score,
    calculate_decay_factor,
    calculate_domain_age_score,
    calculate_keyword_score,
    calculate_mitre_score,
    calculate_risk_score,
    calculate_source_score,
)


def test_cross_source_raw_scores_follow_pdf_steps():
    assert calculate_cross_source_score(1, source_diversity=1) == 20
    assert calculate_cross_source_score(2, source_diversity=1) == 20
    assert calculate_cross_source_score(3, source_diversity=3) == 60


def test_source_quality_uses_doc_weights_and_confidence_bonus():
    result = calculate_source_score([
        {"name": "VirusTotal", "confidence": 50},
        {"name": "BleepingComputer", "confidence": 0},
        {"name": "Unknown Feed", "confidence": 10},
    ])

    assert result["trusted"] == 1
    assert result["news"] == 1
    assert result["other"] == 1
    assert result["score"] > 56
    assert result["confidence_bonus"] > 0


def test_keyword_score_uses_tiered_points():
    result = calculate_keyword_score("Ransomware exploit with phishing backdoor malware")
    assert result["score"] == 90
    assert "ransomware" in [item.lower() for item in result["keywords"]]
    assert "exploit" in [item.lower() for item in result["keywords"]]


def test_domain_age_score_matches_document_thresholds():
    assert calculate_domain_age_score(15)["score"] == 100
    assert calculate_domain_age_score(60)["score"] == 75
    assert calculate_domain_age_score(200)["score"] == 25
    assert calculate_domain_age_score(400)["score"] == 0


def test_mitre_score_is_twenty_points_per_unique_technique():
    result = calculate_mitre_score(["T1190", "TA0011 (Command and Control)", "T1190"])
    assert result["score"] == 40
    assert len(result["techniques"]) == 2


def test_decay_factor_uses_document_bands():
    # Decay floors tuned 2026-05-20: less aggressive penalty on older IOCs
    # because the datalake holds intentionally historical data.
    assert calculate_decay_factor(3)["multiplier"] == 1.0
    assert calculate_decay_factor(20)["multiplier"] == 0.95
    assert calculate_decay_factor(45)["multiplier"] == 0.85
    assert calculate_decay_factor(150)["multiplier"] == 0.78
    assert calculate_decay_factor(240)["multiplier"] == 0.72
    assert calculate_decay_factor(400)["multiplier"] == 0.65


def test_reliability_gate_caps_untrusted_news_to_medium():
    result = calculate_risk_score(
        ioc_value="wmiexec.py",
        ioc_type="domain",
        description="Lazarus ransomware exploit targeting banks with T1190 and C2",
        sources=["BleepingComputer"],
        threat_classification={
            "threat_types": ["Ransomware", "APT", "C2"],
            "threat_actors": ["Lazarus"],
            "mitre_techniques": ["T1190"],
            "confidence": 0.95
        },
        ioc_age_days=2
    )

    assert result["risk_score"] <= 49
    if result["breakdown"]["score_governance"]["weighted_total_before_decay"] >= 50:
        assert result["breakdown"]["policy_gate"]["triggered"] is True
    else:
        assert result["breakdown"]["policy_gate"]["triggered"] is False


def test_reliability_gate_triggers_for_high_risk_news_only_signal():
    result = calculate_risk_score(
        ioc_value="new-banking-portal-alert.com",
        ioc_type="domain",
        description="Lazarus ransomware zero-day exploit against banking systems with T1190 and C2 malware",
        sources=["BleepingComputer", "DarkReading", "SecurityWeek"],
        domain_age_days=7,
        threat_classification={
            "threat_types": ["Ransomware", "APT", "C2"],
            "threat_actors": ["Lazarus"],
            "mitre_techniques": ["T1190", "TA0011"],
            "confidence": 0.99,
        },
        ioc_age_days=1,
    )

    assert result["risk_score"] == 49
    assert result["breakdown"]["policy_gate"]["triggered"] is True


def test_sector_multiplier_is_kept_as_operational_rule():
    result = calculate_risk_score(
        ioc_value="swift-portal-login.com",
        ioc_type="domain",
        description="Lazarus ransomware campaign against banking infrastructure",
        sources=["VirusTotal", "AbuseIPDB", "ThreatFox"],
        domain_age_days=12,
        threat_classification={
            "threat_types": ["Ransomware", "APT"],
            "threat_actors": ["Lazarus"],
            "mitre_techniques": ["T1190"],
            "confidence": 0.98
        },
        ioc_age_days=1
    )

    target_sector = result["breakdown"]["target_sector"]
    assert target_sector["sector"] == "financial"
    assert target_sector["risk_bonus_original"] == 10
    assert target_sector["multiplier_used"] > 1.0
    assert target_sector["score_before_policy"] >= target_sector["score"]


def test_trusted_corroboration_allows_high_risk_scores():
    result = calculate_risk_score(
        ioc_value="critical-banking-ioc.com",
        ioc_type="domain",
        description="Lazarus ransomware zero-day exploit against Thai bank core systems",
        sources=[
            {"name": "VirusTotal", "confidence": 80},
            {"name": "AbuseIPDB", "confidence": 70},
            {"name": "ThreatFox", "confidence": 70},
        ],
        domain_age_days=5,
        threat_classification={
            "threat_types": ["Ransomware", "APT", "C2"],
            "threat_actors": ["Lazarus"],
            "mitre_techniques": ["T1190", "TA0011"],
            "confidence": 0.99
        },
        ioc_age_days=1
    )

    assert result["risk_score"] >= 50
    assert result["severity"] in {"high", "critical"}
    assert result["breakdown"]["policy_gate"]["triggered"] is False


def test_output_contains_doc_aligned_governance_fields():
    result = calculate_risk_score(
        ioc_value="example.org",
        ioc_type="domain",
        description="Simple phishing IOC",
        sources=["VirusTotal"],
        threat_classification={
            "threat_types": ["Phishing"],
            "threat_actors": [],
            "mitre_techniques": [],
            "confidence": 0.7
        }
    )

    assert result["score_model_version"]
    assert result["score_config_version"]
    # Weight tuned 2026-05-20: domain_age restored to 0.10 after Phase 1.8
    # wired enrichment.whois.creation_date as fallback for WHOIS data.
    assert result["breakdown"]["score_governance"]["weights"]["threat_type_severity"] == 0.25
    assert result["breakdown"]["score_governance"]["weights"]["domain_age"] == 0.10
    assert 0 <= result["risk_score"] <= 100
