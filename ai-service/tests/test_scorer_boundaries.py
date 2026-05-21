"""
Boundary-condition tests for the scoring model.

Guards against silent regressions at:
- Decay band transitions
- Single-source ceiling assumptions (Phase 1.11+ design constraint)
- Empty / minimal-input scoring (no NaN, no crash, no negative scores)
- Score range invariants (0 <= risk_score <= 100)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scorer import calculate_decay_factor, calculate_risk_score  # noqa: E402


# ---------------------------------------------------------------------------
# Decay band transitions
# ---------------------------------------------------------------------------


def test_decay_at_band_boundaries_no_regression():
    """Decay multipliers tuned 2026-05-20 (less aggressive on historical data).

    Snapshot test — if decay table changes, this test fails loudly.
    """
    # Inside each band
    assert calculate_decay_factor(0)["multiplier"] == 1.0
    assert calculate_decay_factor(7)["multiplier"] == 1.0
    assert calculate_decay_factor(20)["multiplier"] == 0.95
    assert calculate_decay_factor(45)["multiplier"] == 0.85
    assert calculate_decay_factor(150)["multiplier"] == 0.78
    assert calculate_decay_factor(240)["multiplier"] == 0.72
    assert calculate_decay_factor(400)["multiplier"] == 0.65


def test_decay_handles_negative_ioc_age_gracefully():
    """A negative ioc_age_days (clock skew / collect_time > now) must not crash."""
    result = calculate_decay_factor(-5)
    assert 0 < result["multiplier"] <= 1.0


def test_decay_handles_very_large_ioc_age():
    """Very old IOCs (years) must not produce zero or negative multipliers."""
    result = calculate_decay_factor(10_000)
    assert 0 < result["multiplier"] <= 1.0


# ---------------------------------------------------------------------------
# Score range invariants
# ---------------------------------------------------------------------------


def test_score_never_exceeds_100_even_with_maximal_inputs():
    """Cap at 100 must hold even with every factor maxed out."""
    result = calculate_risk_score(
        ioc_value="banking-attack.com",
        ioc_type="domain",
        description=(
            "Lazarus APT ransomware zero-day exploit C2 backdoor "
            "phishing malware trojan botnet rootkit keylogger"
        ),
        sources=[
            {"name": "VirusTotal", "confidence": 100},
            {"name": "AbuseIPDB", "confidence": 100},
            {"name": "ThreatFox", "confidence": 100},
            {"name": "AlienVault OTX", "confidence": 100},
            {"name": "Cyberint", "confidence": 100},
        ],
        threat_classification={
            "threat_types": ["Ransomware", "APT", "C2", "Zero-day", "Malware"],
            "threat_actors": ["Lazarus", "APT29", "FIN7"],
            "mitre_techniques": ["T1190", "T1566", "T1078", "TA0011"],
            "confidence": 1.0,
        },
        domain_age_days=3,
        ioc_age_days=1,
    )
    assert 0 <= result["risk_score"] <= 100


def test_score_never_negative_with_empty_inputs():
    """No sources, no description, no classification — must score 0+, not crash."""
    result = calculate_risk_score(
        ioc_value="empty.example",
        ioc_type="domain",
        description="",
        sources=[],
        threat_classification={
            "threat_types": [],
            "threat_actors": [],
            "mitre_techniques": [],
            "confidence": 0.0,
        },
    )
    assert result["risk_score"] >= 0
    assert result["risk_score"] <= 100
    assert result["severity"] in {"clean", "low", "medium", "high", "critical"}


def test_score_with_none_threat_classification_does_not_crash():
    """threat_classification=None must be tolerated (defensive default)."""
    result = calculate_risk_score(
        ioc_value="defensive.example",
        ioc_type="domain",
        description="suspicious activity",
        sources=["VirusTotal"],
        threat_classification=None,
    )
    assert 0 <= result["risk_score"] <= 100


def test_score_with_none_sources_does_not_crash():
    """sources=None must be tolerated (defensive default)."""
    result = calculate_risk_score(
        ioc_value="lonely.example",
        ioc_type="domain",
        description="malware",
        sources=None,
        threat_classification={
            "threat_types": ["Malware"],
            "threat_actors": [],
            "mitre_techniques": [],
            "confidence": 0.5,
        },
    )
    assert 0 <= result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# Single-source data-ceiling — Phase 1.16 design assumption
# ---------------------------------------------------------------------------


def test_single_source_cyberint_caps_below_high_threshold():
    """Phase 1.16 design: typical single-source cyberint should NOT reach high
    severity by itself. High requires multi-source corroboration OR strong
    actor/MITRE signal.

    If this fails, weight tuning has drifted from documented assumptions.
    """
    result = calculate_risk_score(
        ioc_value="x" * 64,
        ioc_type="sha256",
        description="malware payload\nRecognized as Generic.Malware.A",
        sources=["cyberint_iocs"],
        threat_classification={
            "threat_types": ["Malware"],
            "threat_actors": [],  # No actor → important constraint
            "mitre_techniques": ["T1587.001"],
            "confidence": 0.34,
        },
        ioc_age_days=15,
    )
    # Should NOT be high (>=50) for single-source, no-actor cyberint
    assert result["risk_score"] < 50, (
        f"Single-source cyberint without actor reached high band — "
        f"score={result['risk_score']} severity={result['severity']}. "
        f"This violates Phase 1.16 design assumption (high requires "
        f"multi-source or actor signal)."
    )


def test_multi_source_with_actor_can_reach_high():
    """Multi-source + named actor + MITRE → should reach high (50+)."""
    result = calculate_risk_score(
        ioc_value="apt-c2.example",
        ioc_type="domain",
        description="Lazarus APT C2 server, ransomware deployment",
        sources=[
            {"name": "VirusTotal", "confidence": 80},
            {"name": "AbuseIPDB", "confidence": 70},
            {"name": "ThreatFox", "confidence": 70},
        ],
        threat_classification={
            "threat_types": ["Ransomware", "APT", "C2"],
            "threat_actors": ["Lazarus"],
            "mitre_techniques": ["T1190", "TA0011"],
            "confidence": 0.95,
        },
        domain_age_days=7,
        ioc_age_days=2,
    )
    assert result["risk_score"] >= 50, (
        f"Multi-source + actor + MITRE failed to reach high — "
        f"score={result['risk_score']}. Weights may be too conservative."
    )


# ---------------------------------------------------------------------------
# Severity threshold transitions
# ---------------------------------------------------------------------------


def test_severity_label_matches_documented_thresholds():
    """Severity thresholds: clean=0, low 1-24, medium 25-49, high 50-74, critical 75+."""
    # Empty inputs → score 0 → "clean" severity
    clean = calculate_risk_score(
        ioc_value="x.example", ioc_type="domain", sources=[],
        threat_classification={"threat_types": [], "threat_actors": [], "mitre_techniques": [], "confidence": 0},
    )
    assert clean["risk_score"] == 0
    assert clean["severity"] == "clean"

    # Single-source phishing → low band
    low = calculate_risk_score(
        ioc_value="phish.example", ioc_type="domain",
        description="phishing",
        sources=["Unknown Feed"],
        threat_classification={"threat_types": ["Phishing"], "threat_actors": [], "mitre_techniques": [], "confidence": 0.5},
        ioc_age_days=10,
    )
    assert low["severity"] in {"low", "medium"}
    assert 0 < low["risk_score"] < 50
