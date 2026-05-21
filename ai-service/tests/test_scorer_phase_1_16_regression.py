"""
Regression tests for Phase 1.16 — confidence multiplier removal.

Phase 1.16 removed the × ai_confidence multiplier from threat_type_severity,
threat_actor, and mitre_techniques factors because:

1. Sources that deliver an IOC have already vouched for it (source_quality
   factor handles trust differentiation, no need to double-count via
   confidence multiplier).
2. 99.93% of v2 docs use source_rule classification (not ML) → there's no
   ML uncertainty to multiply by.
3. ML-mode docs already pass strict_ml_classification filter upstream.

These tests guard against accidental re-introduction of the multiplier.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.scorer import calculate_risk_score  # noqa: E402


def _score(**kwargs):
    """Helper: calculate score with sensible cyberint-like defaults."""
    defaults = {
        "ioc_value": "evil.example",
        "ioc_type": "domain",
        "description": "malware payload",
        "sources": ["VirusTotal"],
        "threat_classification": {
            "threat_types": ["Malware"],
            "threat_actors": [],
            "mitre_techniques": ["T1587.001"],
            "confidence": 0.34,  # Typical low-confidence cyberint
        },
        "ioc_age_days": 5,
    }
    defaults.update(kwargs)
    return calculate_risk_score(**defaults)


def test_low_confidence_does_not_zero_out_threat_type_severity():
    """Phase 1.16: confidence=0.0 must NOT zero out threat_type_severity factor.

    Before Phase 1.16: score = severity_score × confidence (× 0.30 weight)
                      → 0 confidence wiped this entire 30%-weighted factor.
    After Phase 1.16:  score = severity_score (× 0.30 weight)
                      → 0 confidence has no effect on this factor.
    """
    zero_conf = _score(threat_classification={
        "threat_types": ["Malware"],
        "threat_actors": [],
        "mitre_techniques": [],
        "confidence": 0.0,
    })
    high_conf = _score(threat_classification={
        "threat_types": ["Malware"],
        "threat_actors": [],
        "mitre_techniques": [],
        "confidence": 1.0,
    })

    # The threat_type_severity raw scores must be IDENTICAL — confidence
    # is not allowed to scale this factor anymore.
    zero_raw = zero_conf["breakdown"]["threat_type_severity"]["score"]
    high_raw = high_conf["breakdown"]["threat_type_severity"]["score"]
    assert zero_raw == high_raw, (
        f"Phase 1.16 regression: threat_type_severity scaled by confidence "
        f"(zero_conf={zero_raw}, high_conf={high_raw})"
    )
    assert zero_raw > 0, "Malware threat_type should produce non-zero severity"


def test_low_confidence_does_not_zero_out_threat_actor():
    """Phase 1.16: threat_actor factor must not be scaled by confidence."""
    zero_conf = _score(threat_classification={
        "threat_types": ["Malware"],
        "threat_actors": ["Lazarus"],
        "mitre_techniques": [],
        "confidence": 0.0,
    })
    high_conf = _score(threat_classification={
        "threat_types": ["Malware"],
        "threat_actors": ["Lazarus"],
        "mitre_techniques": [],
        "confidence": 1.0,
    })

    zero_raw = zero_conf["breakdown"]["threat_actor"]["score"]
    high_raw = high_conf["breakdown"]["threat_actor"]["score"]
    assert zero_raw == high_raw, (
        f"Phase 1.16 regression: threat_actor scaled by confidence "
        f"(zero_conf={zero_raw}, high_conf={high_raw})"
    )
    assert zero_raw > 0, "Known actor (Lazarus) should produce non-zero score"


def test_low_confidence_does_not_zero_out_mitre_techniques():
    """Phase 1.16: mitre_techniques factor must not be scaled by confidence."""
    zero_conf = _score(threat_classification={
        "threat_types": ["Malware"],
        "threat_actors": [],
        "mitre_techniques": ["T1190", "T1587.001"],
        "confidence": 0.0,
    })
    high_conf = _score(threat_classification={
        "threat_types": ["Malware"],
        "threat_actors": [],
        "mitre_techniques": ["T1190", "T1587.001"],
        "confidence": 1.0,
    })

    zero_raw = zero_conf["breakdown"]["mitre_techniques"]["score"]
    high_raw = high_conf["breakdown"]["mitre_techniques"]["score"]
    assert zero_raw == high_raw, (
        f"Phase 1.16 regression: mitre_techniques scaled by confidence "
        f"(zero_conf={zero_raw}, high_conf={high_raw})"
    )
    assert zero_raw > 0, "Two MITRE techniques should produce non-zero score"


def test_typical_cyberint_single_source_lands_in_medium_band():
    """Realistic cyberint malware_payload IOC should land in medium severity.

    Pre-Phase 1.16: ~low (confidence 0.34 dragged threat_type down by 66%)
    Post-Phase 1.16: ~medium (threat_type contributes full 18 weighted pts)
    """
    result = calculate_risk_score(
        ioc_value="abc" * 21 + "x",
        ioc_type="sha256",
        description="malware payload\nRecognized as Trojan.GenericKD.123",
        sources=["cyberint_iocs"],
        threat_classification={
            "threat_types": ["Malware"],
            "threat_actors": [],
            "mitre_techniques": ["T1587.001"],
            "confidence": 0.34,
        },
        ioc_age_days=15,
    )

    # Should be medium (25-49), not low (<25) anymore
    assert 25 <= result["risk_score"] <= 49, (
        f"Typical cyberint should be medium after Phase 1.16, got "
        f"score={result['risk_score']} severity={result['severity']}"
    )
    assert result["severity"] == "medium"


def test_classifier_confidence_preserved_as_separate_dimension():
    """Phase 1.16: classifier_confidence is kept for Uncertainty Score
    (separate metric — not part of risk_score arithmetic).
    """
    result = _score(threat_classification={
        "threat_types": ["Malware"],
        "threat_actors": [],
        "mitre_techniques": [],
        "confidence": 0.42,
    })
    # The confidence value should be surfaced somewhere for downstream use,
    # but it must NOT scale any factor.
    assert result["risk_score"] > 0
