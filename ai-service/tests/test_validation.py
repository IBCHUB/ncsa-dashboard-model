import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.validation import REJECTED, VALIDATED, evaluate_validation_status  # noqa: E402


def test_validation_auto_validates_trusted_multi_source_signal():
    result = evaluate_validation_status(
        ioc_value="malicious-bank-login.com",
        ioc_type="domain",
        score_result={
            "risk_score": 72,
            "breakdown": {
                "source_quality": {"trusted": 2, "news": 0, "other": 1},
                "cross_source": {"count": 3, "source_diversity": 2},
                "policy_gate": {"triggered": False},
            },
        },
        ai_confidence=0.91,
        sanitization_summary={"sanitized": False},
    )

    assert result["validation_status"] == VALIDATED
    assert result["warehouse_eligible"] is True
    assert result["validation_reasons"] == []


def test_validation_keeps_redaction_reason_for_auto_validated_items():
    result = evaluate_validation_status(
        ioc_value="shared-observation.example",
        ioc_type="domain",
        score_result={
            "risk_score": 42,
            "breakdown": {
                "source_quality": {"trusted": 1, "news": 1, "other": 0},
                "cross_source": {"count": 2, "source_diversity": 2},
                "policy_gate": {"triggered": False},
            },
        },
        ai_confidence=0.8,
        sanitization_summary={"sanitized": True},
    )

    assert result["validation_status"] == VALIDATED
    assert result["validation_reasons"] == ["sensitive_content_was_redacted"]


def test_validation_rejects_without_trusted_corroboration_and_policy_gate():
    result = evaluate_validation_status(
        ioc_value="emerging-alert.example",
        ioc_type="domain",
        score_result={
            "risk_score": 38,
            "breakdown": {
                "source_quality": {"trusted": 0, "news": 2, "other": 0},
                "cross_source": {"count": 2, "source_diversity": 1},
                "policy_gate": {"triggered": True},
            },
        },
        ai_confidence=0.72,
        sanitization_summary={"sanitized": False},
    )

    assert result["validation_status"] == REJECTED
    assert result["warehouse_eligible"] is False
    assert "missing_trusted_source_corroboration" in result["validation_reasons"]
    assert "policy_gate_triggered" in result["validation_reasons"]


def test_validation_rejects_low_confidence_single_source_signal():
    result = evaluate_validation_status(
        ioc_value="",
        ioc_type="domain",
        score_result={
            "risk_score": 5,
            "breakdown": {
                "source_quality": {"trusted": 0, "news": 0, "other": 1},
                "cross_source": {"count": 1, "source_diversity": 1},
                "policy_gate": {"triggered": False},
            },
        },
        ai_confidence=0.1,
        sanitization_summary={"sanitized": False},
    )

    assert result["validation_status"] == REJECTED
    assert result["warehouse_eligible"] is False
    assert "missing_ioc_value" in result["validation_reasons"]


def test_validation_auto_validates_curated_editorial_cve_signal():
    result = evaluate_validation_status(
        ioc_value="CVE-2026-25049",
        ioc_type="cve",
        score_result={
            "risk_score": 7,
            "breakdown": {
                "source_quality": {"trusted": 0, "news": 1, "other": 0},
                "cross_source": {"count": 1, "source_diversity": 1},
                "policy_gate": {"triggered": False},
            },
        },
        ai_confidence=0.12,
        sanitization_summary={"sanitized": False},
    )

    assert result["validation_status"] == VALIDATED
    assert result["warehouse_eligible"] is True


def test_validation_auto_validates_curated_editorial_multi_source_signal():
    result = evaluate_validation_status(
        ioc_value="campaign.example",
        ioc_type="domain",
        score_result={
            "risk_score": 12,
            "breakdown": {
                "source_quality": {"trusted": 0, "news": 2, "other": 0},
                "cross_source": {"count": 2, "source_diversity": 1},
                "policy_gate": {"triggered": False},
            },
        },
        ai_confidence=0.18,
        sanitization_summary={"sanitized": False},
    )

    assert result["validation_status"] == VALIDATED
    assert result["warehouse_eligible"] is True


def test_validation_auto_validates_internal_rule_feed_signal():
    result = evaluate_validation_status(
        ioc_value="d8fe25a9ad08ac12617ac75839d6bd2d09985701e664113e23a40514cfd09f5a",
        ioc_type="sha256",
        score_result={
            "risk_score": 49,
            "breakdown": {
                "source_quality": {"trusted": 0, "news": 0, "other": 1},
                "cross_source": {"count": 1, "source_diversity": 1},
                "policy_gate": {"triggered": True},
            },
        },
        ai_confidence=0.8,
        sanitization_summary={"sanitized": False},
        validation_context={
            "classification_mode": "source_rule",
            "source_types": ["customer-datalake"],
            "ai_threat_types": ["Malware"],
        },
    )

    assert result["validation_status"] == VALIDATED
    assert result["warehouse_eligible"] is True
    assert result["auto_validation_basis"]["internal_rule"] is True


def test_validation_auto_validates_curated_context_rule_even_when_risk_is_capped():
    result = evaluate_validation_status(
        ioc_value="8.8.8.8",
        ioc_type="ip",
        score_result={
            "risk_score": 49,
            "breakdown": {
                "source_quality": {"trusted": 0, "news": 1, "other": 0},
                "cross_source": {"count": 1, "source_diversity": 1},
                "policy_gate": {"triggered": True},
            },
        },
        ai_confidence=0.5,
        sanitization_summary={"sanitized": False},
        validation_context={
            "classification_mode": "source_rule",
            "source_types": ["news"],
            "ai_threat_types": ["Remote Code Execution", "Exploited Vulnerability"],
        },
    )

    assert result["validation_status"] == VALIDATED
    assert result["warehouse_eligible"] is True
    assert result["auto_validation_basis"]["curated_context_rule"] is True


def test_validation_still_rejects_weak_single_source_other_signal():
    result = evaluate_validation_status(
        ioc_value="weak.example",
        ioc_type="domain",
        score_result={
            "risk_score": 12,
            "breakdown": {
                "source_quality": {"trusted": 0, "news": 0, "other": 1},
                "cross_source": {"count": 1, "source_diversity": 1},
                "policy_gate": {"triggered": False},
            },
        },
        ai_confidence=0.3,
        sanitization_summary={"sanitized": False},
        validation_context={
            "classification_mode": "source_rule",
            "source_types": ["external-feed"],
            "ai_threat_types": ["Other"],
        },
    )

    assert result["validation_status"] == REJECTED
    assert result["warehouse_eligible"] is False
