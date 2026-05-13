"""
Validation policy helpers for AI/ML -> Warehouse pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, List
import ipaddress

VALIDATED = "validated"
REJECTED = "rejected"


def _is_private_ip_indicator(ioc_type: str, ioc_value: str) -> bool:
    if str(ioc_type or "").strip().lower() != "ip":
        return False
    try:
        return ipaddress.ip_address(str(ioc_value).strip()).is_private
    except ValueError:
        return False


def evaluate_validation_status(
    ioc_value: str,
    ioc_type: str,
    score_result: Dict[str, Any],
    ai_confidence: float,
    sanitization_summary: Dict[str, Any] | None = None,
    validation_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    sanitization_summary = sanitization_summary or {}
    validation_context = validation_context or {}

    breakdown = score_result.get("breakdown", {})
    source_quality = breakdown.get("source_quality", {})
    cross_source = breakdown.get("cross_source", {})
    policy_gate = breakdown.get("policy_gate", {})

    trusted = int(source_quality.get("trusted", 0) or 0)
    news = int(source_quality.get("news", 0) or 0)
    other = int(source_quality.get("other", 0) or 0)
    source_count = int(cross_source.get("count", 0) or 0)
    source_diversity = int(cross_source.get("source_diversity", 0) or 0)
    risk_score = int(score_result.get("risk_score", 0) or 0)
    confidence = float(ai_confidence or 0.0)
    policy_triggered = bool(policy_gate.get("triggered", False))
    is_private_ip = _is_private_ip_indicator(ioc_type, ioc_value)
    normalized_ioc_type = str(ioc_type or "").strip().lower()
    classification_mode = str(validation_context.get("classification_mode") or "").strip().lower()
    source_types = {
        str(item or "").strip().lower()
        for item in validation_context.get("source_types", []) or []
        if str(item or "").strip()
    }
    threat_types = {
        str(item or "").strip()
        for item in validation_context.get("ai_threat_types", []) or []
        if str(item or "").strip()
    }
    evidence_sources = {
        str(item or "").strip()
        for item in validation_context.get("external_evidence_sources", []) or []
        if str(item or "").strip()
    }
    actionable = bool(validation_context.get("source_actionable"))
    has_meaningful_threat_type = bool(threat_types - {"Other"})

    reasons: List[str] = []
    if not str(ioc_value or "").strip():
        reasons.append("missing_ioc_value")
    if source_count <= 0:
        reasons.append("missing_source_observations")
    if trusted == 0:
        reasons.append("missing_trusted_source_corroboration")
    if policy_triggered:
        reasons.append("policy_gate_triggered")
    if confidence < 0.45:
        reasons.append("low_ai_confidence")
    if source_count < 2:
        reasons.append("single_source_signal")
    if is_private_ip:
        reasons.append("private_ip_indicator_requires_review")
    if sanitization_summary.get("sanitized"):
        reasons.append("sensitive_content_was_redacted")

    curated_editorial_signal = (
        trusted == 0 and
        news >= 1 and
        other == 0 and
        not policy_triggered and
        not is_private_ip and
        "missing_ioc_value" not in reasons and
        "missing_source_observations" not in reasons
    )

    curated_editorial_auto_validated = (
        normalized_ioc_type == "cve"
        or source_count >= 2
        or confidence >= 0.60  # single news source ผ่านได้ถ้า AI confidence สูงพอ
    ) if curated_editorial_signal else False

    internal_rule_signal = (
        classification_mode == "source_rule" and
        bool(source_types & {"customer-datalake", "misp", "sandbox"}) and
        has_meaningful_threat_type and
        confidence >= 0.50 and
        risk_score >= 10
    )

    evidence_backed_signal = (
        bool(evidence_sources) and
        has_meaningful_threat_type and
        (trusted >= 1 or actionable or confidence >= 0.50) and
        risk_score >= 20
    )

    curated_context_rule_signal = (
        classification_mode == "source_rule" and
        news >= 1 and
        trusted == 0 and
        other == 0 and
        has_meaningful_threat_type and
        not is_private_ip and
        (
            source_count >= 2 or
            confidence >= 0.50 or
            normalized_ioc_type == "cve" or
            bool(threat_types & {"Remote Code Execution", "Exploited Vulnerability"})
        )
    )

    rejected = (
        "missing_ioc_value" in reasons or
        "missing_source_observations" in reasons or
        (
            not curated_editorial_auto_validated and
            not internal_rule_signal and
            not evidence_backed_signal and
            not curated_context_rule_signal and
            trusted == 0 and
            source_count <= 1 and
            confidence < 0.2 and
            risk_score < 10
        )
    )

    auto_validated = (
        not rejected and
        (
            trusted >= 1 or
            curated_editorial_auto_validated or
            internal_rule_signal or
            evidence_backed_signal or
            curated_context_rule_signal
        ) and
        (not policy_triggered or internal_rule_signal or evidence_backed_signal or curated_context_rule_signal) and
        (confidence >= 0.45 or curated_editorial_auto_validated or internal_rule_signal or evidence_backed_signal or curated_context_rule_signal) and
        not is_private_ip and
        (
            risk_score >= 25 or
            source_count >= 2 or
            source_diversity >= 2 or
            curated_editorial_auto_validated or
            internal_rule_signal or
            evidence_backed_signal or
            curated_context_rule_signal
        )
    )

    if rejected or not auto_validated:
        status = REJECTED
    else:
        status = VALIDATED
        reasons = [reason for reason in reasons if reason == "sensitive_content_was_redacted"]

    return {
        "validation_status": status,
        "validation_reasons": reasons,
        "warehouse_eligible": status == VALIDATED,
        "trusted_sources": trusted,
        "news_sources": news,
        "other_sources": other,
        "source_count": source_count,
        "source_diversity": source_diversity,
        "policy_gate_triggered": policy_triggered,
        "ai_confidence": round(confidence, 3),
        "auto_validation_basis": {
            "curated_editorial": curated_editorial_auto_validated,
            "internal_rule": internal_rule_signal,
            "evidence_backed": evidence_backed_signal,
            "curated_context_rule": curated_context_rule_signal,
        },
    }
