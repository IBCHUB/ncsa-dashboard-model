"""
Validation policy helpers for AI/ML -> Warehouse pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, List
import ipaddress

VALIDATED_AUTO = "validated_auto"
VALIDATED_MANUAL = "validated_manual"
NEEDS_REVIEW = "needs_review"
REJECTED = "rejected"
REJECTED_MANUAL = "rejected_manual"


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
    sanitization_summary: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    sanitization_summary = sanitization_summary or {}

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
        (
            normalized_ioc_type == "cve"
        ) or (
            source_count >= 2
        )
    ) if curated_editorial_signal else False

    rejected = (
        "missing_ioc_value" in reasons or
        "missing_source_observations" in reasons or
        (
            not curated_editorial_auto_validated and
            trusted == 0 and
            source_count <= 1 and
            confidence < 0.2 and
            risk_score < 10
        )
    )

    auto_validated = (
        not rejected and
        (trusted >= 1 or curated_editorial_auto_validated) and
        not policy_triggered and
        (confidence >= 0.45 or curated_editorial_auto_validated) and
        not is_private_ip and
        (
            risk_score >= 25 or
            source_count >= 2 or
            source_diversity >= 2 or
            curated_editorial_auto_validated
        )
    )

    if rejected:
        status = REJECTED
    elif auto_validated:
        status = VALIDATED_AUTO
        reasons = [reason for reason in reasons if reason == "sensitive_content_was_redacted"]
    else:
        status = NEEDS_REVIEW

    return {
        "validation_status": status,
        "validation_reasons": reasons,
        "warehouse_eligible": status == VALIDATED_AUTO,
        "review_required": status == NEEDS_REVIEW,
        "trusted_sources": trusted,
        "news_sources": news,
        "other_sources": other,
        "source_count": source_count,
        "source_diversity": source_diversity,
        "policy_gate_triggered": policy_triggered,
        "ai_confidence": round(confidence, 3)
    }
