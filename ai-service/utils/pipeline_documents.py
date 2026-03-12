"""
Shared document builders for the AI pipeline.

These helpers aggregate multiple datalake observations for the same IOC,
sanitize sensitive content, run AI enrichment, and attach validation metadata
before the document is persisted to the warehouse index.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from models.classifier import (
    classify_threat,
    extract_mitre_techniques,
    extract_threat_actors,
)
from models.actions import derive_action_metadata
from models.scorer import calculate_risk_score
from models.validation import NEEDS_REVIEW, evaluate_validation_status
from utils.sanitizer import sanitize_observation_fields


def parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def to_iso_z(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def pick_highest_severity(values: Sequence[str]) -> str:
    severity_rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "clean": 0,
    }
    best = "low"
    best_rank = -1
    for raw in values:
        severity = str(raw or "").strip().lower()
        rank = severity_rank.get(severity, -1)
        if rank > best_rank:
            best = severity
            best_rank = rank
    return best if best_rank >= 0 else "low"


def _unique_non_empty(values: Iterable[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        cleaned = str(value or "").strip()
        if not cleaned:
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return output


def build_enriched_ioc_document(ioc_docs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not ioc_docs:
        raise ValueError("ioc_docs must not be empty")

    primary = ioc_docs[0]
    ioc_value = str(primary.get("ioc_value", "")).strip()
    ioc_type = str(primary.get("ioc_type", "unknown")).strip().lower()

    source_names: List[str] = []
    source_objects: List[Dict[str, Any]] = []
    source_types: List[str] = []
    descriptions: List[str] = []
    references: List[str] = []
    raw_tags: List[str] = []
    threat_types_raw: List[str] = []
    severity_values: List[str] = []
    geo_countries: List[str] = []
    first_seen_candidates: List[datetime] = []
    last_seen_candidates: List[datetime] = []

    for doc in ioc_docs:
        source_name = str(doc.get("source_name", "")).strip()
        confidence = float(doc.get("confidence", 0) or 0)

        if source_name:
            if source_name not in source_names:
                source_names.append(source_name)

            matched = next((item for item in source_objects if item["name"] == source_name), None)
            if matched:
                matched["confidence"] = max(float(matched.get("confidence", 0) or 0), confidence)
            else:
                source_objects.append(
                    {
                        "name": source_name,
                        "confidence": confidence,
                        "type": str(doc.get("source_type", "unknown")),
                    }
                )

        source_type = str(doc.get("source_type", "")).strip()
        if source_type and source_type not in source_types:
            source_types.append(source_type)

        description = str(doc.get("description", "")).strip()
        if description:
            descriptions.append(description)

        for tag in doc.get("tags", []) or []:
            raw_tags.append(str(tag))

        reference = str(doc.get("reference", "")).strip()
        if reference:
            references.append(reference)

        for threat in doc.get("threat_type", []) or []:
            if threat:
                threat_types_raw.append(str(threat))

        severity_values.append(str(doc.get("severity", "")).strip().lower())

        geo_country = str(doc.get("geo_country", "")).strip()
        if geo_country:
            geo_countries.append(geo_country)

        event_dt = parse_dt(doc.get("event_time"))
        collect_dt = parse_dt(doc.get("collect_time"))
        if event_dt:
            first_seen_candidates.append(event_dt)
            last_seen_candidates.append(event_dt)
        if collect_dt:
            first_seen_candidates.append(collect_dt)
            last_seen_candidates.append(collect_dt)

    sanitization_result = sanitize_observation_fields(descriptions, references, raw_tags)
    sanitized_descriptions = _unique_non_empty(sanitization_result["descriptions"])
    sanitized_references = _unique_non_empty(sanitization_result["references"])
    sanitized_tags = _unique_non_empty(sanitization_result["tags"])
    sanitization_summary = sanitization_result["summary"]

    merged_description = "\n".join(sanitized_descriptions) if sanitized_descriptions else ""
    sources = source_objects if source_objects else ["unknown"]

    first_seen_dt = min(first_seen_candidates) if first_seen_candidates else None
    last_seen_dt = max(last_seen_candidates) if last_seen_candidates else None
    first_seen = to_iso_z(first_seen_dt) or primary.get("event_time")
    last_seen = to_iso_z(last_seen_dt) or primary.get("collect_time")

    ioc_age_days = None
    if first_seen_dt:
        ioc_age_days = max(0, (datetime.now(timezone.utc) - first_seen_dt.astimezone(timezone.utc)).days)

    classification = classify_threat(merged_description)
    threat_actors = extract_threat_actors(merged_description)
    mitre_techniques = extract_mitre_techniques(merged_description)

    score_result = calculate_risk_score(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        description=merged_description,
        sources=sources,
        ioc_age_days=ioc_age_days,
        threat_classification={
            "threat_types": classification["threat_types"],
            "threat_actors": threat_actors,
            "mitre_techniques": mitre_techniques,
            "confidence": classification["confidence"],
        },
    )

    validation = evaluate_validation_status(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        score_result=score_result,
        ai_confidence=classification["confidence"],
        sanitization_summary=sanitization_summary,
    )
    review_state = "pending" if validation["validation_status"] == NEEDS_REVIEW else "not_required"

    document = {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "source_name": ", ".join(source_names) if source_names else "unknown",
        "source_type": "multi" if len(source_types) > 1 else (source_types[0] if source_types else "unknown"),
        "sources": sources,
        "source_types": source_types,
        "source_count": len(source_names) if source_names else len(source_objects),
        "description": merged_description,
        "threat_type": sorted(set(threat_types_raw)),
        "severity": pick_highest_severity(severity_values),
        "tags": sanitized_tags,
        "reference": "\n".join(sanitized_references),
        "collect_time": last_seen,
        "event_time": first_seen,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "ioc_age_days": ioc_age_days,
        "geo_country": geo_countries[0] if geo_countries else primary.get("geo_country"),
        "ai_risk_score": score_result.get("risk_score", 0),
        "ai_severity": score_result.get("severity", "low"),
        "ai_severity_th": score_result.get("severity_th", "ต่ำ"),
        "ai_threat_types": classification["threat_types"],
        "ai_threat_actors": threat_actors,
        "ai_mitre_techniques": mitre_techniques,
        "ai_classification_confidence": classification["confidence"],
        "ai_score_breakdown": score_result.get("breakdown", {}),
        "ai_top_factors": score_result.get("top_factors", []),
        "score_model_version": score_result.get("score_model_version"),
        "score_config_version": score_result.get("score_config_version"),
        "credibility_score": score_result.get("credibility_score", 0),
        "impact_score": score_result.get("impact_score", 0),
        "validation_status": validation["validation_status"],
        "validation_reasons": validation["validation_reasons"],
        "warehouse_eligible": validation["warehouse_eligible"],
        "review_required": validation["review_required"],
        "review_state": review_state,
        "reviewed_by": None,
        "reviewed_at": None,
        "review_notes": None,
        "cleaning_flags": sanitization_summary.get("flags", []),
        "sanitization_summary": sanitization_summary,
    }
    document.update(derive_action_metadata(document))

    return {
        "document": document,
        "validation": validation,
        "sanitization_summary": sanitization_summary,
        "observation_count": len(ioc_docs),
    }
