"""
Datalake adapter registry.

Adapters convert raw customer datalake records into the canonical IOC shape
used by the existing AI pipeline. Unknown schemas are quarantined instead of
crashing or blocking the whole batch.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _epoch_to_iso(value: Any) -> Optional[str]:
    text = _as_text(value)
    if not text:
        return None
    try:
        return datetime.fromtimestamp(int(text), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _normalize_severity(value: Any) -> str:
    text = _as_text(value).lower()
    if text in {"critical", "high", "medium", "low", "clean"}:
        return text
    score = _parse_int(value, default=-1)
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 0:
        return "low"
    return "low"


def _tag_names(raw: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    for item in _as_list(raw.get("Tag")):
        if isinstance(item, dict):
            name = _as_text(item.get("name"))
            if name:
                tags.append(name)
        else:
            name = _as_text(item)
            if name:
                tags.append(name)
    return tags


def _extract_threats_from_tags(tags: List[str]) -> List[str]:
    threats: List[str] = []
    for tag in tags:
        match = re.search(r'behaviour-tag="([^"]+)"', tag, flags=re.IGNORECASE)
        if match:
            threats.append(match.group(1))
    return threats


def _confidence_from_tags(tags: List[str]) -> int:
    for tag in tags:
        lowered = tag.lower()
        if lowered == "confidence:high":
            return 80
        if lowered == "confidence:medium":
            return 50
        if lowered == "confidence:low":
            return 20
    return 0


def _raw_fingerprint(raw: Dict[str, Any]) -> str:
    payload = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _base_doc(hit: Dict[str, Any], adapter_name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "_id": hit.get("_id"),
        "_index": hit.get("_index"),
        "adapter_name": adapter_name,
        "raw": raw,
    }


def _finalize(
    hit: Dict[str, Any],
    raw: Dict[str, Any],
    adapter_name: str,
    original_ioc_type: Any,
    original_ioc_value: Any,
    normalize_type,
    normalize_value,
    **fields: Any,
) -> Dict[str, Any]:
    normalized_ioc_type = normalize_type(original_ioc_type)
    normalized_ioc_value = normalize_value(original_ioc_value)
    doc = {
        **_base_doc(hit, adapter_name, raw),
        "ioc_value": normalized_ioc_value,
        "ioc_type": normalized_ioc_type,
        "original_ioc_value": original_ioc_value,
        "original_ioc_type": original_ioc_type,
        "canonical_ioc_key": f"{normalized_ioc_type}:{normalized_ioc_value}",
        "ai_processed": bool(raw.get("ai_processed", False)),
    }
    doc.update(fields)
    return doc


def _existing_canonical_adapter(hit: Dict[str, Any], normalize_type, normalize_value) -> Optional[Dict[str, Any]]:
    raw = hit.get("_source", {})
    if not (raw.get("ioc_value") and raw.get("ioc_type")):
        return None

    original_type = raw.get("ioc_type")
    original_value = raw.get("ioc_value")
    return _finalize(
        hit,
        raw,
        "existing_canonical",
        original_type,
        original_value,
        normalize_type,
        normalize_value,
        source_name=raw.get("source_name") or raw.get("ref_doc_index") or "tcti-feeds",
        source_type=raw.get("source_type") or "canonical",
        description=raw.get("description") or "",
        threat_type=raw.get("threat_type") or [],
        severity=raw.get("severity") or _normalize_severity(raw.get("severity_score")),
        tags=raw.get("tags") or [],
        reference=raw.get("reference") or raw.get("ref_doc_id") or raw.get("doc_hash") or "",
        collect_time=raw.get("collect_time") or raw.get("@timestamp") or raw.get("processed_at"),
        event_time=raw.get("event_time") or raw.get("observation_date") or raw.get("@timestamp") or raw.get("processed_at"),
        geo_country=raw.get("geo_country"),
        confidence=_parse_int(raw.get("confidence"), 0),
        source_url=raw.get("source_url") or "",
        source_id=raw.get("source_id") or raw.get("id") or hit.get("_id"),
        enrichment=raw.get("enrichment") if isinstance(raw.get("enrichment"), dict) else {},
        domain_age_days=raw.get("domain_age_days"),
    )


def _cyberint_iocs_adapter(hit: Dict[str, Any], normalize_type, normalize_value) -> Optional[Dict[str, Any]]:
    raw = hit.get("_source", {})
    if not (raw.get("ioc_type") and raw.get("ioc_value") and "cyberint_iocs-" in _as_text(hit.get("_index"))):
        return None

    activity = _as_text(raw.get("detected_activity"))
    description = _as_text(raw.get("description"))
    context_parts = [part for part in [activity.replace("_", " "), description] if part]
    return _finalize(
        hit,
        raw,
        "cyberint_iocs",
        raw.get("ioc_type"),
        raw.get("ioc_value"),
        normalize_type,
        normalize_value,
        source_name="cyberint_iocs",
        source_type="customer-datalake",
        description="\n".join(context_parts),
        threat_type=[activity] if activity else [],
        severity=_normalize_severity(raw.get("severity_score")),
        tags=[activity] if activity else [],
        reference=raw.get("id") or hit.get("_id") or "",
        collect_time=raw.get("@timestamp"),
        event_time=raw.get("observation_date") or raw.get("@timestamp"),
        geo_country=raw.get("geo_country"),
        confidence=_parse_int(raw.get("confidence"), 0),
        source_url="",
        source_id=raw.get("id") or hit.get("_id"),
        enrichment={},
        domain_age_days=None,
    )


def _misp_attribute_adapter(hit: Dict[str, Any], normalize_type, normalize_value) -> Optional[Dict[str, Any]]:
    raw = hit.get("_source", {})
    if not (raw.get("type") and raw.get("value") and "misp_attributes-" in _as_text(hit.get("_index"))):
        return None

    event = raw.get("Event") if isinstance(raw.get("Event"), dict) else {}
    orgc = event.get("Orgc") if isinstance(event.get("Orgc"), dict) else {}
    threat_level = event.get("ThreatLevel") if isinstance(event.get("ThreatLevel"), dict) else {}
    tags = _tag_names(raw)
    event_info = _as_text(event.get("info"))
    comment = _as_text(raw.get("comment"))
    description = "\n".join(part for part in [event_info, comment] if part)
    event_time = raw.get("first_seen") or _epoch_to_iso(raw.get("timestamp")) or raw.get("@timestamp")
    collect_time = raw.get("@timestamp") or raw.get("last_seen") or event_time

    return _finalize(
        hit,
        raw,
        "misp_attribute",
        raw.get("type"),
        raw.get("value"),
        normalize_type,
        normalize_value,
        source_name=orgc.get("name") or "MISP",
        source_type="misp",
        description=description,
        threat_type=_extract_threats_from_tags(tags),
        severity=_normalize_severity(threat_level.get("name")),
        tags=tags,
        reference=raw.get("uuid") or event.get("uuid") or hit.get("_id") or "",
        collect_time=collect_time,
        event_time=event_time,
        geo_country=None,
        confidence=_confidence_from_tags(tags),
        source_url="",
        source_id=raw.get("uuid") or raw.get("id") or hit.get("_id"),
        enrichment={"misp_event": event},
        domain_age_days=None,
    )


def _legacy_external_adapter(hit: Dict[str, Any], normalize_type, normalize_value) -> Optional[Dict[str, Any]]:
    raw = hit.get("_source", {})
    ioc = raw.get("ioc") if isinstance(raw.get("ioc"), dict) else {}
    if not (ioc.get("type") and ioc.get("value")):
        return None

    source = raw.get("source")
    first_source = {}
    if isinstance(source, list) and source and isinstance(source[0], dict):
        first_source = source[0]
    elif isinstance(source, dict):
        first_source = source

    enrichment = raw.get("enrichment") if isinstance(raw.get("enrichment"), dict) else {}
    geo_ip = enrichment.get("geo_ip") if isinstance(enrichment.get("geo_ip"), dict) else {}
    title = _as_text(first_source.get("title") or raw.get("title"))
    description = _as_text(first_source.get("description") or raw.get("description"))

    return _finalize(
        hit,
        raw,
        "legacy_external",
        ioc.get("type"),
        ioc.get("value"),
        normalize_type,
        normalize_value,
        source_name=first_source.get("name") or raw.get("source_name") or raw.get("ref_doc_index") or "tcti-feeds",
        source_type=raw.get("source_type") or "external-feed",
        description="\n".join(part for part in [title, description] if part),
        threat_type=raw.get("threat_type") or [],
        severity=raw.get("severity") or "low",
        tags=raw.get("tags") or first_source.get("tags") or [],
        reference=first_source.get("url") or raw.get("reference") or raw.get("ref_doc_id") or raw.get("doc_hash") or "",
        collect_time=first_source.get("collect_time") or raw.get("@timestamp") or raw.get("processed_at"),
        event_time=raw.get("@timestamp") or raw.get("processed_at") or first_source.get("collect_time"),
        geo_country=geo_ip.get("country_code") or geo_ip.get("country") or raw.get("geo_country"),
        confidence=_parse_int(raw.get("confidence"), 0),
        source_url=first_source.get("url") or "",
        source_id=raw.get("ref_doc_id") or raw.get("doc_hash") or hit.get("_id"),
        enrichment=enrichment,
        domain_age_days=raw.get("domain_age_days"),
    )


def quarantine_document(hit: Dict[str, Any], reason: str) -> Dict[str, Any]:
    raw = hit.get("_source", {})
    raw_keys = sorted(raw.keys()) if isinstance(raw, dict) else []
    return {
        "_id": hit.get("_id"),
        "_index": hit.get("_index"),
        "adapter_name": "unknown",
        "adapter_status": "quarantined",
        "quarantine_reason": reason,
        "raw_keys": raw_keys,
        "raw": raw,
        "source_fingerprint": f"raw:{_as_text(hit.get('_index'))}:{_as_text(hit.get('_id')) or _raw_fingerprint(raw)}",
    }


def normalize_datalake_hit(hit: Dict[str, Any], normalize_type, normalize_value) -> Dict[str, Any]:
    for adapter in (
        _cyberint_iocs_adapter,
        _misp_attribute_adapter,
        _existing_canonical_adapter,
        _legacy_external_adapter,
    ):
        doc = adapter(hit, normalize_type, normalize_value)
        if doc:
            doc["adapter_status"] = "normalized"
            return doc
    return quarantine_document(hit, "unsupported_datalake_schema")
