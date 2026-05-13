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


def _extract_misp_galaxy_value(tag: str, galaxy: str) -> Optional[str]:
    pattern = rf'misp-galaxy:{re.escape(galaxy)}="([^"]+)"'
    match = re.search(pattern, tag, flags=re.IGNORECASE)
    return match.group(1).strip() if match else None


def _extract_risk_score_from_tags(tags: List[str]) -> Optional[int]:
    for tag in tags:
        match = re.search(r"risk-score:(\d+)", tag, flags=re.IGNORECASE)
        if match:
            return max(0, min(100, _parse_int(match.group(1), 0)))
    return None


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


def _unique(values: List[Any]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        cleaned = _as_text(value)
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def _compact_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in evidence.items()
        if value not in (None, "", [], {}, False)
    }


def _flatten_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source_evidence": evidence,
        "source_risk_score": evidence.get("source_risk_score"),
        "source_actionable": bool(evidence.get("source_actionable", False)),
        "external_evidence_sources": evidence.get("external_evidence_sources", []),
        "virustotal_malicious": evidence.get("virustotal_malicious"),
        "virustotal_suspicious": evidence.get("virustotal_suspicious"),
        "related_doc_count": evidence.get("related_doc_count", 0),
        "source_campaigns": evidence.get("source_campaigns", []),
        "source_target_countries": evidence.get("source_target_countries", []),
        "source_malware_family": evidence.get("source_malware_family"),
        "source_threat_actors": evidence.get("source_threat_actors", []),
        "source_mitre_techniques": evidence.get("source_mitre_techniques", []),
        "source_threat_types": evidence.get("source_threat_types", []),
    }


def extract_misp_evidence(raw: Dict[str, Any], tags: Optional[List[str]] = None) -> Dict[str, Any]:
    tags = tags if tags is not None else _tag_names(raw)
    event = raw.get("Event") if isinstance(raw.get("Event"), dict) else {}
    threat_level = event.get("ThreatLevel") if isinstance(event.get("ThreatLevel"), dict) else {}
    actors: List[str] = []
    sectors: List[str] = []
    target_countries: List[str] = []
    for tag in tags:
        actor = _extract_misp_galaxy_value(tag, "threat-actor")
        sector = _extract_misp_galaxy_value(tag, "sector")
        target = _extract_misp_galaxy_value(tag, "target-information")
        if actor:
            actors.append(actor)
        if sector:
            sectors.append(sector)
        if target:
            target_countries.append(target)

    risk_score = _extract_risk_score_from_tags(tags)
    confidence = _confidence_from_tags(tags)
    evidence = {
        "evidence_type": "misp",
        "external_evidence_sources": ["MISP"],
        "source_risk_score": risk_score,
        "source_actionable": bool(raw.get("to_ids", False)),
        "source_confidence": confidence or risk_score,
        "misp_category": raw.get("category"),
        "misp_threat_level": threat_level.get("name"),
        "source_threat_types": _extract_threats_from_tags(tags),
        "source_threat_actors": _unique(actors),
        "source_sectors": _unique(sectors),
        "source_target_countries": _unique(target_countries),
        "raw_tags": tags,
    }
    return _compact_evidence(evidence)


def extract_virustotal_evidence(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    vt = enrichment.get("virustotal") if isinstance(enrichment.get("virustotal"), dict) else {}
    attributes = vt.get("attributes") if isinstance(vt.get("attributes"), dict) else {}
    stats = attributes.get("last_analysis_stats") if isinstance(attributes.get("last_analysis_stats"), dict) else {}
    if not stats:
        return {}
    malicious = _parse_int(stats.get("malicious"), 0)
    suspicious = _parse_int(stats.get("suspicious"), 0)
    harmless = _parse_int(stats.get("harmless"), 0)
    undetected = _parse_int(stats.get("undetected"), 0)
    sources = ["VirusTotal"] if malicious > 0 or suspicious > 0 else []
    evidence = {
        "evidence_type": "virustotal",
        "external_evidence_sources": sources,
        "virustotal_malicious": malicious,
        "virustotal_suspicious": suspicious,
        "virustotal_harmless": harmless,
        "virustotal_undetected": undetected,
        "virustotal_reputation": attributes.get("reputation"),
        "virustotal_meaningful_name": attributes.get("meaningful_name"),
    }
    return _compact_evidence(evidence)


def extract_cyberint_evidence(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    cyberint = enrichment.get("cyberint") if isinstance(enrichment.get("cyberint"), dict) else {}
    if not cyberint:
        return {}
    source_indicators = cyberint.get("source_indicators")
    if not isinstance(source_indicators, list):
        source_indicators = []
    risk = cyberint.get("risk")
    evidence = {
        "evidence_type": "cyberint_enrichment",
        "external_evidence_sources": ["Cyberint"] if risk is not None else [],
        "source_risk_score": _parse_int(risk, 0) if risk is not None else None,
        "source_confidence": _parse_int(risk, 0) if risk is not None else None,
        "cyberint_ref": cyberint.get("ref"),
        "cyberint_source_indicator_count": len(source_indicators),
    }
    return _compact_evidence(evidence)


def extract_correlation_evidence(raw: Dict[str, Any]) -> Dict[str, Any]:
    correlations = raw.get("correlations") if isinstance(raw.get("correlations"), dict) else {}
    related_docs = correlations.get("related_docs") if isinstance(correlations.get("related_docs"), list) else []
    related_iocs: List[str] = []
    related_types: List[str] = []
    for related in related_docs:
        if not isinstance(related, dict):
            continue
        if related.get("original_ioc"):
            related_iocs.append(related["original_ioc"])
        if related.get("type"):
            related_types.append(related["type"])
    evidence = {
        "evidence_type": "correlation",
        "related_doc_count": len(related_docs),
        "related_iocs": _unique(related_iocs[:50]),
        "related_ioc_types": _unique(related_types),
    }
    return _compact_evidence(evidence)


def extract_sandbox_evidence(raw: Dict[str, Any]) -> Dict[str, Any]:
    suspicious = raw.get("suspicious_activities")
    if not isinstance(suspicious, list):
        suspicious = []
    evidence = {
        "evidence_type": "sandbox",
        "external_evidence_sources": ["Sandbox"] if raw.get("verdict") or raw.get("malware_family") else [],
        "source_malware_family": raw.get("malware_family"),
        "sandbox_verdict": raw.get("verdict"),
        "sandbox_state": raw.get("state"),
        "sandbox_suspicious_activities": suspicious[:25],
        "source_threat_types": [raw.get("malware_family")] if raw.get("malware_family") else [],
    }
    return _compact_evidence(evidence)


def _merge_evidence(*items: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {
        "external_evidence_sources": [],
        "source_threat_types": [],
        "source_threat_actors": [],
        "source_mitre_techniques": [],
        "source_campaigns": [],
        "source_target_countries": [],
        "source_sectors": [],
    }
    raw_items = []
    for item in items:
        if not item:
            continue
        raw_items.append(item)
        for key in (
            "external_evidence_sources",
            "source_threat_types",
            "source_threat_actors",
            "source_mitre_techniques",
            "source_campaigns",
            "source_target_countries",
            "source_sectors",
        ):
            merged[key].extend(_as_list(item.get(key)))
        for key in (
            "source_risk_score",
            "source_confidence",
            "virustotal_malicious",
            "virustotal_suspicious",
            "virustotal_harmless",
            "virustotal_undetected",
            "related_doc_count",
        ):
            if item.get(key) is None:
                continue
            current = merged.get(key)
            if key == "related_doc_count":
                merged[key] = _parse_int(current, 0) + _parse_int(item.get(key), 0)
            else:
                merged[key] = max(_parse_int(current, 0), _parse_int(item.get(key), 0))
        if item.get("source_actionable"):
            merged["source_actionable"] = True
        for key in ("source_malware_family", "sandbox_verdict", "sandbox_state", "virustotal_meaningful_name"):
            if not merged.get(key) and item.get(key):
                merged[key] = item.get(key)
    for key, value in list(merged.items()):
        if isinstance(value, list):
            merged[key] = _unique(value)
    if raw_items:
        merged["raw_evidence"] = raw_items
    return _compact_evidence(merged)


def _extract_summary_evidence(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    summary = enrichment.get("summary") if isinstance(enrichment.get("summary"), dict) else {}
    if not summary:
        return {}
    evidence = {
        "evidence_type": "enrichment_summary",
        "source_threat_actors": _as_list(summary.get("actor_groups")),
        "source_campaigns": _as_list(summary.get("campaign_names")),
        "source_target_countries": _as_list(summary.get("countries")),
    }
    return _compact_evidence(evidence)


def _extract_mitre_evidence(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    mitre = enrichment.get("mitre") if isinstance(enrichment.get("mitre"), dict) else {}
    if not mitre:
        return {}
    technique = " ".join(part for part in [_as_text(mitre.get("external_id")), _as_text(mitre.get("name"))] if part)
    evidence = {
        "evidence_type": "mitre",
        "source_mitre_techniques": [technique] if technique else [],
        "mitre_tactics": _as_list(mitre.get("tactics")),
    }
    return _compact_evidence(evidence)


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
    evidence = extract_misp_evidence(raw, tags)
    confidence = evidence.get("source_confidence") or _confidence_from_tags(tags)

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
        threat_type=evidence.get("source_threat_types") or _extract_threats_from_tags(tags),
        severity=_normalize_severity(threat_level.get("name")),
        tags=tags,
        reference=raw.get("uuid") or event.get("uuid") or hit.get("_id") or "",
        collect_time=collect_time,
        event_time=event_time,
        geo_country=None,
        confidence=confidence,
        source_url="",
        source_id=raw.get("uuid") or raw.get("id") or hit.get("_id"),
        enrichment={"misp_event": event},
        domain_age_days=None,
        **_flatten_evidence(evidence),
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
    evidence = _merge_evidence(
        extract_virustotal_evidence(enrichment),
        extract_cyberint_evidence(enrichment),
        _extract_summary_evidence(enrichment),
        _extract_mitre_evidence(enrichment),
        extract_correlation_evidence(raw),
        extract_sandbox_evidence(raw),
    )
    confidence = max(_parse_int(raw.get("confidence"), 0), _parse_int(evidence.get("source_confidence"), 0))

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
        threat_type=_unique(_as_list(raw.get("threat_type")) + _as_list(evidence.get("source_threat_types"))),
        severity=raw.get("severity") or "low",
        tags=raw.get("tags") or first_source.get("tags") or [],
        reference=first_source.get("url") or raw.get("reference") or raw.get("ref_doc_id") or raw.get("doc_hash") or "",
        collect_time=first_source.get("collect_time") or raw.get("@timestamp") or raw.get("processed_at"),
        event_time=raw.get("@timestamp") or raw.get("processed_at") or first_source.get("collect_time"),
        geo_country=geo_ip.get("country_code") or geo_ip.get("country") or raw.get("geo_country"),
        confidence=confidence,
        source_url=first_source.get("url") or "",
        source_id=raw.get("ref_doc_id") or raw.get("doc_hash") or hit.get("_id"),
        enrichment=enrichment,
        domain_age_days=raw.get("domain_age_days"),
        **_flatten_evidence(evidence),
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
