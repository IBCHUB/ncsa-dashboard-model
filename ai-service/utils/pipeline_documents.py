"""
Shared document builders for the AI pipeline.

These helpers aggregate multiple datalake observations for the same IOC,
sanitize sensitive content, run AI enrichment, and attach validation metadata
before the document is persisted to the warehouse index.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from models.classifier import (
    classify_threat,
    extract_mitre_techniques,
    extract_threat_actors,
)
from models.actions import derive_action_metadata
from elastic_client import ElasticClient
from models.scorer import calculate_risk_score
from models.validation import evaluate_validation_status
from pipeline_classification_policy import (
    build_ml_classifier_input,
    build_rule_classification,
    build_skipped_classification,
    decide_classification_mode,
    detect_context_rule_threat_types,
    map_rule_threat_types,
    strict_ml_classification,
)
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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _max_or_none(values: Sequence[int]) -> Optional[int]:
    return max(values) if values else None


def build_classifier_context(
    ioc_value: str,
    ioc_type: str,
    descriptions: List[str],
    threat_types_raw: List[str],
    source_names: List[str],
    source_types: List[str],
    ioc_docs: Sequence[Dict[str, Any]],
) -> str:
    """Build rich context text for the AI classifier.

    When source descriptions are empty or too short, the classifier receives
    nothing and returns zero results.  This function synthesises meaningful
    text from all available structured data so the zero-shot model can still
    detect threat types, actors, and MITRE techniques.

    The output is used **only** as classifier input — the warehouse
    ``description`` field keeps the original source text unchanged.
    """
    parts: List[str] = []

    # 1. IOC identity — always available
    parts.append(f"IOC: {ioc_value} (type: {ioc_type})")

    # 2. Existing descriptions (primary signal when present)
    if descriptions:
        parts.append("\n".join(descriptions))

    # 3. Source-reported threat types
    unique_threats = sorted(set(t for t in threat_types_raw if t))
    if unique_threats:
        parts.append(f"Threat types reported by source: {', '.join(unique_threats)}")

    # 4. Source attribution
    if source_names:
        source_ctx_items = []
        for name, stype in zip(source_names, source_types + [""] * len(source_names)):
            source_ctx_items.append(f"{name} ({stype})" if stype else name)
        parts.append(f"Reported by: {', '.join(source_ctx_items)}")

    # 5–8. Enrichment data extracted from datalake observations
    whois_added = False
    ip_added = False
    categories_added = False
    for doc in ioc_docs:
        enrichment = doc.get("enrichment")
        if not isinstance(enrichment, dict) or not enrichment:
            continue

        evidence = doc.get("source_evidence")
        if isinstance(evidence, dict) and evidence:
            evidence_parts = []
            if evidence.get("virustotal_malicious") is not None:
                evidence_parts.append(
                    f"VirusTotal malicious={evidence.get('virustotal_malicious')} "
                    f"suspicious={evidence.get('virustotal_suspicious', 0)}"
                )
            if evidence.get("source_risk_score") is not None:
                evidence_parts.append(f"source risk score={evidence.get('source_risk_score')}")
            if evidence.get("source_threat_actors"):
                evidence_parts.append(f"actors={', '.join(evidence.get('source_threat_actors', []))}")
            if evidence.get("source_mitre_techniques"):
                evidence_parts.append(f"MITRE={', '.join(evidence.get('source_mitre_techniques', []))}")
            if evidence_parts:
                parts.append("Evidence: " + "; ".join(evidence_parts))

        # WHOIS context (domain registration)
        if not whois_added:
            whois = enrichment.get("whois")
            if isinstance(whois, dict) and whois:
                whois_parts = []
                domain_name = whois.get("domain_name", "")
                if isinstance(domain_name, list):
                    domain_name = domain_name[0] if domain_name else ""
                if domain_name:
                    whois_parts.append(f"Domain {domain_name}")
                registrant_org = whois.get("registrant_organization") or whois.get("org", "")
                registrant_country = whois.get("registrant_country") or whois.get("country", "")
                if registrant_org:
                    whois_parts.append(f"registered to {registrant_org}")
                if registrant_country:
                    whois_parts.append(f"in {registrant_country}")
                creation_date = whois.get("creation_date", "")
                if creation_date:
                    whois_parts.append(f"created {str(creation_date)[:10]}")
                registrar = whois.get("registrar", "")
                if registrar:
                    whois_parts.append(f"registrar: {registrar}")
                if whois_parts:
                    parts.append(" ".join(whois_parts))
                    whois_added = True

        # IP / ASN context
        if not ip_added:
            ip_info = enrichment.get("ip_info")
            if isinstance(ip_info, dict) and ip_info:
                ip_parts = []
                asn_data = ip_info.get("asn_data", {})
                _asn_data = asn_data if isinstance(asn_data, dict) else {}
                country = (
                    ip_info.get("country")
                    or ip_info.get("country_code", "")
                    or _asn_data.get("country", "")
                )
                org = ip_info.get("org", "") or _asn_data.get("org", "")
                asn = ip_info.get("asn", "")
                if country:
                    ip_parts.append(f"IP located in {country}")
                if asn and org:
                    ip_parts.append(f"ASN: {asn} ({org})")
                elif org:
                    ip_parts.append(f"Organization: {org}")
                if ip_parts:
                    parts.append(", ".join(ip_parts))
                    ip_added = True

        # VirusTotal / threat categories
        if not categories_added:
            categories = enrichment.get("categories")
            cat_list: List[str] = []
            if isinstance(categories, list):
                cat_list = [str(c) for c in categories if c]
            elif isinstance(categories, dict):
                cat_list = [str(v) for v in categories.values() if v]
            if cat_list:
                parts.append(f"Threat categories: {', '.join(cat_list)}")
                categories_added = True

    return "\n".join(parts)


def classify_pipeline_context(
    *,
    classifier_input: str,
    source_types: Sequence[str],
    adapter_names: Sequence[str],
    threat_types_raw: Sequence[str],
    ioc_docs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Classify an IOC using ML only when the policy says it is useful."""
    start = time.time()
    ml_input = classifier_input
    context_rule_threat_types = detect_context_rule_threat_types(classifier_input)
    effective_threat_types_raw = _unique_non_empty(
        list(threat_types_raw) + context_rule_threat_types
    )
    decision = decide_classification_mode(
        source_types=source_types,
        adapter_names=adapter_names,
        threat_types_raw=effective_threat_types_raw,
        classifier_input=classifier_input,
    )

    if context_rule_threat_types:
        classification = build_rule_classification(
            threat_types_raw=effective_threat_types_raw,
            ioc_docs=ioc_docs,
        )
        classification_mode = "source_rule"
        classification_reason = "context_rule_threat_metadata"
    elif decision.mode == "ml":
        ml_input = build_ml_classifier_input(classifier_input)
        classification = strict_ml_classification(classify_threat(ml_input))
        classification_mode = decision.mode
        classification_reason = decision.reason
    elif decision.mode == "source_rule":
        classification = build_rule_classification(
            threat_types_raw=effective_threat_types_raw,
            ioc_docs=ioc_docs,
        )
        classification_mode = decision.mode
        classification_reason = decision.reason
    else:
        classification = build_skipped_classification()
        classification_mode = decision.mode
        classification_reason = decision.reason

    # These extractors are rule/keyword-based and inexpensive compared with ML.
    threat_actors = extract_threat_actors(classifier_input)
    mitre_techniques = extract_mitre_techniques(classifier_input)
    elapsed_ms = int((time.time() - start) * 1000)

    return {
        "classification": classification,
        "threat_actors": threat_actors,
        "mitre_techniques": mitre_techniques,
        "classification_mode": classification_mode,
        "classification_reason": classification_reason,
        "classifier_input_chars": decision.classifier_input_chars,
        "classifier_effective_input_chars": len(ml_input) if classification_mode == "ml" else decision.classifier_input_chars,
        "classification_time_ms": elapsed_ms,
        "context_rule_threat_types": context_rule_threat_types,
    }


def build_enriched_ioc_document(ioc_docs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not ioc_docs:
        raise ValueError("ioc_docs must not be empty")

    primary = ioc_docs[0]
    ioc_value = str(primary.get("ioc_value", "")).strip()
    ioc_type = str(primary.get("ioc_type", "unknown")).strip().lower()
    canonical_ioc_key = ElasticClient.canonical_ioc_key(primary)

    source_names: List[str] = []
    source_objects: List[Dict[str, Any]] = []
    source_types: List[str] = []
    source_urls: List[str] = []
    adapter_names: List[str] = []
    descriptions: List[str] = []
    references: List[str] = []
    raw_tags: List[str] = []
    threat_types_raw: List[str] = []
    severity_values: List[str] = []
    geo_countries: List[str] = []
    first_seen_candidates: List[datetime] = []
    last_seen_candidates: List[datetime] = []
    domain_age_candidates: List[int] = []
    original_ioc_values: List[str] = []
    original_ioc_types: List[str] = []
    source_risk_scores: List[int] = []
    source_actionable = False
    external_evidence_sources: List[str] = []
    source_threat_actors: List[str] = []
    source_mitre_techniques: List[str] = []
    source_campaigns: List[str] = []
    source_target_countries: List[str] = []
    source_malware_families: List[str] = []
    source_evidence_items: List[Dict[str, Any]] = []
    vt_malicious_values: List[int] = []
    vt_suspicious_values: List[int] = []
    related_doc_count = 0

    for doc in ioc_docs:
        source_name = str(doc.get("source_name", "")).strip()
        confidence = float(doc.get("confidence", 0) or 0)
        original_ioc_value = str(doc.get("original_ioc_value") or doc.get("ioc_value") or "").strip()
        original_ioc_type = str(doc.get("original_ioc_type") or doc.get("ioc_type") or "").strip()
        if original_ioc_value:
            original_ioc_values.append(original_ioc_value)
        if original_ioc_type:
            original_ioc_types.append(original_ioc_type)

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

        adapter_name = str(doc.get("adapter_name", "")).strip()
        if adapter_name and adapter_name not in adapter_names:
            adapter_names.append(adapter_name)

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

        evidence = doc.get("source_evidence")
        if isinstance(evidence, dict) and evidence:
            source_evidence_items.append(evidence)
            if evidence.get("source_risk_score") is not None:
                source_risk_scores.append(_safe_int(evidence.get("source_risk_score")))
            source_actionable = source_actionable or bool(evidence.get("source_actionable"))
            for item in evidence.get("external_evidence_sources", []) or []:
                external_evidence_sources.append(str(item))
            for item in evidence.get("source_threat_types", []) or []:
                if item:
                    threat_types_raw.append(str(item))
            for item in evidence.get("source_threat_actors", []) or []:
                source_threat_actors.append(str(item))
            for item in evidence.get("source_mitre_techniques", []) or []:
                source_mitre_techniques.append(str(item))
            for item in evidence.get("source_campaigns", []) or []:
                source_campaigns.append(str(item))
            for item in evidence.get("source_target_countries", []) or []:
                source_target_countries.append(str(item))
            malware_family = str(evidence.get("source_malware_family") or "").strip()
            if malware_family:
                source_malware_families.append(malware_family)
            if evidence.get("virustotal_malicious") is not None:
                vt_malicious_values.append(_safe_int(evidence.get("virustotal_malicious")))
            if evidence.get("virustotal_suspicious") is not None:
                vt_suspicious_values.append(_safe_int(evidence.get("virustotal_suspicious")))
            related_doc_count += _safe_int(evidence.get("related_doc_count"), 0)

        severity_values.append(str(doc.get("severity", "")).strip().lower())

        geo_country = str(doc.get("geo_country", "")).strip()
        if geo_country:
            geo_countries.append(geo_country)

        source_url = str(doc.get("source_url", "")).strip()
        if source_url and source_url not in source_urls:
            source_urls.append(source_url)

        doc_domain_age = doc.get("domain_age_days")
        if doc_domain_age is not None:
            domain_age_candidates.append(int(doc_domain_age))

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
    sources = source_names if source_names else ["unknown"]
    evidence_source_names = _unique_non_empty(external_evidence_sources)
    max_source_risk_score = _max_or_none(source_risk_scores)
    scoring_source_objects = list(source_objects)
    scoring_source_names = {str(item.get("name", "")).strip() for item in scoring_source_objects}
    evidence_confidence = max_source_risk_score or 0
    for evidence_source in evidence_source_names:
        if evidence_source and evidence_source not in scoring_source_names:
            scoring_source_objects.append(
                {
                    "name": evidence_source,
                    "confidence": evidence_confidence,
                    "type": "source_evidence",
                }
            )
            scoring_source_names.add(evidence_source)

    first_seen_dt = min(first_seen_candidates) if first_seen_candidates else None
    last_seen_dt = max(last_seen_candidates) if last_seen_candidates else None
    first_seen = to_iso_z(first_seen_dt) or primary.get("event_time")
    last_seen = to_iso_z(last_seen_dt) or primary.get("collect_time")

    ioc_age_days = None
    if first_seen_dt:
        ioc_age_days = max(0, (datetime.now(timezone.utc) - first_seen_dt.astimezone(timezone.utc)).days)

    domain_age_days = min(domain_age_candidates) if domain_age_candidates else None

    classifier_input = build_classifier_context(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        descriptions=sanitized_descriptions,
        threat_types_raw=threat_types_raw,
        source_names=source_names,
        source_types=source_types,
        ioc_docs=ioc_docs,
    )
    classification_result = classify_pipeline_context(
        classifier_input=classifier_input,
        source_types=source_types,
        adapter_names=adapter_names,
        threat_types_raw=threat_types_raw,
        ioc_docs=ioc_docs,
    )
    classification = classification_result["classification"]
    source_threat_actors = _unique_non_empty(source_threat_actors)
    source_mitre_techniques = _unique_non_empty(source_mitre_techniques)
    source_threat_types = _unique_non_empty(threat_types_raw)
    mapped_source_threat_types = map_rule_threat_types(source_threat_types) if source_threat_types else []
    classification_threat_types = _unique_non_empty(
        list(classification["threat_types"]) + mapped_source_threat_types
    )
    threat_actors = _unique_non_empty(
        list(classification_result["threat_actors"]) + source_threat_actors
    )
    mitre_techniques = _unique_non_empty(
        list(classification_result["mitre_techniques"]) + source_mitre_techniques
    )

    score_result = calculate_risk_score(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        description=merged_description,
        sources=scoring_source_objects or sources,
        domain_age_days=domain_age_days,
        ioc_age_days=ioc_age_days,
        threat_classification={
            "threat_types": classification_threat_types,
            "threat_actors": threat_actors,
            "mitre_techniques": mitre_techniques,
            "confidence": classification["confidence"],
            "sector_classifications": classification.get("sector_classifications", []),
        },
    )

    validation = evaluate_validation_status(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        score_result=score_result,
        ai_confidence=classification["confidence"],
        sanitization_summary=sanitization_summary,
        validation_context={
            "classification_mode": classification_result["classification_mode"],
            "classification_reason": classification_result["classification_reason"],
            "source_types": source_types,
            "ai_threat_types": classification_threat_types,
            "external_evidence_sources": evidence_source_names,
            "source_actionable": source_actionable,
        },
    )

    document = {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "canonical_ioc_key": canonical_ioc_key,
        "original_ioc_values": _unique_non_empty(original_ioc_values),
        "original_ioc_types": _unique_non_empty(original_ioc_types),
        "source_name": ", ".join(source_names) if source_names else "unknown",
        "source_type": "multi" if len(source_types) > 1 else (source_types[0] if source_types else "unknown"),
        "sources": sources,
        "source_types": source_types,
        "source_count": len(scoring_source_names) if scoring_source_names else len(sources),
        "source_urls": source_urls,
        "description": merged_description,
        "threat_type": sorted(set(source_threat_types)),
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
        "ai_threat_types": classification_threat_types,
        "ai_threat_actors": threat_actors,
        "ai_mitre_techniques": mitre_techniques,
        "ai_classification_confidence": classification["confidence"],
        "source_risk_score": max_source_risk_score,
        "source_actionable": source_actionable,
        "external_evidence_sources": evidence_source_names,
        "virustotal_malicious": _max_or_none(vt_malicious_values),
        "virustotal_suspicious": _max_or_none(vt_suspicious_values),
        "related_doc_count": related_doc_count,
        "source_campaigns": _unique_non_empty(source_campaigns),
        "source_target_countries": _unique_non_empty(source_target_countries),
        "source_malware_family": (_unique_non_empty(source_malware_families) or [None])[0],
        "source_evidence": source_evidence_items,
        "classification_mode": classification_result["classification_mode"],
        "classification_reason": classification_result["classification_reason"],
        "classifier_input_chars": classification_result["classifier_input_chars"],
        "classifier_effective_input_chars": classification_result["classifier_effective_input_chars"],
        "classification_time_ms": classification_result["classification_time_ms"],
        "ai_score_breakdown": score_result.get("breakdown", {}),
        "ai_top_factors": score_result.get("top_factors", []),
        "score_model_version": score_result.get("score_model_version"),
        "score_config_version": score_result.get("score_config_version"),
        "credibility_score": score_result.get("credibility_score", 0),
        "impact_score": score_result.get("impact_score", 0),
        "validation_status": validation["validation_status"],
        "validation_reasons": validation["validation_reasons"],
        "warehouse_eligible": validation["warehouse_eligible"],
        "cleaning_flags": sanitization_summary.get("flags", []),
        "sanitization_summary": sanitization_summary,
        "cluster_label": None,
        "cluster_probability": None,
    }
    document.update(derive_action_metadata(document))

    return {
        "document": document,
        "validation": validation,
        "sanitization_summary": sanitization_summary,
        "observation_count": len(ioc_docs),
    }
