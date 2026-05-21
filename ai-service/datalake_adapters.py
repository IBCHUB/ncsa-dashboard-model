"""
Datalake adapter registry.

Adapters convert raw customer datalake records into the canonical IOC shape
used by the existing AI pipeline. Unknown schemas are quarantined instead of
crashing or blocking the whole batch.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re

logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.geoip_enrichment import enrich_geo_country

try:
    from utils.whois_enrichment import lookup_domain_age as _lookup_domain_age
except ImportError:
    _lookup_domain_age = None  # type: ignore[assignment]

try:
    from utils.threat_actor_enrichment import lookup_actors_from_description as _lookup_actors
except ImportError:
    _lookup_actors = None  # type: ignore[assignment]


def _build_mitre_actor_evidence(actors: List[str]) -> Dict[str, Any]:
    """Build evidence dict from MITRE actor mapping results."""
    if not actors:
        return {}
    return _compact_evidence({
        "evidence_type": "mitre_actor_mapping",
        "source_threat_actors": actors,
    })


# Maps cyberint_iocs detected_activity values → MITRE ATT&CK technique IDs.
# Each activity can map to 1-2 techniques. Used to populate
# source_mitre_techniques so the scoring pipeline gets MITRE data
# for the 10M cyberint_iocs docs that otherwise have no MITRE info.
_CYBERINT_ACTIVITY_MITRE: Dict[str, List[str]] = {
    "malware_payload":     ["T1587.001"],          # Develop Capabilities: Malware
    "infecting_url":       ["T1189"],              # Drive-by Compromise
    "phishing_website":    ["T1566.002"],          # Phishing: Spearphishing Link
    "infected_machine":    ["T1204.002"],          # User Execution: Malicious File
    "cnc_server":          ["T1102", "T1071"],     # Web Service + App Layer Protocol
    "anonymization":       ["T1090"],              # Proxy
    "infection_source":    ["T1190"],              # Exploit Public-Facing Application
    "botnet":              ["T1583.005"],          # Acquire Infrastructure: Botnet
    "malware":             ["T1587.001"],          # Develop Capabilities: Malware
    "compromised_website": ["T1189"],              # Drive-by Compromise
    "payload_delivery":    ["T1105"],              # Ingress Tool Transfer
    "credential_theft":    ["T1539", "T1555"],     # Steal Web Session Cookie + Credentials
    "data_exfiltration":   ["T1048"],              # Exfiltration Over Alternative Protocol
    "ransomware":          ["T1486"],              # Data Encrypted for Impact
}


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


def _first_text(*values: Any) -> Optional[str]:
    for value in values:
        cleaned = _as_text(value)
        if cleaned and cleaned.lower() not in {"none", "null", "unknown", "n/a", "-"}:
            return cleaned
    return None


def _dict_at_path(value: Any, *path: str) -> Dict[str, Any]:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _iter_dicts(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _extract_geo_country(raw: Dict[str, Any], enrichment: Optional[Dict[str, Any]] = None) -> Optional[str]:
    enrichment = enrichment if isinstance(enrichment, dict) else {}
    # tcti-feeds-* format uses enrichment.geo_ip; *-enrichment-* format uses enrichment.geo
    geo_ip = enrichment.get("geo_ip") if isinstance(enrichment.get("geo_ip"), dict) else {}
    if not geo_ip:
        geo_ip = enrichment.get("geo") if isinstance(enrichment.get("geo"), dict) else {}
    ip_info = enrichment.get("ip_info") if isinstance(enrichment.get("ip_info"), dict) else {}
    # ip_info.asn_data.country (enrichment format) vs ip_info.country (legacy format)
    ip_asn_data = ip_info.get("asn_data") if isinstance(ip_info.get("asn_data"), dict) else {}
    geo_info = raw.get("geo_info") if isinstance(raw.get("geo_info"), dict) else {}
    asn_data = raw.get("asn_data") if isinstance(raw.get("asn_data"), dict) else {}
    event = raw.get("Event") if isinstance(raw.get("Event"), dict) else {}
    source_geo = _dict_at_path(raw, "source", "geo")
    destination_geo = _dict_at_path(raw, "destination", "geo")
    victim_geo = _dict_at_path(raw, "victim", "geo")
    target_geo = _dict_at_path(raw, "target", "geo")
    return _first_text(
        raw.get("geo_country"),
        raw.get("country"),
        raw.get("country_code"),
        raw.get("victim_country"),
        raw.get("victim_country_name"),
        raw.get("source_country"),
        raw.get("source_country_name"),
        raw.get("target_country"),
        raw.get("target_country_name"),
        raw.get("destination_country"),
        raw.get("destination_country_name"),
        raw.get("src_country"),
        raw.get("dst_country"),
        raw.get("dst_country_name"),
        source_geo.get("country_code"),
        source_geo.get("country_name"),
        source_geo.get("country"),
        destination_geo.get("country_code"),
        destination_geo.get("country_name"),
        destination_geo.get("country"),
        victim_geo.get("country_code"),
        victim_geo.get("country_name"),
        victim_geo.get("country"),
        target_geo.get("country_code"),
        target_geo.get("country_name"),
        target_geo.get("country"),
        geo_ip.get("country_code"),
        geo_ip.get("country"),
        ip_info.get("country"),
        ip_asn_data.get("country_code"),
        ip_asn_data.get("country"),
        geo_info.get("country_code"),
        geo_info.get("country"),
        asn_data.get("country_code"),
        asn_data.get("country"),
        event.get("country"),
        event.get("threat_level_country"),
    )


def _infer_external_source_type(raw: Dict[str, Any], source_name: str, source_index: str) -> str:
    explicit = _as_text(raw.get("source_type")).lower()
    if explicit:
        return explicit

    source_key = f"{source_name} {source_index}".lower()
    if any(marker in source_key for marker in ("bleepingcomputer", "thehackernews", "hacker news", "darkreading")):
        return "news"
    if "sandbox" in source_key:
        return "sandbox"
    if "zone-h" in source_key or "zoneh" in source_key:
        return "external-feed"
    return "external-feed"


def _sanitize_malware_family(value: Any) -> Optional[str]:
    family = _as_text(value)
    if not family:
        return None
    lowered = family.lower()
    invalid_markers = (
        "read more",
        "http://",
        "https://",
        "threatcloud intelligence",
        "click here",
        "learn more",
    )
    if any(marker in lowered for marker in invalid_markers):
        return None
    if len(family) > 80:
        return None
    return family


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

    # `risk` has two shapes depending on the source format:
    #   - Plain int/string  (legacy): risk = 80
    #   - Dict (Zone-H enrichment):   risk = {"malicious_score": 100, "detected_activities": [...]}
    risk_score: Optional[int] = None
    threat_types: List[str] = []
    threat_actors: List[str] = []

    occurrences_count = 0
    if isinstance(risk, dict):
        # Zone-H enrichment format — extract malicious_score, activity types, and linked threat actors
        raw_score = _parse_int(risk.get("malicious_score"), 0)
        risk_score = raw_score if raw_score > 0 else None
        occurrences_count = _parse_int(risk.get("occurrences_count"), 0)
        for activity in _as_list(risk.get("detected_activities")):
            if not isinstance(activity, dict):
                continue
            # "type" is the activity label (e.g. "cnc_server", "payload_delivery")
            act_type = _as_text(activity.get("type") or activity.get("activity"))
            if act_type:
                threat_types.append(act_type)
            # related_entities holds the linked threat actor groups
            for entity in _as_list(activity.get("related_entities")):
                if isinstance(entity, dict):
                    name = _first_text(entity.get("entity_name"), entity.get("name"))
                    if name:
                        threat_actors.append(name)
    elif risk is not None:
        # Legacy plain numeric score
        raw_score = _parse_int(risk, 0)
        risk_score = raw_score if raw_score > 0 else None

    # occurrences_count >= 5 means Cyberint confirmed across multiple data points — treat as
    # corroborating source so cross_source score gets a boost
    extra_sources = ["Cyberint (multi-occurrence)"] if occurrences_count >= 5 else []
    evidence = {
        "evidence_type": "cyberint_enrichment",
        "external_evidence_sources": (["Cyberint"] + extra_sources) if risk is not None else [],
        "source_risk_score": risk_score,
        "source_confidence": risk_score,
        "cyberint_ref": cyberint.get("ref"),
        "cyberint_source_indicator_count": len(source_indicators),
        "cyberint_occurrence_count": occurrences_count if occurrences_count > 0 else None,
        "source_threat_types": _unique(threat_types),
        "source_threat_actors": _unique(threat_actors),
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
    malware_family = _sanitize_malware_family(raw.get("malware_family"))
    evidence = {
        "evidence_type": "sandbox",
        "external_evidence_sources": ["Sandbox"] if raw.get("verdict") or malware_family else [],
        "source_malware_family": malware_family,
        "sandbox_verdict": raw.get("verdict"),
        "sandbox_state": raw.get("state"),
        "sandbox_suspicious_activities": suspicious[:25],
        "source_threat_types": [malware_family] if malware_family else [],
    }
    return _compact_evidence(evidence)


def _merge_evidence(*items: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {
        "external_evidence_sources": [],
        "source_threat_types": [],
        "source_threat_actors": [],
        "source_mitre_techniques": [],
        "mitre_tactics": [],
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
            "mitre_tactics",
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


def _extract_related_entities_evidence(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    """Extract top-level enrichment.related_entities threat actors.

    The *-enrichment-* index format stores related threat actor groups directly at
    enrichment.related_entities[], separate from the enrichment.cyberint.risk path.
    """
    entities = enrichment.get("related_entities")
    if not isinstance(entities, list) or not entities:
        return {}
    actors: List[str] = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if _as_text(entity.get("entity_type")).lower() in ("threat-actor-group", "threat_actor", "actor"):
            name = _first_text(entity.get("entity_name"), entity.get("name"))
            if name:
                actors.append(name)
    if not actors:
        return {}
    return _compact_evidence({
        "evidence_type": "related_entities",
        "source_threat_actors": _unique(actors),
    })


def _extract_mitre_evidence(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    mitre_items = _iter_dicts(enrichment.get("mitre"))
    if not mitre_items:
        return {}
    techniques: List[str] = []
    tactics: List[Any] = []
    actors: List[str] = []
    campaigns: List[str] = []
    countries: List[str] = []
    for mitre in mitre_items:
        technique = " ".join(part for part in [_as_text(mitre.get("external_id")), _as_text(mitre.get("name"))] if part)
        if technique:
            techniques.append(technique)
        tactics.extend(_as_list(mitre.get("tactics")))
        for actor in _as_list(mitre.get("actor_groups")):
            if isinstance(actor, dict):
                actor_name = _first_text(actor.get("name"), actor.get("group_name"), actor.get("id"))
                if actor_name:
                    actors.append(actor_name)
                for country in _as_list(actor.get("countries")):
                    country_text = _first_text(country)
                    if country_text:
                        countries.append(country_text)
            else:
                actor_name = _first_text(actor)
                if actor_name:
                    actors.append(actor_name)
        for campaign in _as_list(mitre.get("campaigns")):
            if isinstance(campaign, dict):
                campaign_name = _first_text(campaign.get("name"), campaign.get("id"))
            else:
                campaign_name = _first_text(campaign)
            if campaign_name:
                campaigns.append(campaign_name)
    evidence = {
        "evidence_type": "mitre",
        "source_mitre_techniques": _unique(techniques[:25]),
        "mitre_tactics": _unique(tactics[:25]),
        "source_threat_actors": _unique(actors[:25]),
        "source_campaigns": _unique(campaigns[:25]),
        "source_target_countries": _unique(countries[:25]),
    }
    return _compact_evidence(evidence)


def _raw_fingerprint(raw: Dict[str, Any]) -> str:
    payload = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _source_name_from_index(index_name: str) -> Optional[str]:
    """Derive a meaningful source_name from an ES index name.

    Index patterns:
      cyberint-feeds-2025.04  → cyberint_iocs
      tcti-feeds-sandbox-*    → tcti-feeds-sandbox
      tcti-feeds-darkreading-*→ tcti-feeds-darkreading
      tcti-feeds-thehackernews-* → tcti-feeds-thehackernews
      tcti-feeds-bleepingcomputer-* → tcti-feeds-bleeping
      tcti-feeds-zoneh-*      → tcti-feeds-zoneh
      misp-*                  → misp_attributes
    Falls back to None if the index name is unrecognised.
    """
    if not index_name:
        return None
    idx = index_name.lower()
    if idx.startswith("cyberint"):
        return "cyberint_iocs"
    if idx.startswith("tcti-feeds-sandbox"):
        return "tcti-feeds-sandbox"
    if idx.startswith("tcti-feeds-darkreading"):
        return "tcti-feeds-darkreading"
    if idx.startswith("tcti-feeds-thehackernews") or idx.startswith("tcti-feeds-hackernews"):
        return "tcti-feeds-thehackernews"
    if idx.startswith("tcti-feeds-bleeping"):
        return "tcti-feeds-bleeping"
    if idx.startswith("tcti-feeds-zoneh"):
        return "tcti-feeds-zoneh"
    if idx.startswith("misp"):
        return "misp_attributes"
    if idx.startswith("tcti-feeds"):
        return "cyberint_iocs"
    return None


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
    detected_activity = _as_text(raw.get("detected_activity"))
    raw_threat_types = _unique(_as_list(raw.get("threat_type")) + ([detected_activity] if detected_activity else []))
    source_type = raw.get("source_type") or ("customer-datalake" if detected_activity else "canonical")
    return _finalize(
        hit,
        raw,
        "existing_canonical",
        original_type,
        original_value,
        normalize_type,
        normalize_value,
        source_name=raw.get("source_name") or raw.get("ref_doc_index") or _source_name_from_index(hit.get("_index")) or "cyberint_iocs",
        source_type=source_type,
        description=raw.get("description") or "",
        threat_type=raw_threat_types,
        severity="",
        tags=_unique(_as_list(raw.get("tags")) + ([detected_activity] if detected_activity else [])),
        reference=raw.get("reference") or raw.get("ref_doc_id") or raw.get("doc_hash") or "",
        collect_time=raw.get("collect_time") or raw.get("@timestamp") or raw.get("processed_at"),
        event_time=raw.get("event_time") or raw.get("observation_date") or raw.get("@timestamp") or raw.get("processed_at"),
        geo_country=_extract_geo_country(raw, raw.get("enrichment") if isinstance(raw.get("enrichment"), dict) else {}),
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

    # Capture cyberint's own severity_score (0-100 string) and confidence as source evidence
    # so the scoring pipeline can use them as a baseline when AI confidence is low.
    _sev_str = raw.get("severity_score")
    severity_score_raw: Optional[int] = _parse_int(_sev_str) if _sev_str is not None else None
    confidence_raw = _parse_int(raw.get("confidence"), 0)

    # Map detected_activity → MITRE ATT&CK technique IDs
    mitre_from_activity: List[str] = _CYBERINT_ACTIVITY_MITRE.get(activity, [])

    # Extract threat actors from description using MITRE ATT&CK mapping
    mitre_actors: List[str] = []
    if _lookup_actors is not None and description:
        try:
            mitre_actors = _lookup_actors(description)
        except Exception as exc:
            logger.debug("Actor enrichment failed: %s", exc)
            mitre_actors = []

    source_evidence = _compact_evidence({
        "evidence_type": "cyberint",
        "external_evidence_sources": ["cyberint_iocs"],
        "source_risk_score": severity_score_raw,
        "source_actionable": severity_score_raw is not None and severity_score_raw >= 60,
        "source_confidence": confidence_raw,
        "source_threat_types": [activity] if activity else [],
        "source_mitre_techniques": mitre_from_activity,
        "source_threat_actors": mitre_actors,
    })

    # WHOIS domain age enrichment for URL/domain IOC types
    ioc_type_val = _as_text(raw.get("ioc_type"))
    ioc_value_val = _as_text(raw.get("ioc_value"))
    domain_age: Optional[int] = None
    if _lookup_domain_age is not None:
        domain_age = _lookup_domain_age(ioc_value_val, ioc_type_val)

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
        severity="",
        tags=[activity] if activity else [],
        reference=raw.get("id") or hit.get("_id") or "",
        collect_time=raw.get("@timestamp"),
        event_time=raw.get("observation_date") or raw.get("@timestamp"),
        geo_country=_extract_geo_country(raw),
        confidence=confidence_raw,
        source_url="",
        source_id=raw.get("id") or hit.get("_id"),
        enrichment=raw.get("enrichment") if isinstance(raw.get("enrichment"), dict) else {},
        domain_age_days=domain_age,
        source_evidence=source_evidence,
    )


def _misp_attribute_adapter(hit: Dict[str, Any], normalize_type, normalize_value) -> Optional[Dict[str, Any]]:
    raw = hit.get("_source", {})
    if not (raw.get("type") and raw.get("value") and "misp_attributes-" in _as_text(hit.get("_index"))):
        return None

    event = raw.get("Event") if isinstance(raw.get("Event"), dict) else {}
    orgc = event.get("Orgc") if isinstance(event.get("Orgc"), dict) else {}
    threat_level = event.get("ThreatLevel") if isinstance(event.get("ThreatLevel"), dict) else {}
    # Merge attribute-level and event-level tags — galaxy tags (threat-actor, sector,
    # target-information) are typically set at the event level, not the attribute level.
    attr_tags = _tag_names(raw)
    event_tags = _tag_names(event)
    tags = _unique(attr_tags + event_tags)
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
        severity="",
        tags=tags,
        reference=raw.get("uuid") or event.get("uuid") or hit.get("_id") or "",
        collect_time=collect_time,
        event_time=event_time,
        geo_country=_extract_geo_country(raw, {"misp_event": event}),
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
    source_name = first_source.get("name") or raw.get("source_name") or raw.get("ref_doc_index") or _source_name_from_index(hit.get("_index")) or "cyberint_iocs"
    source_type = _infer_external_source_type(raw, _as_text(source_name), _as_text(hit.get("_index")))
    # Extract threat actors from merged title + description via MITRE mapping
    merged_text = "\n".join(part for part in [title, description] if part)
    mitre_actors: List[str] = []
    if _lookup_actors is not None and merged_text:
        try:
            mitre_actors = _lookup_actors(merged_text)
        except Exception:
            mitre_actors = []

    evidence = _merge_evidence(
        extract_virustotal_evidence(enrichment),
        extract_cyberint_evidence(enrichment),
        _extract_summary_evidence(enrichment),
        _extract_mitre_evidence(enrichment),
        _extract_related_entities_evidence(enrichment),
        extract_correlation_evidence(raw),
        extract_sandbox_evidence(raw),
        _build_mitre_actor_evidence(mitre_actors),
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
        source_name=source_name,
        source_type=source_type,
        description="\n".join(part for part in [title, description] if part),
        threat_type=_unique(_as_list(raw.get("threat_type")) + _as_list(evidence.get("source_threat_types"))),
        severity="",
        tags=raw.get("tags") or first_source.get("tags") or [],
        reference=first_source.get("url") or raw.get("reference") or raw.get("ref_doc_id") or raw.get("doc_hash") or "",
        collect_time=first_source.get("collect_time") or raw.get("@timestamp") or raw.get("processed_at"),
        event_time=raw.get("@timestamp") or raw.get("processed_at") or first_source.get("collect_time"),
        geo_country=_extract_geo_country(raw, enrichment),
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
            # GeoIP fallback: enrich geo_country from IP IOC value if still empty
            doc = enrich_geo_country(doc)
            return doc
    return quarantine_document(hit, "unsupported_datalake_schema")
