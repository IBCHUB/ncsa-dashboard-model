"""
Classification policy for the pipeline.

The policy decides whether an IOC should go through the expensive ML classifier
or be classified from trusted source metadata.  Keep this module dependency-light
so the decision logic can be tested without loading the DeBERTa model.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence


DEFAULT_ML_SOURCE_TYPES = "news,rss,article,report,advisory,blog"
DEFAULT_RULE_SOURCE_TYPES = "customer-datalake,misp,external-feed"
DEFAULT_ML_MIN_CONTEXT_CHARS = 300

THREAT_TYPE_RULE_MAP = {
    "malware_payload": "Malware",
    "malware": "Malware",
    "infecting_url": "Malware",
    "infected_machine": "Malware",
    "infection_source": "Malware",
    "payload_delivery": "Malware",
    "phishing_website": "Phishing",
    "phishing": "Phishing",
    "cnc_server": "C2",
    "c2": "C2",
    "botnet": "Botnet",
    "cc_skimming": "Credential Theft",
    "credential_theft": "Credential Theft",
    "anonymization": "Other",
    "parked": "Other",
}

GENERIC_FEED_PATTERNS = (
    r"\brecognized\s+as\b",
    r"\bmalicious\b\.?$",
    r"\bdetected\s+activity\b",
    r"\bthreat\s+types\s+reported\s+by\s+source\b",
    r"\breported\s+by:\s*(cyberint|misp|feed)",
    r"\burl\s+that\s+may\s+infect\b",
    r"\bobserved\s+infection\b",
)


@dataclass(frozen=True)
class ClassificationDecision:
    mode: str
    reason: str
    classifier_input_chars: int


def _env_csv(name: str, default: str) -> set[str]:
    raw = os.getenv(name, default)
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _normalize_rule_key(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")


def _unique(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        cleaned = str(value or "").strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def is_generic_feed_context(text: str) -> bool:
    cleaned = str(text or "").strip().lower()
    if not cleaned:
        return True
    if len(cleaned) < 120 and any(re.search(pattern, cleaned) for pattern in GENERIC_FEED_PATTERNS):
        return True
    generic_hits = sum(1 for pattern in GENERIC_FEED_PATTERNS if re.search(pattern, cleaned))
    return generic_hits >= 2


def has_rule_signal(source_types: Sequence[str], adapter_names: Sequence[str], threat_types_raw: Sequence[str]) -> bool:
    rule_source_types = _env_csv("PIPELINE_RULE_SOURCE_TYPES", DEFAULT_RULE_SOURCE_TYPES)
    normalized_source_types = {str(source_type or "").strip().lower() for source_type in source_types}
    normalized_adapters = {str(adapter_name or "").strip().lower() for adapter_name in adapter_names}
    if normalized_source_types & rule_source_types:
        return True
    if normalized_adapters & {"cyberint_iocs", "misp_attribute"}:
        return True
    return any(str(threat or "").strip() for threat in threat_types_raw)


def decide_classification_mode(
    *,
    source_types: Sequence[str],
    adapter_names: Sequence[str],
    threat_types_raw: Sequence[str],
    classifier_input: str,
) -> ClassificationDecision:
    configured_mode = os.getenv("PIPELINE_CLASSIFICATION_MODE", "auto").strip().lower()
    input_chars = len(classifier_input or "")
    min_context_chars = _env_int("PIPELINE_ML_MIN_CONTEXT_CHARS", DEFAULT_ML_MIN_CONTEXT_CHARS)
    ml_source_types = _env_csv("PIPELINE_ML_SOURCE_TYPES", DEFAULT_ML_SOURCE_TYPES)
    normalized_source_types = {str(source_type or "").strip().lower() for source_type in source_types}
    rule_signal = has_rule_signal(source_types, adapter_names, threat_types_raw)

    if configured_mode == "ml_all":
        return ClassificationDecision("ml", "mode_override_ml_all", input_chars)

    if configured_mode == "rules_only":
        if rule_signal:
            return ClassificationDecision("source_rule", "mode_override_rules_only", input_chars)
        return ClassificationDecision("skipped", "mode_override_rules_only_no_rule_signal", input_chars)

    if normalized_source_types & ml_source_types:
        return ClassificationDecision("ml", "ml_source_type", input_chars)

    if rule_signal:
        return ClassificationDecision("source_rule", "rule_source_or_threat_metadata", input_chars)

    if input_chars >= min_context_chars and not is_generic_feed_context(classifier_input):
        return ClassificationDecision("ml", "context_rich_text", input_chars)

    if input_chars < min_context_chars:
        return ClassificationDecision("skipped", "insufficient_context", input_chars)

    return ClassificationDecision("skipped", "generic_feed_context", input_chars)


def map_rule_threat_types(threat_types_raw: Sequence[str]) -> List[str]:
    mapped: List[str] = []
    for raw in threat_types_raw:
        key = _normalize_rule_key(raw)
        if not key:
            continue
        mapped.append(THREAT_TYPE_RULE_MAP.get(key, "Other"))
    return _unique(mapped) or ["Other"]


def source_confidence(ioc_docs: Sequence[Dict[str, Any]]) -> float:
    confidences: List[float] = []
    for doc in ioc_docs:
        try:
            value = float(doc.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            continue
        if value > 1:
            value = value / 100.0
        if value > 0:
            confidences.append(value)
    if not confidences:
        return 0.5
    return min(max(confidences), 0.85)


def build_rule_classification(
    *,
    threat_types_raw: Sequence[str],
    ioc_docs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    threat_types = map_rule_threat_types(threat_types_raw)
    confidence = source_confidence(ioc_docs)
    return {
        "labels": threat_types,
        "scores": [confidence for _ in threat_types],
        "threat_types": threat_types,
        "threat_details": [
            {"type": threat_type, "confidence": confidence}
            for threat_type in threat_types
        ],
        "confidence": confidence,
        "sector_classifications": [],
        "model_used": "source_rule",
    }


def build_skipped_classification() -> Dict[str, Any]:
    return {
        "labels": [],
        "scores": [],
        "threat_types": [],
        "threat_details": [],
        "confidence": 0.0,
        "sector_classifications": [],
        "model_used": "skipped",
    }
