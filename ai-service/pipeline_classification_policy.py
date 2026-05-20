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
DEFAULT_RULE_SOURCE_TYPES = "customer-datalake,misp,external-feed,sandbox"
DEFAULT_ML_MIN_CONTEXT_CHARS = 300
DEFAULT_ML_CONFIDENCE_THRESHOLD = 0.75
DEFAULT_ML_MAX_LABELS = 1
DEFAULT_ML_MAX_INPUT_CHARS = 1800

THREAT_TYPE_RULE_MAP = {
    "malware_payload": "Malware",
    "malware": "Malware",
    "infecting_url": "Malware",
    "infected_machine": "Malware",
    "infection_source": "Malware",
    "payload_delivery": "Malware",
    "phishing_website": "Phishing",
    "phishing": "Phishing",
    "spearphishing": "Phishing",
    "maliciousurls": "Phishing",
    "cnc_server": "C2",
    "c2": "C2",
    "botnet": "Botnet",
    "trojan": "Malware",
    "rat": "Malware",
    "backdoor": "Malware",
    "stealer": "Credential Theft",
    "cc_skimming": "Credential Theft",
    "credential_theft": "Credential Theft",
    "data_breach": "Data Breach",
    "data_theft": "Data Breach",
    "stolen_data": "Data Breach",
    "leaked_data": "Data Breach",
    "extortion": "Data Breach",
    "apt": "APT",
    "nation_state": "APT",
    "exploited_vulnerability": "Exploited Vulnerability",
    "remote_code_execution": "Remote Code Execution",
    "rce": "Remote Code Execution",
    "vulnerability": "Exploited Vulnerability",
    "defacement": "Defacement",
    "compromised_website": "Defacement",
    "anonymization": "Other",
    "parked": "Other",
    "malicious": "Malware",
    "ransomware": "Ransomware",
    "command_and_control": "C2",
    "wiper": "Wiper",
    "supply_chain_attack": "Supply Chain Attack",
    "zero_day": "Zero-day Exploit",
    "zero-day": "Zero-day Exploit",
    "spam": "Spam",
    "scanning": "Scanning",
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

NON_INCIDENT_PATTERNS = (
    r"\bhow\s+to\s+use\b",
    r"\bhow\s+to\s+(scan|remove|clean|install|configure)\b",
    r"\bremove\s+the\b",
    r"\bremoval\s+(guide|options)\b",
    r"\bself\s+help\s+(guide|removal)\b",
    r"\btable\s+of\s+contents\b",
    r"\btutorial\b",
    r"\bdownload\s+now\b",
    r"\bstep\s+\d+\b",
    r"\bscan\s+and\s+clean\b",
    r"\bkali\s+linux\s+\d{4}\.\d+\w*\s+released\b",
    r"\bannual\s+theme\s+refresh\b",
    r"\byou\s+consumed\s+your\s+\d+\s+free\s+requests\b",
    r"\bsmart\s+proxy\s+subscription\b",
)

INCIDENT_PATTERNS = (
    r"\b(data\s+theft|data\s+breach|stolen\s+data|leaked\s+data|extortion)\b",
    r"\b(exploit|exploiting|actively\s+exploited|vulnerability|zero[-\s]?day)\b",
    r"\b(phishing|campaign|malware|ransomware|backdoor|trojan|botnet)\b",
    r"\b(apt|threat\s+actor|attackers?|hackers?)\b",
    r"\b(compromised|breached|intrusion|unauthorized\s+access)\b",
)

CONTEXT_RULE_PATTERNS = (
    (
        "Data Breach",
        (
            r"\bdata\s+(theft|breach|leak|exfiltration)\b",
            r"\bstolen\s+data\b",
            r"\bstol(?:e|en)\s+(?:customer\s+|sensitive\s+)?data\b",
            r"\bleaked\s+data\b",
            r"\bdata\s+extortion\b",
            r"\bextortion\b",
            r"\bShinyHunters\b",
        ),
    ),
    (
        "Remote Code Execution",
        (
            r"\bremote\s+code\s+execution\b",
            r"\bRCE\b",
            r"\bexecute\s+arbitrary\s+(commands?|code)\b",
            r"\bcommand\s+injection\b",
            r"\bcode\s+execution\b",
        ),
    ),
    (
        "APT",
        (
            r"\bAPT\d*\b",
            r"\bnation[-\s]state\b",
            r"\bstate[-\s]sponsored\b",
            r"\bChina[-\s]related\s+attacker\b",
        ),
    ),
    (
        "Malware",
        (
            r"\bdeploy(?:ed|s|ing)?\s+malware\b",
            r"\bmalware\s+campaign\b",
        ),
    ),
    (
        "Exploited Vulnerability",
        (
            r"\bCVE-\d{4}-\d{4,}\b",
            r"\bactively\s+exploited\b",
            r"\bknown\s+exploited\s+vulnerabilities\b",
            r"\bKEV\b",
            r"\bcritical\s+(RCE\s+)?flaw\b",
            r"\bhard[-\s]coded\s+flaw\b",
            r"\bexploit\s+(kit|chain|chains)\b",
            r"\bvulnerabilit(?:y|ies)\b",
            r"\bCVSS\b",
            r"\bpatch\s+now\b",
        ),
    ),
    (
        "Credential Theft",
        (
            r"\bcredential\s+(theft|stealing|harvesting)\b",
            r"\bpassword\s+(stealing|harvesting|capture)\b",
            r"\bstealer\b",
        ),
    ),
    (
        "Defacement",
        (
            r"\bdefacement\b",
            r"\bdefaced\b",
            r"\bZone-H\b",
        ),
    ),
)

STRONG_VULNERABILITY_PATTERNS = (
    r"\bCVE-\d{4}-\d{4,}\b",
    r"\bactively\s+exploited\b",
    r"\bknown\s+exploited\s+vulnerabilities\b",
    r"\bKEV\b",
    r"\bremote\s+code\s+execution\b",
    r"\bRCE\b",
    r"\bexecute\s+arbitrary\s+(commands?|code)\b",
    r"\bcommand\s+injection\b",
    r"\bhard[-\s]coded\s+flaw\b",
    r"\bexploit\s+(kit|chain|chains)\b",
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


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
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


def is_non_incident_news_context(text: str) -> bool:
    """Return true for how-to/removal/tutorial content that should not use ML."""
    cleaned = str(text or "").strip().lower()
    if not cleaned:
        return False
    non_incident_hits = sum(1 for pattern in NON_INCIDENT_PATTERNS if re.search(pattern, cleaned))
    if non_incident_hits == 0:
        return False
    incident_hits = sum(1 for pattern in INCIDENT_PATTERNS if re.search(pattern, cleaned))
    return incident_hits == 0 or non_incident_hits >= incident_hits + 1


def detect_context_rule_threat_types(text: str) -> List[str]:
    cleaned = str(text or "")
    if not cleaned.strip():
        return []
    detected: List[str] = []
    for threat_type, patterns in CONTEXT_RULE_PATTERNS:
        if any(re.search(pattern, cleaned, flags=re.IGNORECASE) for pattern in patterns):
            detected.append(threat_type)
    if "Data Breach" in detected and "Exploited Vulnerability" in detected:
        has_strong_vuln_signal = any(
            re.search(pattern, cleaned, flags=re.IGNORECASE)
            for pattern in STRONG_VULNERABILITY_PATTERNS
        )
        if not has_strong_vuln_signal:
            detected = [
                threat_type
                for threat_type in detected
                if threat_type != "Exploited Vulnerability"
            ]
    return _unique(detected)


HASH_IOC_TYPES = {"file/sha256", "file/sha1", "file/md5", "sha256", "sha1", "md5", "hash"}


def has_rule_signal(
    source_types: Sequence[str],
    adapter_names: Sequence[str],
    threat_types_raw: Sequence[str],
    ioc_type: str = "",
) -> bool:
    rule_source_types = _env_csv("PIPELINE_RULE_SOURCE_TYPES", DEFAULT_RULE_SOURCE_TYPES)
    normalized_source_types = {str(source_type or "").strip().lower() for source_type in source_types}
    normalized_adapters = {str(adapter_name or "").strip().lower() for adapter_name in adapter_names}
    normalized_ioc_type = str(ioc_type or "").strip().lower()
    # For hash IOCs, ML can't infer sector/target from the hash alone, so keep them on rules.
    # For url/domain/ipv4 IOCs, allow ML to run (it can read WHOIS/ASN/path tokens in context).
    is_hash_ioc = normalized_ioc_type in HASH_IOC_TYPES
    if normalized_source_types & rule_source_types:
        return True
    if normalized_adapters & {"cyberint_iocs", "misp_attribute"} and (is_hash_ioc or not normalized_ioc_type):
        return True
    return any(str(threat or "").strip() for threat in threat_types_raw)


def decide_classification_mode(
    *,
    source_types: Sequence[str],
    adapter_names: Sequence[str],
    threat_types_raw: Sequence[str],
    classifier_input: str,
    ioc_type: str = "",
) -> ClassificationDecision:
    configured_mode = os.getenv("PIPELINE_CLASSIFICATION_MODE", "auto").strip().lower()
    input_chars = len(classifier_input or "")
    min_context_chars = _env_int("PIPELINE_ML_MIN_CONTEXT_CHARS", DEFAULT_ML_MIN_CONTEXT_CHARS)
    ml_source_types = _env_csv("PIPELINE_ML_SOURCE_TYPES", DEFAULT_ML_SOURCE_TYPES)
    normalized_source_types = {str(source_type or "").strip().lower() for source_type in source_types}
    normalized_ioc_type = str(ioc_type or "").strip().lower()
    is_hash_ioc = normalized_ioc_type in HASH_IOC_TYPES
    rule_signal = has_rule_signal(source_types, adapter_names, threat_types_raw, ioc_type=ioc_type)

    if configured_mode == "ml_all":
        return ClassificationDecision("ml", "mode_override_ml_all", input_chars)

    if configured_mode == "rules_only":
        if rule_signal:
            return ClassificationDecision("source_rule", "mode_override_rules_only", input_chars)
        return ClassificationDecision("skipped", "mode_override_rules_only_no_rule_signal", input_chars)

    if normalized_source_types & ml_source_types:
        if is_non_incident_news_context(classifier_input):
            return ClassificationDecision("skipped", "non_incident_news_content", input_chars)
        return ClassificationDecision("ml", "ml_source_type", input_chars)

    # For non-hash IOCs (url/domain/ip) with rich-enough context, prefer ML over rule
    # so we can extract sector/target_org from WHOIS, ASN, path tokens, etc.
    if (
        not is_hash_ioc
        and normalized_ioc_type
        and input_chars >= min_context_chars
        and not is_generic_feed_context(classifier_input)
    ):
        return ClassificationDecision("ml", "non_hash_ioc_context_rich", input_chars)

    if rule_signal:
        return ClassificationDecision("source_rule", "rule_source_or_threat_metadata", input_chars)

    if input_chars >= min_context_chars and not is_generic_feed_context(classifier_input):
        return ClassificationDecision("ml", "context_rich_text", input_chars)

    if input_chars < min_context_chars:
        return ClassificationDecision("skipped", "insufficient_context", input_chars)

    return ClassificationDecision("skipped", "generic_feed_context", input_chars)


def build_ml_classifier_input(classifier_input: str) -> str:
    max_chars = _env_int("PIPELINE_ML_MAX_INPUT_CHARS", DEFAULT_ML_MAX_INPUT_CHARS)
    text = str(classifier_input or "").strip()
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[:max_chars]


def strict_ml_classification(classification: Dict[str, Any]) -> Dict[str, Any]:
    threshold = _env_float("PIPELINE_ML_CONFIDENCE_THRESHOLD", DEFAULT_ML_CONFIDENCE_THRESHOLD)
    max_labels = max(1, _env_int("PIPELINE_ML_MAX_LABELS", DEFAULT_ML_MAX_LABELS))
    labels = list(classification.get("threat_types") or [])
    details = list(classification.get("threat_details") or [])
    if not details:
        scores = list(classification.get("scores") or [])
        details = [
            {"type": label, "confidence": scores[index] if index < len(scores) else 0.0}
            for index, label in enumerate(labels)
        ]

    ranked = sorted(
        [
            {
                "type": str(item.get("type") or "").strip(),
                "confidence": float(item.get("confidence") or 0.0),
            }
            for item in details
            if str(item.get("type") or "").strip()
        ],
        key=lambda item: item["confidence"],
        reverse=True,
    )
    selected = [item for item in ranked if item["confidence"] >= threshold][:max_labels]

    cleaned = dict(classification)
    cleaned["threat_types"] = [item["type"] for item in selected]
    cleaned["threat_details"] = selected
    cleaned["confidence"] = round(selected[0]["confidence"], 3) if selected else 0.0
    cleaned["ml_output_threshold"] = threshold
    cleaned["ml_output_max_labels"] = max_labels
    cleaned["ml_output_raw_threat_types"] = labels
    return cleaned


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


def _extract_sectors_from_ioc_docs(ioc_docs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract sector signals from rule-mode IOC docs.

    Sources (in priority order):
      1. MISP galaxy tags with `sector:*` or `misp-galaxy:sector="X"` namespace
         (captured by datalake_adapters.extract_misp_evidence via A2 fix).
      2. Cyberint `source_sectors` evidence field.
      3. Tags array entries that look like sector labels.

    Returns list of {sector, confidence, source} dicts compatible with the
    downstream scorer's `sector_classifications` consumer.
    """
    import re as _re

    sectors: List[Dict[str, Any]] = []
    seen: set[str] = set()

    sector_galaxy_re = _re.compile(
        r'(?:misp-galaxy:)?sector\s*[:=]\s*"?([^"\|]+?)"?(?:\s*[,;]|$)',
        flags=_re.IGNORECASE,
    )

    def _add(label: str, source: str, confidence: float = 0.85) -> None:
        cleaned = str(label or "").strip().lower()
        if not cleaned or cleaned in seen:
            return
        seen.add(cleaned)
        sectors.append({
            "sector": cleaned,
            "confidence": round(confidence, 3),
            "source": source,
        })

    for doc in ioc_docs or []:
        if not isinstance(doc, dict):
            continue
        # 1a. MISP galaxy tags (event-level or attribute-level)
        for tag in doc.get("tags") or []:
            match = sector_galaxy_re.search(str(tag))
            if match:
                _add(match.group(1), "misp_galaxy", 0.90)
        # 1b. Cyberint / merged evidence
        evidence = doc.get("source_evidence")
        evidence_items = evidence if isinstance(evidence, list) else [evidence] if isinstance(evidence, dict) else []
        for item in evidence_items:
            if not isinstance(item, dict):
                continue
            for raw_sector in item.get("source_sectors") or []:
                _add(raw_sector, "feed_evidence", 0.80)
            raw_evidence = item.get("raw_evidence")
            if isinstance(raw_evidence, list):
                for entry in raw_evidence:
                    if isinstance(entry, dict):
                        for raw_sector in entry.get("source_sectors") or []:
                            _add(raw_sector, "feed_evidence", 0.80)
        # 1c. Top-level source_sectors flattened by datalake_adapters
        for raw_sector in doc.get("source_sectors") or []:
            _add(raw_sector, "feed_evidence", 0.80)
        # 1d. Tag entries that look like plain sector hints
        for tag in doc.get("tags") or []:
            text = str(tag).strip().lower()
            if text in {"government", "finance", "financial", "healthcare", "energy",
                       "telecom", "telecommunications", "education", "defense",
                       "transportation", "technology", "critical_infrastructure"}:
                _add(text, "tag_keyword", 0.70)

    return sectors


def build_rule_classification(
    *,
    threat_types_raw: Sequence[str],
    ioc_docs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    threat_types = map_rule_threat_types(threat_types_raw)
    confidence = source_confidence(ioc_docs)
    sector_classifications = _extract_sectors_from_ioc_docs(ioc_docs)
    return {
        "labels": threat_types,
        "scores": [confidence for _ in threat_types],
        "threat_types": threat_types,
        "threat_details": [
            {"type": threat_type, "confidence": confidence}
            for threat_type in threat_types
        ],
        "confidence": confidence,
        "sector_classifications": sector_classifications,
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
