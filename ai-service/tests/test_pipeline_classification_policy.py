import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline_classification_policy import (  # noqa: E402
    build_ml_classifier_input,
    build_rule_classification,
    decide_classification_mode,
    detect_context_rule_threat_types,
    is_generic_feed_context,
    is_non_incident_news_context,
    strict_ml_classification,
)


def test_cyberint_ioc_feed_uses_source_rule(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    decision = decide_classification_mode(
        source_types=["customer-datalake"],
        adapter_names=["cyberint_iocs"],
        threat_types_raw=["malware_payload"],
        classifier_input="IOC: abc (type: sha256)\nRecognized as Malicious.",
    )

    assert decision.mode == "source_rule"
    assert decision.reason == "rule_source_or_threat_metadata"


def test_misp_attribute_uses_source_rule(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    decision = decide_classification_mode(
        source_types=["misp"],
        adapter_names=["misp_attribute"],
        threat_types_raw=["Phishing"],
        classifier_input="Cyble Threat Intelligence Feed - phishing domain",
    )

    assert decision.mode == "source_rule"


def test_sandbox_source_uses_source_rule(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    text = " ".join(["Sandbox detonated sample and observed suspicious behavior."] * 20)
    decision = decide_classification_mode(
        source_types=["sandbox"],
        adapter_names=["legacy_external"],
        threat_types_raw=[],
        classifier_input=text,
    )

    assert decision.mode == "source_rule"
    assert decision.reason == "rule_source_or_threat_metadata"


def test_news_source_uses_ml(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    decision = decide_classification_mode(
        source_types=["news"],
        adapter_names=["legacy_external"],
        threat_types_raw=[],
        classifier_input="A long news article describes a ransomware campaign against financial institutions.",
    )

    assert decision.mode == "ml"
    assert decision.reason == "ml_source_type"


def test_removal_guide_news_is_skipped_before_ml(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    text = (
        "Remove the Srchus.xyz Search Redirect. Removal Options. Self Help Guide. "
        "STEP 1: Print out instructions. STEP 2: Use malware removal tools."
    )
    decision = decide_classification_mode(
        source_types=["news"],
        adapter_names=["legacy_external"],
        threat_types_raw=[],
        classifier_input=text,
    )

    assert is_non_incident_news_context(text)
    assert decision.mode == "skipped"
    assert decision.reason == "non_incident_news_content"


def test_non_incident_release_news_is_skipped_before_ml(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    text = "Kali Linux 2025.1a released with 1 new tool and annual theme refresh."
    decision = decide_classification_mode(
        source_types=["news"],
        adapter_names=["legacy_external"],
        threat_types_raw=[],
        classifier_input=text,
    )

    assert is_non_incident_news_context(text)
    assert decision.mode == "skipped"


def test_context_rich_unknown_source_uses_ml(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    text = " ".join(["This report describes credential theft, phishing lures, and C2 infrastructure."] * 8)
    decision = decide_classification_mode(
        source_types=["unknown"],
        adapter_names=["legacy_external"],
        threat_types_raw=[],
        classifier_input=text,
    )

    assert decision.mode == "ml"
    assert decision.reason == "context_rich_text"


def test_short_unknown_source_skips_ml(monkeypatch):
    monkeypatch.delenv("PIPELINE_CLASSIFICATION_MODE", raising=False)
    decision = decide_classification_mode(
        source_types=["unknown"],
        adapter_names=["unknown"],
        threat_types_raw=[],
        classifier_input="IOC: example.com",
    )

    assert decision.mode == "skipped"
    assert decision.reason == "insufficient_context"


def test_generic_feed_context_is_not_ml_candidate():
    assert is_generic_feed_context("Recognized as Malicious.")


def test_rule_mapping_and_confidence_cap():
    classification = build_rule_classification(
        threat_types_raw=["malware_payload", "cnc_server", "unknown_activity"],
        ioc_docs=[{"confidence": 99}],
    )

    assert classification["threat_types"] == ["Malware", "C2", "Other"]
    assert classification["confidence"] == 0.85


def test_context_rule_detects_exploited_rce_vulnerability():
    threats = detect_context_rule_threat_types(
        "CISA added CVE-2026-22719 to KEV after active exploitation. "
        "The flaw allows remote code execution and arbitrary commands."
    )

    assert threats == ["Remote Code Execution", "Exploited Vulnerability"]


def test_context_rule_detects_credential_theft_and_defacement():
    assert detect_context_rule_threat_types("credential harvesting stealer campaign") == ["Credential Theft"]
    assert detect_context_rule_threat_types("Zone-H mirror shows a defaced website") == ["Defacement"]


def test_context_rule_prefers_data_breach_over_generic_vulnerability():
    threats = detect_context_rule_threat_types(
        "ShinyHunters stole Salesforce customer data after abusing an exposed "
        "Aura endpoint vulnerability and then used extortion demands."
    )

    assert threats == ["Data Breach"]


def test_context_rule_detects_apt_and_exploit_kit():
    threats = detect_context_rule_threat_types(
        "Coruna iOS Exploit Kit uses 23 exploit chains. A nation-state operator used the hard-coded flaw."
    )

    assert threats == ["APT", "Exploited Vulnerability"]


def test_context_rule_detects_apt_flaw_and_deployed_malware():
    threats = detect_context_rule_threat_types(
        "A China-related attacker exploited a hard-coded flaw to maintain access and deploy malware."
    )

    assert threats == ["APT", "Malware", "Exploited Vulnerability"]


def test_context_rule_keeps_vulnerability_when_breach_article_has_strong_cve_signal():
    threats = detect_context_rule_threat_types(
        "Attackers stole data after exploiting CVE-2026-22719, an actively "
        "exploited flaw allowing remote code execution."
    )

    assert threats == ["Data Breach", "Remote Code Execution", "Exploited Vulnerability"]


def test_strict_ml_classification_keeps_only_confident_top_label(monkeypatch):
    monkeypatch.delenv("PIPELINE_ML_CONFIDENCE_THRESHOLD", raising=False)
    monkeypatch.delenv("PIPELINE_ML_MAX_LABELS", raising=False)
    result = strict_ml_classification({
        "threat_types": ["Phishing", "Data Breach", "APT"],
        "threat_details": [
            {"type": "Phishing", "confidence": 0.944},
            {"type": "Data Breach", "confidence": 0.894},
            {"type": "APT", "confidence": 0.73},
        ],
        "confidence": 0.944,
        "sector_classifications": [],
    })

    assert result["threat_types"] == ["Phishing"]
    assert result["confidence"] == 0.944
    assert result["ml_output_raw_threat_types"] == ["Phishing", "Data Breach", "APT"]


def test_strict_ml_classification_returns_empty_when_below_threshold(monkeypatch):
    monkeypatch.delenv("PIPELINE_ML_CONFIDENCE_THRESHOLD", raising=False)
    result = strict_ml_classification({
        "threat_types": ["Zero-day Exploit"],
        "threat_details": [{"type": "Zero-day Exploit", "confidence": 0.51}],
        "confidence": 0.51,
    })

    assert result["threat_types"] == []
    assert result["confidence"] == 0.0


def test_ml_classifier_input_is_truncated(monkeypatch):
    monkeypatch.setenv("PIPELINE_ML_MAX_INPUT_CHARS", "12")
    assert build_ml_classifier_input("abcdefghijklmnopqrstuvwxyz") == "abcdefghijkl"
