import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline_classification_policy import (  # noqa: E402
    build_rule_classification,
    decide_classification_mode,
    is_generic_feed_context,
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
