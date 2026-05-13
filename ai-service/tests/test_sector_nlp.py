"""
Tests for NLP-based sector classification integrated into classify_threat().

Verifies:
- Sector labels are returned alongside threat labels from single zero-shot pass
- Sector results do not interfere with threat results
- Keyword fallback triggers when NLP returns no sector
- Confidence tier scaling for risk_bonus
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import (
    LABEL_MAPPING,
    THREAT_LABELS,
    THREAT_TYPE_SEVERITY,
    SECTOR_LABELS,
    SECTOR_LABEL_MAPPING,
    SECTOR_CONFIDENCE_THRESHOLD,
    SECTORS,
    SECTOR_RISK_BONUS,
)


def _make_zero_shot_result(labels_scores: list[tuple[str, float]]) -> dict:
    """Build a fake zero-shot pipeline result dict."""
    labels_scores.sort(key=lambda x: x[1], reverse=True)
    return {
        "labels": [l for l, _ in labels_scores],
        "scores": [s for _, s in labels_scores],
    }


def test_threat_labels_cover_current_datalake_news_taxonomy():
    expected_labels = {
        "ransomware": "Ransomware",
        "phishing": "Phishing",
        "data breach": "Data Breach",
        "supply chain attack": "Supply Chain Attack",
        "zero-day exploit": "Zero-day Exploit",
        "APT": "APT",
    }

    for raw_label, mapped_label in expected_labels.items():
        assert raw_label in THREAT_LABELS
        assert LABEL_MAPPING[raw_label] == mapped_label
        assert mapped_label in THREAT_TYPE_SEVERITY

    rule_only_labels = {
        "Malware",
        "Credential Theft",
        "Exploited Vulnerability",
        "Remote Code Execution",
        "Defacement",
    }
    assert not any(raw in THREAT_LABELS for raw in {"malware", "credential theft", "exploited vulnerability", "remote code execution", "defacement"})
    for mapped_label in rule_only_labels:
        assert mapped_label in THREAT_TYPE_SEVERITY


class TestClassifyThreatReturnsSectorClassifications:
    """classify_threat() should include sector_classifications in its return."""

    @patch("models.classifier.get_detector")
    @patch("models.classifier.get_en_classifier")
    def test_banking_text_returns_financial_sector(self, mock_en, mock_det):
        from models.classifier import classify_threat

        mock_det.return_value.detect_language_of.return_value = MagicMock(
            __eq__=lambda self, other: True  # pretend English
        )
        # Simulate model returning high score for financial sector label
        all_labels = THREAT_LABELS + SECTOR_LABELS
        scores = [(label, 0.1) for label in all_labels]
        scores_dict = dict(scores)
        scores_dict["ransomware"] = 0.85
        scores_dict["targeting financial services or banking"] = 0.78
        result_pairs = [(l, scores_dict.get(l, 0.1)) for l in all_labels]

        mock_en.return_value.return_value = _make_zero_shot_result(result_pairs)

        result = classify_threat("Ransomware attack targeting Thai banking system")

        assert "sector_classifications" in result
        sectors = result["sector_classifications"]
        assert len(sectors) >= 1
        assert sectors[0]["sector"] == "financial"
        assert sectors[0]["confidence"] >= SECTOR_CONFIDENCE_THRESHOLD

    @patch("models.classifier.get_detector")
    @patch("models.classifier.get_en_classifier")
    def test_no_sector_when_all_below_threshold(self, mock_en, mock_det):
        from models.classifier import classify_threat

        mock_det.return_value.detect_language_of.return_value = MagicMock(
            __eq__=lambda self, other: True
        )
        all_labels = THREAT_LABELS + SECTOR_LABELS
        # All sector scores below threshold
        scores = [(label, 0.1) for label in all_labels]
        scores_dict = dict(scores)
        scores_dict["phishing"] = 0.7
        result_pairs = [(l, scores_dict.get(l, 0.1)) for l in all_labels]

        mock_en.return_value.return_value = _make_zero_shot_result(result_pairs)

        result = classify_threat("Generic phishing campaign detected")

        assert result["sector_classifications"] == []

    @patch("models.classifier.get_detector")
    @patch("models.classifier.get_en_classifier")
    def test_sector_labels_do_not_appear_in_threat_types(self, mock_en, mock_det):
        from models.classifier import classify_threat

        mock_det.return_value.detect_language_of.return_value = MagicMock(
            __eq__=lambda self, other: True
        )
        all_labels = THREAT_LABELS + SECTOR_LABELS
        scores = [(label, 0.05) for label in all_labels]
        scores_dict = dict(scores)
        scores_dict["ransomware"] = 0.9
        scores_dict["targeting government or public sector"] = 0.8
        result_pairs = [(l, scores_dict.get(l, 0.05)) for l in all_labels]

        mock_en.return_value.return_value = _make_zero_shot_result(result_pairs)

        result = classify_threat("APT28 ransomware targeting government ministry")

        # Sector labels must NOT leak into threat_types
        for t in result["threat_types"]:
            assert t not in SECTOR_LABEL_MAPPING

        # Sector must be in sector_classifications
        assert any(s["sector"] == "government" for s in result["sector_classifications"])

    def test_empty_text_returns_empty_sectors(self):
        from models.classifier import classify_threat

        result = classify_threat("")
        assert result["sector_classifications"] == []

    def test_error_path_returns_empty_sectors(self):
        from models.classifier import classify_threat

        with patch("models.classifier.get_detector", side_effect=RuntimeError("fail")):
            result = classify_threat("some text here enough to pass length check")
            assert result["sector_classifications"] == []


class TestScorerUsesNlpSector:
    """calculate_risk_score() should use NLP sector from threat_classification."""

    def test_nlp_sector_used_in_breakdown(self):
        from models.scorer import calculate_risk_score

        result = calculate_risk_score(
            ioc_value="malware.banking-trojan.com",
            ioc_type="domain",
            description="Banking trojan targeting financial institutions",
            sources=[{"name": "OSINT-Feed", "type": "osint", "confidence": 75}],
            threat_classification={
                "threat_types": ["Ransomware"],
                "threat_actors": [],
                "mitre_techniques": [],
                "confidence": 0.8,
                "sector_classifications": [
                    {"sector": "financial", "confidence": 0.75, "label": "targeting financial services or banking"}
                ],
            },
        )

        breakdown = result.get("breakdown", {})
        sector = breakdown.get("target_sector", {})
        assert sector["sector"] == "financial"
        assert sector["classification_method"] == "nlp"
        assert sector["confidence"] == 0.75

    def test_keyword_fallback_when_no_nlp_sector(self):
        from models.scorer import calculate_risk_score

        result = calculate_risk_score(
            ioc_value="malware.banking.com",
            ioc_type="domain",
            description="Attack targeting Thai banking system",
            sources=[{"name": "Feed", "type": "osint", "confidence": 70}],
            threat_classification={
                "threat_types": ["Ransomware"],
                "threat_actors": [],
                "mitre_techniques": [],
                "confidence": 0.6,
                "sector_classifications": [],
            },
        )

        breakdown = result.get("breakdown", {})
        sector = breakdown.get("target_sector", {})
        assert sector["classification_method"] == "keyword_fallback"

    def test_confidence_tier_full_bonus(self):
        from models.scorer import calculate_risk_score

        result = calculate_risk_score(
            ioc_value="10.0.0.1",
            ioc_type="ip",
            description="Critical infrastructure attack",
            sources=[{"name": "CERT", "type": "cert", "confidence": 90}],
            threat_classification={
                "threat_types": ["APT"],
                "threat_actors": [],
                "mitre_techniques": [],
                "confidence": 0.9,
                "sector_classifications": [
                    {"sector": "critical_infrastructure", "confidence": 0.80, "label": "targeting critical infrastructure or energy"}
                ],
            },
        )

        sector = result["breakdown"]["target_sector"]
        # Full bonus (15) when confidence >= 0.70
        assert sector["risk_bonus"] == SECTOR_RISK_BONUS["critical_infrastructure"]

    def test_confidence_tier_partial_bonus(self):
        from models.scorer import calculate_risk_score

        result = calculate_risk_score(
            ioc_value="10.0.0.1",
            ioc_type="ip",
            description="Possible government targeting",
            sources=[{"name": "Feed", "type": "osint", "confidence": 70}],
            threat_classification={
                "threat_types": [],
                "threat_actors": [],
                "mitre_techniques": [],
                "confidence": 0.5,
                "sector_classifications": [
                    {"sector": "government", "confidence": 0.55, "label": "targeting government or public sector"}
                ],
            },
        )

        sector = result["breakdown"]["target_sector"]
        # 70% of base bonus (12) = 8 when 0.50 <= confidence < 0.70
        assert sector["risk_bonus"] == int(SECTOR_RISK_BONUS["government"] * 0.7)


class TestConfigIntegrity:
    """Verify config constants are consistent."""

    def test_sector_labels_map_to_valid_sectors(self):
        for label, sector_key in SECTOR_LABEL_MAPPING.items():
            assert sector_key in SECTORS, f"'{sector_key}' not in SECTORS config"
            assert label in SECTOR_LABELS, f"'{label}' not in SECTOR_LABELS list"

    def test_all_sector_labels_have_mapping(self):
        for label in SECTOR_LABELS:
            assert label in SECTOR_LABEL_MAPPING, f"'{label}' missing from SECTOR_LABEL_MAPPING"

    def test_sector_confidence_threshold_is_valid(self):
        assert 0 < SECTOR_CONFIDENCE_THRESHOLD < 1
