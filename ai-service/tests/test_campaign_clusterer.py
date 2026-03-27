"""
Unit tests for HDBSCAN campaign clustering.

Tests cover feature extraction, clustering behaviour, immutability,
and summary generation.
"""

import copy
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.campaign_clusterer import (  # noqa: E402
    CLUSTERING_AVAILABLE,
    build_cluster_summary,
    cluster_iocs,
    extract_features,
)


def _make_doc(
    ioc_value: str = "10.0.0.1",
    ioc_type: str = "ip",
    threat_types: list = None,
    country: str = "US",
    domain_age: int = 30,
    risk_score: float = 50.0,
    source_count: int = 2,
) -> dict:
    """Create a minimal warehouse-style document for testing."""
    return {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "ai_threat_types": threat_types if threat_types is not None else ["Ransomware"],
        "geo_country": country,
        "domain_age_days": domain_age,
        "ai_risk_score": risk_score,
        "source_count": source_count,
    }


# ── extract_features ──────────────────────────────────────────────────


def test_extract_features_shape():
    """5 documents produce array of shape (5, N) where N > 0."""
    docs = [_make_doc(ioc_value=f"10.0.0.{i}") for i in range(5)]
    features = extract_features(docs)

    assert isinstance(features, np.ndarray)
    assert features.shape[0] == 5
    assert features.shape[1] > 0


def test_extract_features_handles_missing_fields():
    """Documents with None / missing fields do not crash."""
    docs = [
        {"ioc_value": "example.com"},
        {"ioc_value": "1.2.3.4", "ai_threat_types": None, "geo_country": None},
        {
            "ioc_value": "evil.net",
            "ai_risk_score": None,
            "domain_age_days": None,
            "source_count": None,
            "ioc_type": None,
        },
    ]
    features = extract_features(docs)

    assert features.shape[0] == 3
    assert not np.any(np.isnan(features))


def test_extract_features_empty_input():
    """Empty document list returns empty array."""
    features = extract_features([])
    assert features.shape[0] == 0


# ── cluster_iocs ──────────────────────────────────────────────────────


@pytest.mark.skipif(
    not CLUSTERING_AVAILABLE,
    reason="sklearn HDBSCAN not installed",
)
def test_cluster_similar_documents():
    """Documents with similar features should cluster together."""
    docs = [
        _make_doc(
            ioc_value=f"192.168.1.{i}",
            ioc_type="ip",
            threat_types=["Ransomware", "Phishing"],
            country="RU",
            domain_age=100 + i,
            risk_score=85.0 + (i * 0.1),
            source_count=4,
        )
        for i in range(15)
    ]
    results = cluster_iocs(docs, min_cluster_size=3, min_samples=2)

    assert len(results) == 15
    labels = {r["cluster_label"] for r in results}
    assert any(label >= 0 for label in labels), (
        "At least some similar documents should be clustered (label >= 0)"
    )


@pytest.mark.skipif(
    not CLUSTERING_AVAILABLE,
    reason="sklearn HDBSCAN not installed",
)
def test_cluster_diverse_documents():
    """Very different documents should mostly be noise."""
    threat_options = [
        ["Ransomware"], ["Phishing"], ["DDoS"],
        ["Data Breach"], ["APT"], ["Zero-Day Exploit"],
    ]
    country_options = ["US", "CN", "RU", "DE", "BR", "JP"]
    ioc_type_options = ["ip", "domain", "url", "hash", "cve", "ip"]
    docs = [
        _make_doc(
            ioc_value=f"diverse-{i}.example.com",
            ioc_type=ioc_type_options[i],
            threat_types=threat_options[i],
            country=country_options[i],
            domain_age=i * 500,
            risk_score=float(i * 15),
            source_count=i + 1,
        )
        for i in range(6)
    ]
    results = cluster_iocs(docs, min_cluster_size=5, min_samples=3)

    noise_count = sum(1 for r in results if r["cluster_label"] == -1)
    assert noise_count > 0, "Diverse documents should produce some noise"


def test_cluster_too_few_documents():
    """Fewer than min_cluster_size documents all get label=-1."""
    docs = [_make_doc(ioc_value="10.0.0.1"), _make_doc(ioc_value="10.0.0.2")]
    results = cluster_iocs(docs, min_cluster_size=5, min_samples=3)

    assert len(results) == 2
    assert all(r["cluster_label"] == -1 for r in results)


def test_cluster_empty_input():
    """Empty list input returns empty list."""
    results = cluster_iocs([])
    assert results == []


def test_cluster_immutability():
    """Input documents must not be mutated by cluster_iocs."""
    docs = [
        _make_doc(ioc_value=f"10.0.0.{i}")
        for i in range(6)
    ]
    originals = copy.deepcopy(docs)
    cluster_iocs(docs, min_cluster_size=3, min_samples=2)

    assert docs == originals, "cluster_iocs must not mutate input documents"


def test_cluster_result_structure():
    """Each result dict contains the required keys with correct types."""
    docs = [_make_doc(ioc_value=f"10.0.0.{i}") for i in range(3)]
    results = cluster_iocs(docs, min_cluster_size=5)

    for result in results:
        assert "ioc_value" in result
        assert "ioc_type" in result
        assert "cluster_label" in result
        assert "cluster_probability" in result
        assert isinstance(result["cluster_label"], int)
        assert isinstance(result["cluster_probability"], float)


# ── build_cluster_summary ─────────────────────────────────────────────


def test_build_cluster_summary_structure():
    """Summary contains expected keys for each cluster."""
    docs = [
        _make_doc(ioc_value="10.0.0.1", threat_types=["Ransomware"], country="US"),
        _make_doc(ioc_value="10.0.0.2", threat_types=["Ransomware"], country="US"),
        _make_doc(ioc_value="10.0.0.3", threat_types=["Phishing"], country="CN"),
    ]
    cluster_results = [
        {"ioc_value": "10.0.0.1", "ioc_type": "ip", "cluster_label": 0, "cluster_probability": 0.9},
        {"ioc_value": "10.0.0.2", "ioc_type": "ip", "cluster_label": 0, "cluster_probability": 0.8},
        {"ioc_value": "10.0.0.3", "ioc_type": "ip", "cluster_label": -1, "cluster_probability": 0.0},
    ]

    summary = build_cluster_summary(docs, cluster_results)

    assert "0" in summary
    assert "-1" in summary

    cluster_0 = summary["0"]
    assert cluster_0["cluster_label"] == 0
    assert cluster_0["size"] == 2
    assert "dominant_threat_types" in cluster_0
    assert "dominant_country" in cluster_0
    assert "avg_risk_score" in cluster_0
    assert "ioc_types" in cluster_0
    assert "representative_iocs" in cluster_0
    assert cluster_0["dominant_country"] == "US"
    assert "Ransomware" in cluster_0["dominant_threat_types"]


def test_build_cluster_summary_empty():
    """Empty cluster results return empty summary."""
    summary = build_cluster_summary([], [])
    assert summary == {}
