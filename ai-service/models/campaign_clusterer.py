"""
HDBSCAN Campaign Clustering for IOC Campaign Detection

Groups IOCs into campaigns based on behavioral and infrastructure similarities.
Features: threat types, ASN, country, domain age, risk score, source count.

Design reference: 03Attack-Relationship specification.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List, Sequence

import numpy as np

try:
    from sklearn.cluster import HDBSCAN
    from sklearn.preprocessing import StandardScaler

    CLUSTERING_AVAILABLE = True
except ImportError:
    CLUSTERING_AVAILABLE = False

logger = logging.getLogger(__name__)

KNOWN_THREAT_TYPES: List[str] = [
    "Ransomware",
    "Phishing",
    "DDoS",
    "Data Breach",
    "Supply Chain Attack",
    "Zero-Day Exploit",
    "APT",
]

KNOWN_IOC_TYPES: List[str] = ["ip", "domain", "url", "hash", "cve"]

TOP_COUNTRIES: List[str] = [
    "US", "CN", "RU", "DE", "NL",
    "GB", "FR", "KR", "JP", "BR",
]


def _one_hot_threat_types(raw_types: List[str]) -> List[float]:
    """One-hot encode threat types against KNOWN_THREAT_TYPES."""
    normalized = [t.strip().lower() for t in raw_types if t]
    known_lower = [k.lower() for k in KNOWN_THREAT_TYPES]
    return [
        1.0 if label in normalized else 0.0
        for label in known_lower
    ]


def _one_hot_country(country: str) -> List[float]:
    """One-hot encode country against TOP_COUNTRIES + 'other'."""
    normalized = (country or "").strip().upper()
    encoding = [
        1.0 if normalized == c else 0.0
        for c in TOP_COUNTRIES
    ]
    is_other = 1.0 if (normalized and normalized not in TOP_COUNTRIES) else 0.0
    return [*encoding, is_other]


def _one_hot_ioc_type(ioc_type: str) -> List[float]:
    """One-hot encode IOC type against KNOWN_IOC_TYPES."""
    normalized = (ioc_type or "").strip().lower()
    return [
        1.0 if normalized == t else 0.0
        for t in KNOWN_IOC_TYPES
    ]


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def extract_features(documents: Sequence[Dict[str, Any]]) -> np.ndarray:
    """Extract feature vectors from warehouse documents.

    Features per document:
    - ai_threat_types: one-hot encoded (7 dimensions)
    - geo_country: one-hot encoded (11 dimensions: top 10 + other)
    - domain_age_days: numeric, normalized (1 dimension)
    - ai_risk_score: numeric 0-100 (1 dimension)
    - source_count: numeric (1 dimension)
    - ioc_type: one-hot encoded (5 dimensions)

    Returns:
        numpy array of shape (len(documents), N) where N is the feature count.
    """
    if not documents:
        return np.empty((0, 0))

    rows: List[List[float]] = []
    for doc in documents:
        threat_types_raw = doc.get("ai_threat_types") or []
        if isinstance(threat_types_raw, str):
            threat_types_raw = [threat_types_raw]

        threat_encoding = _one_hot_threat_types(threat_types_raw)
        country_encoding = _one_hot_country(doc.get("geo_country", ""))
        domain_age = _safe_float(doc.get("domain_age_days"), 0.0)
        risk_score = _safe_float(doc.get("ai_risk_score"), 0.0)
        source_count = _safe_float(doc.get("source_count"), 1.0)
        ioc_type_encoding = _one_hot_ioc_type(doc.get("ioc_type", ""))

        row = [
            *threat_encoding,
            *country_encoding,
            domain_age,
            risk_score,
            source_count,
            *ioc_type_encoding,
        ]
        rows.append(row)

    return np.array(rows, dtype=np.float64)


def cluster_iocs(
    documents: Sequence[Dict[str, Any]],
    min_cluster_size: int = 5,
    min_samples: int = 3,
) -> List[Dict[str, Any]]:
    """Cluster IOC documents into campaigns using HDBSCAN.

    Args:
        documents: Warehouse documents to cluster.
        min_cluster_size: Minimum cluster size for HDBSCAN.
        min_samples: Minimum samples for HDBSCAN core point determination.

    Returns:
        List of dicts with ioc_value, ioc_type, cluster_label, cluster_probability.
        Noise points receive cluster_label=-1.
    """
    if not documents:
        return []

    if len(documents) < min_cluster_size:
        return [
            {
                "ioc_value": doc.get("ioc_value", ""),
                "ioc_type": doc.get("ioc_type", "unknown"),
                "cluster_label": -1,
                "cluster_probability": 0.0,
            }
            for doc in documents
        ]

    if not CLUSTERING_AVAILABLE:
        logger.warning(
            "sklearn.cluster.HDBSCAN not available; "
            "returning all IOCs as noise (cluster_label=-1)"
        )
        return [
            {
                "ioc_value": doc.get("ioc_value", ""),
                "ioc_type": doc.get("ioc_type", "unknown"),
                "cluster_label": -1,
                "cluster_probability": 0.0,
            }
            for doc in documents
        ]

    features = extract_features(documents)
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
    )
    clusterer.fit(scaled_features)

    labels = clusterer.labels_
    probabilities = (
        clusterer.probabilities_
        if hasattr(clusterer, "probabilities_")
        else np.zeros(len(documents))
    )

    return [
        {
            "ioc_value": doc.get("ioc_value", ""),
            "ioc_type": doc.get("ioc_type", "unknown"),
            "cluster_label": int(labels[i]),
            "cluster_probability": float(probabilities[i]),
        }
        for i, doc in enumerate(documents)
    ]


def build_cluster_summary(
    documents: Sequence[Dict[str, Any]],
    cluster_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a summary of clusters with dominant features.

    Args:
        documents: Original warehouse documents (same order as cluster_results).
        cluster_results: Output from cluster_iocs().

    Returns:
        Dict keyed by cluster_label with summary statistics per cluster.
    """
    if not cluster_results:
        return {}

    clusters: Dict[int, List[int]] = {}
    for idx, result in enumerate(cluster_results):
        label = result.get("cluster_label", -1)
        if label not in clusters:
            clusters[label] = []
        clusters[label] = [*clusters[label], idx]

    summary: Dict[str, Any] = {}
    for label, indices in sorted(clusters.items()):
        cluster_docs = [documents[i] for i in indices if i < len(documents)]
        cluster_cr = [cluster_results[i] for i in indices if i < len(cluster_results)]

        all_threat_types: List[str] = []
        all_countries: List[str] = []
        risk_scores: List[float] = []
        ioc_types: List[str] = []

        for doc in cluster_docs:
            threat_types = doc.get("ai_threat_types") or []
            if isinstance(threat_types, str):
                threat_types = [threat_types]
            all_threat_types.extend(threat_types)

            country = (doc.get("geo_country") or "").strip()
            if country:
                all_countries.append(country)

            risk_scores.append(_safe_float(doc.get("ai_risk_score"), 0.0))
            ioc_types.append((doc.get("ioc_type") or "unknown").strip().lower())

        threat_counter = Counter(all_threat_types)
        country_counter = Counter(all_countries)
        ioc_type_counter = Counter(ioc_types)

        dominant_threat_types = [
            item for item, _ in threat_counter.most_common(3)
        ] if threat_counter else []

        dominant_country = (
            country_counter.most_common(1)[0][0] if country_counter else None
        )

        representative_iocs = [
            cr.get("ioc_value", "") for cr in cluster_cr[:3]
        ]

        summary[str(label)] = {
            "cluster_label": label,
            "size": len(indices),
            "dominant_threat_types": dominant_threat_types,
            "dominant_country": dominant_country,
            "avg_risk_score": round(
                sum(risk_scores) / len(risk_scores), 2
            ) if risk_scores else 0.0,
            "ioc_types": dict(ioc_type_counter),
            "representative_iocs": representative_iocs,
        }

    return summary
