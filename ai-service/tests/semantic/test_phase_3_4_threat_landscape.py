"""Phase 3.4 — Threat Landscape semantic correctness.

Verifies that the `intelligence_sources` list on `/threat-landscape` does not
leak datalake daily-index names (e.g. `cyberint_iocs-2025.09.03`) into the UI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import services.dashboard_router as dashboard_router  # noqa: E402


def test_normalize_datalake_source_strips_date_suffix():
    """BUG-3.4-1 regression: daily-rotated `_index` names like
    `cyberint_iocs-2025.09.03` must collapse to the base source name.
    """
    fn = dashboard_router._normalize_datalake_source_key
    assert fn("cyberint_iocs-2025.09.03") == "cyberint_iocs"
    assert fn("cyberint_iocs-2025.12.31") == "cyberint_iocs"
    assert fn("custom-feed-2026.01.01") == "custom-feed"


def test_normalize_datalake_source_passthrough_when_no_date_suffix():
    """Bucket keys without date suffix must pass through unchanged."""
    fn = dashboard_router._normalize_datalake_source_key
    assert fn("cyberint_iocs") == "cyberint_iocs"
    assert fn("Cyble Threat Intelligence Feed") == "Cyble Threat Intelligence Feed"
    assert fn("Zone-H") == "Zone-H"


def test_normalize_datalake_source_handles_empty_and_none():
    """Empty / None must not crash; default to 'unknown'."""
    fn = dashboard_router._normalize_datalake_source_key
    assert fn("") == "unknown"
    assert fn(None) == "unknown"
    assert fn("   ") == "unknown"


def test_threat_landscape_consolidates_daily_datalake_indices():
    """BUG-3.4-1 regression: when datalake aggregates over `_index` and
    produces multiple daily-rotated buckets, the merged `intelligence_sources`
    list must show one consolidated source entry, not 10+ date-stamped names.
    """
    warehouse_aggs = {
        "total": 0,
        "high_risk": {"doc_count": 0},
        "severity_counts": {"buckets": {k: {"doc_count": 0} for k in ("critical", "high", "medium", "low", "clean")}},
        "threat_types": {"buckets": []},
        "threat_actors": {"buckets": []},
        "sectors": {"buckets": []},
        "sources": {"buckets": [{"key": "cyberint_iocs", "doc_count": 100}]},
        "countries": {"buckets": []},
        "ioc_types": {"buckets": []},
        "risk_score_ranges": {"buckets": []},
        "threat_type_cardinality": {"value": 0},
        "threat_actor_cardinality": {"value": 0},
        "source_count": {"value": 1},
    }
    datalake_aggs = {
        "sources": {
            "buckets": [
                {"key": "cyberint_iocs-2025.09.03", "doc_count": 1_049_096},
                {"key": "cyberint_iocs-2025.09.02", "doc_count": 889_575},
                {"key": "cyberint_iocs-2025.09.09", "doc_count": 744_026},
                {"key": "cyberint_iocs-2025.09.04", "doc_count": 738_605},
            ]
        }
    }

    payload = dashboard_router._build_threat_landscape_payload_from_aggs(warehouse_aggs, datalake_aggs)
    sources = payload["intelligence_sources"]
    labels = [item["label"] for item in sources]

    # All datalake daily indices must collapse into one `cyberint_iocs` bucket.
    assert "cyberint_iocs" in labels
    assert all("2025." not in label for label in labels), (
        f"Date-stamped index name leaked into intelligence_sources: {labels}"
    )

    # Verify total = 100 (warehouse) + 1,049,096 + 889,575 + 744,026 + 738,605 (datalake)
    cyberint = next(item for item in sources if item["label"] == "cyberint_iocs")
    assert cyberint["value"] == 100 + 1_049_096 + 889_575 + 744_026 + 738_605
