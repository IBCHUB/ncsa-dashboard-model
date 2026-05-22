"""Phase 3.2 — Operations Dashboard semantic correctness.

Verifies that the four KPI fields returned by `_operations_overview_from_aggs`
match the UI labels that the frontend (`lib/dashboard.ts:285-289`) displays:

  - active_ioc          → "Total Threat"  (total docs in window)
  - critical_ioc_active → "Active IOC"    (unique active IOCs)
  - new_ioc             → "Critical IOCs" (unique critical IOCs)
  - high_ioc_active     → "High IOCs"     (unique high IOCs)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import services.dashboard_router as dashboard_router  # noqa: E402


def _aggs_fixture():
    """A typical `_warehouse_dashboard_aggs` output for the test."""
    return {
        "total": 276228,  # all docs in window
        "active_iocs": {"value": 274994},  # cardinality canonical_ioc_key
        "source_count": {"value": 7},
        "critical_active": {
            "doc_count": 8596,  # docs with severity=critical
            "active_iocs": {"value": 8553},  # cardinality unique critical IOCs
        },
        "high_active": {
            "doc_count": 5,
            "active_iocs": {"value": 5},
        },
    }


def test_operations_overview_active_ioc_is_total_threat_count():
    """BUG-3.2-1 regression: `active_ioc` must return TOTAL DOC COUNT to
    match the frontend label "Total Threat", not the cardinality of unique IOCs.
    """
    overview = dashboard_router._operations_overview_from_aggs(_aggs_fixture())
    assert overview["active_ioc"] == 276228  # = aggs["total"], not aggs["active_iocs"]


def test_operations_overview_critical_ioc_active_is_unique_active_iocs():
    """BUG-3.2-1 regression: `critical_ioc_active` must return CARDINALITY OF
    UNIQUE ACTIVE IOCs to match the frontend label "Active IOC", not the doc
    count filtered by severity=critical.
    """
    overview = dashboard_router._operations_overview_from_aggs(_aggs_fixture())
    assert overview["critical_ioc_active"] == 274994  # = aggs["active_iocs"].value


def test_operations_overview_new_ioc_is_unique_critical_iocs():
    """BUG-3.2-1 regression: `new_ioc` must return CARDINALITY OF UNIQUE
    CRITICAL IOCs to match the frontend label "Critical IOCs", not the
    24-hour recent doc count.
    """
    overview = dashboard_router._operations_overview_from_aggs(_aggs_fixture())
    assert overview["new_ioc"] == 8553  # = aggs["critical_active"]["active_iocs"]["value"]


def test_operations_overview_high_ioc_active_uses_cardinality():
    """BUG-3.2-1 regression: `high_ioc_active` should use cardinality of
    unique high-severity IOCs (label "High IOCs"), not raw doc count.
    For consistency with other KPI fields.
    """
    overview = dashboard_router._operations_overview_from_aggs(_aggs_fixture())
    assert overview["high_ioc_active"] == 5  # = aggs["high_active"]["active_iocs"]["value"]


def test_operations_overview_falls_back_safely_on_missing_aggs():
    """Empty aggs must return zeros without exception."""
    overview = dashboard_router._operations_overview_from_aggs({})
    assert overview == {
        "active_ioc": 0,
        "critical_ioc_active": 0,
        "new_ioc": 0,
        "sources_active": 0,
        "high_ioc_active": 0,
    }


def test_operations_overview_python_path_aligns_with_agg_semantics():
    """Both code paths must report the same semantic per label."""
    docs = [
        {"canonical_ioc_key": "url:a", "ioc_value": "a", "severity": "critical", "source_name": "s1"},
        {"canonical_ioc_key": "url:a", "ioc_value": "a", "severity": "critical", "source_name": "s1"},  # duplicate IOC
        {"canonical_ioc_key": "url:b", "ioc_value": "b", "severity": "medium", "source_name": "s2"},
        {"canonical_ioc_key": "url:c", "ioc_value": "c", "severity": "high", "source_name": "s2"},
    ]
    overview = dashboard_router._operations_overview(docs)
    assert overview["active_ioc"] == 4  # total docs (Total Threat)
    assert overview["critical_ioc_active"] == 3  # unique canonical_ioc_key (Active IOC)
    assert overview["new_ioc"] == 2  # critical-severity docs (Critical IOCs)
    assert overview["high_ioc_active"] == 1  # high-severity docs (High IOCs)
    assert overview["sources_active"] == 2  # unique sources
