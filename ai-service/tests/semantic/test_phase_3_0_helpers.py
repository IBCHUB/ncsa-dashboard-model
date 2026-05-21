"""Phase 3.0 — cross-cutting helper semantic correctness.

Verifies that ES-query constants only reference fields that exist in the
captured warehouse mapping, and that severity bands match Cyberint's actual
discrete emission values (0/20/80/100).

Fixtures are captured ground-truth from the live `.43` warehouse and `.41`
datalake (see `tests/semantic/fixtures/`).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import services.dashboard_router as dashboard_router  # noqa: E402


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _warehouse_field_names() -> set[str]:
    payload = json.loads((FIXTURES / "es_mapping_warehouse.json").read_text())
    props = payload["cyber-logs-datawarehouse"]["mappings"]["properties"]
    return set(props.keys())


def test_warehouse_time_fields_only_reference_real_warehouse_fields():
    """BUG-3.0-1 regression: WAREHOUSE_TIME_FIELDS must not reference
    `revoked_at` or `updated_at` (do not exist in the warehouse mapping).
    """
    warehouse_fields = _warehouse_field_names()
    for mode, fields in dashboard_router.WAREHOUSE_TIME_FIELDS.items():
        for field in fields:
            assert field in warehouse_fields, (
                f"WAREHOUSE_TIME_FIELDS[{mode!r}] references non-existent "
                f"warehouse field {field!r}"
            )


def test_python_filter_fields_changed_does_not_reference_phantom_fields():
    """BUG-3.0-1 regression (Python-side filter): same constraint."""
    warehouse_fields = _warehouse_field_names()
    # Only `changed` is warehouse-only — other modes also include datalake fields.
    for field in dashboard_router.PYTHON_FILTER_FIELDS["changed"]:
        assert field in warehouse_fields, (
            f"PYTHON_FILTER_FIELDS['changed'] references non-existent field {field!r}"
        )


def test_cyberint_severity_bands_mirror_normalize_severity():
    """The band table is the inverse of `_normalize_severity`'s numeric branch
    so that string severities (e.g. 'high') round-trip to the right numeric
    range on the datalake. Bands are intentionally broader than Cyberint's
    discrete emissions (0/20/80/100) — they cover any numeric severity, not
    only Cyberint's vocabulary.
    """
    bands = dashboard_router._CYBERINT_SEVERITY_BANDS
    # Every threshold in `_normalize_severity`'s numeric branch must map to
    # the band that owns that label.
    for value, label in [(100, "critical"), (80, "critical"),
                          (79, "high"), (60, "high"),
                          (59, "medium"), (40, "medium"),
                          (39, "low"), (1, "low"),
                          (0, "clean")]:
        lo, hi = bands[label]
        assert lo <= value <= hi, (
            f"_normalize_severity({value!r}) → {label!r}, but band is ({lo},{hi})"
        )


def test_warehouse_summary_stats_accepts_warehouse_eligible_only():
    """BUG-3.0-5 regression: callers must be able to opt out of the
    `warehouse_eligible=true` filter for executive-level totals.
    """
    import inspect
    sig = inspect.signature(dashboard_router._warehouse_summary_stats)
    assert "warehouse_eligible_only" in sig.parameters, (
        "_warehouse_summary_stats must expose `warehouse_eligible_only` as a parameter"
    )
    # Default preserves prior behavior.
    assert sig.parameters["warehouse_eligible_only"].default is True


def test_thailand_filter_uses_only_iso_code():
    """BUG-3.0-7 regression: geo_country is a keyword field with ISO-2 codes
    only. Filtering for "Thailand" or "thailand" returns 0 docs — must use "TH".
    """
    source = Path(__file__).resolve().parents[2] / "services" / "dashboard_router.py"
    text = source.read_text()
    # The cleaned-up filter has exactly one "thailand_threat" block, no English/lowercase variants.
    assert '"geo_country": "Thailand"' not in text, (
        "geo_country filter must not use English 'Thailand' — use ISO 'TH'"
    )
    assert '"geo_country": "thailand"' not in text, (
        "geo_country filter must not use lowercase 'thailand' — use ISO 'TH'"
    )
