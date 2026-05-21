"""Unit tests for dashboard_router foundation helpers (Phase 2.1).

These tests pin down the behavior of the helpers reused across most
dashboard endpoints so that Phase 2.2+ refactors can't silently regress
correctness of date filtering, severity translation, source/sector
display, ES query building, or auth wiring.
"""

from __future__ import annotations

import os
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import services.dashboard_router as r  # noqa: E402


# ---------------------------------------------------------------------------
# 2.1a — Time / date helpers
# ---------------------------------------------------------------------------


def test_parse_dt_returns_none_for_blank_and_garbage():
    assert r._parse_dt(None) is None
    assert r._parse_dt("") is None
    assert r._parse_dt("   ") is None
    assert r._parse_dt("not-a-date") is None


def test_parse_dt_normalizes_z_suffix_to_utc():
    parsed = r._parse_dt("2026-05-21T10:30:00Z")
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_parse_dt_passes_through_naive_as_utc():
    parsed = r._parse_dt("2026-05-21T10:30:00")
    assert parsed is not None
    assert parsed.tzinfo is r.UTC


def test_date_filter_drops_silently_when_fields_empty(caplog):
    # Phase 2.1a-1 regression: when fields list is empty but a range was
    # requested, we used to silently return None and let callers bypass
    # the date filter. The helper now logs a warning so this drop is
    # visible in production.
    with caplog.at_level("WARNING", logger="services.dashboard_router"):
        result = r._date_filter({"gte": "2026-05-01", "lte": "2026-05-21"}, [])
    assert result is None
    assert any("date filter dropped" in rec.message for rec in caplog.records)


def test_datalake_changed_mode_no_longer_drops_date_filter():
    # Phase 2.1a-1 regression: DATALAKE_TIME_FIELDS["changed"] used to be []
    # which caused _datalake_search_filters to silently return all docs when
    # the caller passed time_mode=changed with a date range.
    assert r.DATALAKE_TIME_FIELDS["changed"] == ["@timestamp"]
    filters = r._datalake_search_filters(
        start_date="2026-05-01",
        end_date="2026-05-21",
        time_mode=r.TIME_MODE_CHANGED,
    )
    assert any("range" in str(f) or ("bool" in f and "should" in f["bool"]) for f in filters)


def test_resolve_date_bounds_handles_iso_with_time_component():
    # Phase 2.1a-2 regression: passing a string that already contained "T"
    # caused the helper to append "T00:00:00+07:00" and produce an invalid
    # ISO string, which fromisoformat rejected → bound silently became None.
    start, end = r._resolve_date_bounds("2026-05-21T10:00:00Z", "2026-05-22T15:00:00Z")
    assert start is not None
    assert end is not None
    assert start < end


def test_resolve_date_bounds_appends_bangkok_window_for_date_only():
    start, end = r._resolve_date_bounds("2026-05-21", "2026-05-21")
    assert start is not None and end is not None
    # Start of Bangkok day comes before end of same day.
    assert (end - start).total_seconds() > 23 * 3600


def test_date_query_range_returns_none_for_empty_inputs():
    assert r._date_query_range(None, None) is None


def test_date_query_range_normalizes_bare_dates_to_bangkok_window():
    rng = r._date_query_range("2026-05-21", "2026-05-22")
    assert rng == {"gte": "2026-05-21T00:00:00+07:00", "lte": "2026-05-22T23:59:59+07:00"}


def test_date_query_range_preserves_full_iso_input():
    rng = r._date_query_range("2026-05-21T10:00:00Z", "2026-05-22T15:00:00Z")
    assert rng == {"gte": "2026-05-21T10:00:00Z", "lte": "2026-05-22T15:00:00Z"}


# ---------------------------------------------------------------------------
# 2.1b — Severity normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Critical", "critical"),
        ("very high", "critical"),
        ("HIGH", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("clean", "clean"),
        ("info", "clean"),
        (None, "low"),
        ("", "low"),
        ("unknown-string", "low"),
    ],
)
def test_normalize_severity_string_inputs(value, expected):
    assert r._normalize_severity(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("100", "critical"),
        ("80", "critical"),
        ("79", "high"),
        ("60", "high"),
        ("59", "medium"),
        ("40", "medium"),
        ("39", "low"),
        ("1", "low"),
        ("0", "clean"),
    ],
)
def test_normalize_severity_numeric_cyberint_bands(value, expected):
    # Cyberint datalake `severity` field is numeric (0/20/80/100). The mapping
    # is intentionally distinct from the AI scoring-v3.0.0 thresholds.
    assert r._normalize_severity(value) == expected


def test_highest_severity_from_buckets_picks_highest_non_empty():
    buckets = [
        {"key": "low", "doc_count": 5},
        {"key": "high", "doc_count": 2},
        {"key": "critical", "doc_count": 0},  # ignored — empty
        {"key": "medium", "doc_count": 7},
    ]
    assert r._highest_severity_from_buckets(buckets) == "High"


def test_highest_severity_from_buckets_returns_clean_when_all_empty():
    buckets = [{"key": "critical", "doc_count": 0}, {"key": "high", "doc_count": 0}]
    assert r._highest_severity_from_buckets(buckets) == "Clean"


# ---------------------------------------------------------------------------
# 2.1c — Source / sector display helpers
# ---------------------------------------------------------------------------


def test_source_display_name_known_aliases():
    assert r._source_display_name("cyberint_iocs") == "Cyberint IOC Feed"
    assert r._source_display_name("The Hacker News") == "The Hacker News"
    assert r._source_display_name("thehackernews") == "The Hacker News"
    assert r._source_display_name("zone-h") == "Zone-H Defacement Feed"


def test_source_display_name_picks_priority_when_comma_joined():
    # Phase 2.1c — comma-joined source_name from the pipeline must pick
    # the highest-priority recognized feed, not the first listed.
    assert r._source_display_name("cyberint_iocs, The Hacker News") == "The Hacker News"


def test_source_category_news_takes_priority_over_substring_match():
    # Phase 2.1c-1 regression: news feeds must be categorized before the
    # cyberint substring catch-all so a name like "tcti-feeds-thehackernews"
    # isn't mislabelled as "trusted" because it isn't.
    assert r._source_category("tcti-feeds-darkreading") == "news"
    assert r._source_category("The Hacker News") == "news"
    assert r._source_category("cyberint_iocs") == "trusted"


def test_sector_display_name_logs_unmapped_once(caplog):
    # Phase 2.1c-2: previously unknown sectors silently collapsed to "Other".
    # The helper now logs once per unique unmapped value.
    r._UNMAPPED_SECTOR_SEEN.clear()
    with caplog.at_level("INFO", logger="services.dashboard_router"):
        assert r._sector_display_name("Defense") == "Other"
        assert r._sector_display_name("Defense") == "Other"  # second call, no extra log
    matching = [rec for rec in caplog.records if "sector display name unmapped" in rec.message]
    assert len(matching) == 1


def test_sector_display_name_recognized_aliases():
    assert r._sector_display_name("Banking") == "Banking and Finance"
    assert r._sector_display_name("ภาคการเงิน") == "Banking and Finance"


# ---------------------------------------------------------------------------
# 2.1d — ES query builders
# ---------------------------------------------------------------------------


def test_warehouse_filters_merge_severities_and_risk_levels():
    # Phase 2.1d-3 regression: severities and risk_levels both target
    # the AI severity field. Passing different values used to AND them
    # into an empty result. They must now be unioned.
    filters = r._warehouse_search_filters(
        severities=["critical"],
        risk_levels=["high"],
        warehouse_eligible_only=None,
    )
    severity_terms = [f for f in filters if "terms" in f and "severity" in f["terms"]]
    assert len(severity_terms) == 1
    assert sorted(severity_terms[0]["terms"]["severity"]) == ["critical", "high"]


def test_datalake_filters_map_severity_strings_to_numeric_bands():
    # Phase 2.1d-2 regression: datalake `severity` is numeric. Filtering
    # by string ["critical"] used to produce a terms clause that couldn't
    # match any doc. We now translate to a numeric range query.
    filters = r._datalake_search_filters(severities=["critical", "high"])
    bool_clauses = [f for f in filters if "bool" in f]
    assert bool_clauses, "expected a bool/should clause for severity bands"
    should = bool_clauses[0]["bool"]["should"]
    bands = [(clause["range"]["severity"]["gte"], clause["range"]["severity"]["lte"]) for clause in should]
    assert (80, 100) in bands
    assert (60, 79) in bands


def test_scroll_all_warehouse_docs_propagates_min_risk_score(monkeypatch):
    # Phase 2.1d-1 regression: signature accepted min_risk_score but
    # the function forgot to forward it to _warehouse_search_filters,
    # so scroll endpoints returned docs below the requested threshold.
    captured = {}

    def fake_filters(**kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr(r, "_warehouse_search_filters", fake_filters)
    monkeypatch.setattr(r, "_scroll_all_documents", lambda *a, **kw: [])
    r._scroll_all_warehouse_docs(
        min_risk_score=50,
        validation_statuses=["validated"],
        review_states=["approved"],
        warehouse_eligible_only=False,
    )
    assert captured.get("min_risk_score") == 50
    assert captured.get("validation_statuses") == ["validated"]
    assert captured.get("review_states") == ["approved"]
    assert captured.get("warehouse_eligible_only") is False


# ---------------------------------------------------------------------------
# 2.1e — Auth + safe_search
# ---------------------------------------------------------------------------


def test_safe_search_re_raises_connection_errors_as_503(monkeypatch):
    # Phase 2.1e-1 regression: connection-class errors used to be swallowed
    # and surfaced as "no data" in the UI. They must now raise 503 so the
    # frontend can show an outage banner.
    class _FakeConnectionError(Exception):
        pass

    _FakeConnectionError.__name__ = "ConnectionError"

    def fail(self, index, body):
        raise _FakeConnectionError("connection refused")

    class _FakeClient:
        def search_index(self, *a, **kw):
            raise _FakeConnectionError("connection refused")

    monkeypatch.setattr(r, "get_elastic_client", lambda: _FakeClient())
    with pytest.raises(HTTPException) as excinfo:
        r._safe_search("idx", {"query": {"match_all": {}}})
    assert excinfo.value.status_code == 503


# ---------------------------------------------------------------------------
# 2.2 — Authorization + notification scoping
# ---------------------------------------------------------------------------


def test_require_admin_rejects_general_role():
    from fastapi import HTTPException as HE
    with pytest.raises(HE) as excinfo:
        r.require_admin(current_user={"user_id": "u-1", "role_name": "General"})
    assert excinfo.value.status_code == 403


@pytest.mark.parametrize("role", ["Admin", "Super Admin", "admin", "SuperAdmin", "superadmin"])
def test_require_admin_allows_admin_roles(role):
    user = r.require_admin(current_user={"user_id": "u-1", "role_name": role})
    assert user["user_id"] == "u-1"


def test_notification_visible_to_broadcast_to_everyone():
    from services.dashboard_bootstrap import DashboardState

    broadcast = {"notification_id": "n-1"}  # no recipient_user_id
    assert DashboardState._notification_visible_to(broadcast, "any-user") is True
    assert DashboardState._notification_visible_to(broadcast, None) is True


def test_notification_visible_to_targeted_only_to_owner():
    from services.dashboard_bootstrap import DashboardState

    targeted = {"notification_id": "n-2", "recipient_user_id": "usr-a"}
    assert DashboardState._notification_visible_to(targeted, "usr-a") is True
    assert DashboardState._notification_visible_to(targeted, "usr-b") is False
    assert DashboardState._notification_visible_to(targeted, None) is False


def test_safe_search_query_error_falls_back_to_empty(monkeypatch):
    # Phase 2.1e-1: only connection-class errors raise. Query-level errors
    # (malformed body etc.) still degrade to empty hits so a single bad
    # endpoint can't take the whole dashboard down.
    class _FakeClient:
        def search_index(self, *a, **kw):
            raise ValueError("invalid query syntax")

    monkeypatch.setattr(r, "get_elastic_client", lambda: _FakeClient())
    result = r._safe_search("idx", {"query": {}})
    assert result == {"hits": {"total": {"value": 0}, "hits": []}}
