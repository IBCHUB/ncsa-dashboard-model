"""
Canonical dashboard API routes for `ncsa-dashboard-web`.

ELK-backed analytics and IOC endpoints use the existing warehouse and datalake
indices. Admin/system endpoints use a bootstrap in-process store
until dedicated services exist.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from datetime import date, datetime, timedelta, timezone
import hashlib
import io
import json
import logging
from math import floor
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo
import zipfile
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from config import NEWS_SOURCES
from elastic_client import get_elastic_client
from models.actions import ACTION_CLOSED, ACTION_IN_PROGRESS, ACTION_OPEN, derive_action_metadata
from models.forecaster import holt_winters_forecast
from services.dashboard_bootstrap import get_dashboard_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

BANGKOK_TZ = ZoneInfo("Asia/Bangkok")
UTC = timezone.utc
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "clean": 0}
RISK_LEVELS = [
    {"value": "critical", "label": "Critical"},
    {"value": "high", "label": "High"},
    {"value": "medium", "label": "Medium"},
    {"value": "low", "label": "Low"},
    {"value": "clean", "label": "Clean"},
]
IOC_TYPE_LOOKUPS = [
    {"value": "ip", "label": "IP Address"},
    {"value": "domain", "label": "Domain"},
    {"value": "url", "label": "URL"},
    {"value": "hash", "label": "Hash"},
    {"value": "sha256", "label": "Sha256"},
    {"value": "sha1", "label": "Sha1"},
    {"value": "md5", "label": "md5"},
    {"value": "cve", "label": "cve"},
]
EXPORT_FORMATS = [
    {"value": "csv", "label": "CSV"},
    {"value": "xlsx", "label": "XLSX"},
    {"value": "pdf", "label": "PDF"},
]
IOC_TYPE_LABELS = {item["value"]: item["label"] for item in IOC_TYPE_LOOKUPS}
REPORT_KEY_ALIASES = {
    "intelligence-sources": "intelligence-sources",
    "intelligence-source": "intelligence-sources",
    "sources": "intelligence-sources",
    "threat-types": "threat-types",
    "threat-type": "threat-types",
    "attack-origins": "attack-origins",
    "attack-origin": "attack-origins",
    "origins": "attack-origins",
    "target-sectors": "target-sectors",
    "target-sector": "target-sectors",
    "sector": "target-sectors",
    "sectors": "target-sectors",
}
HTTP_BEARER = HTTPBearer(auto_error=False)
COUNTRY_CODE_MAP = {
    "thailand": "TH",
    "china": "CN",
    "india": "IN",
    "indonesia": "ID",
    "austria": "AT",
    "russia": "RU",
    "vietnam": "VN",
    "netherlands": "NL",
    "united states": "US",
    "singapore": "SG",
    "germany": "DE",
    "united kingdom": "GB",
    "france": "FR",
    "australia": "AU",
    "japan": "JP",
    "south korea": "KR",
    "iran": "IR",
    "poland": "PL",
}
HIGH_CONFIDENCE_SOURCE_NAMES = {
    "VirusTotal",
    "AbuseIPDB",
    "ThreatFox",
    "URLhaus",
    "MalwareBazaar",
    "Recorded Future",
    "Cyberint",
    "AlienVault",
    "MITRE",
    "Sandbox",
    "Suricata",
    "Snort",
}


class LoginRequest(BaseModel):
    username: str
    password: str


class AssignRequest(BaseModel):
    assignee_id: str
    handover_note: Optional[str] = None


class BlockIpRequest(BaseModel):
    target_ioc: str
    enforcement_point_ids: List[str]
    duration_mode: str
    duration_days: Optional[int] = None
    reason: str


class ReportFilterRequest(BaseModel):
    start_date: date
    end_date: date
    threat_types: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    ioc_types: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)


class IOCReportPreviewRequest(ReportFilterRequest):
    limit: int = Field(default=200, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    page: Optional[int] = Field(default=None, ge=1)
    page_size: Optional[int] = Field(default=None, ge=1, le=500)


class ExportReportRequest(ReportFilterRequest):
    export_format: str


class IOCExportRequest(ReportFilterRequest):
    query: Optional[str] = None
    risk_levels: List[str] = Field(default_factory=list)
    high_risk_only: bool = False
    page: Optional[int] = Field(default=None, ge=1)
    page_size: Optional[int] = Field(default=None, ge=1, le=500)
    export_format: str


class DashboardDateRangeRequest(BaseModel):
    start_date: date
    end_date: date


class ExecutiveReportRequest(DashboardDateRangeRequest):
    threat_types: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)


class OperationsReportRequest(DashboardDateRangeRequest):
    query: Optional[str] = None
    threat_types: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    page: int = 1
    page_size: int = 20


class ThreatIntelligenceExportRequest(DashboardDateRangeRequest):
    section: str
    export_format: str


class AttackTimeExportRequest(OperationsReportRequest):
    export_format: str


class ActionReportRequest(BaseModel):
    query: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    threat_types: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    statuses: List[str] = Field(default_factory=list)
    export_format: Optional[str] = None


class MostFrequentThreatsRequest(BaseModel):
    start_date: date
    end_date: date
    threat_types: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    risk_levels: List[str] = Field(default_factory=list)


class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    national_id: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    avatar_url: Optional[str] = None


class PasswordResetRequest(BaseModel):
    current_password: Optional[str] = None
    reset_mode: str
    new_password: Optional[str] = None


class DeleteAccountRequest(BaseModel):
    confirmation_text: str
    reason: Optional[str] = None


class UserCreateRequest(BaseModel):
    name: str
    email: str
    password: str
    group_id: str
    national_id: Optional[str] = None
    phone_number: Optional[str] = None
    status: str
    avatar_url: Optional[str] = None
    username: Optional[str] = None


class UserUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    group_id: Optional[str] = None
    national_id: Optional[str] = None
    phone_number: Optional[str] = None
    status: Optional[str] = None
    avatar_url: Optional[str] = None


class PermissionRuleRequest(BaseModel):
    module: str
    read: bool
    edit: bool


class UserGroupCreateRequest(BaseModel):
    name: str
    permissions: List[PermissionRuleRequest]


class UserGroupUpdateRequest(BaseModel):
    name: Optional[str] = None
    permissions: Optional[List[PermissionRuleRequest]] = None


class BulkNotificationReadRequest(BaseModel):
    type: Optional[str] = None


def _meta(**extra: Any) -> Dict[str, Any]:
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "timezone": "Asia/Bangkok",
        **extra,
    }


def _success(data: Any, **meta_extra: Any) -> Dict[str, Any]:
    return {"data": data, "meta": _meta(**meta_extra), "error": None}


def _paged(data: Any, page: int, page_size: int, total: int, **meta_extra: Any) -> Dict[str, Any]:
    total_pages = max(1, (total + page_size - 1) // page_size) if page_size > 0 else 1
    return {"data": data, "meta": _meta(page=page, page_size=page_size, total=total, total_pages=total_pages, **meta_extra), "error": None}


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _to_bangkok_date(value: datetime) -> str:
    return value.astimezone(BANGKOK_TZ).strftime("%Y-%m-%d")


def _to_bangkok_hour(value: datetime) -> str:
    return value.astimezone(BANGKOK_TZ).strftime("%Y-%m-%d %H:00")


def _start_bangkok_day(value: datetime) -> datetime:
    localized = value.astimezone(BANGKOK_TZ)
    return datetime(localized.year, localized.month, localized.day, tzinfo=BANGKOK_TZ)


def _start_bangkok_hour(value: datetime) -> datetime:
    localized = value.astimezone(BANGKOK_TZ)
    return datetime(localized.year, localized.month, localized.day, localized.hour, tzinfo=BANGKOK_TZ)


def _normalize_severity(value: Optional[str]) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "very high"}:
        return "critical"
    if text == "high":
        return "high"
    if text == "medium":
        return "medium"
    if text in {"clean", "info"}:
        return "clean"
    return "low"


def _severity_label(value: str) -> str:
    return value.capitalize() if value else "Low"


def _pick_activity_time(doc: Dict[str, Any]) -> Optional[datetime]:
    return _parse_dt(
        doc.get("last_seen")
        or doc.get("event_time")
        or doc.get("collect_time")
        or doc.get("processed_at")
        or doc.get("first_seen")
        or doc.get("created_at")
    )


def _pick_event_time(doc: Dict[str, Any]) -> Optional[datetime]:
    return _parse_dt(doc.get("event_time") or doc.get("first_seen") or doc.get("collect_time") or doc.get("processed_at") or doc.get("created_at"))


def _date_query_range(start_date: Optional[str], end_date: Optional[str]) -> Optional[Dict[str, str]]:
    if not start_date and not end_date:
        return None
    range_query: Dict[str, str] = {}
    if start_date:
        range_query["gte"] = start_date if "T" in start_date else f"{start_date}T00:00:00+07:00"
    if end_date:
        range_query["lte"] = end_date if "T" in end_date else f"{end_date}T23:59:59+07:00"
    return range_query


def _resolve_anchor_end(end_date: Optional[str]) -> datetime:
    if end_date:
        normalized = end_date if "T" in end_date else f"{end_date}T23:59:59+07:00"
        parsed = _parse_dt(normalized)
        if parsed:
            return parsed.astimezone(UTC)
    return datetime.now(UTC)


def _date_filter(range_query: Optional[Dict[str, str]], fields: Sequence[str]) -> Optional[Dict[str, Any]]:
    if not range_query:
        return None
    should = [{"range": {field: range_query}} for field in fields]
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _normalize_sources(doc: Dict[str, Any]) -> List[str]:
    raw_sources = doc.get("sources") or []
    if isinstance(raw_sources, list) and raw_sources:
        values = []
        for source in raw_sources:
            if isinstance(source, dict):
                values.append(str(source.get("name", "")).strip())
            else:
                values.append(str(source).strip())
        return [item for item in values if item]
    source_name = str(doc.get("source_name", "")).strip()
    return [item.strip() for item in source_name.split(",") if item.strip()]


def _sector_info(doc: Dict[str, Any]) -> Dict[str, str]:
    sector = (((doc.get("ai_score_breakdown") or {}).get("target_sector") or {}) if isinstance(doc.get("ai_score_breakdown"), dict) else {}) or {}
    return {
        "sector": str(sector.get("sector") or "general"),
        "sector_name": str(sector.get("sector_name") or "General/Multiple"),
        "sector_name_th": str(sector.get("sector_name_th") or "ทั่วไป"),
        "icon": str(sector.get("icon") or "🌐"),
    }


def _country_from_doc(doc: Dict[str, Any]) -> Optional[str]:
    enrichment = doc.get("enrichment") or {}
    ip_info = enrichment.get("ip_info") if isinstance(enrichment, dict) and isinstance(enrichment.get("ip_info"), dict) else {}
    asn_data = (doc.get("asn_data") or {}) if isinstance(doc.get("asn_data"), dict) else {}
    geo_info = (doc.get("geo_info") or {}) if isinstance(doc.get("geo_info"), dict) else {}
    direct_ip = (doc.get("ip_info") or {}) if isinstance(doc.get("ip_info"), dict) else {}
    return (
        ip_info.get("country")
        or direct_ip.get("country")
        or asn_data.get("country_code")
        or geo_info.get("country")
        or doc.get("geo_country")
    )


def _country_code_from_name(country_name: Optional[str]) -> Optional[str]:
    if not country_name:
        return None
    normalized = str(country_name).strip().lower()
    return COUNTRY_CODE_MAP.get(normalized)


def _indicator_id(ioc_type: str, ioc_value: str) -> str:
    return f"{str(ioc_type or '').lower()}::{str(ioc_value or '').strip()}"


def _indicator_or_doc_id(doc: Dict[str, Any]) -> str:
    ioc_type = str(doc.get("ioc_type") or "").strip().lower()
    ioc_value = str(doc.get("ioc_value") or "").strip()
    if ioc_type and ioc_value:
        return _indicator_id(ioc_type, ioc_value)
    if doc.get("_id"):
        return f"doc::{doc['_id']}"
    return f"doc::{_hash_id(str(doc.get('description') or ''), str(doc.get('reference') or ''), str(_pick_activity_time(doc) or ''))}"


def _split_indicator_id(ioc_id: str) -> Tuple[str, str]:
    if "::" not in ioc_id:
        raise ValueError("IOC identifier must be in '<ioc_type>::<ioc_value>' format")
    ioc_type, ioc_value = ioc_id.split("::", 1)
    return ioc_type, ioc_value


def _lookup_items(values: Iterable[str]) -> List[Dict[str, Any]]:
    seen = set()
    items = []
    for value in sorted({str(item).strip() for item in values if str(item).strip()}, key=str.lower):
        lowered = value.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        items.append({"value": value, "label": value, "description": None, "active": True})
    return items


def _hash_id(*parts: str) -> str:
    payload = "|".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()[:16]


def _page_slice(items: List[Dict[str, Any]], page: int, page_size: int) -> List[Dict[str, Any]]:
    offset = max(page - 1, 0) * page_size
    return items[offset: offset + page_size]


def _token_from_request(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    return request.cookies.get("token")


def require_dashboard_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTP_BEARER),
) -> Dict[str, Any]:
    token = _token_from_request(request, credentials)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    user = get_dashboard_state().get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


def _safe_search(index: str, body: Dict[str, Any]) -> Dict[str, Any]:
    client = get_elastic_client()
    try:
        return client.search_index(index, body)
    except Exception as exc:
        logger.error("Elasticsearch search failed for %s: %s", index, exc)
        return {"hits": {"total": {"value": 0}, "hits": []}}


def _search_documents(
    index: str,
    query_text: str = "*",
    filters: Optional[List[Dict[str, Any]]] = None,
    limit: int = 100,
    offset: int = 0,
    sort: Optional[List[Dict[str, Any]]] = None,
    fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    must: List[Dict[str, Any]] = []
    if query_text and query_text != "*" and fields:
        must.append({"multi_match": {"query": query_text, "fields": fields}})
    body = {
        "query": {
            "bool": {
                "must": must if must else [{"match_all": {}}],
                "filter": filters or [],
            }
        },
        "sort": sort or [{"processed_at": {"order": "desc", "missing": "_last"}}],
        "from": offset,
        "size": limit,
    }
    return _safe_search(index, body)


def _search_warehouse_docs(
    query_text: str = "*",
    ioc_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    validation_statuses: Optional[List[str]] = None,
    review_states: Optional[List[str]] = None,
    warehouse_eligible_only: Optional[bool] = True,
    sort_by: str = "risk",
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    client = get_elastic_client()
    filters: List[Dict[str, Any]] = []
    if ioc_types:
        filters.append({"terms": {"ioc_type": [item.lower() for item in ioc_types]}})
    if severities:
        filters.append({"terms": {"ai_severity": [_normalize_severity(item) for item in severities]}})
    if sources:
        filters.append({"terms": {"source_name": sources}})
    if threat_types:
        filters.append({"terms": {"ai_threat_types": threat_types}})
    if validation_statuses:
        filters.append({"terms": {"validation_status": validation_statuses}})
    if review_states:
        filters.append({"terms": {"review_state": review_states}})
    if warehouse_eligible_only is not None:
        if warehouse_eligible_only:
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"warehouse_eligible": True}},
                            {"bool": {"must_not": [{"exists": {"field": "warehouse_eligible"}}]}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )
        else:
            filters.append({"term": {"warehouse_eligible": False}})
    date_filter = _date_filter(_date_query_range(start_date, end_date), ["event_time", "first_seen", "collect_time", "processed_at"])
    if date_filter:
        filters.append(date_filter)
    sort = (
        [{"ai_risk_score": {"order": "desc", "missing": "_last"}}, {"processed_at": {"order": "desc", "missing": "_last"}}]
        if sort_by == "risk"
        else [{"event_time": {"order": "desc", "missing": "_last"}}, {"processed_at": {"order": "desc", "missing": "_last"}}]
    )
    return _search_documents(
        client.warehouse_index,
        query_text=query_text,
        filters=filters,
        limit=limit,
        offset=offset,
        sort=sort,
        fields=["ioc_value^3", "description", "reference", "ai_threat_types", "ai_threat_actors", "source_name"],
    )


def _search_datalake_docs(
    query_text: str = "*",
    ioc_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    client = get_elastic_client()
    filters: List[Dict[str, Any]] = []
    if ioc_types:
        filters.append({"terms": {"ioc_type": [item.lower() for item in ioc_types]}})
    if severities:
        filters.append({"terms": {"severity": [_normalize_severity(item) for item in severities]}})
    if sources:
        filters.append({"terms": {"source_name": sources}})
    if threat_types:
        filters.append({"terms": {"threat_type": threat_types}})
    date_filter = _date_filter(_date_query_range(start_date, end_date), ["event_time", "collect_time", "created_at"])
    if date_filter:
        filters.append(date_filter)
    return _search_documents(
        client.datalake_index,
        query_text=query_text,
        filters=filters,
        limit=limit,
        offset=offset,
        sort=[{"event_time": {"order": "desc", "missing": "_last"}}, {"collect_time": {"order": "desc", "missing": "_last"}}],
        fields=["ioc_value^3", "description", "reference", "source_name", "threat_type"],
    )


def _is_action_document(doc: Dict[str, Any]) -> bool:
    action_meta = derive_action_metadata(doc)
    return bool(action_meta["action_required"] or action_meta["action_status"])


def _search_action_docs(
    query_text: str = "*",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    severities: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    result = _search_warehouse_docs(
        query_text=query_text,
        start_date=start_date,
        end_date=end_date,
        severities=severities,
        sources=sources,
        threat_types=threat_types,
        warehouse_eligible_only=None,
        limit=limit,
        offset=offset,
    )
    docs = _hits_to_docs(result)
    docs = [doc for doc in docs if str(doc.get("tlp") or "amber").strip().lower() != "red"]
    docs = [doc for doc in docs if _is_action_document(doc)]
    docs.sort(
        key=lambda item: (
            2 if derive_action_metadata(item)["action_status"] == ACTION_OPEN else 1 if derive_action_metadata(item)["action_status"] == ACTION_IN_PROGRESS else 0,
            int(item.get("ai_risk_score") or 0),
            _pick_event_time(item) or datetime.min.replace(tzinfo=UTC),
        ),
        reverse=True,
    )
    return docs[offset:offset + limit]


def _hits_to_docs(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"_id": hit.get("_id"), **(hit.get("_source") or {})} for hit in result.get("hits", {}).get("hits", [])]


def _fetch_datalake_by_indicators(indicators: Sequence[Tuple[str, str]], limit: int = 2000) -> List[Dict[str, Any]]:
    unique = []
    seen = set()
    for ioc_type, ioc_value in indicators:
        key = _indicator_id(ioc_type, ioc_value)
        if key in seen or not ioc_type or not ioc_value:
            continue
        seen.add(key)
        unique.append((ioc_type.lower(), ioc_value))

    if not unique:
        return []

    client = get_elastic_client()
    results: List[Dict[str, Any]] = []
    chunk_size = 100
    for index in range(0, len(unique), chunk_size):
        batch = unique[index:index + chunk_size]
        should = [
            {"bool": {"must": [{"term": {"ioc_type": ioc_type}}, {"term": {"ioc_value": ioc_value}}]}}
            for ioc_type, ioc_value in batch
        ]
        body = {
            "query": {"bool": {"should": should, "minimum_should_match": 1}},
            "sort": [{"event_time": {"order": "desc", "missing": "_last"}}, {"collect_time": {"order": "desc", "missing": "_last"}}],
            "size": limit,
        }
        result = _safe_search(client.datalake_index, body)
        results.extend(_hits_to_docs(result))
        if len(results) >= limit:
            break
    return results[:limit]


def _get_processed_doc(doc_id: str) -> Optional[Dict[str, Any]]:
    return get_elastic_client().get_warehouse_document(doc_id)


def _get_warehouse_doc_by_indicator(ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
    result = _search_warehouse_docs(query_text="*", ioc_types=[ioc_type], limit=50)
    for doc in _hits_to_docs(result):
        if str(doc.get("ioc_value")) == ioc_value and str(doc.get("ioc_type", "")).lower() == ioc_type.lower():
            return doc
    return None


def _build_threat_level(docs: List[Dict[str, Any]], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(UTC)
    today = _start_bangkok_day(now)
    today_key = _to_bangkok_date(today)
    counts_by_day = { _to_bangkok_date(today - timedelta(days=index + 1)): 0 for index in range(14) }
    todays_docs: List[Dict[str, Any]] = []
    for doc in docs:
        event_time = _pick_event_time(doc)
        if not event_time:
            continue
        event_key = _to_bangkok_date(event_time)
        if event_key == today_key:
            todays_docs.append(doc)
        elif event_key in counts_by_day:
            counts_by_day[event_key] += 1

    total_today = len(todays_docs)
    baseline_avg = (sum(counts_by_day.values()) / len(counts_by_day)) if counts_by_day else 0
    spike_ratio = total_today / baseline_avg if baseline_avg > 0 else (3 if total_today > 0 else 0)
    high_critical = [doc for doc in todays_docs if _normalize_severity(doc.get("ai_severity") or doc.get("severity")) in {"critical", "high"}]
    severity_ratio = len(high_critical) / total_today if total_today else 0

    cii_sectors = {"critical_infrastructure", "government", "healthcare", "financial", "technology"}
    sector_counts: Dict[str, Dict[str, Any]] = {}
    cii_present = False
    for doc in high_critical:
        sector = _sector_info(doc)
        if sector["sector"] in cii_sectors:
            cii_present = True
        current = sector_counts.setdefault(sector["sector"], {"sector_name": sector["sector_name"], "sector_name_th": sector["sector_name_th"], "count": 0})
        current["count"] += 1
    weighted_sector_count = len(sector_counts) * (1.5 if cii_present else 1.0)

    actor_counts: Dict[str, int] = {}
    for doc in todays_docs:
        for actor in doc.get("ai_threat_actors") or []:
            actor_counts[actor] = actor_counts.get(actor, 0) + 1

    def volume_score(value: float) -> Dict[str, Any]:
        if value >= 3:
            score, description = 100, "ผิดปกติมาก"
        elif value >= 2:
            score, description = 80, "สูงกว่าปกติชัดเจน"
        elif value >= 1.5:
            score, description = 60, "เริ่มผิดปกติ"
        elif value >= 1:
            score, description = 40, "ปกติ"
        else:
            score, description = 20, "น้อยกว่าปกติ"
        return {"score": score, "input": round(value, 2), "label": "IOC Volume Spike", "description": description}

    def severity_score(value: float) -> Dict[str, Any]:
        if value >= 0.5:
            score, description = 100, "ครึ่งหนึ่งเป็นภัยรุนแรง"
        elif value >= 0.3:
            score, description = 80, "สัดส่วนภัยรุนแรงสูง"
        elif value >= 0.15:
            score, description = 60, "สัดส่วนปานกลาง"
        elif value >= 0.05:
            score, description = 40, "สัดส่วนปกติ"
        else:
            score, description = 20, "ส่วนใหญ่เป็น Low"
        return {"score": score, "input": round(value, 2), "label": "Severity Distribution", "description": description}

    def sector_score(value: float) -> Dict[str, Any]:
        if value >= 4:
            score, description = 100, "กระทบหลายภาคส่วนรวม CII"
        elif value >= 3:
            score, description = 80, "กระทบหลายภาคส่วน"
        elif value >= 2:
            score, description = 60, "กระทบอย่างน้อย 2 ภาคส่วน"
        elif value >= 1:
            score, description = 40, "พบผลกระทบบางส่วน"
        else:
            score, description = 10, "ยังไม่พบผลกระทบภาคส่วนสำคัญ"
        return {"score": score, "input": round(value, 2), "label": "Sector Impact", "description": description}

    def actor_score(count: int) -> Dict[str, Any]:
        if count >= 5:
            score, description = 100, "ตรวจพบ named actors หลายราย"
        elif count >= 3:
            score, description = 80, "ตรวจพบ actor activity ชัดเจน"
        elif count == 2:
            score, description = 60, "ตรวจพบ actor 2 ราย"
        elif count == 1:
            score, description = 40, "ตรวจพบ actor 1 ราย"
        else:
            score, description = 10, "ไม่พบ named actor"
        return {"score": score, "input": count, "label": "Threat Actor Activity", "description": description}

    factors = {
        "volume": volume_score(spike_ratio),
        "severity": severity_score(severity_ratio),
        "sector": sector_score(weighted_sector_count),
        "actor": actor_score(len(actor_counts)),
    }
    score = round(factors["volume"]["score"] * 0.30 + factors["severity"]["score"] * 0.25 + factors["sector"]["score"] * 0.25 + factors["actor"]["score"] * 0.20)
    if score >= 76:
        level, level_th = "critical", "วิกฤต"
    elif score >= 51:
        level, level_th = "elevated", "ยกระดับ"
    elif score >= 26:
        level, level_th = "guarded", "เฝ้าระวัง"
    else:
        level, level_th = "low", "ต่ำ"

    top_sectors = [
        {"sector": key, "sector_name": value["sector_name"], "sector_name_th": value["sector_name_th"], "count": value["count"]}
        for key, value in sorted(sector_counts.items(), key=lambda item: item[1]["count"], reverse=True)[:5]
    ]
    named_actors = [{"name": key, "count": value} for key, value in sorted(actor_counts.items(), key=lambda item: item[1], reverse=True)[:5]]

    return {
        "date": today_key,
        "timezone": "Asia/Bangkok",
        "score": score,
        "level": level,
        "level_th": level_th,
        "factors": factors,
        "inputs": {
            "total_iocs": total_today,
            "baseline_avg_14d": round(baseline_avg, 2),
            "spike_ratio": round(spike_ratio, 2),
            "critical_high_ratio": round(severity_ratio, 2),
            "high_critical_sector_count": len(sector_counts),
            "cii_sector_present": cii_present,
            "named_actor_count": len(actor_counts),
        },
        "top_sectors": top_sectors,
        "named_actors": named_actors,
    }


def _build_severity_distribution(docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts = Counter(_normalize_severity(doc.get("ai_severity") or doc.get("severity")) for doc in docs)
    total = sum(counts.values()) or 1
    color_map = {
        "critical": "#E31B54",
        "high": "#EC4A0A",
        "medium": "#FDB022",
        "low": "#6BADF1",
        "clean": "#667085",
    }
    items = []
    for severity in ["critical", "high", "medium", "low", "clean"]:
        value = counts.get(severity, 0)
        if value == 0 and severity == "clean":
            continue
        items.append(
            {
                "key": severity,
                "label": _severity_label(severity),
                "color": color_map[severity],
                "value": value,
                "percentage": round((value / total) * 100, 2),
            }
        )
    return items


def _latest_indicator_docs(docs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    latest_docs: Dict[str, Dict[str, Any]] = {}
    latest_times: Dict[str, datetime] = {}
    min_time = datetime.min.replace(tzinfo=UTC)
    for doc in docs:
        key = _indicator_or_doc_id(doc)
        activity_time = _pick_activity_time(doc) or _pick_event_time(doc) or min_time
        if key not in latest_docs or activity_time >= latest_times[key]:
            latest_docs[key] = doc
            latest_times[key] = activity_time
    return list(latest_docs.values())


def _primary_threat_type(doc: Dict[str, Any]) -> str:
    threat_values = doc.get("ai_threat_types") or doc.get("threat_type") or []
    if isinstance(threat_values, list):
        for threat in threat_values:
            label = str(threat or "").strip()
            if label:
                return label
    label = str(threat_values or "").strip()
    return label or "Unknown"


def _group_severity_label(docs: Sequence[Dict[str, Any]]) -> str:
    highest = "clean"
    for doc in docs:
        severity = _normalize_severity(doc.get("ai_severity") or doc.get("severity"))
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity
    return _severity_label(highest)


def _build_exposure_summary(
    visible_docs: Sequence[Dict[str, Any]],
    active_docs: Sequence[Dict[str, Any]],
    previous_visible_docs: Optional[Sequence[Dict[str, Any]]] = None,
    previous_active_docs: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    active_list = _latest_indicator_docs(active_docs)
    previous_visible_list = list(previous_visible_docs or [])
    previous_active_list = _latest_indicator_docs(previous_active_docs or [])

    payload = {
        "total_threats": len(visible_docs),
        "ioc_active": len(active_list),
        "critical_active": sum(
            1 for doc in active_list if _normalize_severity(doc.get("ai_severity") or doc.get("severity")) == "critical"
        ),
        "high_active": sum(
            1 for doc in active_list if _normalize_severity(doc.get("ai_severity") or doc.get("severity")) == "high"
        ),
    }
    previous_payload = {
        "total_threats": len(previous_visible_list),
        "ioc_active": len(previous_active_list),
        "critical_active": sum(
            1 for doc in previous_active_list if _normalize_severity(doc.get("ai_severity") or doc.get("severity")) == "critical"
        ),
        "high_active": sum(
            1 for doc in previous_active_list if _normalize_severity(doc.get("ai_severity") or doc.get("severity")) == "high"
        ),
    }
    payload["comparison"] = {
        key: _comparison_metric(payload[key], previous_payload[key])
        for key in ("total_threats", "ioc_active", "critical_active", "high_active")
    }
    return payload


def _build_threat_volume_nodes(docs: Sequence[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for doc in docs:
        grouped[_primary_threat_type(doc)].append(doc)

    nodes: List[Dict[str, Any]] = []
    sorted_groups = sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True)
    for index, (label, threat_docs) in enumerate(sorted_groups[:limit]):
        nodes.append(
            {
                "id": f"{_slugify_text(label)}:{index}",
                "label": label,
                "severity": _group_severity_label(threat_docs),
                "value": len(threat_docs),
            }
        )
    return nodes


def _build_heatmap(docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    x_axis = [f"{hour:02d}:00" for hour in range(24)]
    y_axis = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    counts = {(day, hour): 0 for day in range(7) for hour in range(24)}
    for doc in docs:
        event_time = _pick_event_time(doc)
        if not event_time:
            continue
        localized = event_time.astimezone(BANGKOK_TZ)
        counts[(localized.weekday(), localized.hour)] += 1
    cells = []
    for day_index, day_label in enumerate(y_axis):
        for hour, hour_label in enumerate(x_axis):
            cells.append({"x": hour_label, "y": day_label, "value": counts[(day_index, hour)]})
    peak_day, peak_hour = max(counts.items(), key=lambda item: item[1]) if counts else ((0, 0), 0)
    peak_value = counts.get(peak_day, 0) if isinstance(peak_day, tuple) else 0
    peak_day_index, peak_hour_index = peak_day if isinstance(peak_day, tuple) else (0, 0)
    peak_label = f"{y_axis[peak_day_index]}, {x_axis[peak_hour_index]} - {(peak_hour_index + 1) % 24:02d}:00"
    return {
        "mode": "day-hour",
        "x_axis": x_axis,
        "y_axis": y_axis,
        "cells": cells,
        "peak": {
            "day": y_axis[peak_day_index],
            "hour": x_axis[peak_hour_index],
            "end_hour": f"{peak_hour_index + 1:02d}:00",
            "label": peak_label,
            "value": peak_value,
        },
    }


def _build_ioc_export_rows(items: Sequence[Dict[str, Any]]) -> List[List[str]]:
    rows = [[
        "rank",
        "ioc_id",
        "ioc_value",
        "ioc_type",
        "ioc_type_label",
        "severity",
        "risk_score",
        "threat_types",
        "sources",
        "first_seen",
        "last_seen",
    ]]
    for item in items:
        rows.append(
            [
                str(item.get("rank") or ""),
                str(item.get("ioc_id") or ""),
                str(item.get("ioc_value") or ""),
                str(item.get("ioc_type") or ""),
                str(item.get("ioc_type_label") or ""),
                str(item.get("severity") or ""),
                str(item.get("risk_score") or ""),
                " | ".join(str(value) for value in (item.get("threat_types") or [])),
                " | ".join(str(value) for value in (item.get("sources") or [])),
                str(item.get("first_seen") or ""),
                str(item.get("last_seen") or ""),
            ]
        )
    return rows


def _build_top_list(counter: Counter, labels: Optional[Dict[str, str]] = None, limit: int = 5) -> List[Dict[str, Any]]:
    total = sum(counter.values()) or 1
    output = []
    for key, value in counter.most_common(limit):
        output.append({
            "key": key,
            "label": labels.get(key, key) if labels else key,
            "value": value,
            "percentage": round((value / total) * 100, 2),
            "color": None,
        })
    return output


def _slugify_text(value: str) -> str:
    text = str(value or "").strip().lower()
    return "".join(character if character.isalnum() else "-" for character in text).strip("-") or "unknown"


def _normalize_report_key(report_key: str) -> str:
    normalized = REPORT_KEY_ALIASES.get(str(report_key or "").strip().lower())
    if not normalized:
        raise HTTPException(status_code=404, detail="Unsupported report key")
    return normalized


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _percentage(value: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((value / total) * 100, 2)


def _comparison_metric(current_value: int, previous_value: int) -> Dict[str, Any]:
    if previous_value <= 0:
        if current_value <= 0:
            return {"previous_value": previous_value, "delta_percent": 0.0, "direction": "flat"}
        return {"previous_value": previous_value, "delta_percent": 100.0, "direction": "up"}

    change = round(((current_value - previous_value) / previous_value) * 100, 2)
    if change > 0:
        direction = "up"
    elif change < 0:
        direction = "down"
    else:
        direction = "flat"
    return {"previous_value": previous_value, "delta_percent": change, "direction": direction}


def _previous_date_window(start_date: Optional[str], end_date: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not start_date or not end_date:
        return None, None
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if start_bound is None or end_bound is None:
        return None, None
    span_days = max((end_bound.date() - start_bound.date()).days + 1, 1)
    previous_end = start_bound.date() - timedelta(days=1)
    previous_start = previous_end - timedelta(days=span_days - 1)
    return previous_start.isoformat(), previous_end.isoformat()


def _unique_list(values: Iterable[Any], limit: Optional[int] = None) -> List[Any]:
    output: List[Any] = []
    seen = set()
    for value in values:
        normalized = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        output.append(value)
        if limit and len(output) >= limit:
            break
    return output


def _primary_source(doc: Dict[str, Any]) -> str:
    sources = _normalize_sources(doc)
    return sources[0] if sources else str(doc.get("source_name") or "unknown")


def _coordinates_from_doc(doc: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    geo_info = doc.get("geo_info") or {}
    if isinstance(geo_info, dict):
        latitude = geo_info.get("latitude") or geo_info.get("lat")
        longitude = geo_info.get("longitude") or geo_info.get("lon")
        if latitude is not None and longitude is not None:
            return _safe_float(latitude, None), _safe_float(longitude, None)
    coordinates = doc.get("coordinates") or doc.get("Coordinates")
    if isinstance(coordinates, str) and "," in coordinates:
        latitude_text, longitude_text = coordinates.split(",", 1)
        return _safe_float(latitude_text.strip(), None), _safe_float(longitude_text.strip(), None)
    enrichment_ip = (doc.get("enrichment") or {}).get("ip_info") or {}
    enrichment_loc = enrichment_ip.get("loc") if isinstance(enrichment_ip, dict) else None
    if isinstance(enrichment_loc, str) and "," in enrichment_loc:
        lat_text, lon_text = enrichment_loc.split(",", 1)
        return _safe_float(lat_text.strip(), None), _safe_float(lon_text.strip(), None)
    return None, None


def _origin_display_severity(severity_counts: Counter) -> str:
    critical = int(severity_counts.get("critical", 0))
    high = int(severity_counts.get("high", 0))
    if critical > 0 and critical >= high:
        return "critical"
    return "high"


def _build_attack_origin_map(visible_docs: Sequence[Dict[str, Any]], related_docs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    origin_docs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    country_counts: Counter = Counter()

    for doc in list(visible_docs) + list(related_docs):
        country = _country_from_doc(doc)
        if not country:
            continue
        country_counts[country] += 1
        origin_docs[country].append(doc)

    origins: List[Dict[str, Any]] = []
    trusted_source_union = set()
    for country, value in country_counts.most_common(10):
        docs = origin_docs[country]
        severity_counts = Counter(
            _normalize_severity(doc.get("ai_severity") or doc.get("severity"))
            for doc in docs
        )
        sector_counts = Counter(
            _sector_info(doc)["sector_name"]
            for doc in docs
            if isinstance(doc.get("ai_score_breakdown"), dict)
        )
        latitude = None
        longitude = None
        for doc in docs:
            candidate_latitude, candidate_longitude = _coordinates_from_doc(doc)
            if candidate_latitude is not None and candidate_longitude is not None:
                latitude, longitude = candidate_latitude, candidate_longitude
                break
        source_counter = Counter(
            source
            for doc in docs
            for source in _normalize_sources(doc)
            if source in HIGH_CONFIDENCE_SOURCE_NAMES or _safe_float(doc.get("confidence"), 0.0) >= 9.0
        )
        trusted_sources = [
            source
            for source, count in source_counter.most_common(4)
            if count >= 5
        ]
        trusted_source_union.update(trusted_sources)
        origins.append(
            {
                "country_code": _country_code_from_name(country),
                "country_name": country,
                "value": value,
                "latitude": latitude,
                "longitude": longitude,
                "severity": _origin_display_severity(severity_counts),
                "critical_count": int(severity_counts.get("critical", 0)),
                "high_count": int(severity_counts.get("high", 0)),
                "primary_sector": sector_counts.most_common(1)[0][0] if sector_counts else "General/Multiple",
                "high_confidence_sources": len(trusted_sources),
                "trusted_sources": trusted_sources,
            }
        )

    return {
        "target_country": "Thailand",
        "high_confidence_sources": len(trusted_source_union),
        "origins": origins,
        "connections": [
            {
                "origin_country": origin["country_name"],
                "target_country": "Thailand",
                "count": origin["value"],
                "severity": origin["severity"],
            }
            for origin in origins
        ],
    }


def _severity_breakdown_counts(docs: Sequence[Dict[str, Any]], severity_field: str = "ai_severity") -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
    for doc in docs:
        severity = _normalize_severity(doc.get(severity_field) or doc.get("severity"))
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _group_dimension_values(
    report_key: str,
    doc: Dict[str, Any],
    datalake_candidates: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[str]:
    if report_key == "intelligence-sources":
        return _normalize_sources(doc) or ["unknown"]
    if report_key == "threat-types":
        values = doc.get("ai_threat_types") or doc.get("threat_type") or []
        return [str(value) for value in values if str(value).strip()] or ["Unknown"]
    if report_key == "attack-origins":
        values = [
            _country_from_doc(candidate)
            for candidate in (datalake_candidates or [])
        ]
        values.append(_country_from_doc(doc))
        countries = [str(value) for value in values if str(value or "").strip()]
        return countries or ["Unknown"]
    sector = _sector_info(doc)
    return [sector["sector_name_th"] or "ทั่วไป"]


def _filter_warehouse_docs(
    docs: Sequence[Dict[str, Any]],
    query: Optional[str] = None,
    threat_types: Optional[Sequence[str]] = None,
    sources: Optional[Sequence[str]] = None,
    severities: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    allowed_threat_types = {item.lower() for item in (threat_types or []) if str(item).strip()}
    allowed_sources = {item.lower() for item in (sources or []) if str(item).strip()}
    allowed_severities = {_normalize_severity(item) for item in (severities or []) if str(item).strip()}
    query_text = str(query or "").strip().lower()
    filtered = []
    for doc in docs:
        if allowed_threat_types:
            doc_threat_types = {str(item).lower() for item in (doc.get("ai_threat_types") or doc.get("threat_type") or [])}
            if not doc_threat_types.intersection(allowed_threat_types):
                continue
        if allowed_sources:
            doc_sources = {item.lower() for item in _normalize_sources(doc)}
            if not doc_sources.intersection(allowed_sources):
                continue
        if allowed_severities:
            severity = _normalize_severity(doc.get("ai_severity") or doc.get("severity"))
            if severity not in allowed_severities:
                continue
        if query_text:
            haystack = " ".join(
                [
                    str(doc.get("ioc_value") or ""),
                    str(doc.get("description") or ""),
                    str(doc.get("reference") or ""),
                    " ".join(str(item) for item in (doc.get("ai_threat_types") or [])),
                    " ".join(_normalize_sources(doc)),
                ]
            ).lower()
            if query_text not in haystack:
                continue
        filtered.append(doc)
    return filtered


def _resolve_date_bounds(start_date: Optional[str], end_date: Optional[str]) -> Tuple[Optional[datetime], Optional[datetime]]:
    start_bound = _parse_dt(f"{start_date}T00:00:00+07:00") if start_date else None
    end_bound = _parse_dt(f"{end_date}T23:59:59+07:00") if end_date else None
    return start_bound, end_bound


def _ioc_doc_matches_date_range(doc: Dict[str, Any], start_date: Optional[str] = None, end_date: Optional[str] = None) -> bool:
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if start_bound is None and end_bound is None:
        return True

    observed_from = _parse_dt(
        doc.get("first_seen") or doc.get("event_time") or doc.get("collect_time") or doc.get("processed_at") or doc.get("created_at")
    )
    observed_to = _parse_dt(
        doc.get("last_seen") or doc.get("collect_time") or doc.get("processed_at") or doc.get("first_seen") or doc.get("event_time") or doc.get("created_at")
    )
    if observed_from is None and observed_to is None:
        return True

    effective_from = observed_from or observed_to
    effective_to = observed_to or observed_from
    if effective_from and effective_to and effective_to < effective_from:
        effective_from, effective_to = effective_to, effective_from

    if start_bound and effective_to and effective_to < start_bound:
        return False
    if end_bound and effective_from and effective_from > end_bound:
        return False
    return True


def _collect_ioc_docs(
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[Sequence[str]] = None,
    threat_types: Optional[Sequence[str]] = None,
    risk_levels: Optional[Sequence[str]] = None,
    ioc_types: Optional[Sequence[str]] = None,
    severities: Optional[Sequence[str]] = None,
    high_risk_only: bool = False,
    sort_by: str = "risk",
    sort_order: str = "desc",
) -> List[Dict[str, Any]]:
    effective_severities = list(severities or risk_levels or [])
    docs = _hits_to_docs(
        _search_warehouse_docs(
            query_text=query or "*",
            ioc_types=list(ioc_types or []) or None,
            severities=effective_severities or None,
            start_date=start_date,
            end_date=end_date,
            sort_by=sort_by,
            limit=5000,
        )
    )
    docs = _filter_warehouse_docs(
        docs,
        query=query,
        threat_types=threat_types,
        sources=sources,
        severities=effective_severities or None,
    )
    docs = [doc for doc in docs if _ioc_doc_matches_date_range(doc, start_date=start_date, end_date=end_date)]
    if high_risk_only:
        docs = [doc for doc in docs if int(doc.get("ai_risk_score") or 0) >= 80]
    docs = sorted(
        docs,
        key=lambda item: (int(item.get("ai_risk_score") or 0), _pick_event_time(item) or datetime.min.replace(tzinfo=UTC)),
        reverse=(sort_order != "asc"),
    )
    return docs


def _build_ioc_export_csv(items: Sequence[Dict[str, Any]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in _build_ioc_export_rows(items):
        writer.writerow(row)
    return buffer.getvalue().encode("utf-8-sig")


def _xlsx_column_name(index: int) -> str:
    value = index
    output = ""
    while value > 0:
        value, remainder = divmod(value - 1, 26)
        output = chr(65 + remainder) + output
    return output


def _build_ioc_export_xlsx(items: Sequence[Dict[str, Any]]) -> bytes:
    rows = _build_ioc_export_rows(items)
    shared_strings: List[str] = []
    shared_index: Dict[str, int] = {}

    def shared_string_id(value: Any) -> int:
        normalized = str(value or "")
        if normalized not in shared_index:
            shared_index[normalized] = len(shared_strings)
            shared_strings.append(normalized)
        return shared_index[normalized]

    sheet_rows: List[str] = []
    for row_index, row in enumerate(rows, start=1):
        cells: List[str] = []
        for column_index, value in enumerate(row, start=1):
            cell_ref = f"{_xlsx_column_name(column_index)}{row_index}"
            style = ' s="1"' if row_index == 1 else ""
            cells.append(f'<c r="{cell_ref}" t="s"{style}><v>{shared_string_id(value)}</v></c>')
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    column_widths = [
        8, 28, 32, 16, 18, 14, 12, 28, 28, 22, 22,
    ]
    columns_xml = "".join(
        f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(column_widths, start=1)
    )
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<cols>{columns_xml}</cols>"
        f'<sheetData>{"".join(sheet_rows)}</sheetData>'
        '</worksheet>'
    )
    shared_strings_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{sum(len(row) for row in rows)}" uniqueCount="{len(shared_strings)}">'
        + "".join(f"<si><t>{xml_escape(value)}</t></si>" for value in shared_strings)
        + "</sst>"
    )
    created_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w", compression=zipfile.ZIP_DEFLATED) as workbook:
        workbook.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
            '</Types>',
        )
        workbook.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>',
        )
        workbook.writestr(
            "docProps/app.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            '<Application>NCSA Dashboard</Application>'
            '</Properties>',
        )
        workbook.writestr(
            "docProps/core.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:title>IOC Report</dc:title>'
            '<dc:creator>NCSA Dashboard</dc:creator>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{created_at}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{created_at}</dcterms:modified>'
            '</cp:coreProperties>',
        )
        workbook.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="IOC Report" sheetId="1" r:id="rId1"/></sheets>'
            '</workbook>',
        )
        workbook.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
            '</Relationships>',
        )
        workbook.writestr(
            "xl/styles.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2">'
            '<font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><name val="Calibri"/></font>'
            '</fonts>'
            '<fills count="2">'
            '<fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="solid"><fgColor rgb="FFDEEAF6"/><bgColor indexed="64"/></patternFill></fill>'
            '</fills>'
            '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2">'
            '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="1" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
            '</cellXfs>'
            '</styleSheet>',
        )
        workbook.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        workbook.writestr("xl/sharedStrings.xml", shared_strings_xml)
    return content.getvalue()


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_text_chunk(lines: Sequence[str], page_width: int = 842, page_height: int = 595) -> bytes:
    baseline = page_height - 40
    output = [
        "BT",
        "/F1 8 Tf",
        "11 TL",
        f"40 {baseline} Td",
    ]
    for line in lines:
        ascii_line = str(line or "").encode("latin-1", "replace").decode("latin-1")
        output.append(f"({_pdf_escape(ascii_line)}) Tj")
        output.append("T*")
    output.append("ET")
    return "\n".join(output).encode("latin-1", "replace")


def _build_ioc_export_pdf(items: Sequence[Dict[str, Any]]) -> bytes:
    widths = [6, 28, 10, 10, 6, 28, 24, 16, 16]
    headings = ["Rank", "IOC Value", "Type", "Severity", "Risk", "Threat Types", "Sources", "First Seen", "Last Seen"]

    def format_line(values: Sequence[Any]) -> str:
        cells = []
        for width, value in zip(widths, values):
            text = str(value or "")
            if len(text) > width:
                text = f"{text[:max(width - 3, 0)]}..." if width > 3 else text[:width]
            cells.append(text.ljust(width))
        return " | ".join(cells)

    rows = _build_ioc_export_rows(items)
    content_lines = [
        "IOC Report Export",
        f"Generated at: {datetime.now(BANGKOK_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')}",
        "",
        format_line(headings),
        "-" * len(format_line(headings)),
    ]
    for row in rows[1:]:
        content_lines.append(
            format_line([row[0], row[2], row[4], row[5], row[6], row[7], row[8], row[9], row[10]])
        )

    lines_per_page = 45
    line_chunks = [content_lines[index:index + lines_per_page] for index in range(0, len(content_lines), lines_per_page)] or [[]]
    objects: List[bytes] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    catalog_id = add_object(b"<< /Type /Catalog /Pages 2 0 R >>")
    add_object(b"<< /Type /Pages /Kids [] /Count 0 >>")
    font_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_ids: List[int] = []
    for chunk in line_chunks:
        content_stream = _pdf_text_chunk(chunk)
        content_id = add_object(b"<< /Length %d >>\nstream\n" % len(content_stream) + content_stream + b"\nendstream")
        page_id = add_object(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode(
                "ascii"
            )
        )
        page_ids.append(page_id)

    objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{page_id} 0 R' for page_id in page_ids)}] /Count {len(page_ids)} >>".encode("ascii")
    assert catalog_id == 1

    buffer = io.BytesIO()
    buffer.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f"{index} 0 obj\n".encode("ascii"))
        buffer.write(payload)
        buffer.write(b"\nendobj\n")
    xref_offset = buffer.tell()
    buffer.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    buffer.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii")
    )
    return buffer.getvalue()


def _build_ioc_export_artifact(items: Sequence[Dict[str, Any]], export_format: str) -> Tuple[str, bytes, str]:
    normalized = str(export_format or "csv").strip().lower()
    if normalized == "xlsx":
        return "xlsx", _build_ioc_export_xlsx(items), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if normalized == "pdf":
        return "pdf", _build_ioc_export_pdf(items), "application/pdf"
    if normalized == "csv":
        return "csv", _build_ioc_export_csv(items), "text/csv; charset=utf-8"
    raise HTTPException(status_code=400, detail="Unsupported export format")


def _build_report_ranking(
    report_key: str,
    docs: Sequence[Dict[str, Any]],
    datalake_lookup: Dict[str, List[Dict[str, Any]]],
    trend_chart: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    series_by_label = {str(item.get("label")): item for item in trend_chart.get("series") or []}
    total_events = len(docs)

    for doc in docs:
        indicator = _indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", ""))
        datalake_candidates = datalake_lookup.get(indicator, [])
        group_values = _group_dimension_values(report_key, doc, datalake_candidates)
        event_time = _pick_event_time(doc)
        threat_types = [str(item) for item in (doc.get("ai_threat_types") or doc.get("threat_type") or []) if str(item).strip()]
        severity = _normalize_severity(doc.get("ai_severity") or doc.get("severity"))
        for label in group_values:
            current = grouped.setdefault(
                label,
                {
                    "label": label,
                    "count": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0},
                    "sources": set(),
                    "sample_iocs": [],
                    "main_threat_counter": Counter(),
                    "last_seen": None,
                },
            )
            current["count"] += 1
            current["severity_distribution"][severity] += 1
            current["sources"].update(_normalize_sources(doc))
            current["main_threat_counter"].update(threat_types)
            if doc.get("ioc_value"):
                current["sample_iocs"] = _unique_list(current["sample_iocs"] + [str(doc["ioc_value"])], limit=5)
            if event_time and (current["last_seen"] is None or event_time > current["last_seen"]):
                current["last_seen"] = event_time

    ranking_items: List[Dict[str, Any]] = []
    for index, current in enumerate(
        sorted(grouped.values(), key=lambda item: (-item["count"], str(item["label"]).lower())),
        start=1,
    ):
        series = series_by_label.get(current["label"]) or {}
        main_threat = current["main_threat_counter"].most_common(1)
        ranking_items.append(
            {
                "rank": index,
                "label": current["label"],
                "group_type": report_key,
                "change_direction": series.get("direction", "flat"),
                "change_percent": round(_safe_float(series.get("change_percent"), 0.0), 2),
                "main_threat_type": main_threat[0][0] if main_threat else None,
                "severity_distribution": current["severity_distribution"],
                "total_events": current["count"],
                "share_percent": _percentage(current["count"], total_events),
                "sources": sorted(current["sources"]),
                "sample_iocs": current["sample_iocs"],
                "last_seen": current["last_seen"].isoformat().replace("+00:00", "Z") if current["last_seen"] else None,
            }
        )

    top_chart = {
        "items": [
            {
                "key": item["label"],
                "label": item["label"],
                "value": item["total_events"],
                "percentage": item["share_percent"],
                "color": None,
            }
            for item in ranking_items[:10]
        ]
    }
    severity_rows = [
        {"label": item["label"], **item["severity_distribution"]}
        for item in ranking_items[:10]
    ]
    return ranking_items, top_chart, severity_rows


def _build_time_series_points(counts: Dict[str, Dict[str, int]], bucket_keys: List[str], key: str) -> List[int]:
    return [counts.get(key, {}).get(bucket, 0) for bucket in bucket_keys]


def _calculate_change(points: List[int]) -> Tuple[str, float]:
    half = max(1, floor(len(points) / 2))
    previous = points[:half] or [0]
    recent = points[half:] or [0]
    prev_avg = sum(previous) / len(previous)
    recent_avg = sum(recent) / len(recent)
    if prev_avg == 0 and recent_avg == 0:
        return "flat", 0.0
    if prev_avg == 0:
        return "up", 100.0
    change = ((recent_avg - prev_avg) / prev_avg) * 100
    if change >= 10:
        return "up", change
    if change <= -10:
        return "down", change
    return "flat", change


def _build_trend_analytics(
    warehouse_docs: List[Dict[str, Any]],
    datalake_docs: List[Dict[str, Any]],
    now: Optional[datetime] = None,
    window_hours: int = 24,
    forecast_hours: int = 24,
    training_window_hours: int = 72,
) -> Dict[str, Any]:
    now = now or datetime.now(UTC)
    current_hour = _start_bangkok_hour(now)
    visible_hours = [current_hour - timedelta(hours=(window_hours - index - 1)) for index in range(window_hours)]
    training_hours = [current_hour - timedelta(hours=(training_window_hours - index - 1)) for index in range(training_window_hours)]
    visible_keys = [_to_bangkok_hour(item) for item in visible_hours]
    training_keys = {_to_bangkok_hour(item) for item in training_hours}
    visible_set = set(visible_keys)

    datalake_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for doc in datalake_docs:
        datalake_map[_indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", ""))].append(doc)

    visible_buckets: Dict[str, Dict[str, Any]] = {}
    training_buckets: Dict[str, Dict[str, Any]] = {}
    source_counts: Dict[str, Dict[str, int]] = defaultdict(dict)
    threat_counts: Dict[str, Dict[str, int]] = defaultdict(dict)
    sector_counts: Dict[str, Dict[str, int]] = defaultdict(dict)
    country_counts: Dict[str, Dict[str, int]] = defaultdict(dict)

    for doc in warehouse_docs:
        event_time = _pick_event_time(doc)
        if not event_time:
            continue
        hour_key = _to_bangkok_hour(event_time)
        if hour_key not in training_keys:
            continue
        severity = _normalize_severity(doc.get("ai_severity") or doc.get("severity"))
        training_point = training_buckets.setdefault(hour_key, {"hour": hour_key, "label": hour_key[5:], "total": 0, "critical": 0, "high": 0})
        training_point["total"] += 1
        if severity == "critical":
            training_point["critical"] += 1
        if severity in {"critical", "high"}:
            training_point["high"] += 1

        if hour_key in visible_set:
            visible_point = visible_buckets.setdefault(hour_key, {"hour": hour_key, "label": hour_key[5:], "total": 0, "critical": 0, "high": 0})
            visible_point["total"] += 1
            if severity == "critical":
                visible_point["critical"] += 1
            if severity in {"critical", "high"}:
                visible_point["high"] += 1

            for source in _normalize_sources(doc):
                source_counts[source][hour_key] = source_counts[source].get(hour_key, 0) + 1
            for threat_type in (doc.get("ai_threat_types") or doc.get("threat_type") or []):
                if not threat_type:
                    continue
                threat_counts[str(threat_type)][hour_key] = threat_counts[str(threat_type)].get(hour_key, 0) + 1
            sector = _sector_info(doc)
            sector_counts[sector["sector_name_th"]][hour_key] = sector_counts[sector["sector_name_th"]].get(hour_key, 0) + 1
            datalake_candidates = datalake_map.get(_indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", "")), [])
            country = next((value for value in (_country_from_doc(item) for item in datalake_candidates) if value), None) or _country_from_doc(doc)
            if country:
                country_counts[country][hour_key] = country_counts[country].get(hour_key, 0) + 1

    historical = [visible_buckets.get(bucket, {"hour": bucket, "label": bucket[5:], "total": 0, "critical": 0, "high": 0}) for bucket in visible_keys]
    training_list = [training_buckets.get(_to_bangkok_hour(item), {"hour": _to_bangkok_hour(item), "label": _to_bangkok_hour(item)[5:], "total": 0, "critical": 0, "high": 0}) for item in training_hours]

    forecast_hours_list = [current_hour + timedelta(hours=index + 1) for index in range(forecast_hours)]
    total_forecast = holt_winters_forecast([point["total"] for point in training_list], forecast_hours)
    critical_forecast = holt_winters_forecast([point["critical"] for point in training_list], forecast_hours)
    high_forecast = holt_winters_forecast([point["high"] for point in training_list], forecast_hours)
    forecast = [
        {
            "hour": _to_bangkok_hour(hour),
            "label": _to_bangkok_hour(hour)[5:],
            "total": total_forecast[index],
            "critical": critical_forecast[index],
            "high": high_forecast[index],
        }
        for index, hour in enumerate(forecast_hours_list)
    ]

    def build_series(title: str, dimension: str, counts: Dict[str, Dict[str, int]]) -> Dict[str, Any]:
        totals = {key: sum(bucket.values()) for key, bucket in counts.items()}
        ordered = [item[0] for item in sorted(totals.items(), key=lambda item: item[1], reverse=True)[:5]]
        series = []
        for key in ordered:
            points = _build_time_series_points(counts, visible_keys, key)
            direction, change_percent = _calculate_change(points)
            series.append({
                "key": key,
                "label": key,
                "points": points,
                "total": totals[key],
                "direction": direction,
                "change_percent": round(change_percent, 2),
            })
        return {
            "title": title,
            "dimension": dimension,
            "buckets": [bucket[5:] for bucket in visible_keys],
            "series": series,
        }

    threat_type_chart = build_series("Top 5 Threat Types", "threat_types", threat_counts)
    return {
        "meta": {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "timezone": "Asia/Bangkok",
            "window_hours": window_hours,
            "forecast_hours": forecast_hours,
            "training_window_hours": training_window_hours,
        },
        "summary": {
            "total_events": sum(item["total"] for item in historical),
            "critical_events": sum(item["critical"] for item in historical),
            "high_events": sum(item["high"] for item in historical),
            "forecast_total": sum(item["total"] for item in forecast),
            "forecast_critical": sum(item["critical"] for item in forecast),
            "forecast_high": sum(item["high"] for item in forecast),
            "top_rising_threat_types": [
                {
                    "key": item["key"],
                    "label": item["label"],
                    "change_percent": item["change_percent"],
                    "total": item["total"],
                }
                for item in sorted(threat_type_chart["series"], key=lambda item: item["change_percent"], reverse=True)[:4]
            ],
        },
        "comparison_charts": {
            "sources": build_series("Top 5 Sources", "sources", source_counts),
            "threat_types": threat_type_chart,
            "sectors": build_series("Top 5 Sectors", "sectors", sector_counts),
            "countries": build_series("Top 5 Countries", "countries", country_counts),
        },
        "threat_volume_trend": historical,
        "attack_volume_trend": {
            "model": "holt_winters_additive",
            "historical": historical,
            "forecast": forecast,
        },
    }


def _build_executive_attack_volume_trend(
    docs: List[Dict[str, Any]],
    now: datetime,
    start_date: str,
    end_date: str,
) -> Dict[str, Any]:
    start_day = datetime.strptime(start_date, "%Y-%m-%d").date()
    end_day = datetime.strptime(end_date, "%Y-%m-%d").date()
    day_span = max(0, (end_day - start_day).days)

    if day_span == 0:
        trend_training_docs = _hits_to_docs(
            _search_warehouse_docs(
                start_date=(now - timedelta(hours=72)).isoformat(),
                end_date=now.isoformat(),
                sort_by="time",
                limit=5000,
            )
        )
        trend_datalake_docs = _fetch_datalake_by_indicators(
            [(doc.get("ioc_type", ""), doc.get("ioc_value", "")) for doc in trend_training_docs],
            limit=5000,
        )
        trend = _build_trend_analytics(trend_training_docs, trend_datalake_docs, now=now)
        return {
            "points": [
                {**point, "timestamp": point["hour"], "point_type": "historical"}
                for point in trend["attack_volume_trend"]["historical"]
            ] + [
                {**point, "timestamp": point["hour"], "point_type": "forecast"}
                for point in trend["attack_volume_trend"]["forecast"]
            ],
            "forecast_start_index": len(trend["attack_volume_trend"]["historical"]),
        }

    buckets: Dict[str, Dict[str, Any]] = {}
    current_day = start_day
    while current_day <= end_day:
        key = current_day.strftime("%Y-%m-%d")
        buckets[key] = {
            "timestamp": f"{key}T00:00:00+07:00",
            "label": current_day.strftime("%d-%m-%y"),
            "total": 0,
            "critical": 0,
            "high": 0,
            "point_type": "historical",
        }
        current_day += timedelta(days=1)

    for doc in docs:
        event_time = _pick_event_time(doc)
        if not event_time:
            continue
        day_key = _to_bangkok_date(event_time)
        bucket = buckets.get(day_key)
        if not bucket:
            continue
        severity = _normalize_severity(doc.get("ai_severity") or doc.get("severity"))
        bucket["total"] += 1
        if severity == "critical":
            bucket["critical"] += 1
        if severity in {"critical", "high"}:
            bucket["high"] += 1

    points = [buckets[key] for key in sorted(buckets.keys())]
    return {
        "points": points,
        "forecast_start_index": len(points),
    }


def _operations_overview(docs: List[Dict[str, Any]], anchor_end: Optional[datetime] = None) -> Dict[str, Any]:
    severities = [_normalize_severity(doc.get("ai_severity") or doc.get("severity")) for doc in docs]
    unique_sources = {source for doc in docs for source in _normalize_sources(doc)}
    anchor = anchor_end or datetime.now(UTC)
    recent_cutoff = anchor - timedelta(days=1)
    new_ioc = 0
    for doc in docs:
        event_time = _pick_event_time(doc)
        if event_time and recent_cutoff <= event_time <= anchor:
            new_ioc += 1
    return {
        "active_ioc": len(docs),
        "critical_ioc_active": sum(1 for severity in severities if severity == "critical"),
        "new_ioc": new_ioc,
        "sources_active": len(unique_sources),
    }


def _action_status(doc: Dict[str, Any], assignment: Optional[Dict[str, Any]]) -> str:
    action_meta = derive_action_metadata(doc)
    if action_meta["action_status"] == ACTION_CLOSED:
        return ACTION_CLOSED
    if action_meta["action_status"] == ACTION_IN_PROGRESS:
        return ACTION_IN_PROGRESS
    if assignment:
        return ACTION_IN_PROGRESS
    return action_meta["action_status"] or ACTION_OPEN


def _build_action_ticket(doc: Dict[str, Any], assignment: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    severity = _severity_label(_normalize_severity(doc.get("ai_severity") or doc.get("severity")))
    sector = _sector_info(doc)
    action_meta = derive_action_metadata(doc)
    country = _country_from_doc(doc)
    ioc_type = str(doc.get("ioc_type", "")).lower()
    context_parts = [
        ", ".join(doc.get("ai_threat_types") or []) or "Unknown Threat",
        sector["sector_name"],
    ]
    if country:
        context_parts.append(country)
    timestamp = _pick_event_time(doc)
    return {
        "action_id": doc["_id"],
        "status": _action_status(doc, assignment),
        "severity": severity,
        "title": action_meta["action_title"] or f"Review {severity} Threat",
        "ioc_type": ioc_type,
        "ioc_type_label": IOC_TYPE_LABELS.get(ioc_type, str(doc.get("ioc_type", "unknown")).upper()),
        "context": " · ".join(part for part in context_parts if part),
        "sources": _normalize_sources(doc) or ["unknown"],
        "sla": "2 hours" if severity == "Critical" else "24 hours",
        "event_time": (timestamp or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
        "owner_name": (assignment or {}).get("assignee", {}).get("name"),
    }


def _build_action_detail(doc: Dict[str, Any]) -> Dict[str, Any]:
    state = get_dashboard_state()
    assignment = state.get_action_assignment(doc["_id"])
    action = _build_action_ticket(doc, assignment)
    action_meta = derive_action_metadata(doc)
    datalake_docs = _fetch_datalake_by_indicators([(doc.get("ioc_type", ""), doc.get("ioc_value", ""))], limit=100)
    primary_event = datalake_docs[0] if datalake_docs else {}
    sector = _sector_info(doc)
    related_nodes = [
        {"id": f"ioc:{doc.get('ioc_value')}", "type": "ioc", "label": doc.get("ioc_value")},
        {"id": f"type:{(doc.get('ai_threat_types') or ['unknown'])[0]}", "type": "threat_type", "label": (doc.get("ai_threat_types") or ["Unknown"])[0]},
    ]
    related_edges = [{"source": related_nodes[0]["id"], "target": related_nodes[1]["id"], "relation": "classified_as"}]
    owner = assignment["assignee"] if assignment else {
        "user_id": "usr-unassigned",
        "name": doc.get("reviewed_by") or "Unassigned",
        "avatar_url": "/user.png",
    }
    notes = state.get_action_notes(doc["_id"])
    if doc.get("review_notes"):
        notes.append(
            {
                "note_id": f"note-{_hash_id(doc['_id'], 'review')}",
                "author_name": doc.get("reviewed_by") or "System",
                "created_at": doc.get("reviewed_at") or doc.get("processed_at"),
                "content": doc.get("review_notes"),
            }
        )
    activity_log = []
    if doc.get("processed_at"):
        activity_log.append({"timestamp": doc["processed_at"], "message": "IOC processed by AI pipeline"})
    if action_meta.get("action_updated_at") and action_meta.get("action_status"):
        activity_log.append({"timestamp": action_meta["action_updated_at"], "message": f"Action status changed to {action_meta['action_status']}"})
    if action_meta.get("action_closed_at"):
        close_reason = action_meta.get("action_closed_reason") or "closed"
        activity_log.append({"timestamp": action_meta["action_closed_at"], "message": f"Action closed: {close_reason}"})
    for event in datalake_docs[:5]:
        event_time = _pick_event_time(event)
        if event_time:
            activity_log.append(
                {
                    "timestamp": event_time.isoformat().replace("+00:00", "Z"),
                    "message": event.get("description") or event.get("reference") or "Observed in Data Lake",
                }
            )
    related_evidence = []
    if primary_event.get("reference"):
        related_evidence.append({"type": "reference", "label": "Source Reference", "value": primary_event["reference"]})
    if primary_event.get("source_ip"):
        related_evidence.append({"type": "attacker", "label": "Source (Attacker)", "value": primary_event["source_ip"]})
    if primary_event.get("target_ip"):
        related_evidence.append({"type": "victim", "label": "Target (Victim)", "value": primary_event["target_ip"]})
    return {
        "action": action,
        "owner": owner,
        "context": {
            "target": doc.get("ioc_value"),
            "source": primary_event.get("source_ip") or ", ".join(_normalize_sources(doc) or ["unknown"]),
            "source_name": primary_event.get("source_name") or _primary_source(doc),
            "target_victim": primary_event.get("target_ip"),
            "sector": sector["sector_name"],
            "threat_type": ", ".join(doc.get("ai_threat_types") or []) or "Unknown",
            "country": _country_from_doc(primary_event) or _country_from_doc(doc),
            "description": primary_event.get("description") or doc.get("description") or "",
        },
        "related_evidence": related_evidence,
        "related_evidence_graph": {
            "nodes": related_nodes,
            "edges": related_edges,
        },
        "evidence_graph": {
            "nodes": related_nodes,
            "edges": related_edges,
        },
        "remediation_plan": [
            "Validate evidence and source observations",
            "Confirm IOC against warehouse and datalake records",
            "Escalate or block if confidence remains high",
            "Document actions in analyst notes",
        ],
        "activity_log": activity_log,
        "notes": notes,
        "available_actions": ["assign", "false_positive", "block_ip"],
        "related_ioc_count": len(doc.get("ai_threat_types") or []),
    }


def _utcnow_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _build_ioc_record(rank: int, doc: Dict[str, Any]) -> Dict[str, Any]:
    ioc_type = str(doc.get("ioc_type", "")).lower()
    return {
        "ioc_id": _indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", "")),
        "rank": rank,
        "ioc_value": doc.get("ioc_value"),
        "ioc_type": ioc_type,
        "ioc_type_label": IOC_TYPE_LABELS.get(ioc_type, ioc_type.upper()),
        "severity": _severity_label(_normalize_severity(doc.get("ai_severity") or doc.get("severity"))),
        "risk_score": int(doc.get("ai_risk_score") or 0),
        "threat_types": doc.get("ai_threat_types") or doc.get("threat_type") or [],
        "sources": _normalize_sources(doc) or ["unknown"],
        "first_seen": doc.get("first_seen") or doc.get("event_time") or doc.get("collect_time"),
        "last_seen": doc.get("last_seen") or doc.get("collect_time") or doc.get("processed_at"),
    }


def _build_ioc_detail(warehouse_doc: Dict[str, Any], datalake_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    top_factors = warehouse_doc.get("ai_top_factors") or []
    breakdown_factors = [
        {
            "factor": item.get("factor") or item.get("label") or f"factor-{index}",
            "score": item.get("score", item.get("weighted_score", 0)),
            "weight": item.get("weighted_score", 0),
            "explanation": item.get("label", ""),
        }
        for index, item in enumerate(top_factors)
    ]
    relationship_nodes = []
    relationship_edges = []
    ioc_node_id = f"ioc:{warehouse_doc.get('ioc_value')}"
    relationship_nodes.append({"id": ioc_node_id, "type": "ioc", "label": warehouse_doc.get("ioc_value")})
    for threat_type in warehouse_doc.get("ai_threat_types") or []:
        node_id = f"type:{threat_type}"
        relationship_nodes.append({"id": node_id, "type": "threat_type", "label": threat_type})
        relationship_edges.append({"source": ioc_node_id, "target": node_id, "relation": "classified_as"})
    for actor in warehouse_doc.get("ai_threat_actors") or []:
        node_id = f"actor:{actor}"
        relationship_nodes.append({"id": node_id, "type": "threat_actor", "label": actor})
        relationship_edges.append({"source": ioc_node_id, "target": node_id, "relation": "attributed_to"})
    for doc in datalake_docs:
        enrichment = doc.get("enrichment") or {}
        related = enrichment.get("related_entities") or {}
        for malware in related.get("malware_family") or []:
            node_id = f"malware:{malware}"
            relationship_nodes.append({"id": node_id, "type": "malware", "label": malware})
            relationship_edges.append({"source": ioc_node_id, "target": node_id, "relation": "uses_malware"})
        if doc.get("cluster_label") is not None:
            node_id = f"campaign:{doc['cluster_label']}"
            relationship_nodes.append({"id": node_id, "type": "campaign", "label": f"cluster_{doc['cluster_label']}"})
            relationship_edges.append({"source": ioc_node_id, "target": node_id, "relation": "same_campaign"})
    sector = _sector_info(warehouse_doc)
    country = next((value for value in (_country_from_doc(item) for item in datalake_docs) if value), None) or _country_from_doc(warehouse_doc)
    first_enrichment = datalake_docs[0] if datalake_docs else {}
    _fe_enrich = (first_enrichment.get("enrichment") or {}) if isinstance(first_enrichment.get("enrichment"), dict) else {}
    _fe_ip_info = (_fe_enrich.get("ip_info") or {}) if isinstance(_fe_enrich.get("ip_info"), dict) else {}
    asn_data = (
        first_enrichment.get("asn_data")
        or ((first_enrichment.get("ip_info") or {}).get("asn_data") if isinstance(first_enrichment.get("ip_info"), dict) else {})
        or _fe_ip_info.get("asn_data")
        or {}
    )
    whois = first_enrichment.get("whois") or _fe_enrich.get("whois") or {}
    latitude, longitude = _coordinates_from_doc(first_enrichment)
    history_preview = []
    for doc in datalake_docs[:5]:
        observed_at = _pick_event_time(doc)
        history_preview.append(
            {
                "observed_at": observed_at.isoformat().replace("+00:00", "Z") if observed_at else None,
                "source": doc.get("source_name") or "unknown",
                "severity": _severity_label(_normalize_severity(doc.get("severity"))),
                "description": doc.get("description") or doc.get("reference") or "-",
            }
        )
    references = _unique_list([doc.get("reference") for doc in datalake_docs if doc.get("reference")], limit=10)
    return {
        "key_identifiers": {
            "ioc_value": warehouse_doc.get("ioc_value"),
            "ioc_type": warehouse_doc.get("ioc_type"),
            "ioc_type_label": IOC_TYPE_LABELS.get(str(warehouse_doc.get("ioc_type", "")).lower(), str(warehouse_doc.get("ioc_type", "")).upper()),
            "severity": _severity_label(_normalize_severity(warehouse_doc.get("ai_severity") or warehouse_doc.get("severity"))),
            "sources": _normalize_sources(warehouse_doc) or ["unknown"],
            "first_seen": warehouse_doc.get("first_seen") or warehouse_doc.get("event_time") or warehouse_doc.get("collect_time"),
            "threat_types": warehouse_doc.get("ai_threat_types") or warehouse_doc.get("threat_type") or [],
        },
        "risk_assessment": {
            "model": warehouse_doc.get("score_model_version") or "ai-scoring",
            "risk_score": int(warehouse_doc.get("ai_risk_score") or 0),
            "risk_level": _severity_label(_normalize_severity(warehouse_doc.get("ai_severity") or warehouse_doc.get("severity"))),
            "severity": _severity_label(_normalize_severity(warehouse_doc.get("ai_severity") or warehouse_doc.get("severity"))),
            "summary": ", ".join(warehouse_doc.get("ai_threat_types") or []) or "Threat score computed from AI scoring pipeline",
            "contributing_factors": breakdown_factors,
        },
        "geo_location_owner": {
            "country": country or "Unknown",
            "city": (
                ((first_enrichment.get("geo_info") or {}) if isinstance(first_enrichment.get("geo_info"), dict) else {}).get("city")
                or _fe_ip_info.get("city")
            ),
            "asn_org": asn_data.get("org"),
            "latitude": latitude,
            "longitude": longitude,
        },
        "network_ownership": {
            "organization": whois.get("org") or asn_data.get("org"),
            "net_name": first_enrichment.get("net_name") or whois.get("net_name"),
            "net_range": first_enrichment.get("net_range") or whois.get("net_range"),
            "cidr": first_enrichment.get("cidr") or whois.get("cidr") or _fe_ip_info.get("cidr"),
            "country": country,
            "allocation_type": first_enrichment.get("allocation_type") or whois.get("allocation_type"),
            "rir": first_enrichment.get("rir") or whois.get("rir"),
            "registered_on": first_enrichment.get("registered_on") or whois.get("registered_on"),
            "last_updated": first_enrichment.get("last_updated") or whois.get("last_updated"),
        },
        "asn_infrastructure": {
            "asn": asn_data.get("asn"),
            "asn_name": asn_data.get("org"),
            "asn_description": asn_data.get("org"),
            "asn_type": first_enrichment.get("asn_type") or _fe_ip_info.get("asn_type"),
            "hosting_type": first_enrichment.get("hosting_type") or _fe_ip_info.get("hosting_type"),
        },
        "abuse_contact": {
            "abuse_email": whois.get("registrant_email") or _fe_ip_info.get("abuse_email"),
            "abuse_contact": first_enrichment.get("abuse_contact") or _fe_ip_info.get("abuse_contact"),
            "noc_email": first_enrichment.get("noc_email") or _fe_ip_info.get("noc_email"),
            "tech_email": first_enrichment.get("tech_email") or _fe_ip_info.get("tech_email"),
        },
        "score_breakdown": warehouse_doc.get("ai_score_breakdown") or {},
        "target_sector": sector,
        "enrichment_context": {
            "references": references,
            "cluster_labels": _unique_list([doc.get("cluster_label") for doc in datalake_docs if doc.get("cluster_label") is not None]),
            "related_entities": _unique_list(
                [doc.get("enrichment", {}).get("related_entities") for doc in datalake_docs if isinstance(doc.get("enrichment", {}).get("related_entities"), dict)],
                limit=5,
            ),
            "source_documents": [
                {
                    "source_name": doc.get("source_name"),
                    "reference": doc.get("reference"),
                    "event_time": (_pick_event_time(doc) or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
                }
                for doc in datalake_docs[:10]
            ],
        },
        "history_preview": history_preview,
        "relationship": {
            "nodes": relationship_nodes,
            "edges": relationship_edges,
            "capabilities": {"campaigns": any(node["type"] == "campaign" for node in relationship_nodes)},
        },
    }


def _filter_news_docs(docs: List[Dict[str, Any]], query_text: Optional[str] = None, sources: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    allowed_sources = {item.lower() for item in NEWS_SOURCES}
    filtered = []
    for doc in docs:
        source_name = str(doc.get("source_name") or "").strip()
        source_type = str(doc.get("source_type") or "").strip().lower()
        if not source_name:
            continue
        if source_name.lower() not in allowed_sources and source_type not in {"news", "rss", "article"}:
            continue
        if sources and source_name not in sources:
            continue
        haystack = f"{doc.get('description', '')} {doc.get('reference', '')}".lower()
        if query_text and query_text.lower() not in haystack and query_text.lower() not in source_name.lower():
            continue
        filtered.append(doc)
    return filtered


def _build_news_articles(docs: List[Dict[str, Any]], query_text: Optional[str] = None, sources: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    articles: Dict[str, Dict[str, Any]] = {}
    for doc in _filter_news_docs(docs, query_text=query_text, sources=sources):
        source_name = doc.get("source_name") or "unknown"
        title_source = str(doc.get("title") or doc.get("description") or doc.get("reference") or doc.get("ioc_value") or "Threat intelligence article").strip()
        title = title_source.split(".")[0][:120] or "Threat intelligence article"
        published_at = (_pick_event_time(doc) or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
        article_key = _hash_id(source_name, str(doc.get("reference") or title), _to_bangkok_date(_pick_event_time(doc) or datetime.now(UTC)))
        article = articles.setdefault(
            article_key,
            {
                "article_id": article_key,
                "title": title,
                "published_at": published_at,
                "source": source_name,
                "summary": doc.get("description") or doc.get("reference"),
                "related_ioc_count": 0,
                "related_iocs": [],
                "url": doc.get("reference"),
                "source_type": doc.get("source_type") or "news",
                "references": [],
                "snippets": [],
            },
        )
        ioc_value = str(doc.get("ioc_value") or "").strip()
        if ioc_value and ioc_value not in article["related_iocs"]:
            article["related_iocs"].append(ioc_value)
            article["related_ioc_count"] = len(article["related_iocs"])
        if doc.get("reference"):
            article["references"] = _unique_list(article["references"] + [doc["reference"]], limit=10)
        if doc.get("description"):
            article["snippets"] = _unique_list(article["snippets"] + [doc["description"]], limit=5)
    return list(articles.values())


def _queue_export_job(
    export_format: str,
    file_prefix: str,
    report_type: str,
    filters: Optional[Dict[str, Any]] = None,
    file_content: Optional[bytes] = None,
    media_type: Optional[str] = None,
) -> Dict[str, Any]:
    state = get_dashboard_state()
    return state.create_export_job(
        export_format,
        file_prefix,
        report_type=report_type,
        filters=filters or {},
        file_content=file_content,
        media_type=media_type,
    )


def _public_export_job(job: Dict[str, Any], request: Request) -> Dict[str, Any]:
    payload = dict(job)
    if get_dashboard_state().get_export_file(str(job.get("export_id"))):
        payload["download_url"] = str(request.url_for("export_download", export_id=str(job["export_id"])))
    return payload


@router.post("/auth/login", tags=["Auth"])
def dashboard_login(request: LoginRequest):
    state = get_dashboard_state()
    payload = state.authenticate(request.username, request.password)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    response = JSONResponse(_success(payload))
    response.set_cookie("token", payload["access_token"], httponly=True, samesite="strict")
    return response


@router.get("/auth/me", tags=["Auth"])
def dashboard_me(current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    return _success(get_dashboard_state().public_user(current_user))


@router.post("/auth/logout", tags=["Auth"])
def dashboard_logout(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTP_BEARER),
):
    token = _token_from_request(request, credentials)
    if token:
        get_dashboard_state().logout(token)
    response = JSONResponse(_success({"logged_out": True}))
    response.delete_cookie("token")
    return response


@router.get("/lookups/threat-types", tags=["Lookups"])
def list_threat_types(active: bool = True, query: Optional[str] = None, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    warehouse = _hits_to_docs(_search_warehouse_docs(limit=5000))
    datalake = _hits_to_docs(_search_datalake_docs(limit=5000))
    values = []
    for doc in warehouse:
        values.extend(doc.get("ai_threat_types") or [])
        values.extend(doc.get("threat_type") or [])
    for doc in datalake:
        values.extend(doc.get("threat_type") or [])
    items = _lookup_items(values)
    if query:
        items = [item for item in items if query.lower() in item["label"].lower()]
    return _success({"items": items})


@router.get("/lookups/severities", tags=["Lookups"])
def list_severities(active: bool = True, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    items = [{"value": item["value"], "label": item["label"], "description": None, "active": active} for item in RISK_LEVELS]
    return _success({"items": items})


@router.get("/lookups/risk-levels", tags=["Lookups"])
def list_risk_levels(active: bool = True, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    items = [{"value": item["value"], "label": item["label"], "description": None, "active": active} for item in RISK_LEVELS]
    return _success({"items": items})


@router.get("/lookups/sources", tags=["Lookups"])
def list_sources(active: bool = True, query: Optional[str] = None, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    warehouse = _hits_to_docs(_search_warehouse_docs(limit=5000))
    datalake = _hits_to_docs(_search_datalake_docs(limit=5000))
    values = []
    for doc in warehouse + datalake:
        values.extend(_normalize_sources(doc))
    items = _lookup_items(values)
    if query:
        items = [item for item in items if query.lower() in item["label"].lower()]
    return _success({"items": items})


@router.get("/lookups/export-formats", tags=["Lookups"])
def list_export_formats(current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    items = [{"value": item["value"], "label": item["label"], "description": None, "active": True} for item in EXPORT_FORMATS]
    return _success({"items": items})


@router.get("/lookups/assignees", tags=["Lookups"])
def list_assignees(query: Optional[str] = None, status: Optional[str] = None, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    items = get_dashboard_state().list_assignees(query=query, status=status)
    return _success({"items": items})


@router.get("/lookups/enforcement-points", tags=["Lookups"])
def list_enforcement_points(query: Optional[str] = None, type: Optional[str] = None, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    items = get_dashboard_state().list_enforcement_points(query=query, kind=type)
    return _success({"items": items})


@router.get("/executive/dashboard", tags=["Executive"])
def executive_dashboard(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    now = _resolve_anchor_end(end_date)
    if not end_date:
        end_date = _to_bangkok_date(now)
    if not start_date:
        start_date = _to_bangkok_date(now - timedelta(hours=24))

    visible_docs = _hits_to_docs(_search_warehouse_docs(start_date=start_date, end_date=end_date, sort_by="time", limit=5000))
    active_ioc_docs = _collect_ioc_docs(start_date=start_date, end_date=end_date, sort_by="time")
    visible_datalake_docs = _hits_to_docs(_search_datalake_docs(start_date=start_date, end_date=end_date, limit=5000))
    threat_level_docs = _hits_to_docs(_search_warehouse_docs(start_date=_to_bangkok_date(now - timedelta(days=14)), end_date=end_date, sort_by="time", limit=5000))
    previous_start_date, previous_end_date = _previous_date_window(start_date, end_date)
    previous_visible_docs = (
        _hits_to_docs(_search_warehouse_docs(start_date=previous_start_date, end_date=previous_end_date, sort_by="time", limit=5000))
        if previous_start_date and previous_end_date
        else []
    )
    previous_active_ioc_docs = (
        _collect_ioc_docs(start_date=previous_start_date, end_date=previous_end_date, sort_by="time")
        if previous_start_date and previous_end_date
        else []
    )
    severity_distribution = _build_severity_distribution(visible_docs)
    treemap_nodes = _build_threat_volume_nodes(visible_docs)
    threat_level = _build_threat_level(threat_level_docs, now=now)
    primary_sector = threat_level["top_sectors"][0] if threat_level["top_sectors"] else {"sector_name": "General/Multiple"}
    attack_origin_map = _build_attack_origin_map(visible_docs, visible_datalake_docs)
    attack_volume_trend = _build_executive_attack_volume_trend(visible_docs, now=now, start_date=start_date, end_date=end_date)
    payload = {
        "threat_level": {
            "date": threat_level["date"],
            "level": threat_level["level"],
            "level_th": threat_level["level_th"],
            "score": threat_level["score"],
            "delta_percent": round(threat_level["inputs"]["spike_ratio"] * 10, 2),
            "primary_sector": {
                "name": primary_sector.get("sector_name", "General/Multiple"),
                "value": primary_sector.get("count", 0),
            },
        },
        "exposure_today": _build_exposure_summary(
            visible_docs,
            active_ioc_docs,
            previous_visible_docs=previous_visible_docs,
            previous_active_docs=previous_active_ioc_docs,
        ),
        "severity_distribution": severity_distribution,
        "threat_volume_severity": {"nodes": treemap_nodes},
        "attack_volume_trend": attack_volume_trend,
        "attack_origin_map": attack_origin_map,
    }
    return _success(payload)


@router.post("/reports/executive/preview", tags=["Reports"])
def executive_report_preview(request: ExecutiveReportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = executive_dashboard(
        start_date=request.start_date.isoformat(),
        end_date=request.end_date.isoformat(),
        current_user=current_user,
    )["data"]
    payload["filters"] = {
        "start_date": request.start_date.isoformat(),
        "end_date": request.end_date.isoformat(),
        "threat_types": request.threat_types,
        "sources": request.sources,
        "severities": request.severities,
    }
    return _success(payload)


@router.post("/reports/executive/export", tags=["Reports"], status_code=202)
def executive_report_export(request: ExportReportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    job = _queue_export_job(
        request.export_format,
        "executive-dashboard",
        "executive-dashboard",
        {
            "start_date": request.start_date.isoformat(),
            "end_date": request.end_date.isoformat(),
            "threat_types": request.threat_types,
            "sources": request.sources,
            "severities": request.severities,
        },
    )
    return _success(job)


@router.get("/operations/dashboard", tags=["Operations"])
def operations_dashboard(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    anchor_end = _resolve_anchor_end(end_date) if end_date else None
    docs = _hits_to_docs(_search_warehouse_docs(start_date=start_date, end_date=end_date, sort_by="time", limit=5000))
    heatmap_docs = _collect_ioc_docs(start_date=start_date, end_date=end_date, sort_by="time")
    datalake_docs = _hits_to_docs(_search_datalake_docs(start_date=start_date, end_date=end_date, limit=5000))
    source_counts = Counter(source for doc in docs for source in _normalize_sources(doc))
    threat_counts = Counter(threat for doc in docs for threat in (doc.get("ai_threat_types") or doc.get("threat_type") or []))
    country_counts = Counter(country for country in (_country_from_doc(doc) for doc in datalake_docs + docs) if country)
    sector_counts = Counter(_sector_info(doc)["sector_name_th"] for doc in docs)
    payload = {
        "overview": _operations_overview(docs, anchor_end=anchor_end),
        "incident_by_severity": _build_severity_distribution(docs),
        "attack_time_heatmap": _build_heatmap(heatmap_docs),
        "top_intelligence_sources": _build_top_list(source_counts),
        "top_threat_types": _build_top_list(threat_counts),
        "top_attack_origins": _build_top_list(country_counts),
        "target_sectors": _build_top_list(sector_counts),
    }
    return _success(payload)


@router.get("/operations/reports/{report_key}", tags=["Operations"])
def operations_report(
    report_key: str,
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    threat_types: Optional[List[str]] = Query(default=None),
    sources: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    normalized_key = _normalize_report_key(report_key)
    docs = _hits_to_docs(_search_warehouse_docs(start_date=start_date, end_date=end_date, sort_by="time", limit=5000))
    docs = _filter_warehouse_docs(docs, query=query, threat_types=threat_types, sources=sources, severities=severities)
    datalake_docs = _fetch_datalake_by_indicators([(doc.get("ioc_type", ""), doc.get("ioc_value", "")) for doc in docs], limit=5000)
    trend = _build_trend_analytics(docs, datalake_docs)
    chart_key = {
        "intelligence-sources": "sources",
        "threat-types": "threat_types",
        "attack-origins": "countries",
        "target-sectors": "sectors",
    }[normalized_key]
    chart = trend["comparison_charts"][chart_key]
    datalake_lookup: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for doc in datalake_docs:
        datalake_lookup[_indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", ""))].append(doc)
    ranking_items, top_chart, severity_rows = _build_report_ranking(normalized_key, docs, datalake_lookup, chart)
    payload = {
        "report_key": normalized_key,
        "title": normalized_key.replace("-", " ").title(),
        "summary": {
            "total_groups": len(ranking_items),
            "total_events": len(docs),
            "date_range": {"start_date": start_date, "end_date": end_date},
        },
        "filters": {
            "query": query,
            "threat_types": threat_types or [],
            "sources": sources or [],
            "severities": severities or [],
        },
        "top_chart": top_chart,
        "severity_distribution": {"rows": severity_rows},
        "trend_comparison": chart,
        "ranking": {
            "items": _page_slice(ranking_items, page, page_size),
            "total": len(ranking_items),
            "page": page,
            "page_size": page_size,
        },
    }
    return _success(payload)


@router.post("/reports/operations/{report_key}/preview", tags=["Reports"])
def operations_report_preview(report_key: str, request: OperationsReportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = operations_report(
        report_key=report_key,
        page=request.page,
        page_size=request.page_size,
        query=request.query,
        start_date=request.start_date.isoformat(),
        end_date=request.end_date.isoformat(),
        threat_types=request.threat_types or None,
        sources=request.sources or None,
        severities=request.severities or None,
        current_user=current_user,
    )["data"]
    return _success(payload)


@router.post("/reports/operations/attack-time/export", tags=["Reports"], status_code=202)
def attack_time_report_export(request: AttackTimeExportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    job = _queue_export_job(
        request.export_format,
        "operations-attack-time",
        "operations-attack-time",
        {
            "query": request.query,
            "start_date": request.start_date.isoformat(),
            "end_date": request.end_date.isoformat(),
            "threat_types": request.threat_types,
            "sources": request.sources,
            "severities": request.severities,
            "page": request.page,
            "page_size": request.page_size,
        },
    )
    return _success(job)


@router.post("/reports/operations/{report_key}/export", tags=["Reports"], status_code=202)
def operations_report_export(report_key: str, request: ExportReportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    normalized_key = _normalize_report_key(report_key)
    job = _queue_export_job(
        request.export_format,
        f"operations-{normalized_key}",
        f"operations-{normalized_key}",
        {
            "start_date": request.start_date.isoformat(),
            "end_date": request.end_date.isoformat(),
            "threat_types": request.threat_types,
            "sources": request.sources,
            "severities": request.severities,
        },
    )
    return _success(job)


@router.post("/reports/threat-intelligence/export", tags=["Reports"], status_code=202)
def threat_intelligence_report_export(request: ThreatIntelligenceExportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    section = str(request.section or "").strip().lower()
    if section not in {"overview", "ioc"}:
        raise HTTPException(status_code=400, detail="Unsupported threat intelligence export section")
    job = _queue_export_job(
        request.export_format,
        f"threat-intelligence-{section}",
        f"threat-intelligence-{section}",
        {
            "section": section,
            "start_date": request.start_date.isoformat(),
            "end_date": request.end_date.isoformat(),
        },
    )
    return _success(job)


@router.get("/operations/attack-time-report", tags=["Operations"])
def attack_time_report(
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    threat_types: Optional[List[str]] = Query(default=None),
    sources: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    events = _hits_to_docs(
        _search_datalake_docs(
            query_text=query or "*",
            start_date=start_date,
            end_date=end_date,
            threat_types=threat_types,
            sources=sources,
            severities=severities,
            limit=2000,
        )
    )
    heatmap = _build_heatmap(events)
    by_day_hour = Counter()
    for event in events:
        event_time = _pick_event_time(event)
        if not event_time:
            continue
        local = event_time.astimezone(BANGKOK_TZ)
        by_day_hour[(local.strftime("%A"), local.hour)] += 1
    peak = max(by_day_hour.items(), key=lambda item: item[1])[0] if by_day_hour else ("Monday", 0)
    quiet = min(by_day_hour.items(), key=lambda item: item[1])[0] if by_day_hour else ("Sunday", 3)
    paged_items = []
    sorted_events = sorted(events, key=lambda item: _pick_event_time(item) or datetime.min.replace(tzinfo=UTC), reverse=True)
    for event in _page_slice(sorted_events, page, page_size):
        timestamp = _pick_event_time(event)
        paged_items.append(
            {
                "event_id": event["_id"],
                "timestamp": (timestamp or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
                "severity": _severity_label(_normalize_severity(event.get("severity"))),
                "threat_types": event.get("threat_type") or [],
                "ioc_value": event.get("ioc_value"),
                "source_attacker": event.get("source_ip"),
                "target_victim": event.get("target_ip"),
                "source_name": event.get("source_name") or "unknown",
                "description": event.get("description"),
            }
        )
    payload = {
        "summary": {
            "peak_attack_time": {"day": peak[0], "time_range": f"{peak[1]:02d}:00 - {min(23, peak[1] + 2):02d}:00"},
            "quietest_period": {"day": quiet[0], "time_range": f"{quiet[1]:02d}:00 - {min(23, quiet[1] + 2):02d}:00"},
            "avg_attack_rate": round(len(events) / max(len({item.get('event_time') for item in events if item.get('event_time')}), 1), 2),
            "highest_day": peak[0],
            "total_events": len(events),
        },
        "filters": {
            "query": query,
            "start_date": start_date,
            "end_date": end_date,
            "threat_types": threat_types or [],
            "sources": sources or [],
            "severities": severities or [],
        },
        "heatmap": heatmap,
        "events": {"items": paged_items, "total": len(sorted_events)},
    }
    return _paged(payload, page=page, page_size=page_size, total=len(sorted_events))


@router.get("/operations/events/{event_id}", tags=["Operations"])
def operation_event_detail(event_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    client = get_elastic_client()
    document = client.get_index_document(client.datalake_index, event_id)
    if not document:
        raise HTTPException(status_code=404, detail="Event not found")
    timestamp = _pick_event_time(document)
    payload = {
        "event_id": event_id,
        "formatted": {
            "event_id": event_id,
            "timestamp": (timestamp or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
            "severity": _severity_label(_normalize_severity(document.get("severity"))),
            "threat_types": document.get("threat_type") or [],
            "ioc_value": document.get("ioc_value"),
            "source_attacker": document.get("source_ip"),
            "target_victim": document.get("target_ip"),
            "source_name": document.get("source_name") or "unknown",
            "description": document.get("description"),
        },
        "raw_json": document,
    }
    return _success(payload)


@router.get("/actions", tags=["Actions"])
def list_actions(
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    threat_types: Optional[List[str]] = Query(default=None),
    sources: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    status: Optional[List[str]] = Query(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    docs = _search_action_docs(
        query_text=query or "*",
        start_date=start_date,
        end_date=end_date,
        threat_types=threat_types,
        sources=sources,
        severities=severities,
        limit=2000,
    )
    state = get_dashboard_state()
    action_pairs = [(doc, _build_action_ticket(doc, state.get_action_assignment(doc["_id"]))) for doc in docs]
    if status:
        requested_statuses = {item.strip().lower() for item in status if str(item).strip()}
        action_pairs = [(doc, item) for doc, item in action_pairs if item["status"] in requested_statuses]
    filtered_docs = [doc for doc, _ in action_pairs]
    items = [item for _, item in action_pairs]
    facets = {
        "threat_types": [{"value": key, "label": key, "count": value} for key, value in Counter(threat for doc in filtered_docs for threat in (doc.get("ai_threat_types") or [])).most_common(10)],
        "sources": [{"value": key, "label": key, "count": value} for key, value in Counter(source for doc in filtered_docs for source in _normalize_sources(doc)).most_common(10)],
        "severities": [{"value": key, "label": _severity_label(key), "count": value} for key, value in Counter(_normalize_severity(doc.get("ai_severity") or doc.get("severity")) for doc in filtered_docs).most_common(5)],
        "statuses": [{"value": key, "label": key.replace("_", " ").title(), "count": value} for key, value in Counter(item["status"] for item in items).most_common()],
    }
    summary = {
        "total": len(items),
        "open": sum(1 for item in items if item["status"] == "open"),
        "in_progress": sum(1 for item in items if item["status"] == "in_progress"),
        "closed": sum(1 for item in items if item["status"] == "closed"),
    }
    paged_items = _page_slice(items, page, page_size)
    return _paged({"summary": summary, "facets": facets, "items": paged_items}, page=page, page_size=page_size, total=len(items))


@router.post("/reports/actions/preview", tags=["Reports"])
def action_report_preview(request: ActionReportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = list_actions(
        page=1,
        page_size=200,
        query=request.query,
        start_date=request.start_date.isoformat() if request.start_date else None,
        end_date=request.end_date.isoformat() if request.end_date else None,
        threat_types=request.threat_types or None,
        sources=request.sources or None,
        severities=request.severities or None,
        status=request.statuses or None,
        current_user=current_user,
    )["data"]
    return _success(payload)


@router.post("/reports/actions/export", tags=["Reports"], status_code=202)
def action_report_export(request: ActionReportRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    export_format = request.export_format or "csv"
    job = _queue_export_job(
        export_format,
        "actions",
        "actions",
        {
            "query": request.query,
            "start_date": request.start_date.isoformat() if request.start_date else None,
            "end_date": request.end_date.isoformat() if request.end_date else None,
            "threat_types": request.threat_types,
            "sources": request.sources,
            "severities": request.severities,
            "statuses": request.statuses,
        },
    )
    return _success(job)


@router.get("/actions/{action_id}", tags=["Actions"])
def action_detail(action_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    doc = _get_processed_doc(action_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Action not found")
    return _success(_build_action_detail(doc))


@router.get("/actions/{action_id}/related-iocs", tags=["Actions"])
def related_iocs(action_id: str, page: int = 1, page_size: int = 20, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    doc = _get_processed_doc(action_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Action not found")
    threat_types = doc.get("ai_threat_types") or []
    warehouse_docs = _hits_to_docs(_search_warehouse_docs(threat_types=threat_types, limit=500))
    related = [
        _build_ioc_record(index + 1, item)
        for index, item in enumerate(
            [
                item for item in warehouse_docs
                if _indicator_id(item.get("ioc_type", ""), item.get("ioc_value", "")) != _indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", ""))
            ]
        )
    ]
    return _paged({"items": _page_slice(related, page, page_size)}, page=page, page_size=page_size, total=len(related))


@router.post("/actions/{action_id}/assign", tags=["Actions"])
def assign_action(action_id: str, request: AssignRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    state = get_dashboard_state()
    assignee = next((item for item in state.list_assignees() if item["user_id"] == request.assignee_id), None)
    if not assignee:
        raise HTTPException(status_code=404, detail="Assignee not found")
    state.assign_action(action_id, assignee, request.handover_note or "")
    doc = _get_processed_doc(action_id)
    if doc:
        get_elastic_client().update_warehouse_document(
            action_id,
            {
                "action_required": True,
                "action_status": ACTION_IN_PROGRESS,
                "action_updated_at": _utcnow_z(),
                "action_opened_at": doc.get("action_opened_at") or doc.get("processed_at") or doc.get("event_time"),
            },
        )
    if request.handover_note:
        state.append_action_note(action_id, current_user["name"], request.handover_note)
    return _success({"action_id": action_id, "status": ACTION_IN_PROGRESS, "audit_id": f"audit-{_hash_id(action_id, assignee['user_id'])}", "message": "Action assigned"})


@router.post("/actions/{action_id}/false-positive", tags=["Actions"])
async def mark_false_positive(
    action_id: str,
    reason_category: str = Form(...),
    justification: str = Form(...),
    evidence_file: Optional[UploadFile] = File(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    doc = _get_processed_doc(action_id)
    if doc:
        get_elastic_client().update_warehouse_document(
            action_id,
            {
                "action_required": False,
                "action_status": ACTION_CLOSED,
                "action_closed_reason": "false_positive",
                "action_closed_at": _utcnow_z(),
                "action_updated_at": _utcnow_z(),
            },
        )
    note_content = justification
    if evidence_file is not None:
        note_content = f"{justification} (evidence: {evidence_file.filename})"
    get_dashboard_state().append_action_note(action_id, current_user["name"], note_content)
    return _success({"action_id": action_id, "status": ACTION_CLOSED, "audit_id": f"audit-{_hash_id(action_id, reason_category)}", "message": "Marked as false positive"})


@router.post("/actions/{action_id}/block-ip", tags=["Actions"])
def block_ip(action_id: str, request: BlockIpRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    note = f"Block {request.target_ioc} on {', '.join(request.enforcement_point_ids)} ({request.duration_mode})"
    get_dashboard_state().append_action_note(action_id, current_user["name"], note)
    doc = _get_processed_doc(action_id)
    if doc:
        get_elastic_client().update_warehouse_document(
            action_id,
            {
                "action_required": True,
                "action_status": ACTION_IN_PROGRESS,
                "action_reason": "block_ip",
                "action_updated_at": _utcnow_z(),
                "action_opened_at": doc.get("action_opened_at") or doc.get("processed_at") or doc.get("event_time"),
            },
        )
    return _success(
        {
            "action_id": action_id,
            "status": ACTION_IN_PROGRESS,
            "audit_id": f"audit-{_hash_id(action_id, request.target_ioc)}",
            "message": "Block request queued",
            "execution": {
                "target_ioc": request.target_ioc,
                "enforcement_point_ids": request.enforcement_point_ids,
                "duration_mode": request.duration_mode,
                "duration_days": request.duration_days,
                "reason": request.reason,
            },
        }
    )


@router.get("/iocs", tags=["IOCs"])
def list_iocs(
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = Query(default=None),
    threat_types: Optional[List[str]] = Query(default=None),
    risk_levels: Optional[List[str]] = Query(default=None),
    ioc_types: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    high_risk_only: bool = False,
    sort_by: str = "risk",
    sort_order: str = "desc",
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    docs = _collect_ioc_docs(
        query=query,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        risk_levels=risk_levels,
        ioc_types=ioc_types,
        severities=severities,
        high_risk_only=high_risk_only,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    items = [_build_ioc_record(index + 1, doc) for index, doc in enumerate(docs)]
    facets = {
        "sources": [{"value": key, "label": key, "count": value} for key, value in Counter(source for doc in docs for source in _normalize_sources(doc)).most_common(10)],
        "threat_types": [{"value": key, "label": key, "count": value} for key, value in Counter(threat for doc in docs for threat in (doc.get("ai_threat_types") or doc.get("threat_type") or [])).most_common(10)],
        "risk_levels": [{"value": key, "label": _severity_label(key), "count": value} for key, value in Counter(_normalize_severity(doc.get("ai_severity") or doc.get("severity")) for doc in docs).most_common(5)],
        "ioc_types": [{"value": key, "label": key.upper(), "count": value} for key, value in Counter(str(doc.get("ioc_type", "")).lower() for doc in docs).most_common(10)],
        "severities": [{"value": key, "label": _severity_label(key), "count": value} for key, value in Counter(_normalize_severity(doc.get("ai_severity") or doc.get("severity")) for doc in docs).most_common(5)],
    }
    quick_filters = {
        "ioc_types": [{"value": item["value"], "label": item["label"], "count": next((facet["count"] for facet in facets["ioc_types"] if facet["value"] == item["value"]), 0)} for item in IOC_TYPE_LOOKUPS],
        "severities": [{"value": item["value"], "label": item["label"], "count": next((facet["count"] for facet in facets["severities"] if facet["value"] == item["value"]), 0)} for item in RISK_LEVELS],
    }
    return _paged({"summary": {"total_indicators": len(items)}, "quick_filters": quick_filters, "facets": facets, "items": _page_slice(items, page, page_size)}, page=page, page_size=page_size, total=len(items))


@router.get("/iocs/{ioc_id}", tags=["IOCs"])
def ioc_detail(ioc_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    ioc_type, ioc_value = _split_indicator_id(ioc_id)
    warehouse_doc = _get_warehouse_doc_by_indicator(ioc_type, ioc_value)
    if not warehouse_doc:
        raise HTTPException(status_code=404, detail="IOC not found")
    datalake_docs = _fetch_datalake_by_indicators([(ioc_type, ioc_value)], limit=200)
    return _success(_build_ioc_detail(warehouse_doc, datalake_docs))


@router.get("/iocs/{ioc_id}/events", tags=["IOCs"])
def ioc_events(ioc_id: str, page: int = 1, page_size: int = 20, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    ioc_type, ioc_value = _split_indicator_id(ioc_id)
    docs = sorted(
        _fetch_datalake_by_indicators([(ioc_type, ioc_value)], limit=500),
        key=lambda item: _pick_event_time(item) or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    items = [
        {
            "observed_at": ((_pick_event_time(doc) or datetime.now(UTC)).isoformat().replace("+00:00", "Z")),
            "source": doc.get("source_name") or "unknown",
            "severity": _severity_label(_normalize_severity(doc.get("severity"))),
            "description": doc.get("description") or doc.get("reference") or "-",
        }
        for doc in _page_slice(docs, page, page_size)
    ]
    return _paged({"items": items}, page=page, page_size=page_size, total=len(docs))


@router.get("/ioc-analytics", tags=["IOCs"])
def ioc_analytics(
    tab: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    warehouse_docs = _collect_ioc_docs(start_date=start_date, end_date=end_date)
    datalake_docs = _hits_to_docs(_search_datalake_docs(start_date=start_date, end_date=end_date, limit=5000))
    if tab == "ioc-summary":
        by_type = Counter(str(doc.get("ioc_type", "")).lower() for doc in warehouse_docs)
        by_severity = Counter(_normalize_severity(doc.get("ai_severity") or doc.get("severity")) for doc in warehouse_docs)
        by_source_breakdown: Dict[str, Dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0})
        by_type_breakdown: Dict[str, Dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0})
        for doc in warehouse_docs:
            severity = _normalize_severity(doc.get("ai_severity") or doc.get("severity"))
            for source in _normalize_sources(doc):
                by_source_breakdown[source][severity] += 1
            ioc_type = IOC_TYPE_LABELS.get(str(doc.get("ioc_type", "")).lower(), str(doc.get("ioc_type", "")).upper())
            by_type_breakdown[ioc_type][severity] += 1
        risk_distribution = [
            {"bucket": "0-19", "value": sum(1 for doc in warehouse_docs if int(doc.get("ai_risk_score") or 0) < 20)},
            {"bucket": "20-39", "value": sum(1 for doc in warehouse_docs if 20 <= int(doc.get("ai_risk_score") or 0) < 40)},
            {"bucket": "40-59", "value": sum(1 for doc in warehouse_docs if 40 <= int(doc.get("ai_risk_score") or 0) < 60)},
            {"bucket": "60-79", "value": sum(1 for doc in warehouse_docs if 60 <= int(doc.get("ai_risk_score") or 0) < 80)},
            {"bucket": "80-100", "value": sum(1 for doc in warehouse_docs if int(doc.get("ai_risk_score") or 0) >= 80)},
        ]
        payload = {
            "tab": "ioc-summary",
            "cards": {
                "total_ioc": len(warehouse_docs),
                "clean_ioc": by_severity.get("clean", 0),
                "active_ioc": len(warehouse_docs),
                "risk_ioc": sum(1 for doc in warehouse_docs if int(doc.get("ai_risk_score") or 0) >= 80),
            },
            "charts": {
                "ioc_by_type": [{"key": key, "label": IOC_TYPE_LABELS.get(key, key.upper()), "color": None, "value": value, "percentage": round((value / max(len(warehouse_docs), 1)) * 100, 2)} for key, value in by_type.most_common()],
                "ioc_by_severity": _build_severity_distribution(warehouse_docs),
                "severity_by_source": [{"source": source, **breakdown} for source, breakdown in by_source_breakdown.items()],
                "severity_by_type": [{"type": ioc_type, **breakdown} for ioc_type, breakdown in by_type_breakdown.items()],
                "risk_score_distribution": risk_distribution,
            },
        }
        return _success(payload)

    if tab == "statistics-import":
        by_source = Counter(doc.get("source_name") or "unknown" for doc in datalake_docs)
        by_type = Counter(str(doc.get("ioc_type", "")).lower() for doc in datalake_docs)
        threat_type_distribution = Counter(threat for doc in datalake_docs for threat in (doc.get("threat_type") or []))
        by_severity = Counter(_normalize_severity(doc.get("severity")) for doc in datalake_docs)
        daily_counts: Dict[str, int] = defaultdict(int)
        for doc in datalake_docs:
            timestamp = _pick_event_time(doc)
            if timestamp:
                daily_counts[_to_bangkok_date(timestamp)] += 1
        payload = {
            "tab": "statistics-import",
            "cards": {
                "total_import": len(datalake_docs),
                "successful_import": len(datalake_docs),
                "failed_import": 0,
                "avg_import_per_day": round(sum(daily_counts.values()) / max(len(daily_counts), 1), 2),
            },
            "charts": {
                "import_volume_over_time": {"points": [{"timestamp": day, "value": value} for day, value in sorted(daily_counts.items())]},
                "ioc_by_intelligence_source": [{"key": key, "label": key, "color": None, "value": value, "percentage": round((value / max(len(datalake_docs), 1)) * 100, 2)} for key, value in by_source.most_common()],
                "ioc_by_type": [{"key": key, "label": IOC_TYPE_LABELS.get(key, key.upper()), "color": None, "value": value, "percentage": round((value / max(len(datalake_docs), 1)) * 100, 2)} for key, value in by_type.most_common()],
                "threat_type_distribution": [{"key": key, "label": key, "color": None, "value": value, "percentage": round((value / max(len(datalake_docs), 1)) * 100, 2)} for key, value in threat_type_distribution.most_common()],
                "ioc_by_severity": [{"key": key, "label": _severity_label(key), "color": None, "value": value, "percentage": round((value / max(len(datalake_docs), 1)) * 100, 2)} for key, value in by_severity.most_common()],
                "import_by_source": [{"key": key, "label": key, "value": value} for key, value in by_source.most_common()],
                "import_by_type": [{"key": key, "label": IOC_TYPE_LABELS.get(key, key.upper()), "value": value} for key, value in by_type.most_common()],
                "import_by_severity": [{"key": key, "label": _severity_label(key), "value": value} for key, value in by_severity.most_common()],
            },
        }
        return _success(payload)

    raise HTTPException(status_code=400, detail="Unsupported analytics tab")


@router.post("/reports/ioc/preview", tags=["Reports"])
def ioc_report_preview(request: IOCReportPreviewRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    docs = _collect_ioc_docs(
        start_date=request.start_date.isoformat(),
        end_date=request.end_date.isoformat(),
        threat_types=request.threat_types or None,
        sources=request.sources or None,
        ioc_types=request.ioc_types or None,
        severities=request.severities or None,
    )
    use_page_pagination = "page" in request.model_fields_set or "page_size" in request.model_fields_set
    if use_page_pagination:
        effective_page_size = request.page_size or request.limit
        effective_page = request.page or 1
        effective_limit = effective_page_size
        effective_offset = max(effective_page - 1, 0) * effective_page_size
    else:
        effective_limit = request.limit
        effective_offset = request.offset

    paged_docs = docs[effective_offset: effective_offset + effective_limit]
    items = [
        _build_ioc_record(effective_offset + index + 1, doc)
        for index, doc in enumerate(paged_docs)
    ]
    severity_distribution = _build_severity_distribution(docs)
    source_counts = Counter(source for doc in docs for source in _normalize_sources(doc))
    type_counts = Counter(str(doc.get("ioc_type", "")).lower() for doc in docs)
    payload = {
        "summary": {
            "total_rows": len(docs),
            "generated_for": f"{request.start_date.isoformat()} to {request.end_date.isoformat()}",
            "high_risk_count": sum(1 for doc in docs if _safe_int(doc.get("ai_risk_score")) >= 80),
        },
        "filters": request.model_dump(exclude_none=True),
        "charts": {
            "severity_distribution": severity_distribution,
            "top_sources": _build_top_list(source_counts),
            "top_ioc_types": [
                {
                    "key": key,
                    "label": IOC_TYPE_LABELS.get(key, key.upper()),
                    "value": value,
                    "percentage": _percentage(value, len(docs)),
                    "color": None,
                }
                for key, value in type_counts.most_common()
            ],
        },
        "items": items,
    }
    return _success(payload)


@router.post("/reports/ioc/export", tags=["Reports"], status_code=202)
def ioc_report_export(
    request: IOCExportRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    docs = _collect_ioc_docs(
        query=request.query,
        start_date=request.start_date.isoformat(),
        end_date=request.end_date.isoformat(),
        threat_types=request.threat_types or None,
        sources=request.sources or None,
        risk_levels=request.risk_levels or None,
        ioc_types=request.ioc_types or None,
        severities=request.severities or None,
        high_risk_only=request.high_risk_only,
    )
    items = [_build_ioc_record(index + 1, doc) for index, doc in enumerate(docs)]
    selected_format, file_content, media_type = _build_ioc_export_artifact(items, request.export_format)
    filters = request.model_dump(exclude_none=True)
    filters["export_format"] = selected_format
    job = _queue_export_job(
        selected_format,
        "ioc-report",
        "ioc-report",
        filters,
        file_content=file_content,
        media_type=media_type,
    )
    return _success(_public_export_job(job, http_request))


@router.post("/reports/most-frequent-threats/preview", tags=["Reports"])
def most_frequent_threats_preview(request: MostFrequentThreatsRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    datalake_docs = _hits_to_docs(
        _search_datalake_docs(
            start_date=request.start_date.isoformat(),
            end_date=request.end_date.isoformat(),
            threat_types=request.threat_types or None,
            severities=request.severities or request.risk_levels or None,
            limit=5000,
        )
    )
    grouped: Dict[str, Dict[str, Any]] = {}
    for doc in datalake_docs:
        key = _indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", ""))
        item = grouped.setdefault(
            key,
            {
                "ioc_value": doc.get("ioc_value"),
                "ioc_type": doc.get("ioc_type"),
                "hits": 0,
                "severity": _severity_label(_normalize_severity(doc.get("severity"))),
                "sources": set(),
                "risk_score": 0,
            },
        )
        item["hits"] += 1
        item["sources"].add(doc.get("source_name") or "unknown")
    items = []
    for index, item in enumerate(sorted(grouped.values(), key=lambda current: current["hits"], reverse=True), start=1):
        items.append(
            {
                "rank": index,
                "ioc_value": item["ioc_value"],
                "ioc_type": item["ioc_type"],
                "hits": item["hits"],
                "severity": item["severity"],
                "risk_score": item["risk_score"],
                "sources": sorted(item["sources"]),
            }
        )
    return _success(
        {
            "summary": {
                "total_rows": len(items),
                "start_date": request.start_date.isoformat(),
                "end_date": request.end_date.isoformat(),
            },
            "filters": request.model_dump(),
            "items": items,
        }
    )


@router.get("/exports/{export_id}", tags=["Reports"])
def export_job(export_id: str, request: Request, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    job = get_dashboard_state().get_export_job(export_id)
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")
    return _success(_public_export_job(job, request))


@router.get("/exports/{export_id}/download", tags=["Reports"])
def export_download(export_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    state = get_dashboard_state()
    job = state.get_export_job(export_id)
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")
    export_file = state.get_export_file(export_id)
    if not export_file:
        raise HTTPException(status_code=404, detail="Export file not found")
    headers = {"Content-Disposition": f'attachment; filename="{job["file_name"]}"'}
    return Response(content=export_file["content"], media_type=export_file["media_type"], headers=headers)


@router.get("/news", tags=["News"])
def list_news(
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = Query(default=None),
    sort_by: str = "published_at",
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    docs = _hits_to_docs(_search_datalake_docs(query_text=query or "*", start_date=start_date, end_date=end_date, sources=sources, limit=5000))
    items = _build_news_articles(docs, query_text=query, sources=sources)
    if sort_by == "title":
        items = sorted(items, key=lambda item: str(item.get("title") or "").lower())
    elif sort_by == "source":
        items = sorted(
            items,
            key=lambda item: (
                str(item.get("source") or "").lower(),
                _parse_dt(item.get("published_at")) or datetime.min.replace(tzinfo=UTC),
            ),
            reverse=True,
        )
    else:
        items = sorted(
            items,
            key=lambda item: _parse_dt(item.get("published_at")) or datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )
    return _paged({"items": _page_slice(items, page, page_size)}, page=page, page_size=page_size, total=len(items))


@router.get("/news/{article_id}", tags=["News"])
def news_detail(
    article_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    docs = _hits_to_docs(_search_datalake_docs(start_date=start_date, end_date=end_date, limit=5000))
    articles = {item["article_id"]: item for item in _build_news_articles(docs)}
    article = articles.get(article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    related_ioc_records = []
    for ioc_value in article.get("related_iocs") or []:
        warehouse_doc = next(
            (
                doc for doc in _hits_to_docs(_search_warehouse_docs(query_text=ioc_value, limit=20))
                if str(doc.get("ioc_value")) == ioc_value
            ),
            None,
        )
        if warehouse_doc:
            related_ioc_records.append(_build_ioc_record(len(related_ioc_records) + 1, warehouse_doc))
    payload = {
        **article,
        "content_excerpt": (article.get("snippets") or [article.get("summary")])[0],
        "related_ioc_records": related_ioc_records,
    }
    return _success(payload)


@router.get("/account/profile", tags=["Account"])
def get_profile(current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    profile = get_dashboard_state().profile(current_user["user_id"])
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _success(profile)


@router.patch("/account/profile", tags=["Account"])
def update_profile(request: ProfileUpdateRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    profile = get_dashboard_state().update_profile(current_user["user_id"], request.model_dump(exclude_none=True))
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _success(profile)


@router.post("/account/password/reset", tags=["Account"])
def reset_password(request: PasswordResetRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    state = get_dashboard_state()
    if request.reset_mode == "user_change":
        if not request.current_password:
            raise HTTPException(status_code=400, detail="current_password is required for user_change mode")
        if not state.verify_password(current_user["user_id"], request.current_password):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
    updated = state.reset_password(current_user["user_id"], request.new_password)
    if not updated:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _success({"success": True, "message": "Password reset completed"})


@router.delete("/account", tags=["Account"])
def delete_account(request: DeleteAccountRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    if request.confirmation_text.strip().lower() not in {"delete my user account", "delete"}:
        raise HTTPException(status_code=400, detail="Confirmation text mismatch")
    deleted = get_dashboard_state().delete_user(current_user["user_id"])
    if not deleted:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _success({"success": True, "message": "Account deleted"})


@router.get("/users", tags=["Users"])
def list_users(
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    status: Optional[str] = None,
    group_ids: Optional[List[str]] = Query(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    items = get_dashboard_state().list_users()
    if query:
        items = [item for item in items if query.lower() in f"{item['name']} {item['email']}".lower()]
    if status:
        items = [item for item in items if str(item["status"]).lower() == status.lower()]
    if group_ids:
        items = [item for item in items if item.get("group_id") in group_ids]
    return _paged({"items": _page_slice(items, page, page_size)}, page=page, page_size=page_size, total=len(items))


@router.post("/users", tags=["Users"], status_code=201)
def create_user(request: UserCreateRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = get_dashboard_state().create_user(request.model_dump())
    return _success(payload)


@router.patch("/users/{user_id}", tags=["Users"])
def update_user(user_id: str, request: UserUpdateRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = get_dashboard_state().update_user(user_id, request.model_dump(exclude_none=True))
    if not payload:
        raise HTTPException(status_code=404, detail="User not found")
    return _success(payload)


@router.delete("/users/{user_id}", tags=["Users"])
def delete_user(user_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    deleted = get_dashboard_state().delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    return _success({"success": True, "message": "User deleted"})


@router.get("/user-groups", tags=["Users"])
def list_user_groups(page: int = 1, page_size: int = 20, query: Optional[str] = None, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    items = get_dashboard_state().list_groups()
    if query:
        items = [item for item in items if query.lower() in item["name"].lower()]
    users = get_dashboard_state().list_users()
    member_counts = Counter(user.get("group_id") for user in users)
    items = [{**item, "member_count": member_counts.get(item.get("group_id"), 0)} for item in items]
    return _paged({"items": _page_slice(items, page, page_size)}, page=page, page_size=page_size, total=len(items))


@router.post("/user-groups", tags=["Users"], status_code=201)
def create_user_group(request: UserGroupCreateRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = get_dashboard_state().create_group({"name": request.name, "permissions": [item.model_dump() for item in request.permissions]})
    return _success(payload)


@router.patch("/user-groups/{group_id}", tags=["Users"])
def update_user_group(group_id: str, request: UserGroupUpdateRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = {
        key: value
        for key, value in request.model_dump(exclude_none=True).items()
        if value is not None
    }
    if "permissions" in payload:
        payload["permissions"] = [item for item in payload["permissions"]]
    group = get_dashboard_state().update_group(group_id, payload)
    if not group:
        raise HTTPException(status_code=404, detail="User group not found")
    return _success(group)


@router.delete("/user-groups/{group_id}", tags=["Users"])
def delete_user_group(group_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    deleted = get_dashboard_state().delete_group(group_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User group not found")
    return _success({"success": True, "message": "User group deleted"})


@router.get("/notifications", tags=["Notifications"])
def list_notifications(
    page: int = 1,
    page_size: int = 20,
    unread_only: bool = False,
    type: Optional[str] = None,
    status: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    items = get_dashboard_state().list_notifications()
    if unread_only:
        items = [item for item in items if item.get("unread")]
    if type:
        items = [item for item in items if item.get("type") == type]
    if status:
        normalized_status = status.lower()
        if normalized_status == "unread":
            items = [item for item in items if item.get("unread")]
        elif normalized_status == "read":
            items = [item for item in items if not item.get("unread")]
    items = sorted(items, key=lambda item: item.get("created_at") or "", reverse=True)
    unread_count = sum(1 for item in items if item.get("unread"))
    return _paged({"unread_count": unread_count, "items": _page_slice(items, page, page_size)}, page=page, page_size=page_size, total=len(items))


@router.post("/notifications/{notification_id}/read", tags=["Notifications"])
def mark_notification_read(notification_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    payload = get_dashboard_state().mark_notification_read(notification_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Notification not found")
    return _success(payload)


@router.post("/notifications/read-all", tags=["Notifications"])
def mark_all_notifications_read(payload: Optional[BulkNotificationReadRequest] = Body(default=None), current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    notification_type = payload.type if payload else None
    result = get_dashboard_state().mark_all_notifications_read(notification_type=notification_type)
    return _success(result)
