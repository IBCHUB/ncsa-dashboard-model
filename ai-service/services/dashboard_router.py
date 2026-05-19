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
import hmac
import ipaddress
import io
import json
import logging
from math import floor
import os
import re
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo
import zipfile
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, Body, Depends, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from config import NEWS_SOURCES
from elastic_client import get_elastic_client
from models.actions import ACTION_CLOSED, ACTION_IN_PROGRESS, ACTION_OPEN, derive_action_metadata
from models.forecaster import guarded_holt_winters_forecast
from services.dashboard_bootstrap import get_dashboard_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

BANGKOK_TZ = ZoneInfo("Asia/Bangkok")
UTC = timezone.utc
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "clean": 0}

# ---------------------------------------------------------------------------
# Time-mode constants: each mode selects the semantically correct date fields
# ---------------------------------------------------------------------------
TIME_MODE_OBSERVED = "observed"
TIME_MODE_PROCESSED = "processed"
TIME_MODE_PUBLISHED = "published"
TIME_MODE_CHANGED = "changed"

WAREHOUSE_TIME_FIELDS: dict[str, list[str]] = {
    "observed": ["event_time", "first_seen", "last_seen"],
    "processed": ["processed_at", "created_at", "collect_time"],
    "published": ["published_at"],
    "changed": ["revoked_at", "last_shared_at", "updated_at"],
}

DATALAKE_TIME_FIELDS: dict[str, list[str]] = {
    "observed": ["observation_date", "first_seen"],
    "processed": ["@timestamp", "processed_at"],
    "published": ["published_at"],
    "changed": [],
}

PYTHON_FILTER_FIELDS: dict[str, list[str]] = {
    "observed": ["event_time", "first_seen", "last_seen", "observation_date"],
    "processed": ["processed_at", "created_at", "collect_time"],
    "published": ["published_at"],
    "changed": ["revoked_at", "last_shared_at", "updated_at"],
}
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
DASHBOARD_CACHE_TTL_SECONDS = int(os.getenv("DASHBOARD_CACHE_TTL_SECONDS", "120"))
_DASHBOARD_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_DASHBOARD_CACHE_LOCK = threading.Lock()
COUNTRY_CODE_MAP = {
    "afghanistan": "AF", "albania": "AL", "algeria": "DZ", "argentina": "AR",
    "armenia": "AM", "australia": "AU", "austria": "AT", "azerbaijan": "AZ",
    "bahrain": "BH", "bangladesh": "BD", "belarus": "BY", "belgium": "BE",
    "bolivia": "BO", "bosnia and herzegovina": "BA", "brazil": "BR",
    "brunei": "BN", "bulgaria": "BG", "cambodia": "KH", "cameroon": "CM",
    "canada": "CA", "chile": "CL", "china": "CN", "colombia": "CO",
    "costa rica": "CR", "croatia": "HR", "cuba": "CU", "cyprus": "CY",
    "czech republic": "CZ", "czechia": "CZ", "denmark": "DK",
    "dominican republic": "DO", "ecuador": "EC", "egypt": "EG",
    "el salvador": "SV", "estonia": "EE", "ethiopia": "ET", "finland": "FI",
    "france": "FR", "georgia": "GE", "germany": "DE", "ghana": "GH",
    "greece": "GR", "guatemala": "GT", "honduras": "HN", "hong kong": "HK",
    "hungary": "HU", "iceland": "IS", "india": "IN", "indonesia": "ID",
    "iran": "IR", "iraq": "IQ", "ireland": "IE", "israel": "IL",
    "italy": "IT", "jamaica": "JM", "japan": "JP", "jordan": "JO",
    "kazakhstan": "KZ", "kenya": "KE", "kuwait": "KW", "kyrgyzstan": "KG",
    "laos": "LA", "latvia": "LV", "lebanon": "LB", "libya": "LY",
    "lithuania": "LT", "luxembourg": "LU", "macau": "MO", "malaysia": "MY",
    "maldives": "MV", "malta": "MT", "mexico": "MX", "moldova": "MD",
    "mongolia": "MN", "montenegro": "ME", "morocco": "MA", "mozambique": "MZ",
    "myanmar": "MM", "nepal": "NP", "netherlands": "NL", "new zealand": "NZ",
    "nicaragua": "NI", "nigeria": "NG", "north korea": "KP",
    "north macedonia": "MK", "norway": "NO", "oman": "OM", "pakistan": "PK",
    "palestine": "PS", "panama": "PA", "paraguay": "PY", "peru": "PE",
    "philippines": "PH", "poland": "PL", "portugal": "PT", "qatar": "QA",
    "romania": "RO", "russia": "RU", "russian federation": "RU",
    "saudi arabia": "SA", "senegal": "SN", "serbia": "RS", "singapore": "SG",
    "slovakia": "SK", "slovenia": "SI", "south africa": "ZA",
    "south korea": "KR", "spain": "ES", "sri lanka": "LK", "sudan": "SD",
    "sweden": "SE", "switzerland": "CH", "syria": "SY", "taiwan": "TW",
    "tajikistan": "TJ", "tanzania": "TZ", "thailand": "TH", "tunisia": "TN",
    "turkey": "TR", "turkmenistan": "TM", "uganda": "UG", "ukraine": "UA",
    "united arab emirates": "AE", "united kingdom": "GB", "united states": "US",
    "uruguay": "UY", "uzbekistan": "UZ", "venezuela": "VE", "vietnam": "VN",
    "yemen": "YE", "zambia": "ZM", "zimbabwe": "ZW",
}
HIGH_CONFIDENCE_SOURCE_NAMES = {
    "VirusTotal",
    "AbuseIPDB",
    "ThreatFox",
    "URLhaus",
    "MalwareBazaar",
    "Recorded Future",
    "Cyberint",
    "cyberint_iocs",
    "Cyble Threat Intelligence Feed",
    "AlienVault",
    "MITRE",
    "Sandbox",
    "Suricata",
    "Snort",
}
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _is_high_confidence_source(source_name: Any) -> bool:
    source = str(source_name or "").strip()
    if not source:
        return False
    normalized = source.lower()
    return (
        source in HIGH_CONFIDENCE_SOURCE_NAMES
        or normalized in {item.lower() for item in HIGH_CONFIDENCE_SOURCE_NAMES}
        or normalized.startswith("cyberint")
        or "cyble threat intelligence" in normalized
    )


class LoginRequest(BaseModel):
    username: str
    password: str


class SSOExchangeRequest(BaseModel):
    sso_id: Optional[str] = None
    id: Optional[str] = None
    sub: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    display_name: Optional[str] = None
    phone: Optional[str] = None
    phone_number: Optional[str] = None
    pid: Optional[str] = None
    national_id: Optional[str] = None
    role: Optional[str] = None
    role_name: Optional[str] = None
    user_group: Optional[str] = None
    group_id: Optional[str] = None
    avatar_url: Optional[str] = None


class AssignRequest(BaseModel):
    assignee_id: str
    handover_note: Optional[str] = None


class BlockIpRequest(BaseModel):
    target_ioc: str
    enforcement_point_ids: List[str]
    duration_mode: str
    duration_days: Optional[int] = None
    reason: str


class ActionNoteRequest(BaseModel):
    content: str = Field(..., min_length=1)


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


class MLFeedbackRequest(BaseModel):
    warehouse_doc_id: Optional[str] = None
    ioc_type: str = Field(..., min_length=1)
    ioc_value: str = Field(..., min_length=1)
    current_labels: List[str] = Field(default_factory=list)
    expected_labels: List[str] = Field(default_factory=list)
    feedback_type: str = Field(default="wrong_label", pattern="^(wrong_label|missing_label|false_positive|false_negative|other)$")
    note: Optional[str] = None
    source: str = "dashboard"


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


def _cache_key(name: str, **params: Any) -> str:
    return json.dumps({"name": name, "params": params}, sort_keys=True, default=str, ensure_ascii=True)


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    if DASHBOARD_CACHE_TTL_SECONDS <= 0:
        return None
    now = time.monotonic()
    with _DASHBOARD_CACHE_LOCK:
        cached = _DASHBOARD_CACHE.get(key)
        if not cached:
            return None
        expires_at, payload = cached
        if expires_at <= now:
            _DASHBOARD_CACHE.pop(key, None)
            return None
        return payload


def _cache_set(key: str, payload: Dict[str, Any], ttl: Optional[int] = None) -> Dict[str, Any]:
    effective_ttl = DASHBOARD_CACHE_TTL_SECONDS if ttl is None else ttl
    if effective_ttl > 0:
        with _DASHBOARD_CACHE_LOCK:
            _DASHBOARD_CACHE[key] = (time.monotonic() + effective_ttl, payload)
            if len(_DASHBOARD_CACHE) > 512:
                oldest_keys = sorted(_DASHBOARD_CACHE, key=lambda item: _DASHBOARD_CACHE[item][0])[:128]
                for old_key in oldest_keys:
                    _DASHBOARD_CACHE.pop(old_key, None)
    return payload


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


def _source_severity(doc: Dict[str, Any]) -> str:
    return _normalize_severity(doc.get("severity"))


def _ai_severity(doc: Dict[str, Any]) -> str:
    return _normalize_severity(doc.get("ai_severity") or doc.get("severity"))


def _severity_label(value: str) -> str:
    return value.capitalize() if value else "Low"


def _highest_severity_from_buckets(buckets: Sequence[Dict[str, Any]]) -> str:
    highest = "clean"
    for bucket in buckets:
        if int(bucket.get("doc_count") or 0) <= 0:
            continue
        severity = _normalize_severity(bucket.get("key"))
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity
    return _severity_label(highest)


def _pick_activity_time(doc: Dict[str, Any]) -> Optional[datetime]:
    return _parse_dt(
        doc.get("last_seen")
        or doc.get("event_time")
        or doc.get("observation_date")
        or doc.get("collect_time")
        or doc.get("processed_at")
        or doc.get("first_seen")
        or doc.get("@timestamp")
        or doc.get("created_at")
    )


def _pick_event_time(doc: Dict[str, Any]) -> Optional[datetime]:
    return _parse_dt(doc.get("event_time") or doc.get("observation_date") or doc.get("first_seen") or doc.get("@timestamp") or doc.get("collect_time") or doc.get("processed_at") or doc.get("created_at"))


def _pick_display_time(doc: Dict[str, Any], time_mode: str = "processed") -> Optional[datetime]:
    """Mode-aware timestamp for display — matches the filter semantics so users see consistent data."""
    fields = PYTHON_FILTER_FIELDS.get(time_mode, PYTHON_FILTER_FIELDS["processed"])
    for field in fields:
        result = _parse_dt(doc.get(field))
        if result:
            return result
    return _pick_event_time(doc)


def _pick_display_time_in_range(
    doc: Dict[str, Any],
    time_mode: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Optional[datetime]:
    """Prefer the timestamp that actually made the record match the selected range."""
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    fields = PYTHON_FILTER_FIELDS.get(time_mode, PYTHON_FILTER_FIELDS["processed"])
    if start_bound or end_bound:
        for field in fields:
            result = _parse_dt(doc.get(field))
            if result is None:
                continue
            if start_bound and result < start_bound:
                continue
            if end_bound and result > end_bound:
                continue
            return result
    return _pick_display_time(doc, time_mode)


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
    if not range_query or not fields:
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


SECTOR_DISPLAY_NAMES = {
    "national security": "National Security",
    "security": "National Security",
    "ความมั่นคงของรัฐ": "National Security",
    "ด้านความมั่นคงของรัฐ": "National Security",
    "government": "Essential Government Services",
    "public service": "Essential Government Services",
    "public services": "Essential Government Services",
    "essential government services": "Essential Government Services",
    "ภาครัฐ": "Essential Government Services",
    "บริการภาครัฐ": "Essential Government Services",
    "บริการภาครัฐที่สำคัญ": "Essential Government Services",
    "ด้านบริการภาครัฐที่สำคัญ": "Essential Government Services",
    "finance": "Finance and Banking",
    "financial": "Finance and Banking",
    "financial services": "Finance and Banking",
    "banking": "Finance and Banking",
    "finance and banking": "Finance and Banking",
    "ภาคการเงิน": "Finance and Banking",
    "การเงิน": "Finance and Banking",
    "การเงินการธนาคาร": "Finance and Banking",
    "ด้านการเงินการธนาคาร": "Finance and Banking",
    "technology": "Information Technology and Telecommunications",
    "telecom": "Information Technology and Telecommunications",
    "telecommunications": "Information Technology and Telecommunications",
    "information technology": "Information Technology and Telecommunications",
    "information technology and telecommunications": "Information Technology and Telecommunications",
    "เทคโนโลยี": "Information Technology and Telecommunications",
    "โทรคมนาคม": "Information Technology and Telecommunications",
    "เทคโนโลยีสารสนเทศและโทรคมนาคม": "Information Technology and Telecommunications",
    "ด้านเทคโนโลยีสารสนเทศและโทรคมนาคม": "Information Technology and Telecommunications",
    "transportation": "Transportation and Logistics",
    "transport": "Transportation and Logistics",
    "logistics": "Transportation and Logistics",
    "transportation and logistics": "Transportation and Logistics",
    "ขนส่ง": "Transportation and Logistics",
    "คมนาคม": "Transportation and Logistics",
    "การขนส่งและโลจิสติกส์": "Transportation and Logistics",
    "ด้านการขนส่งและโลจิสติกส์": "Transportation and Logistics",
    "energy": "Energy and Public Utilities",
    "utilities": "Energy and Public Utilities",
    "energy and public utilities": "Energy and Public Utilities",
    "พลังงาน": "Energy and Public Utilities",
    "สาธารณูปโภค": "Energy and Public Utilities",
    "พลังงานและสาธารณูปโภค": "Energy and Public Utilities",
    "ด้านพลังงานและสาธารณูปโภค": "Energy and Public Utilities",
    "health": "Public Health",
    "healthcare": "Public Health",
    "public health": "Public Health",
    "สาธารณสุข": "Public Health",
    "ด้านสาธารณสุข": "Public Health",
    "critical infrastructure": "Other Designated CII",
    "โครงสร้างพื้นฐาน": "Other Designated CII",
    "โครงสร้างพื้นฐานสำคัญ": "Other Designated CII",
    "other": "Other Designated CII",
    "อื่นๆ": "Other Designated CII",
    "อื่น ๆ": "Other Designated CII",
}


def _sector_display_name(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    lowered = raw.lower()
    if lowered in {"none", "null", "unknown", "n/a", "-", "ไม่ระบุ"}:
        return None
    if lowered in {"general/multiple", "ทั่วไป"}:
        return "General/Multiple"
    return SECTOR_DISPLAY_NAMES.get(lowered) or SECTOR_DISPLAY_NAMES.get(raw) or raw


def _sector_info(doc: Dict[str, Any]) -> Dict[str, Any]:
    if doc.get("target_sector") or doc.get("target_sector_name") or doc.get("target_sector_name_th"):
        sector_name = _sector_display_name(doc.get("target_sector_name") or doc.get("target_sector") or doc.get("target_sector_name_th"))
        return {
            "sector": doc.get("target_sector"),
            "sector_name": sector_name,
            "sector_name_th": doc.get("target_sector_name_th"),
            "icon": doc.get("target_sector_icon"),
        }
    sector = (((doc.get("ai_score_breakdown") or {}).get("target_sector") or {}) if isinstance(doc.get("ai_score_breakdown"), dict) else {}) or {}
    sector_name = _sector_display_name(sector.get("sector_name") or sector.get("sector") or sector.get("sector_name_th"))
    return {
        "sector": sector.get("sector"),
        "sector_name": sector_name,
        "sector_name_th": sector.get("sector_name_th"),
        "icon": sector.get("icon"),
    }


def _country_from_doc(doc: Dict[str, Any]) -> Optional[str]:
    enrichment = doc.get("enrichment") or {}
    ip_info = enrichment.get("ip_info") if isinstance(enrichment, dict) and isinstance(enrichment.get("ip_info"), dict) else {}
    asn_data = (doc.get("asn_data") or {}) if isinstance(doc.get("asn_data"), dict) else {}
    geo_info = (doc.get("geo_info") or {}) if isinstance(doc.get("geo_info"), dict) else {}
    direct_ip = (doc.get("ip_info") or {}) if isinstance(doc.get("ip_info"), dict) else {}
    geo_ip = enrichment.get("geo_ip") if isinstance(enrichment, dict) and isinstance(enrichment.get("geo_ip"), dict) else {}
    source_geo = (((doc.get("source") or {}).get("geo") or {}) if isinstance(doc.get("source"), dict) else {}) or {}
    destination_geo = (((doc.get("destination") or {}).get("geo") or {}) if isinstance(doc.get("destination"), dict) else {}) or {}
    victim_geo = (((doc.get("victim") or {}).get("geo") or {}) if isinstance(doc.get("victim"), dict) else {}) or {}
    target_geo = (((doc.get("target") or {}).get("geo") or {}) if isinstance(doc.get("target"), dict) else {}) or {}
    country = (
        ip_info.get("country")
        or direct_ip.get("country")
        or geo_ip.get("country_code")
        or geo_ip.get("country")
        or asn_data.get("country_code")
        or asn_data.get("country")
        or geo_info.get("country")
        or geo_info.get("country_code")
        or doc.get("geo_country")
        or doc.get("country")
        or doc.get("country_code")
        or doc.get("victim_country")
        or doc.get("victim_country_name")
        or doc.get("source_country")
        or doc.get("source_country_name")
        or doc.get("target_country")
        or doc.get("target_country_name")
        or doc.get("destination_country")
        or doc.get("destination_country_name")
        or doc.get("dst_country")
        or doc.get("dst_country_name")
        or source_geo.get("country_code")
        or source_geo.get("country_name")
        or source_geo.get("country")
        or destination_geo.get("country_code")
        or destination_geo.get("country_name")
        or destination_geo.get("country")
        or victim_geo.get("country_code")
        or victim_geo.get("country_name")
        or victim_geo.get("country")
        or target_geo.get("country_code")
        or target_geo.get("country_name")
        or target_geo.get("country")
    )
    normalized = str(country or "").strip()
    if not normalized or normalized.lower() in {"none", "null", "unknown", "n/a", "-"}:
        return None
    return _country_name_from_code_or_raw(normalized)


def _country_code_from_name(country_name: Optional[str]) -> Optional[str]:
    if not country_name:
        return None
    raw = str(country_name).strip()
    if len(raw) == 2 and raw.isalpha():
        return raw.upper()
    normalized = raw.lower()
    return COUNTRY_CODE_MAP.get(normalized)


_COUNTRY_NAME_FROM_CODE: Dict[str, str] = {code: name.title() for name, code in COUNTRY_CODE_MAP.items()}


def _country_name_from_code_or_raw(raw_value: Optional[str]) -> str:
    """Return a human-readable country name.

    If *raw_value* is a 2-letter ISO code that we recognise, return the
    full name (e.g. ``"US"`` → ``"United States"``).  Otherwise return
    the original value unchanged.
    """
    if not raw_value:
        return "Unknown"
    trimmed = str(raw_value).strip()
    if len(trimmed) == 2 and trimmed.isalpha():
        return _COUNTRY_NAME_FROM_CODE.get(trimmed.upper(), trimmed.upper())
    normalized = trimmed.lower()
    if normalized in COUNTRY_CODE_MAP:
        return _COUNTRY_NAME_FROM_CODE.get(COUNTRY_CODE_MAP[normalized], trimmed.title())
    return trimmed


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


def _infer_ioc_type_from_value(value: str) -> Optional[str]:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    if re.match(r"^[a-z][a-z0-9+.-]*://", candidate, flags=re.IGNORECASE):
        return "url"
    try:
        ipaddress.ip_address(candidate.strip("[]"))
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", candidate):
        return "hash"
    if "/" not in candidate and " " not in candidate and "." in candidate:
        return "domain"
    return None


def _refang_indicator_value(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    return (
        candidate
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("HXXPS://", "https://")
        .replace("HXXP://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[@]", "@")
        .replace("(@)", "@")
        .replace("{@}", "@")
    )


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


def _lookup_items_from_counts(counts: Counter) -> List[Dict[str, Any]]:
    return [
        {"value": key, "label": key, "description": None, "active": True, "count": count}
        for key, count in counts.most_common()
        if str(key).strip()
    ]


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _extract_cve_ids(*values: Any) -> List[str]:
    matches: List[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            matches.extend(_extract_cve_ids(*value))
            continue
        if isinstance(value, dict):
            matches.extend(_extract_cve_ids(*value.values()))
            continue
        matches.extend(match.upper() for match in CVE_PATTERN.findall(str(value)))
    return _unique_list(matches, limit=50)


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


def require_internal_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> str:
    allowed_keys = {
        key.strip()
        for key in os.getenv("AI_SERVICE_API_KEYS", "").split(",")
        if key.strip()
    }
    if not allowed_keys:
        logger.error("SSO exchange is enabled but AI_SERVICE_API_KEYS is empty")
        raise HTTPException(status_code=500, detail="Server authentication misconfigured.")
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API Key. Include 'X-API-Key' header.")
    if not any(hmac.compare_digest(x_api_key, key) for key in allowed_keys):
        logger.warning("Invalid internal API key attempt on SSO exchange")
        raise HTTPException(status_code=403, detail="Invalid API Key.")
    return x_api_key


def _safe_search(index: str, body: Dict[str, Any]) -> Dict[str, Any]:
    client = get_elastic_client()
    try:
        return client.search_index(index, body)
    except Exception as exc:
        logger.error("Elasticsearch search failed for %s: %s", index, exc)
        return {"hits": {"total": {"value": 0}, "hits": []}}


def _scroll_all_documents(
    index: str,
    filters: Optional[List[Dict[str, Any]]] = None,
    sort: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Fetch ALL matching documents via scroll API (no size limit)."""
    body: Dict[str, Any] = {
        "query": {
            "bool": {
                "must": [{"match_all": {}}],
                "filter": filters or [],
            }
        },
    }
    if sort:
        body["sort"] = sort
    client = get_elastic_client()
    try:
        raw_hits = client.scroll_search(index, body, page_size=2000)
    except Exception as exc:
        logger.error("Elasticsearch scroll failed for %s: %s", index, exc)
        return []
    return [{"_id": hit.get("_id"), **(hit.get("_source") or {})} for hit in raw_hits]


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
        "track_total_hits": True,
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


def _warehouse_search_filters(
    ioc_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    risk_levels: Optional[List[str]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    validation_statuses: Optional[List[str]] = None,
    review_states: Optional[List[str]] = None,
    warehouse_eligible_only: Optional[bool] = True,
    min_risk_score: Optional[int] = None,
    time_mode: str = TIME_MODE_PROCESSED,
) -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = []
    if ioc_types:
        filters.append({"terms": {"ioc_type": [item.lower() for item in ioc_types]}})
    if severities:
        filters.append({"terms": {"severity": [_normalize_severity(item) for item in severities]}})
    if risk_levels:
        filters.append({"terms": {"ai_severity": [_normalize_severity(item) for item in risk_levels]}})
    if sources:
        filters.append({"terms": {"source_name": sources}})
    if threat_types:
        filters.append({"terms": {"ai_threat_types": threat_types}})
    if validation_statuses:
        filters.append({"terms": {"validation_status": validation_statuses}})
    if review_states:
        filters.append({"terms": {"review_state": review_states}})
    if min_risk_score is not None:
        filters.append({"range": {"ai_risk_score": {"gte": min_risk_score}}})
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
    date_filter = _date_filter(
        _date_query_range(start_date, end_date),
        WAREHOUSE_TIME_FIELDS.get(time_mode, WAREHOUSE_TIME_FIELDS["processed"]),
    )
    if date_filter:
        filters.append(date_filter)
    return filters


def _search_warehouse_docs(
    query_text: str = "*",
    ioc_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    risk_levels: Optional[List[str]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    validation_statuses: Optional[List[str]] = None,
    review_states: Optional[List[str]] = None,
    warehouse_eligible_only: Optional[bool] = True,
    min_risk_score: Optional[int] = None,
    sort_by: str = "risk",
    limit: int = 100,
    offset: int = 0,
    time_mode: str = TIME_MODE_PROCESSED,
) -> Dict[str, Any]:
    client = get_elastic_client()
    filters = _warehouse_search_filters(
        ioc_types=ioc_types,
        severities=severities,
        risk_levels=risk_levels,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        validation_statuses=validation_statuses,
        review_states=review_states,
        warehouse_eligible_only=warehouse_eligible_only,
        min_risk_score=min_risk_score,
        time_mode=time_mode,
    )
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


def _scroll_all_warehouse_docs(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    ioc_types: Optional[List[str]] = None,
    risk_levels: Optional[List[str]] = None,
    min_risk_score: Optional[int] = None,
    sort_by: str = "risk",
    time_mode: str = TIME_MODE_PROCESSED,
) -> List[Dict[str, Any]]:
    """Fetch ALL matching warehouse documents via scroll (no size cap)."""
    client = get_elastic_client()
    filters = _warehouse_search_filters(
        ioc_types=ioc_types,
        severities=severities,
        risk_levels=risk_levels,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        time_mode=time_mode,
    )
    sort = (
        [{"ai_risk_score": {"order": "desc", "missing": "_last"}}, {"processed_at": {"order": "desc", "missing": "_last"}}]
        if sort_by == "risk"
        else [{"event_time": {"order": "desc", "missing": "_last"}}, {"processed_at": {"order": "desc", "missing": "_last"}}]
    )
    return _scroll_all_documents(client.warehouse_index, filters=filters, sort=sort)


def _scroll_all_datalake_docs(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    ioc_types: Optional[List[str]] = None,
    time_mode: str = TIME_MODE_PROCESSED,
) -> List[Dict[str, Any]]:
    """Fetch ALL matching datalake documents via scroll (no size cap)."""
    client = get_elastic_client()
    filters = _datalake_search_filters(
        ioc_types=ioc_types,
        severities=severities,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        time_mode=time_mode,
    )
    sort = [
        {"@timestamp": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
        {"observation_date": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
    ]
    return _scroll_all_documents(client.datalake_index, filters=filters, sort=sort)


def _scroll_all_news_docs(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Fetch ALL matching news documents via scroll (no size cap)."""
    client = get_elastic_client()
    filters: List[Dict[str, Any]] = [
        {
            "bool": {
                "should": [
                    {"terms": {"source_type": ["news", "rss", "article"]}},
                    {"terms": {"source_name": NEWS_SOURCES}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    if sources:
        filters.append(
            {
                "bool": {
                    "should": [{"match_phrase": {"source_name": source}} for source in sources],
                    "minimum_should_match": 1,
                }
            }
        )
    date_filter = _date_filter(_date_query_range(start_date, end_date), WAREHOUSE_TIME_FIELDS[TIME_MODE_PUBLISHED])
    if date_filter:
        filters.append(date_filter)
    sort = [{"published_at": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}]
    return _scroll_all_documents(client.warehouse_index, filters=filters, sort=sort)


def _search_total(result: Dict[str, Any]) -> int:
    total = result.get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        return int(total.get("value") or 0)
    try:
        return int(total or 0)
    except (TypeError, ValueError):
        return 0


def _warehouse_summary_stats(start_date: Optional[str], end_date: Optional[str], time_mode: str = TIME_MODE_PROCESSED) -> Dict[str, Any]:
    client = get_elastic_client()
    filters = _warehouse_search_filters(start_date=start_date, end_date=end_date, time_mode=time_mode)
    severity_filters = {
        severity: {"term": {"severity": severity}}
        for severity in ("critical", "high", "medium", "low", "clean")
    }
    base_query = {
        "bool": {
            "must": [{"match_all": {}}],
            "filter": filters,
        }
    }
    summary_body = {
        "size": 0,
        "track_total_hits": True,
        "query": base_query,
        "aggs": {
            "severity_counts": {"filters": {"filters": severity_filters}},
            "critical_active": {
                "filter": {"term": {"severity": "critical"}},
            },
            "high_active": {
                "filter": {"term": {"severity": "high"}},
            },
            "thailand_threat": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"geo_country": "Thailand"}},
                            {"term": {"geo_country": "TH"}},
                            {"term": {"geo_country": "thailand"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            },
        },
    }
    result = _safe_search(client.warehouse_index, summary_body)
    aggs = result.get("aggregations") or {}
    severity_buckets = (aggs.get("severity_counts") or {}).get("buckets") or {}

    terms_body = {
        "size": 0,
        "track_total_hits": False,
        "query": base_query,
        "aggs": {
            "threat_types": {
                "terms": {"field": "ai_threat_types", "size": 12, "missing": "Other"},
                "aggs": {"severity": {"terms": {"field": "severity", "size": 5, "missing": "low"}}},
            },
            "sectors": {
                "terms": {"field": "target_sector_name", "size": 12, "missing": "General/Multiple"},
                "aggs": {"severity": {"terms": {"field": "severity", "size": 5, "missing": "low"}}},
            },
        },
    }
    terms_result = _safe_search(client.warehouse_index, terms_body)
    terms_aggs = terms_result.get("aggregations") or {}

    def _terms_with_severity(agg_key: str) -> List[Dict[str, Any]]:
        return [
            {
                "label": str(bucket.get("key") or "Other"),
                "value": int(bucket.get("doc_count") or 0),
                "severity": _highest_severity_from_buckets((bucket.get("severity") or {}).get("buckets") or []),
            }
            for bucket in (terms_aggs.get(agg_key) or {}).get("buckets", [])
        ]

    threat_types = _terms_with_severity("threat_types")
    sector_terms = _terms_with_severity("sectors")
    return {
        "total_threats": _search_total(result),
        "ioc_active": _search_total(result),
        "critical_active": int((aggs.get("critical_active") or {}).get("doc_count") or 0),
        "high_active": int((aggs.get("high_active") or {}).get("doc_count") or 0),
        "thailand_threat": int((aggs.get("thailand_threat") or {}).get("doc_count") or 0),
        "severity_counts": {
            severity: int((severity_buckets.get(severity) or {}).get("doc_count") or 0)
            for severity in ("critical", "high", "medium", "low", "clean")
        },
        "threat_types": threat_types,
        "sector_terms": sector_terms,
    }


def _severity_filters_config(field: str = "severity") -> Dict[str, Dict[str, Any]]:
    return {
        severity: {"term": {field: severity}}
        for severity in ("critical", "high", "medium", "low", "clean")
    }


def _severity_counts_from_filter_agg(agg: Dict[str, Any]) -> Dict[str, int]:
    buckets = (agg or {}).get("buckets") or {}
    return {
        severity: int((buckets.get(severity) or {}).get("doc_count") or 0)
        for severity in ("critical", "high", "medium", "low", "clean")
    }


def _range_counts_from_agg(agg: Dict[str, Any], labels: Sequence[str]) -> Dict[str, int]:
    buckets = (agg or {}).get("buckets") or []
    output = {label: 0 for label in labels}
    for bucket in buckets:
        key = str(bucket.get("key") or "")
        if key in output:
            output[key] = int(bucket.get("doc_count") or 0)
    return output


def _terms_items_from_buckets(
    buckets: Sequence[Dict[str, Any]],
    *,
    total: Optional[int] = None,
    labels: Optional[Dict[str, str]] = None,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    effective_total = total if total is not None else sum(int(bucket.get("doc_count") or 0) for bucket in buckets)
    output = []
    for bucket in list(buckets)[:limit]:
        key = str(bucket.get("key") or "").strip()
        if not key or key.lower() in {"none", "null", "unknown", "-"}:
            continue
        value = int(bucket.get("doc_count") or 0)
        output.append(
            {
                "key": key,
                "label": labels.get(key, key) if labels else key,
                "value": value,
                "percentage": _percentage(value, effective_total or 1),
                "color": None,
            }
        )
    return output


SOURCE_DISPLAY_NAMES = {
    "cyberint_iocs": "Cyberint IOC Feed",
    "Cyberint IOCs": "Cyberint IOC Feed",
    "Cyberint IOC Feed": "Cyberint IOC Feed",
    "misp_attribute": "MISP Attribute Feed",
    "MISP": "MISP Intelligence",
    "sandbox": "Sandbox Analysis",
    "Zone-H": "Zone-H Defacement Feed",
    "DarkReading": "DarkReading News",
    "BleepingComputer News": "BleepingComputer News",
    "TheHackerNews": "The Hacker News",
    "tcti-feeds": "TCTI Feed",
}


def _source_display_name(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "Unknown"
    return SOURCE_DISPLAY_NAMES.get(raw, raw.replace("_", " "))


def _format_source_terms(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for item in items:
        raw_key = item.get("label") or item.get("key")
        label = _source_display_name(raw_key)
        if label.lower() in {"unknown", "none", "null", "n/a", "-"}:
            continue
        value = int(item.get("value") or item.get("count") or 0)
        current = grouped.setdefault(
            label,
            {
                "key": label,
                "label": label,
                "value": 0,
                "percentage": 0.0,
                "color": item.get("color"),
                "source_group": _source_category(raw_key),
            },
        )
        current["value"] += value
    total = sum(int(item["value"]) for item in grouped.values())
    for item in grouped.values():
        item["percentage"] = _percentage(int(item["value"]), total)
    return sorted(grouped.values(), key=lambda item: int(item["value"]), reverse=True)


def _format_sector_terms(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for item in items:
        label = _sector_display_name(item.get("label") or item.get("key")) or "General/Multiple"
        value = int(item.get("value") or item.get("count") or 0)
        current = grouped.setdefault(
            label,
            {
                "key": label,
                "label": label,
                "value": 0,
                "percentage": 0.0,
                "color": item.get("color"),
            },
        )
        current["value"] += value
    total = sum(int(item["value"]) for item in grouped.values())
    for item in grouped.values():
        item["percentage"] = _percentage(int(item["value"]), total)
    return sorted(grouped.values(), key=lambda item: int(item["value"]), reverse=True)


def _source_category(value: Any) -> str:
    source = str(value or "").strip().lower()
    if not source:
        return "other"
    if source in {"cyberint_iocs", "sandbox"} or source.startswith("cyberint") or "cyble threat intelligence" in source:
        return "trusted"
    if source in {"zone-h", "darkreading", "thehackernews", "the hacker news"} or "news" in source:
        return "news"
    return "other"


def _date_histogram_bounds(start_date: Optional[str], end_date: Optional[str]) -> Optional[Dict[str, str]]:
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if not start_bound or not end_bound:
        return None
    return {
        "min": start_bound.astimezone(BANGKOK_TZ).isoformat(),
        "max": end_bound.astimezone(BANGKOK_TZ).isoformat(),
    }


def _build_heatmap_from_histogram(buckets: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    x_axis = [f"{hour:02d}:00" for hour in range(24)]
    y_axis = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    counts = {(day, hour): 0 for day in range(7) for hour in range(24)}
    for bucket in buckets:
        parsed = _parse_dt(bucket.get("key_as_string"))
        if not parsed:
            continue
        localized = parsed.astimezone(BANGKOK_TZ)
        counts[(localized.weekday(), localized.hour)] += int(bucket.get("doc_count") or 0)
    cells = [
        {"x": hour_label, "y": day_label, "value": counts[(day_index, hour)]}
        for day_index, day_label in enumerate(y_axis)
        for hour, hour_label in enumerate(x_axis)
    ]
    peak_key, peak_value = max(counts.items(), key=lambda item: item[1]) if counts else ((0, 0), 0)
    peak_day_index, peak_hour_index = peak_key
    return {
        "mode": "day-hour",
        "x_axis": x_axis,
        "y_axis": y_axis,
        "cells": cells,
        "peak": {
            "day": y_axis[peak_day_index],
            "hour": x_axis[peak_hour_index],
            "end_hour": f"{(peak_hour_index + 1) % 24:02d}:00",
            "label": f"{y_axis[peak_day_index]}, {x_axis[peak_hour_index]} - {(peak_hour_index + 1) % 24:02d}:00",
            "value": peak_value,
        },
    }


def _hour_range_label(hour: int, span: int = 3) -> str:
    start = int(hour) % 24
    end = (start + span) % 24
    return f"{start:02d}:00 - {end:02d}:00"


def _heatmap_time_axis() -> List[str]:
    return [_hour_range_label(hour) for hour in range(0, 24, 3)]


def _attack_time_heatmap_mode(start_date: Optional[str], end_date: Optional[str]) -> str:
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if not start_bound or not end_bound:
        return "day-hour"
    start_local = start_bound.astimezone(BANGKOK_TZ).date()
    end_local = end_bound.astimezone(BANGKOK_TZ).date()
    day_count = max(1, (end_local - start_local).days + 1)
    if day_count <= 1:
        return "time-threat-type"
    if day_count <= 7:
        return "time-date"
    if day_count <= 45 and start_local.year == end_local.year and start_local.month == end_local.month:
        return "time-day"
    if day_count <= 45:
        return "time-date"
    return "time-month"


def _attack_time_x_axis(mode: str, start_date: Optional[str], end_date: Optional[str]) -> List[str]:
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if not start_bound or not end_bound:
        return [f"{hour:02d}:00" for hour in range(24)]
    start_local = start_bound.astimezone(BANGKOK_TZ).date()
    end_local = end_bound.astimezone(BANGKOK_TZ).date()
    if mode == "time-day":
        return [str(day) for day in range(start_local.day, end_local.day + 1)]
    if mode == "time-date":
        day_count = max(1, (end_local - start_local).days + 1)
        return [(start_local + timedelta(days=offset)).strftime("%d-%m-%y") for offset in range(day_count)]
    if mode == "time-month":
        labels: List[str] = []
        cursor = date(start_local.year, start_local.month, 1)
        end_month = date(end_local.year, end_local.month, 1)
        while cursor <= end_month:
            labels.append(cursor.strftime("%b %Y"))
            if cursor.month == 12:
                cursor = date(cursor.year + 1, 1, 1)
            else:
                cursor = date(cursor.year, cursor.month + 1, 1)
        return labels
    return []


def _attack_time_x_label(mode: str, localized: datetime) -> str:
    if mode == "time-day":
        return str(localized.day)
    if mode == "time-date":
        return localized.strftime("%d-%m-%y")
    if mode == "time-month":
        return localized.strftime("%b %Y")
    return f"{localized.hour:02d}:00"


def _primary_threat_label(doc: Dict[str, Any]) -> str:
    values = doc.get("ai_threat_types") or doc.get("threat_type") or []
    if isinstance(values, str):
        values = [values]
    for value in values:
        label = str(value or "").strip()
        if label:
            return label
    return "Other"


def _build_time_matrix_heatmap(mode: str, x_axis: Sequence[str], counts: Dict[tuple, int]) -> Dict[str, Any]:
    y_axis = _heatmap_time_axis()
    cells = [
        {"x": x_label, "y": y_label, "value": int(counts.get((x_label, y_label), 0))}
        for y_label in y_axis
        for x_label in x_axis
    ]
    peak_cell = max(cells, key=lambda item: item["value"]) if cells else {"x": "", "y": "", "value": 0}
    return {
        "mode": mode,
        "x_axis": list(x_axis),
        "y_axis": y_axis,
        "cells": cells,
        "peak": {
            "day": str(peak_cell.get("x") or "-"),
            "hour": str(peak_cell.get("y") or "-"),
            "end_hour": "",
            "label": f"{peak_cell.get('x') or '-'}, {peak_cell.get('y') or '-'}",
            "value": int(peak_cell.get("value") or 0),
        },
    }


def _build_attack_time_heatmap_from_docs(
    docs: List[Dict[str, Any]],
    *,
    time_mode: str = TIME_MODE_OBSERVED,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Dict[str, Any]:
    mode = _attack_time_heatmap_mode(start_date, end_date)
    if mode == "day-hour":
        return _build_day_hour_heatmap(docs, time_mode=time_mode, start_date=start_date, end_date=end_date)

    if mode == "time-threat-type":
        threat_counts = Counter(_primary_threat_label(doc) for doc in docs)
        x_axis = [label for label, _ in threat_counts.most_common(12)] or ["Other"]
    else:
        x_axis = _attack_time_x_axis(mode, start_date, end_date)

    x_lookup = set(x_axis)
    counts: Dict[tuple, int] = defaultdict(int)
    for doc in docs:
        event_time = _pick_display_time_in_range(doc, time_mode, start_date, end_date)
        if not event_time:
            continue
        localized = event_time.astimezone(BANGKOK_TZ)
        y_label = _hour_range_label((localized.hour // 3) * 3)
        x_label = _primary_threat_label(doc) if mode == "time-threat-type" else _attack_time_x_label(mode, localized)
        if x_label in x_lookup:
            counts[(x_label, y_label)] += 1
    return _build_time_matrix_heatmap(mode, x_axis, counts)


def _build_attack_time_heatmap_from_aggs(
    *,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    query: Optional[str] = None,
    time_mode: str = TIME_MODE_OBSERVED,
) -> Dict[str, Any]:
    mode = _attack_time_heatmap_mode(start_date, end_date)
    if mode == "day-hour":
        return _build_heatmap_from_histogram([])

    client = get_elastic_client()
    filters = _warehouse_search_filters(
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        severities=severities,
        time_mode=time_mode,
    )
    must: List[Dict[str, Any]] = []
    if query and query != "*":
        must.append(
            {
                "multi_match": {
                    "query": query,
                    "fields": ["ioc_value^3", "description", "reference", "ai_threat_types", "ai_threat_actors", "source_name"],
                }
            }
        )
    histogram_field = "last_seen" if time_mode == TIME_MODE_OBSERVED else "processed_at"
    date_histogram: Dict[str, Any] = {
        "field": histogram_field,
        "fixed_interval": "3h",
        "min_doc_count": 0,
        "format": "strict_date_optional_time",
        "time_zone": "Asia/Bangkok",
    }
    bounds = _date_histogram_bounds(start_date, end_date)
    if bounds:
        date_histogram["extended_bounds"] = bounds
        date_histogram["hard_bounds"] = bounds

    if mode == "time-threat-type":
        aggs: Dict[str, Any] = {
            "threat_types": {
                "terms": {"field": "ai_threat_types", "size": 12, "missing": "Other"},
                "aggs": {"time_ranges": {"date_histogram": date_histogram}},
            }
        }
    else:
        aggs = {"time_ranges": {"date_histogram": date_histogram}}

    result = _safe_search(
        client.warehouse_index,
        {
            "size": 0,
            "track_total_hits": False,
            "query": {"bool": {"must": must if must else [{"match_all": {}}], "filter": filters}},
            "aggs": aggs,
        },
    )
    aggregations = result.get("aggregations") or {}

    if mode == "time-threat-type":
        threat_buckets = (aggregations.get("threat_types") or {}).get("buckets") or []
        x_axis = [str(bucket.get("key") or "Other") for bucket in threat_buckets if int(bucket.get("doc_count") or 0) > 0] or ["Other"]
        x_lookup = set(x_axis)
        counts: Dict[tuple, int] = defaultdict(int)
        for bucket in threat_buckets:
            x_label = str(bucket.get("key") or "Other")
            if x_label not in x_lookup:
                continue
            for time_bucket in ((bucket.get("time_ranges") or {}).get("buckets") or []):
                parsed = _parse_dt(time_bucket.get("key_as_string"))
                if not parsed:
                    continue
                localized = parsed.astimezone(BANGKOK_TZ)
                y_label = _hour_range_label((localized.hour // 3) * 3)
                counts[(x_label, y_label)] += int(time_bucket.get("doc_count") or 0)
        return _build_time_matrix_heatmap(mode, x_axis, counts)

    x_axis = _attack_time_x_axis(mode, start_date, end_date)
    x_lookup = set(x_axis)
    counts = defaultdict(int)
    for time_bucket in ((aggregations.get("time_ranges") or {}).get("buckets") or []):
        parsed = _parse_dt(time_bucket.get("key_as_string"))
        if not parsed:
            continue
        localized = parsed.astimezone(BANGKOK_TZ)
        x_label = _attack_time_x_label(mode, localized)
        if x_label not in x_lookup:
            continue
        y_label = _hour_range_label((localized.hour // 3) * 3)
        counts[(x_label, y_label)] += int(time_bucket.get("doc_count") or 0)
    return _build_time_matrix_heatmap(mode, x_axis, counts)


def _warehouse_dashboard_aggs(
    *,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    risk_levels: Optional[List[str]] = None,
    query: Optional[str] = None,
    min_risk_score: Optional[int] = None,
    include_heatmap: bool = False,
    include_trend: bool = False,
    time_mode: str = TIME_MODE_PROCESSED,
) -> Dict[str, Any]:
    client = get_elastic_client()
    filters = _warehouse_search_filters(
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        severities=severities,
        risk_levels=risk_levels,
        min_risk_score=min_risk_score,
        time_mode=time_mode,
    )
    must: List[Dict[str, Any]] = []
    if query and query != "*":
        must.append(
            {
                "multi_match": {
                    "query": query,
                    "fields": ["ioc_value^3", "description", "reference", "ai_threat_types", "ai_threat_actors", "source_name"],
                }
            }
        )
    histogram_field = "last_seen" if time_mode == TIME_MODE_OBSERVED else "processed_at"
    date_histogram: Dict[str, Any] = {
        "field": histogram_field,
        "calendar_interval": _aggregation_interval(start_date, end_date) if include_trend else "hour",
        "min_doc_count": 0,
        "format": "strict_date_optional_time",
    }
    bounds = _date_histogram_bounds(start_date, end_date)
    if bounds:
        date_histogram["extended_bounds"] = bounds
        # hard_bounds prevents buckets outside the requested range.  Without
        # this, 'observed' mode (event_time) may span years of historical
        # timestamps and exceed the max_buckets limit (65 536).
        date_histogram["hard_bounds"] = bounds
    aggs: Dict[str, Any] = {
        "active_iocs": {"cardinality": {"field": "canonical_ioc_key.keyword", "precision_threshold": 40000}},
        "source_count": {"cardinality": {"field": "source_name", "precision_threshold": 40000}},
        "severity_counts": {"filters": {"filters": _severity_filters_config("severity")}},
        "risk_level_counts": {"filters": {"filters": _severity_filters_config("ai_severity")}},
        "critical_active": {
            "filter": {"term": {"severity": "critical"}},
            "aggs": {
                "active_iocs": {
                    "cardinality": {
                        "field": "canonical_ioc_key.keyword",
                        "precision_threshold": 40000,
                    }
                }
            },
        },
        "high_active": {
            "filter": {"term": {"severity": "high"}},
            "aggs": {
                "active_iocs": {
                    "cardinality": {
                        "field": "canonical_ioc_key.keyword",
                        "precision_threshold": 40000,
                    }
                }
            },
        },
        "clean_count": {"filter": {"term": {"severity": "clean"}}},
        "risk_score_ranges": {
            "range": {
                "field": "ai_risk_score",
                "ranges": [
                    {"key": "0-19", "to": 20},
                    {"key": "20-39", "from": 20, "to": 40},
                    {"key": "40-59", "from": 40, "to": 60},
                    {"key": "60-79", "from": 60, "to": 80},
                    {"key": "80-100", "from": 80},
                ],
            }
        },
        "avg_risk_score": {"avg": {"field": "ai_risk_score"}},
        "high_risk": {"filter": {"range": {"ai_risk_score": {"gte": 80}}}},
        "quality_complete": {
            "filter": {
                "bool": {
                    "must": [
                        {"exists": {"field": "ioc_value"}},
                        {"exists": {"field": "ioc_type"}},
                        {"exists": {"field": "source_name"}},
                        {"exists": {"field": "severity"}},
                    ]
                }
            }
        },
        "ioc_types": {"terms": {"field": "ioc_type", "size": 25, "missing": "unknown"}},
        "sources": {"terms": {"field": "source_name", "size": 25, "missing": "unknown"}},
        "threat_types": {"terms": {"field": "ai_threat_types", "size": 25, "missing": "Other"}},
        "countries": {
            "terms": {"field": "geo_country", "size": 25, "missing": "unknown"},
            "aggs": {
                "severity": {"filters": {"filters": _severity_filters_config("severity")}},
                "sources": {"terms": {"field": "source_name", "size": 10}},
                "sectors": {"terms": {"field": "target_sector_name", "size": 5, "missing": "General/Multiple"}},
            },
        },
        "sectors": {
            "terms": {"field": "target_sector_name", "size": 25, "missing": "General/Multiple"},
            "aggs": {"severity": {"terms": {"field": "severity", "size": 5, "missing": "low"}}},
        },
        "severity_by_source": {
            "terms": {"field": "source_name", "size": 25, "missing": "unknown"},
            "aggs": {"severity": {"filters": {"filters": _severity_filters_config("severity")}}},
        },
        "severity_by_type": {
            "terms": {"field": "ioc_type", "size": 25, "missing": "unknown"},
            "aggs": {"severity": {"filters": {"filters": _severity_filters_config("severity")}}},
        },
    }
    if include_heatmap:
        aggs["heatmap"] = {"date_histogram": date_histogram}
    if include_trend:
        aggs["trend"] = {
            "date_histogram": date_histogram,
            "aggs": {
                "severity": {"filters": {"filters": _severity_filters_config("severity")}},
                "sources": {"terms": {"field": "source_name", "size": 25, "missing": "unknown"}},
            },
        }
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": must if must else [{"match_all": {}}],
                "filter": filters,
            }
        },
        "aggs": aggs,
    }
    result = _safe_search(client.warehouse_index, body)
    aggs_result = result.get("aggregations") or {}
    aggs_result["total"] = _search_total(result)
    return aggs_result


def _datalake_search_filters(
    ioc_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    time_mode: str = TIME_MODE_PROCESSED,
) -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = []
    if ioc_types:
        filters.append({"terms": {"ioc_type": [item.lower() for item in ioc_types]}})
    if severities:
        filters.append({"terms": {"severity": [_normalize_severity(item) for item in severities]}})
    if sources:
        filters.append({"terms": {"source_name": sources}})
    if threat_types:
        filters.append({"terms": {"threat_type": threat_types}})
    date_filter = _date_filter(
        _date_query_range(start_date, end_date),
        DATALAKE_TIME_FIELDS.get(time_mode, DATALAKE_TIME_FIELDS["processed"]),
    )
    if date_filter:
        filters.append(date_filter)
    return filters


def _datalake_dashboard_aggs(
    *,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    time_mode: str = TIME_MODE_PROCESSED,
) -> Dict[str, Any]:
    client = get_elastic_client()
    dl_histogram_field = "observation_date" if time_mode == TIME_MODE_OBSERVED else "@timestamp"
    date_histogram: Dict[str, Any] = {
        "field": dl_histogram_field,
        "calendar_interval": "day",
        "min_doc_count": 0,
        "format": "strict_date_optional_time",
    }
    bounds = _date_histogram_bounds(start_date, end_date)
    if bounds:
        date_histogram["extended_bounds"] = bounds
        date_histogram["hard_bounds"] = bounds
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [{"match_all": {}}],
                "filter": _datalake_search_filters(
                    start_date=start_date,
                    end_date=end_date,
                    sources=sources,
                    severities=severities,
                    threat_types=threat_types,
                    time_mode=time_mode,
                ),
            }
        },
        "aggs": {
            "sources": {"terms": {"field": "source_name", "size": 25, "missing": "unknown"}},
            "ioc_types": {"terms": {"field": "ioc_type", "size": 25, "missing": "unknown"}},
            "threat_types": {"terms": {"field": "threat_type", "size": 25, "missing": "Other"}},
            "severity_counts": {"filters": {"filters": _severity_filters_config("severity")}},
            "quality_complete": {
                "filter": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "ioc_value"}},
                            {"exists": {"field": "ioc_type"}},
                            {"exists": {"field": "source_name"}},
                            {"exists": {"field": "severity"}},
                        ]
                    }
                }
            },
            "import_timeline": {
                "date_histogram": date_histogram,
                "aggs": {"sources": {"terms": {"field": "source_name", "size": 25, "missing": "unknown"}}},
            },
        },
    }
    result = _safe_search(client.datalake_index, body)
    aggs = result.get("aggregations") or {}
    aggs["total"] = _search_total(result)
    return aggs


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
    time_mode: str = TIME_MODE_PROCESSED,
) -> Dict[str, Any]:
    client = get_elastic_client()
    filters = _datalake_search_filters(
        ioc_types=ioc_types,
        severities=severities,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        time_mode=time_mode,
    )
    return _search_documents(
        client.datalake_index,
        query_text=query_text,
        filters=filters,
        limit=limit,
        offset=offset,
        sort=[
            {"@timestamp": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
            {"observation_date": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
        ],
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
    return_es_total: bool = False,
) -> "List[Dict[str, Any]] | tuple[List[Dict[str, Any]], int]":
    # Actions intentionally use processed-time semantics (when the alert was ingested/actioned)
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
    es_total = _search_total(result)
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
    sliced = docs[offset:offset + limit]
    if return_es_total:
        return sliced, es_total
    return sliced


def _hits_to_docs(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"_id": hit.get("_id"), **(hit.get("_source") or {})} for hit in result.get("hits", {}).get("hits", [])]


def _fetch_datalake_by_indicators(indicators: Sequence[Tuple[str, str]]) -> List[Dict[str, Any]]:
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
        should = []
        for ioc_type, ioc_value in batch:
            value_variants = _unique_list(
                [
                    value
                    for value in [
                    ioc_value,
                    _refang_indicator_value(ioc_value),
                    _refang_indicator_value(ioc_value).replace(".", "[.]") if "." in _refang_indicator_value(ioc_value) else None,
                    ]
                    if isinstance(value, str) and value.strip()
                ],
                limit=3,
            )
            for value_variant in value_variants:
                should.extend(
                    [
                        {"bool": {"must": [{"term": {"ioc_type": ioc_type}}, {"term": {"ioc_value": value_variant}}]}},
                        {"bool": {"must": [{"term": {"ioc_type.keyword": ioc_type}}, {"term": {"ioc_value.keyword": value_variant}}]}},
                        {"bool": {"must": [{"term": {"type.keyword": ioc_type}}, {"term": {"value.keyword": value_variant}}]}},
                        {"bool": {"must": [{"match_phrase": {"type": ioc_type}}, {"match_phrase": {"value": value_variant}}]}},
                        {"bool": {"must": [{"term": {"ioc.type.keyword": ioc_type}}, {"term": {"ioc.value.keyword": value_variant}}]}},
                        {"bool": {"must": [{"match_phrase": {"ioc.type": ioc_type}}, {"match_phrase": {"ioc.value": value_variant}}]}},
                        {"bool": {"must": [{"term": {"Attribute.type.keyword": ioc_type}}, {"term": {"Attribute.value.keyword": value_variant}}]}},
                        {"bool": {"must": [{"match_phrase": {"Attribute.type": ioc_type}}, {"match_phrase": {"Attribute.value": value_variant}}]}},
                    ]
                )
        body = {
            "query": {"bool": {"should": should, "minimum_should_match": 1}},
        }
        raw_hits = client.scroll_search(client.datalake_index, body, page_size=2000)
        results.extend({"_id": hit.get("_id"), **(hit.get("_source") or {})} for hit in raw_hits)
    results.sort(
        key=lambda item: _datalake_event_time(item) or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    return results


def _fetch_datalake_by_cluster(cluster_labels: List, limit: int = 50) -> List[Dict[str, Any]]:
    labels = [cl for cl in cluster_labels if cl is not None]
    if not labels:
        return []
    client = get_elastic_client()
    body = {
        "query": {"terms": {"cluster_label": labels}},
        "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}],
    }
    raw_hits = client.scroll_search(client.datalake_index, body, page_size=limit)
    return [{"_id": hit.get("_id"), **(hit.get("_source") or {})} for hit in raw_hits[:limit]]


def _datalake_event_time(doc: Dict[str, Any]) -> Optional[datetime]:
    event = doc.get("Event") if isinstance(doc.get("Event"), dict) else {}
    return (
        _pick_display_time(doc, TIME_MODE_OBSERVED)
        or _parse_dt(event.get("date"))
        or _parse_dt(doc.get("@timestamp"))
        or _pick_event_time(doc)
    )


def _datalake_event_source(doc: Dict[str, Any]) -> str:
    event = doc.get("Event") if isinstance(doc.get("Event"), dict) else {}
    orgc = event.get("Orgc") if isinstance(event.get("Orgc"), dict) else {}
    org = event.get("Org") if isinstance(event.get("Org"), dict) else {}
    source = doc.get("source")
    source_name = None
    if isinstance(source, dict):
        source_name = source.get("name")
    elif isinstance(source, list):
        source_name = next((item.get("name") for item in source if isinstance(item, dict) and item.get("name")), None)
    return str(doc.get("source_name") or source_name or orgc.get("name") or org.get("name") or doc.get("source_type") or "-")


def _datalake_event_severity(doc: Dict[str, Any]) -> str:
    event = doc.get("Event") if isinstance(doc.get("Event"), dict) else {}
    threat_level = event.get("ThreatLevel") if isinstance(event.get("ThreatLevel"), dict) else {}
    return _severity_label(_normalize_severity(doc.get("severity") or threat_level.get("name")))


def _datalake_event_description(doc: Dict[str, Any]) -> str:
    event = doc.get("Event") if isinstance(doc.get("Event"), dict) else {}
    attribute = doc.get("Attribute") if isinstance(doc.get("Attribute"), dict) else {}
    source = doc.get("source")
    source_description = None
    if isinstance(source, dict):
        source_description = source.get("description")
    elif isinstance(source, list):
        source_description = next((item.get("description") for item in source if isinstance(item, dict) and item.get("description")), None)
    return str(
        doc.get("description")
        or doc.get("title")
        or doc.get("reference")
        or attribute.get("comment")
        or event.get("info")
        or source_description
        or doc.get("value")
        or doc.get("ioc_value")
        or "N/A"
    )


def _detail_text(value: Any) -> Optional[str]:
    if isinstance(value, (list, tuple, set)):
        for item in value:
            cleaned = _detail_text(item)
            if cleaned:
                return cleaned
        return None
    if isinstance(value, dict):
        return None
    text = str(value or "").strip()
    if not text or text.lower() in {"none", "null", "unknown", "n/a", "na", "-"}:
        return None
    return text


def _first_detail_text(*values: Any) -> Optional[str]:
    for value in values:
        cleaned = _detail_text(value)
        if cleaned:
            return cleaned
    return None


def _nested_dict(value: Any, *path: str) -> Dict[str, Any]:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _doc_enrichment(doc: Dict[str, Any]) -> Dict[str, Any]:
    enrichment = doc.get("enrichment")
    return enrichment if isinstance(enrichment, dict) else {}


def _doc_geo_ip(doc: Dict[str, Any]) -> Dict[str, Any]:
    return _nested_dict(_doc_enrichment(doc), "geo_ip")


def _doc_ip_info(doc: Dict[str, Any]) -> Dict[str, Any]:
    return (
        (doc.get("ip_info") if isinstance(doc.get("ip_info"), dict) else {})
        or _nested_dict(_doc_enrichment(doc), "ip_info")
    )


def _doc_asn_data(doc: Dict[str, Any]) -> Dict[str, Any]:
    direct_ip_info = doc.get("ip_info") if isinstance(doc.get("ip_info"), dict) else {}
    enrichment = _doc_enrichment(doc)
    enrichment_ip_info = _nested_dict(enrichment, "ip_info")
    return (
        (doc.get("asn_data") if isinstance(doc.get("asn_data"), dict) else {})
        or _nested_dict(direct_ip_info, "asn_data")
        or _nested_dict(enrichment, "asn_data")
        or _nested_dict(enrichment, "asn")
        or _nested_dict(enrichment_ip_info, "asn_data")
    )


def _doc_whois(doc: Dict[str, Any]) -> Dict[str, Any]:
    return (
        (doc.get("whois") if isinstance(doc.get("whois"), dict) else {})
        or _nested_dict(_doc_enrichment(doc), "whois")
    )


def _doc_geo_info(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc.get("geo_info") if isinstance(doc.get("geo_info"), dict) else {}


def _first_dict_from_docs(docs: Sequence[Dict[str, Any]], extractor) -> Dict[str, Any]:
    for doc in docs:
        candidate = extractor(doc)
        if isinstance(candidate, dict) and any(_detail_text(value) for value in candidate.values()):
            return candidate
    return {}


def _first_doc_text(docs: Sequence[Dict[str, Any]], *fields: str) -> Optional[str]:
    for doc in docs:
        for field in fields:
            cleaned = _detail_text(doc.get(field))
            if cleaned:
                return cleaned
    return None


def _coordinates_from_docs(docs: Sequence[Dict[str, Any]]) -> Tuple[Optional[float], Optional[float]]:
    for doc in docs:
        latitude, longitude = _coordinates_from_doc(doc)
        if latitude is not None and longitude is not None:
            return latitude, longitude
    return None, None


def _get_processed_doc(doc_id: str) -> Optional[Dict[str, Any]]:
    return get_elastic_client().get_warehouse_document(doc_id)


def _get_warehouse_doc_by_indicator(ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
    normalized_type = str(ioc_type or "").strip().lower()
    normalized_value = str(ioc_value or "").strip()
    if not normalized_type or not normalized_value:
        return None
    client = get_elastic_client()
    result = _safe_search(
        client.warehouse_index,
        {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"ioc_type": normalized_type}},
                        {"term": {"ioc_value": normalized_value}},
                    ]
                }
            },
            "sort": [
                {"ai_risk_score": {"order": "desc", "missing": "_last"}},
                {"processed_at": {"order": "desc", "missing": "_last"}},
            ],
            "size": 1,
        },
    )
    docs = _hits_to_docs(result)
    return docs[0] if docs else None


def _get_warehouse_doc_by_value(ioc_value: str) -> Optional[Dict[str, Any]]:
    normalized_value = _refang_indicator_value(ioc_value)
    if not normalized_value:
        return None
    inferred_type = _infer_ioc_type_from_value(normalized_value)
    if inferred_type:
        exact_doc = _get_warehouse_doc_by_indicator(inferred_type, normalized_value)
        if exact_doc:
            return exact_doc
    client = get_elastic_client()
    result = _safe_search(
        client.warehouse_index,
        {
            "query": {"term": {"ioc_value": normalized_value}},
            "sort": [
                {"ai_risk_score": {"order": "desc", "missing": "_last"}},
                {"processed_at": {"order": "desc", "missing": "_last"}},
            ],
            "size": 1,
        },
    )
    docs = _hits_to_docs(result)
    return docs[0] if docs else None


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
    high_critical = [doc for doc in todays_docs if _source_severity(doc) in {"critical", "high"}]
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
    counts = Counter(_source_severity(doc) for doc in docs)
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


def _primary_threat_type(doc: Dict[str, Any]) -> Optional[str]:
    threat_values = doc.get("ai_threat_types") or doc.get("threat_type") or []
    if isinstance(threat_values, list):
        for threat in threat_values:
            label = str(threat or "").strip()
            if label:
                return label
    label = str(threat_values or "").strip()
    return label or None


def _group_severity_label(docs: Sequence[Dict[str, Any]]) -> str:
    highest = "clean"
    for doc in docs:
        severity = _source_severity(doc)
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity
    return _severity_label(highest)


def _build_exposure_summary(
    visible_docs: Sequence[Dict[str, Any]] = (),
    active_docs: Sequence[Dict[str, Any]] = (),
    previous_visible_docs: Optional[Sequence[Dict[str, Any]]] = None,
    previous_active_docs: Optional[Sequence[Dict[str, Any]]] = None,
    current_stats: Optional[Dict[str, Any]] = None,
    previous_stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    active_list = _latest_indicator_docs(active_docs)
    previous_visible_list = list(previous_visible_docs or [])
    previous_active_list = _latest_indicator_docs(previous_active_docs or [])

    payload = (
        {key: int(current_stats.get(key) or 0) for key in ("total_threats", "ioc_active", "critical_active", "high_active")}
        if current_stats
        else {
            "total_threats": len(visible_docs),
            "ioc_active": len(active_list),
            "critical_active": sum(
                1 for doc in active_list if _source_severity(doc) == "critical"
            ),
            "high_active": sum(
                1 for doc in active_list if _source_severity(doc) == "high"
            ),
        }
    )
    previous_payload = (
        {key: int(previous_stats.get(key) or 0) for key in ("total_threats", "ioc_active", "critical_active", "high_active")}
        if previous_stats
        else {
            "total_threats": len(previous_visible_list),
            "ioc_active": len(previous_active_list),
            "critical_active": sum(
                1 for doc in previous_active_list if _source_severity(doc) == "critical"
            ),
            "high_active": sum(
                1 for doc in previous_active_list if _source_severity(doc) == "high"
            ),
        }
    )
    payload["comparison"] = {
        key: _comparison_metric(payload[key], previous_payload[key])
        for key in ("total_threats", "ioc_active", "critical_active", "high_active")
    }
    payload["worldwide_threat"] = payload["total_threats"]
    thailand_current = int((current_stats or {}).get("thailand_threat") or 0) if current_stats else 0
    thailand_previous = int((previous_stats or {}).get("thailand_threat") or 0) if previous_stats else 0
    payload["thailand_threat"] = thailand_current
    payload["comparison"]["thailand_threat"] = _comparison_metric(thailand_current, thailand_previous)
    return payload


def _build_severity_distribution_from_counts(counts: Dict[str, int]) -> List[Dict[str, Any]]:
    color_map = {
        "critical": "#E31B54",
        "high": "#EC4A0A",
        "medium": "#FDB022",
        "low": "#6BADF1",
        "clean": "#667085",
    }
    total = sum(int(counts.get(severity) or 0) for severity in color_map) or 1
    items = []
    for severity in ["critical", "high", "medium", "low", "clean"]:
        value = int(counts.get(severity) or 0)
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


def _build_threat_volume_nodes(docs: Sequence[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for doc in docs:
        threat_type = _primary_threat_type(doc)
        if threat_type:
            grouped[threat_type].append(doc)

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


def _build_threat_volume_nodes_from_terms(terms: Sequence[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    return [
        {
            "id": f"{_slugify_text(str(item.get('label') or 'Other'))}:{index}",
            "label": str(item.get("label") or "Other"),
            "severity": str(item.get("severity") or "Low"),
            "value": int(item.get("value") or 0),
        }
        for index, item in enumerate(list(terms)[:limit])
        if int(item.get("value") or 0) > 0
    ]


def _build_day_hour_heatmap(
    docs: List[Dict[str, Any]],
    time_mode: str = TIME_MODE_OBSERVED,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Dict[str, Any]:
    x_axis = [f"{hour:02d}:00" for hour in range(24)]
    y_axis = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    counts = {(day, hour): 0 for day in range(7) for hour in range(24)}
    for doc in docs:
        event_time = _pick_display_time_in_range(doc, time_mode, start_date, end_date)
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
            "end_hour": f"{(peak_hour_index + 1) % 24:02d}:00",
            "label": peak_label,
            "value": peak_value,
        },
    }


def _build_heatmap(
    docs: List[Dict[str, Any]],
    time_mode: str = TIME_MODE_OBSERVED,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Dict[str, Any]:
    return _build_attack_time_heatmap_from_docs(
        docs,
        time_mode=time_mode,
        start_date=start_date,
        end_date=end_date,
    )


def _target_victim_from_doc(doc: Dict[str, Any]) -> Optional[str]:
    for field in (
        "target_victim",
        "target_ip",
        "target_country",
        "target_country_name",
        "victim_country",
        "victim_country_name",
        "target_organization",
        "target_org",
    ):
        value = str(doc.get(field) or "").strip()
        if value and value.lower() not in {"none", "null", "unknown", "n/a", "-"}:
            return value
    return None


def _attack_time_event_row(
    doc: Dict[str, Any],
    time_mode: str = TIME_MODE_OBSERVED,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Dict[str, Any]:
    timestamp = _pick_display_time_in_range(doc, time_mode, start_date, end_date)
    sources = _normalize_sources(doc)
    threat_types = [str(item) for item in (doc.get("ai_threat_types") or doc.get("threat_type") or []) if str(item).strip()]
    return {
        "event_id": doc["_id"],
        "timestamp": timestamp.isoformat().replace("+00:00", "Z") if timestamp else None,
        "severity": _severity_label(_normalize_severity(doc.get("severity"))),
        "threat_types": threat_types,
        "ioc_value": doc.get("ioc_value") or doc.get("value"),
        "source_attacker": doc.get("source_ip") or _country_from_doc(doc),
        "target_victim": _target_victim_from_doc(doc),
        "source_name": sources[0] if sources else None,
        "description": doc.get("description") or doc.get("reference"),
    }


def _average_events_per_day(total_events: int, docs: Sequence[Dict[str, Any]], start_date: Optional[str], end_date: Optional[str], time_mode: str) -> float:
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if start_bound and end_bound:
        days = max((end_bound.date() - start_bound.date()).days + 1, 1)
        return round(total_events / days, 2)
    unique_days = {
        timestamp.astimezone(BANGKOK_TZ).date()
        for doc in docs
        if (timestamp := _pick_display_time_in_range(doc, time_mode, start_date, end_date))
    }
    return round(total_events / max(len(unique_days), 1), 2)


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
        if current_value > 0:
            return {"previous_value": previous_value, "delta_percent": 100.0, "direction": "up"}
        return {"previous_value": previous_value, "delta_percent": 0.0, "direction": "flat"}

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


def _primary_source(doc: Dict[str, Any]) -> Optional[str]:
    sources = _normalize_sources(doc)
    return sources[0] if sources else None


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
    if high > 0:
        return "high"
    if int(severity_counts.get("medium", 0)) > 0:
        return "medium"
    if int(severity_counts.get("low", 0)) > 0:
        return "low"
    return "clean"


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
            _source_severity(doc)
            for doc in docs
        )
        display_severity = _origin_display_severity(severity_counts)
        # Filter out countries where the highest severity is "clean"
        if display_severity == "clean":
            continue
        # Exclude clean count from the total value
        clean_count = int(severity_counts.get("clean", 0))
        value_without_clean = max(value - clean_count, 0)
        if value_without_clean == 0:
            continue
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
            if _is_high_confidence_source(source) or _safe_float(doc.get("confidence"), 0.0) >= 9.0
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
                "country_name": _country_name_from_code_or_raw(country),
                "value": value_without_clean,
                "latitude": latitude,
                "longitude": longitude,
                "severity": display_severity,
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
        return _normalize_sources(doc)
    if report_key == "threat-types":
        values = doc.get("ai_threat_types") or doc.get("threat_type") or []
        return [str(value) for value in values if str(value).strip()]
    if report_key == "attack-origins":
        values = [
            _country_from_doc(candidate)
            for candidate in (datalake_candidates or [])
        ]
        values.append(_country_from_doc(doc))
        countries = [str(value) for value in values if str(value or "").strip()]
        return countries
    sector = _sector_info(doc)
    return [sector["sector_name_th"]] if sector.get("sector_name_th") else []


def _filter_warehouse_docs(
    docs: Sequence[Dict[str, Any]],
    query: Optional[str] = None,
    threat_types: Optional[Sequence[str]] = None,
    sources: Optional[Sequence[str]] = None,
    severities: Optional[Sequence[str]] = None,
    risk_levels: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    allowed_threat_types = {item.lower() for item in (threat_types or []) if str(item).strip()}
    allowed_sources = {item.lower() for item in (sources or []) if str(item).strip()}
    allowed_severities = {_normalize_severity(item) for item in (severities or []) if str(item).strip()}
    allowed_risk_levels = {_normalize_severity(item) for item in (risk_levels or []) if str(item).strip()}
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
            severity = _source_severity(doc)
            if severity not in allowed_severities:
                continue
        if allowed_risk_levels:
            risk_level = _ai_severity(doc)
            if risk_level not in allowed_risk_levels:
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


def _ioc_doc_matches_date_range(
    doc: Dict[str, Any],
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    time_mode: str = TIME_MODE_PROCESSED,
) -> bool:
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if start_bound is None and end_bound is None:
        return True

    mode_fields = PYTHON_FILTER_FIELDS.get(time_mode, PYTHON_FILTER_FIELDS["processed"])
    candidate_times = [_parse_dt(doc.get(field)) for field in mode_fields]
    for candidate in candidate_times:
        if candidate is None:
            continue
        if start_bound and candidate < start_bound:
            continue
        if end_bound and candidate > end_bound:
            continue
        return True

    # Range-overlap check: use first/last from mode-specific fields
    observed_from: Optional[datetime] = None
    observed_to: Optional[datetime] = None
    for field in mode_fields:
        parsed = _parse_dt(doc.get(field))
        if parsed is not None:
            if observed_from is None or parsed < observed_from:
                observed_from = parsed
            if observed_to is None or parsed > observed_to:
                observed_to = parsed

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
    return_es_total: bool = False,
    time_mode: str = TIME_MODE_PROCESSED,
    limit: int = 10000,
) -> "List[Dict[str, Any]] | tuple[List[Dict[str, Any]], int]":
    """Collect IOC docs using ES pagination instead of scroll-all."""
    min_risk = 80 if high_risk_only else None
    result = _search_warehouse_docs(
        query_text=query or "*",
        start_date=start_date,
        end_date=end_date,
        sources=list(sources or []) or None,
        threat_types=list(threat_types or []) or None,
        severities=list(severities or []) or None,
        ioc_types=list(ioc_types or []) or None,
        risk_levels=list(risk_levels or []) or None,
        min_risk_score=min_risk,
        sort_by=sort_by,
        limit=limit,
        offset=0,
        time_mode=time_mode,
    )
    es_total = _search_total(result)
    docs = _hits_to_docs(result)
    docs = sorted(
        docs,
        key=lambda item: (int(item.get("ai_risk_score") or 0), _pick_event_time(item) or datetime.min.replace(tzinfo=UTC)),
        reverse=(sort_order != "asc"),
    )
    if return_es_total:
        return docs, es_total
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
        severity = _source_severity(doc)
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
                "severity": max(
                    ("critical", "high", "medium", "low", "clean"),
                    key=lambda s, dist=item.get("severity_distribution", {}): int(dist.get(s) or 0),
                ) if item.get("severity_distribution") else None,
            }
            for item in ranking_items[:10]
        ]
    }
    severity_rows = [
        {"label": item["label"], **item["severity_distribution"]}
        for item in ranking_items[:10]
    ]
    return ranking_items, top_chart, severity_rows


AGGREGATABLE_REPORT_DIMENSIONS = {
    "intelligence-sources": {"field": "source_name", "missing": "unknown", "chart_title": "Top 5 Sources"},
    "threat-types": {"field": "ai_threat_types", "missing": "Unknown", "chart_title": "Top 5 Threat Types"},
    "attack-origins": {"field": "geo_country", "missing": "Unknown", "chart_title": "Top 5 Countries"},
    "target-sectors": {"field": "target_sector_name", "missing": "General/Multiple", "chart_title": "Top 5 Sectors"},
}


def _total_hits_value(result: Dict[str, Any]) -> int:
    total = (result.get("hits") or {}).get("total")
    if isinstance(total, dict):
        return int(total.get("value") or 0)
    return int(total or 0)


def _aggregation_interval(start_date: Optional[str], end_date: Optional[str]) -> str:
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    if start_bound and end_bound:
        days = max(1, (end_bound - start_bound).days)
        if days > 120:
            return "week"
        if days > 31:
            return "day"
    return "hour"


def _format_trend_bucket_label(key_as_string: Optional[str], interval: str) -> str:
    if not key_as_string:
        return "-"
    parsed = _parse_dt(key_as_string)
    if not parsed:
        return str(key_as_string)
    local = parsed.astimezone(BANGKOK_TZ)
    if interval == "hour":
        return local.strftime("%m-%d %H:%M")
    if interval == "week":
        return local.strftime("%Y-%m-%d")
    return local.strftime("%m-%d")


def _is_missing_dimension_label(value: Any) -> bool:
    label = str(value or "").strip().lower()
    return label in {"", "-", "none", "null", "unknown", "n/a", "na"}


def _report_dimension_label(report_key: str, raw_value: Any) -> Optional[str]:
    label_text = str(raw_value or "").strip()
    if _is_missing_dimension_label(label_text):
        return None
    if report_key == "attack-origins":
        country_label = _country_name_from_code_or_raw(label_text)
        if _is_missing_dimension_label(country_label) or _country_code_from_name(country_label) is None:
            return None
        return country_label
    if report_key == "intelligence-sources":
        return _source_display_name(label_text)
    if report_key == "target-sectors":
        return _sector_display_name(label_text)
    return label_text


def _build_aggregated_trend(
    groups_bucket: Dict[str, Any],
    report_key: str,
    interval: str,
) -> Dict[str, Any]:
    group_buckets = []
    for bucket in (groups_bucket.get("buckets") or []):
        label = _report_dimension_label(report_key, bucket.get("key"))
        if not label:
            continue
        group_buckets.append((bucket, label))
        if len(group_buckets) >= 5:
            break
    ordered_bucket_keys: List[int] = []
    labels_by_key: Dict[int, str] = {}
    series_by_label: List[Dict[str, Any]] = []

    for bucket, _label in group_buckets:
        for point in ((bucket.get("timeline") or {}).get("buckets") or []):
            key = int(point.get("key") or 0)
            if key not in labels_by_key:
                ordered_bucket_keys.append(key)
                labels_by_key[key] = _format_trend_bucket_label(point.get("key_as_string"), interval)

    ordered_bucket_keys.sort()
    for bucket, label in group_buckets:
        timeline = {
            int(point.get("key") or 0): int(point.get("doc_count") or 0)
            for point in ((bucket.get("timeline") or {}).get("buckets") or [])
        }
        points = [timeline.get(key, 0) for key in ordered_bucket_keys]
        direction, change_percent = _calculate_change(points)
        series_by_label.append(
            {
                "key": label,
                "label": label,
                "points": points,
                "total": int(bucket.get("doc_count") or 0),
                "direction": direction,
                "change_percent": round(change_percent, 2),
            }
        )

    title = AGGREGATABLE_REPORT_DIMENSIONS.get(report_key, {}).get("chart_title", "Top 5 Events")
    return {
        "title": title,
        "dimension": report_key,
        "buckets": [labels_by_key[key] for key in ordered_bucket_keys],
        "series": series_by_label,
    }


def _build_aggregated_report_payload(
    report_key: str,
    *,
    page: int,
    page_size: int,
    query: Optional[str],
    start_date: Optional[str],
    end_date: Optional[str],
    threat_types: Optional[List[str]],
    sources: Optional[List[str]],
    severities: Optional[List[str]],
    time_mode: str = TIME_MODE_PROCESSED,
) -> Optional[Dict[str, Any]]:
    dimension = AGGREGATABLE_REPORT_DIMENSIONS.get(report_key)
    if not dimension:
        return None

    client = get_elastic_client()
    filters = _warehouse_search_filters(
        severities=severities,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        time_mode=time_mode,
    )
    must: List[Dict[str, Any]] = []
    if query and query != "*":
        must.append(
            {
                "multi_match": {
                    "query": query,
                    "fields": ["ioc_value^3", "description", "reference", "ai_threat_types", "ai_threat_actors", "source_name"],
                }
            }
        )

    interval = _aggregation_interval(start_date, end_date)
    requested_group_size = max(page * page_size, 10)
    group_size = min(max(requested_group_size, 100), 10000)
    field = str(dimension["field"])
    terms_config: Dict[str, Any] = {
        "field": field,
        "size": group_size,
        "order": {"_count": "desc"},
    }
    if dimension.get("missing") is not None:
        terms_config["missing"] = dimension["missing"]

    report_time_field = "last_seen" if time_mode == TIME_MODE_OBSERVED else "processed_at"
    timeline_histogram: Dict[str, Any] = {
        "field": report_time_field,
        "calendar_interval": interval,
        "min_doc_count": 0,
        "format": "strict_date_optional_time",
    }
    bounds = _date_histogram_bounds(start_date, end_date)
    if bounds:
        timeline_histogram["hard_bounds"] = bounds

    body: Dict[str, Any] = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": must if must else [{"match_all": {}}],
                "filter": filters,
            }
        },
        "aggs": {
            "group_count": {"cardinality": {"field": field}},
            "severity_total": {"terms": {"field": "severity", "size": 10, "missing": "clean"}},
            "top_threat_total": {"terms": {"field": "ai_threat_types", "size": 1, "missing": "Unknown"}},
            "top_iocs_total": {
                "top_hits": {
                    "size": 5,
                    "_source": ["ioc_value", "ioc_type", report_time_field, "ai_risk_score"],
                    "sort": [
                        {"ai_risk_score": {"order": "desc", "missing": "_last"}},
                        {report_time_field: {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
                    ],
                }
            },
            "groups": {
                "terms": terms_config,
                "aggs": {
                    "severity": {"terms": {"field": "severity", "size": 10, "missing": "clean"}},
                    "top_threat": {"terms": {"field": "ai_threat_types", "size": 1, "missing": "Unknown"}},
                    "latest_seen": {"max": {"field": report_time_field, "format": "strict_date_optional_time"}},
                    "top_iocs": {
                        "top_hits": {
                            "size": 5,
                            "_source": ["ioc_value", "ioc_type", report_time_field, "ai_risk_score"],
                            "sort": [
                                {"ai_risk_score": {"order": "desc", "missing": "_last"}},
                                {report_time_field: {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
                            ],
                        }
                    },
                    "timeline": {"date_histogram": timeline_histogram},
                },
            },
        },
    }
    result = _safe_search(client.warehouse_index, body)
    aggs = result.get("aggregations") or {}
    if not aggs:
        result = _safe_search(client.warehouse_index, body)
        aggs = result.get("aggregations") or {}
    groups = (aggs.get("groups") or {}).get("buckets")
    if groups is None:
        return None

    total_events = _total_hits_value(result)
    ranking_items: List[Dict[str, Any]] = []
    visible_rank = 1
    for bucket in groups:
        label = _report_dimension_label(report_key, bucket.get("key"))
        if not label:
            continue
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
        for severity_bucket in ((bucket.get("severity") or {}).get("buckets") or []):
            severity = _normalize_severity(severity_bucket.get("key"))
            severity_counts[severity] = int(severity_bucket.get("doc_count") or 0)

        top_threat_bucket = next(iter((bucket.get("top_threat") or {}).get("buckets") or []), None)
        top_hits = ((bucket.get("top_iocs") or {}).get("hits") or {}).get("hits") or []
        sample_iocs = _unique_list([str((hit.get("_source") or {}).get("ioc_value") or "") for hit in top_hits if (hit.get("_source") or {}).get("ioc_value")], limit=5)
        latest_seen = (bucket.get("latest_seen") or {}).get("value_as_string")
        item = {
            "rank": visible_rank,
            "label": label,
            "group_type": report_key,
            "change_direction": "flat",
            "change_percent": 0,
            "main_threat_type": str(top_threat_bucket.get("key")) if top_threat_bucket else None,
            "severity_distribution": severity_counts,
            "total_events": int(bucket.get("doc_count") or 0),
            "share_percent": 0,
            "sources": [label] if report_key == "intelligence-sources" and label else [],
            "top_asset": sample_iocs[0] if sample_iocs else None,
            "sample_iocs": sample_iocs,
            "last_seen": latest_seen,
        }
        if report_key == "attack-origins":
            item["country_code"] = _country_code_from_name(label)
        ranking_items.append(item)
        visible_rank += 1

    if report_key == "attack-origins" and not ranking_items and total_events > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
        for severity_bucket in ((aggs.get("severity_total") or {}).get("buckets") or []):
            severity = _normalize_severity(severity_bucket.get("key"))
            severity_counts[severity] = int(severity_bucket.get("doc_count") or 0)
        top_threat_bucket = next(iter((aggs.get("top_threat_total") or {}).get("buckets") or []), None)
        top_hits = ((aggs.get("top_iocs_total") or {}).get("hits") or {}).get("hits") or []
        sample_iocs = _unique_list([str((hit.get("_source") or {}).get("ioc_value") or "") for hit in top_hits if (hit.get("_source") or {}).get("ioc_value")], limit=5)
        ranking_items.append(
            {
                "rank": 1,
                "label": "Unknown",
                "group_type": report_key,
                "change_direction": "flat",
                "change_percent": 0,
                "main_threat_type": str(top_threat_bucket.get("key")) if top_threat_bucket else None,
                "severity_distribution": severity_counts,
                "total_events": total_events,
                "share_percent": 100,
                "sources": [],
                "top_asset": sample_iocs[0] if sample_iocs else None,
                "sample_iocs": sample_iocs,
                "last_seen": None,
                "country_code": None,
            }
        )

    groups_total = sum(item["total_events"] for item in ranking_items)
    for item in ranking_items:
        item["share_percent"] = _percentage(item["total_events"], groups_total)

    trend_comparison = _build_aggregated_trend(aggs.get("groups") or {}, report_key, interval)
    series_by_label = {item["label"]: item for item in trend_comparison.get("series") or []}
    for item in ranking_items:
        series = series_by_label.get(item["label"]) or {}
        item["change_direction"] = series.get("direction", "flat")
        item["change_percent"] = round(_safe_float(series.get("change_percent"), 0.0), 2)

    top_chart = {
        "items": [
            {
                "key": item["label"],
                "label": item["label"],
                "value": item["total_events"],
                "percentage": item["share_percent"],
                "color": None,
                "severity": max(
                    ("critical", "high", "medium", "low", "clean"),
                    key=lambda s, dist=item.get("severity_distribution", {}): int(dist.get(s) or 0),
                ) if item.get("severity_distribution") else None,
            }
            for item in ranking_items[:10]
        ]
    }
    severity_rows = [{"label": item["label"], **item["severity_distribution"]} for item in ranking_items[:10]]
    # Buckets such as literal "None"/"null" are skipped above because they are
    # not user-meaningful dimensions. Keep totals aligned with rendered rows.
    group_total = len(ranking_items)

    return {
        "report_key": report_key,
        "title": report_key.replace("-", " ").title(),
        "summary": {
            "total_groups": group_total,
            "total_events": total_events,
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
        "trend_comparison": trend_comparison,
        "ranking": {
            "items": _page_slice(ranking_items, page, page_size),
            "total": group_total,
            "page": page,
            "page_size": page_size,
        },
        "meta": {
            "aggregation_mode": "elasticsearch",
            "sample_limited": False,
        },
    }


def _empty_operations_report_payload(
    report_key: str,
    *,
    page: int,
    page_size: int,
    query: Optional[str],
    start_date: Optional[str],
    end_date: Optional[str],
    threat_types: Optional[List[str]],
    sources: Optional[List[str]],
    severities: Optional[List[str]],
    reason: str,
) -> Dict[str, Any]:
    return {
        "report_key": report_key,
        "title": report_key.replace("-", " ").title(),
        "summary": {
            "total_groups": 0,
            "total_events": 0,
            "date_range": {"start_date": start_date, "end_date": end_date},
        },
        "filters": {
            "query": query,
            "threat_types": threat_types or [],
            "sources": sources or [],
            "severities": severities or [],
        },
        "top_chart": {"items": []},
        "severity_distribution": {"rows": []},
        "trend_comparison": {
            "title": AGGREGATABLE_REPORT_DIMENSIONS.get(report_key, {}).get("chart_title", "Events"),
            "dimension": report_key,
            "buckets": [],
            "series": [],
        },
        "ranking": {
            "items": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
        },
        "meta": {
            "aggregation_mode": "elasticsearch",
            "sample_limited": False,
            "data_available": False,
            "reason": reason,
        },
    }


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
        event_time = _parse_dt(doc.get("processed_at") or doc.get("created_at")) or _pick_event_time(doc)
        if not event_time:
            continue
        hour_key = _to_bangkok_hour(event_time)
        if hour_key not in training_keys:
            continue
        severity = _source_severity(doc)
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

    forecast_hours_list = [current_hour + timedelta(hours=index) for index in range(forecast_hours)]
    total_forecast = guarded_holt_winters_forecast([point["total"] for point in training_list], forecast_hours)
    critical_forecast = guarded_holt_winters_forecast([point["critical"] for point in training_list], forecast_hours)
    high_forecast = guarded_holt_winters_forecast([point["high"] for point in training_list], forecast_hours)
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
        # Use ES date_histogram aggregation instead of scroll-all
        hourly_aggs = _warehouse_dashboard_aggs(
            start_date=(now - timedelta(hours=72)).isoformat(),
            end_date=now.isoformat(),
            include_trend=True,
            time_mode=TIME_MODE_OBSERVED,
        )
        hourly_buckets = (hourly_aggs.get("trend") or {}).get("buckets") or []
        historical_points = []
        for bucket in hourly_buckets:
            ts = bucket.get("key_as_string") or ""
            severity_buckets = (bucket.get("severity") or {}).get("buckets") or {}
            historical_points.append({
                "hour": ts,
                "timestamp": ts,
                "count": int(bucket.get("doc_count") or 0),
                "point_type": "historical",
                "critical": int((severity_buckets.get("critical") or {}).get("doc_count") or 0),
                "high": int((severity_buckets.get("high") or {}).get("doc_count") or 0),
                "medium": int((severity_buckets.get("medium") or {}).get("doc_count") or 0),
                "low": int((severity_buckets.get("low") or {}).get("doc_count") or 0),
            })
        return {
            "points": historical_points,
            "forecast_start_index": len(historical_points),
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
        severity = _source_severity(doc)
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


def _build_executive_attack_volume_trend_from_buckets(buckets: Sequence[Dict[str, Any]], forecast_days: int = 7) -> Dict[str, Any]:
    points = []
    for bucket in buckets:
        parsed = _parse_dt(bucket.get("key_as_string"))
        if not parsed:
            continue
        local = parsed.astimezone(BANGKOK_TZ)
        severity_counts = _severity_counts_from_filter_agg(bucket.get("severity") or {})
        points.append(
            {
                "timestamp": local.isoformat(),
                "label": local.strftime("%m-%d %H:%M") if local.hour else local.strftime("%d-%m-%y"),
                "total": int(bucket.get("doc_count") or 0),
                "critical": int(severity_counts.get("critical") or 0),
                "high": int(severity_counts.get("high") or 0),
                "point_type": "historical",
            }
        )
    daily_agg: Dict[str, Dict[str, int]] = {}
    for p in points:
        ts = _parse_dt(p["timestamp"])
        if not ts:
            continue
        day_key = ts.strftime("%Y-%m-%d")
        day_bucket = daily_agg.setdefault(day_key, {"total": 0, "critical": 0, "high": 0})
        day_bucket["total"] += p["total"]
        day_bucket["critical"] += p["critical"]
        day_bucket["high"] += p["high"]
    daily_keys = sorted(daily_agg.keys())
    forecast_points: List[Dict[str, Any]] = []
    if daily_keys and forecast_days > 0:
        season = min(7, max(1, len(daily_keys)))
        total_fc = guarded_holt_winters_forecast(
            [daily_agg[k]["total"] for k in daily_keys],
            forecast_days,
            season_length=season,
        )
        critical_fc = guarded_holt_winters_forecast(
            [daily_agg[k]["critical"] for k in daily_keys],
            forecast_days,
            season_length=season,
        )
        high_fc = guarded_holt_winters_forecast(
            [daily_agg[k]["high"] for k in daily_keys],
            forecast_days,
            season_length=season,
        )
        last_day = datetime.strptime(daily_keys[-1], "%Y-%m-%d").replace(tzinfo=BANGKOK_TZ)
        for i in range(forecast_days):
            fc_day = last_day + timedelta(days=i + 1)
            forecast_points.append(
                {
                    "timestamp": fc_day.isoformat(),
                    "label": fc_day.strftime("%d-%m-%y"),
                    "total": total_fc[i],
                    "critical": critical_fc[i],
                    "high": high_fc[i],
                    "point_type": "forecast",
                }
            )
    return {
        "points": points + forecast_points,
        "forecast_start_index": len(points),
    }


def _build_threat_level_from_aggregations(
    stats: Dict[str, Any],
    aggs: Dict[str, Any],
    *,
    now: datetime,
) -> Dict[str, Any]:
    total = int(stats.get("total_threats") or 0)
    critical = int((stats.get("severity_counts") or {}).get("critical") or 0)
    high = int((stats.get("severity_counts") or {}).get("high") or 0)
    critical_high = critical + high
    severity_ratio = critical_high / total if total else 0

    trend_buckets = (aggs.get("trend") or {}).get("buckets") or []
    daily_counts = [int(b.get("doc_count") or 0) for b in trend_buckets]
    if len(daily_counts) >= 2:
        latest_count = daily_counts[-1]
        baseline_counts = daily_counts[:-1]
        baseline_avg = sum(baseline_counts) / len(baseline_counts) if baseline_counts else 0
        spike_ratio = latest_count / baseline_avg if baseline_avg > 0 else (3.0 if latest_count > 0 else 0.0)
    else:
        baseline_avg = 0.0
        spike_ratio = 0.0

    cii_sectors = {"critical_infrastructure", "government", "healthcare", "financial", "technology"}
    top_sectors = []
    cii_present = False
    sector_count = 0
    for bucket in ((aggs.get("sectors") or {}).get("buckets") or [])[:10]:
        key = str(bucket.get("key") or "").strip()
        if not key or key.lower() in {"none", "null", "unknown", "general/multiple"}:
            continue
        sev_buckets = (bucket.get("severity") or {}).get("buckets") or []
        has_high_crit = any(
            str(sb.get("key") or "").lower() in {"critical", "high"} and int(sb.get("doc_count") or 0) > 0
            for sb in sev_buckets
        )
        if has_high_crit:
            sector_count += 1
            if key.lower().replace(" ", "_") in cii_sectors or key.lower() in cii_sectors:
                cii_present = True
        if len(top_sectors) < 5:
            top_sectors.append({
                "sector": key,
                "sector_name": key,
                "sector_name_th": key,
                "count": int(bucket.get("doc_count") or 0),
            })
    weighted_sector_count = sector_count * (1.5 if cii_present else 1.0)

    actor_counts: Dict[str, int] = {}
    for bucket in ((aggs.get("threat_types") or {}).get("buckets") or []):
        key = str(bucket.get("key") or "").strip().lower()
        if key in {"apt", "apt group", "threat actor", "named actor"}:
            actor_counts[key] = int(bucket.get("doc_count") or 0)
    named_actor_count = len(actor_counts)

    def volume_score(value: float) -> Dict[str, Any]:
        if value >= 3:
            s, d = 100, "ผิดปกติมาก"
        elif value >= 2:
            s, d = 80, "สูงกว่าปกติชัดเจน"
        elif value >= 1.5:
            s, d = 60, "เริ่มผิดปกติ"
        elif value >= 1:
            s, d = 40, "ปกติ"
        else:
            s, d = 20, "น้อยกว่าปกติ"
        return {"score": s, "input": round(value, 2), "label": "IOC Volume Spike", "description": d}

    def sev_score(value: float) -> Dict[str, Any]:
        if value >= 0.5:
            s, d = 100, "ครึ่งหนึ่งเป็นภัยรุนแรง"
        elif value >= 0.3:
            s, d = 80, "สัดส่วนภัยรุนแรงสูง"
        elif value >= 0.15:
            s, d = 60, "สัดส่วนปานกลาง"
        elif value >= 0.05:
            s, d = 40, "สัดส่วนปกติ"
        else:
            s, d = 20, "ส่วนใหญ่เป็น Low"
        return {"score": s, "input": round(value, 2), "label": "Severity Distribution", "description": d}

    def sec_score(value: float) -> Dict[str, Any]:
        if value >= 4:
            s, d = 100, "กระทบหลายภาคส่วนรวม CII"
        elif value >= 3:
            s, d = 80, "กระทบหลายภาคส่วน"
        elif value >= 2:
            s, d = 60, "กระทบอย่างน้อย 2 ภาคส่วน"
        elif value >= 1:
            s, d = 40, "พบผลกระทบบางส่วน"
        else:
            s, d = 10, "ยังไม่พบผลกระทบภาคส่วนสำคัญ"
        return {"score": s, "input": round(value, 2), "label": "Sector Impact", "description": d}

    def act_score(count: int) -> Dict[str, Any]:
        if count >= 5:
            s, d = 100, "ตรวจพบ named actors หลายราย"
        elif count >= 3:
            s, d = 80, "ตรวจพบ actor activity ชัดเจน"
        elif count == 2:
            s, d = 60, "ตรวจพบ actor 2 ราย"
        elif count == 1:
            s, d = 40, "ตรวจพบ actor 1 ราย"
        else:
            s, d = 10, "ไม่พบ named actor"
        return {"score": s, "input": count, "label": "Threat Actor Activity", "description": d}

    factors = {
        "volume": volume_score(spike_ratio),
        "severity": sev_score(severity_ratio),
        "sector": sec_score(weighted_sector_count),
        "actor": act_score(named_actor_count),
    }
    score = round(
        factors["volume"]["score"] * 0.30
        + factors["severity"]["score"] * 0.25
        + factors["sector"]["score"] * 0.25
        + factors["actor"]["score"] * 0.20
    )
    if score >= 76:
        level, level_th = "critical", "วิกฤต"
    elif score >= 51:
        level, level_th = "elevated", "ยกระดับ"
    elif score >= 26:
        level, level_th = "guarded", "เฝ้าระวัง"
    else:
        level, level_th = "low", "ต่ำ"

    named_actors = [{"name": key, "count": value} for key, value in sorted(actor_counts.items(), key=lambda item: item[1], reverse=True)[:5]]

    return {
        "date": _to_bangkok_date(now),
        "timezone": "Asia/Bangkok",
        "score": score,
        "level": level,
        "level_th": level_th,
        "factors": factors,
        "inputs": {
            "total_iocs": total,
            "baseline_avg_14d": round(baseline_avg, 2),
            "spike_ratio": round(spike_ratio, 2),
            "critical_high_ratio": round(severity_ratio, 4),
            "high_critical_sector_count": sector_count,
            "cii_sector_present": cii_present,
            "named_actor_count": named_actor_count,
        },
        "top_sectors": top_sectors,
        "named_actors": named_actors,
    }


def _build_attack_origin_map_from_aggs(aggs: Dict[str, Any]) -> Dict[str, Any]:
    origins = []
    trusted_source_union = set()
    for bucket in ((aggs.get("countries") or {}).get("buckets") or [])[:10]:
        country = str(bucket.get("key") or "").strip()
        if not country or country.lower() in {"none", "null", "unknown", "-"}:
            continue
        severity_counts = _severity_counts_from_filter_agg(bucket.get("severity") or {})
        display_severity = _origin_display_severity(Counter(severity_counts))
        # Filter out countries where the highest severity is "clean"
        if display_severity == "clean":
            continue
        # Exclude clean count from the total value
        clean_count = int(severity_counts.get("clean") or 0)
        total_count = int(bucket.get("doc_count") or 0)
        value_without_clean = max(total_count - clean_count, 0)
        if value_without_clean == 0:
            continue
        source_buckets = (bucket.get("sources") or {}).get("buckets") or []
        trusted_sources = [
            str(source_bucket.get("key") or "")
            for source_bucket in source_buckets
            if _is_high_confidence_source(source_bucket.get("key"))
            or int(source_bucket.get("doc_count") or 0) >= 5
        ][:4]
        trusted_source_union.update(trusted_sources)
        sector_bucket = next(iter((bucket.get("sectors") or {}).get("buckets") or []), None)
        primary_sector = str((sector_bucket or {}).get("key") or "General/Multiple")
        origins.append(
            {
                "country_code": _country_code_from_name(country),
                "country_name": _country_name_from_code_or_raw(country),
                "value": value_without_clean,
                "latitude": None,
                "longitude": None,
                "severity": display_severity,
                "critical_count": int(severity_counts.get("critical") or 0),
                "high_count": int(severity_counts.get("high") or 0),
                "primary_sector": primary_sector,
                "high_confidence_sources": len(trusted_sources),
                "trusted_sources": trusted_sources,
            }
        )
    all_source_buckets = (aggs.get("sources") or {}).get("buckets") or []
    all_trusted_sources = {
        str(source_bucket.get("key") or "")
        for source_bucket in all_source_buckets
        if _is_high_confidence_source(source_bucket.get("key"))
    }
    trusted_source_union.update(all_trusted_sources)

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


def _operations_overview_from_aggs(aggs: Dict[str, Any], recent_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "active_ioc": int((aggs.get("active_iocs") or {}).get("value") or aggs.get("total") or 0),
        "critical_ioc_active": int((aggs.get("critical_active") or {}).get("doc_count") or 0),
        "new_ioc": int((recent_stats or {}).get("total_threats") or 0),
        "sources_active": int((aggs.get("source_count") or {}).get("value") or 0),
        "high_ioc_active": int((aggs.get("high_active") or {}).get("doc_count") or 0),
    }


def _operations_overview(docs: List[Dict[str, Any]], anchor_end: Optional[datetime] = None) -> Dict[str, Any]:
    severities = [_source_severity(doc) for doc in docs]
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
        "high_ioc_active": sum(1 for severity in severities if severity == "high"),
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
    severity = _severity_label(_source_severity(doc))
    sector = _sector_info(doc)
    action_meta = derive_action_metadata(doc)
    country = _country_from_doc(doc)
    ioc_type = str(doc.get("ioc_type", "")).lower()
    context_parts = [
        sector["sector_name"],
    ]
    if doc.get("ai_threat_types"):
        context_parts.insert(0, ", ".join(doc.get("ai_threat_types") or []))
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
        "sources": _normalize_sources(doc),
        "sla": "2 hours" if severity == "Critical" else "24 hours",
        "event_time": timestamp.isoformat().replace("+00:00", "Z") if timestamp else None,
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
    related_nodes = [{"id": f"ioc:{doc.get('ioc_value')}", "type": "ioc", "label": doc.get("ioc_value")}]
    related_edges = []
    threat_types = [item for item in (doc.get("ai_threat_types") or []) if str(item).strip()]
    if threat_types:
        related_nodes.append({"id": f"type:{threat_types[0]}", "type": "threat_type", "label": threat_types[0]})
        related_edges.append({"source": related_nodes[0]["id"], "target": related_nodes[1]["id"], "relation": "classified_as"})
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
                    "message": event.get("description") or event.get("reference"),
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
            "source": primary_event.get("source_ip") or ", ".join(_normalize_sources(doc)),
            "source_name": primary_event.get("source_name") or _primary_source(doc),
            "target_victim": primary_event.get("target_ip"),
            "sector": sector["sector_name"],
            "threat_type": ", ".join(doc.get("ai_threat_types") or []),
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
        "severity": _severity_label(_source_severity(doc)),
        "risk_score": int(doc.get("ai_risk_score") or 0),
        "threat_types": doc.get("ai_threat_types") or doc.get("threat_type") or [],
        "sources": _normalize_sources(doc),
        "first_seen": doc.get("first_seen") or doc.get("event_time") or doc.get("collect_time"),
        "last_seen": doc.get("last_seen") or doc.get("collect_time") or doc.get("processed_at"),
        "score_breakdown": doc.get("ai_score_breakdown") or {},
        "top_factors": doc.get("ai_top_factors") or [],
        "credibility_score": int(doc.get("credibility_score") or 0),
        "impact_score": int(doc.get("impact_score") or 0),
        "operational_risk_score": int(doc.get("operational_risk_score") or doc.get("ai_risk_score") or 0),
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
    for actor in _relationship_actors(warehouse_doc):
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
    enrichment_docs = [doc for doc in datalake_docs if isinstance(doc, dict)]
    first_enrichment = enrichment_docs[0] if enrichment_docs else {}
    country = next((value for value in (_country_from_doc(item) for item in enrichment_docs) if value), None) or _country_from_doc(warehouse_doc)
    geo_info = _first_dict_from_docs(enrichment_docs, _doc_geo_info)
    geo_ip = _first_dict_from_docs(enrichment_docs, _doc_geo_ip)
    ip_info = _first_dict_from_docs(enrichment_docs, _doc_ip_info)
    asn_data = _first_dict_from_docs(enrichment_docs, _doc_asn_data)
    whois = _first_dict_from_docs(enrichment_docs, _doc_whois)
    owner_org = _first_detail_text(
        whois.get("org"),
        whois.get("organization"),
        asn_data.get("org"),
        asn_data.get("asn_name"),
        ip_info.get("org"),
        ip_info.get("isp"),
        geo_ip.get("org"),
        geo_ip.get("isp"),
        geo_ip.get("as_org"),
    )
    asn_number = _first_detail_text(
        asn_data.get("asn"),
        asn_data.get("as_number"),
        asn_data.get("number"),
        ip_info.get("asn"),
        ip_info.get("as_number"),
        geo_ip.get("asn"),
        geo_ip.get("as_number"),
    )
    latitude, longitude = _coordinates_from_docs(enrichment_docs)
    history_preview = []
    for doc in datalake_docs[:5]:
        observed_at = _pick_event_time(doc)
        history_preview.append(
            {
                "observed_at": observed_at.isoformat().replace("+00:00", "Z") if observed_at else None,
                "source": _datalake_event_source(doc),
                "severity": _datalake_event_severity(doc),
                "description": _datalake_event_description(doc),
            }
        )
    references = _unique_list([doc.get("reference") for doc in datalake_docs if doc.get("reference")], limit=10)
    return {
        "key_identifiers": {
            "ioc_value": warehouse_doc.get("ioc_value"),
            "ioc_type": warehouse_doc.get("ioc_type"),
            "ioc_type_label": IOC_TYPE_LABELS.get(str(warehouse_doc.get("ioc_type", "")).lower(), str(warehouse_doc.get("ioc_type", "")).upper()),
            "severity": _severity_label(_source_severity(warehouse_doc)),
            "sources": _normalize_sources(warehouse_doc),
            "first_seen": warehouse_doc.get("first_seen") or warehouse_doc.get("event_time") or warehouse_doc.get("collect_time"),
            "threat_types": warehouse_doc.get("ai_threat_types") or warehouse_doc.get("threat_type") or [],
        },
        "risk_assessment": {
            "model": warehouse_doc.get("score_model_version") or "ai-scoring",
            "risk_score": int(warehouse_doc.get("ai_risk_score") or 0),
            "risk_level": _severity_label(_ai_severity(warehouse_doc)),
            "severity": _severity_label(_source_severity(warehouse_doc)),
            "summary": ", ".join(warehouse_doc.get("ai_threat_types") or []) or None,
            "contributing_factors": breakdown_factors,
        },
        "geo_location_owner": {
            "country": country,
            "city": _first_detail_text(geo_info.get("city"), ip_info.get("city"), geo_ip.get("city")),
            "asn_org": owner_org,
            "latitude": latitude,
            "longitude": longitude,
        },
        "network_ownership": {
            "organization": owner_org,
            "net_name": _first_detail_text(_first_doc_text(enrichment_docs, "net_name", "netname"), whois.get("net_name"), whois.get("netname")),
            "net_range": _first_detail_text(_first_doc_text(enrichment_docs, "net_range", "range"), whois.get("net_range"), whois.get("range")),
            "cidr": _first_detail_text(_first_doc_text(enrichment_docs, "cidr"), whois.get("cidr"), ip_info.get("cidr")),
            "country": country,
            "allocation_type": _first_detail_text(_first_doc_text(enrichment_docs, "allocation_type"), whois.get("allocation_type")),
            "rir": _first_detail_text(_first_doc_text(enrichment_docs, "rir"), whois.get("rir")),
            "registered_on": _first_detail_text(_first_doc_text(enrichment_docs, "registered_on"), whois.get("registered_on"), whois.get("creation_date"), whois.get("created")),
            "last_updated": _first_detail_text(_first_doc_text(enrichment_docs, "last_updated"), whois.get("last_updated"), whois.get("updated_date"), whois.get("updated")),
        },
        "asn_infrastructure": {
            "asn": asn_number,
            "asn_name": owner_org,
            "asn_description": _first_detail_text(asn_data.get("description"), ip_info.get("asn_description"), owner_org),
            "asn_type": _first_detail_text(_first_doc_text(enrichment_docs, "asn_type"), ip_info.get("asn_type")),
            "hosting_type": _first_detail_text(_first_doc_text(enrichment_docs, "hosting_type"), ip_info.get("hosting_type")),
        },
        "abuse_contact": {
            "abuse_email": _first_detail_text(whois.get("abuse_email"), whois.get("registrant_email"), ip_info.get("abuse_email")),
            "abuse_contact": _first_detail_text(_first_doc_text(enrichment_docs, "abuse_contact"), ip_info.get("abuse_contact")),
            "noc_email": _first_detail_text(_first_doc_text(enrichment_docs, "noc_email"), ip_info.get("noc_email")),
            "tech_email": _first_detail_text(_first_doc_text(enrichment_docs, "tech_email"), ip_info.get("tech_email")),
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
                    "source_name": _datalake_event_source(doc),
                    "reference": doc.get("reference"),
                    "event_time": (_datalake_event_time(doc) or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
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


def _relationship_node(node_id: str, node_type: str, label: Any, **extra: Any) -> Dict[str, Any]:
    node = {"id": node_id, "type": node_type, "label": str(label or "")}
    node.update({key: value for key, value in extra.items() if value is not None})
    return node


def _relationship_edge(source: str, target: str, relation: str, **extra: Any) -> Dict[str, Any]:
    edge = {"source": source, "target": target, "relation": relation}
    edge.update({key: value for key, value in extra.items() if value is not None})
    return edge


def _relationship_actors(doc: Dict[str, Any], max_actors: int = 5) -> List[str]:
    """Return actors reliable enough for relationship graph edges.

    Some source-rule records contain a broad actor catalogue from scoring
    evidence. Treating those as graph evidence creates false relationships.
    """
    actors = _unique_list(str(actor).strip() for actor in (doc.get("ai_threat_actors") or []) if str(actor).strip())
    if len(actors) > max_actors:
        return []
    return actors


def _is_displayable_relationship_threat_type(value: Any) -> bool:
    label = str(value or "").strip().lower()
    return bool(label) and label not in {"other", "unknown", "none", "null", "n/a", "-"}


def _iter_relationship_evidence_items(value: Any, depth: int = 0) -> Iterable[Dict[str, Any]]:
    if depth > 3:
        return
    if isinstance(value, dict):
        yield value
        raw_evidence = value.get("raw_evidence")
        if isinstance(raw_evidence, (dict, list)):
            yield from _iter_relationship_evidence_items(raw_evidence, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _iter_relationship_evidence_items(item, depth + 1)


def _relationship_infer_ioc_type(value: Any, type_hint: Any = None) -> Optional[str]:
    normalized_hint = str(type_hint or "").strip().lower()
    hint_map = {
        "ip": "ip",
        "ip-src": "ip",
        "ip-dst": "ip",
        "ip_address": "ip",
        "ip-address": "ip",
        "ip_addresses": "ip",
        "ip-addresses": "ip",
        "ipv4-addr": "ip",
        "ipv4": "ip",
        "ipv6": "ip",
        "domain": "domain",
        "domain-name": "domain",
        "hostname": "domain",
        "url": "url",
        "uri": "url",
        "file_name": "file",
        "filename": "file",
        "file-name": "file",
        "file": "file",
        "md5": "hash",
        "sha1": "hash",
        "sha-1": "hash",
        "sha256": "hash",
        "sha-256": "hash",
        "hash": "hash",
        "hashes": "hash",
        "cve": "cve",
        "vulnerability": "cve",
    }
    raw = _refang_indicator_value(str(value or "").strip())
    if not raw:
        return None
    if any(char in raw for char in ("[", "]", "{", "}")):
        return None
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", raw, flags=re.IGNORECASE):
        return "cve"
    if normalized_hint in hint_map:
        return hint_map[normalized_hint]
    inferred = _infer_ioc_type_from_value(raw)
    if inferred == "domain":
        # Avoid drawing file-like or template fragments as domains.
        if any(char in raw for char in ("/", "[", "]", "{", "}", " ")):
            return None
        labels = raw.split(".")
        if len(labels) < 2 or not re.fullmatch(r"[A-Za-z]{2,24}", labels[-1]):
            return None
        if labels[-1].lower() in {"exe", "dll", "php", "js", "gpg", "bin", "bat", "cmd", "ps1", "sh"}:
            return None
    return inferred


def _relationship_node_for_indicator(ioc_type: str, ioc_value: str, **extra: Any) -> Dict[str, Any]:
    normalized_type = str(ioc_type or "").strip().lower()
    normalized_value = _refang_indicator_value(str(ioc_value or "").strip())
    if normalized_type == "cve":
        return _relationship_node(f"cve:{normalized_value.upper()}", "cve", normalized_value.upper(), **extra)
    return _relationship_node(
        f"ioc:{_indicator_id(normalized_type, normalized_value)}",
        "ioc",
        normalized_value,
        ioc_type=normalized_type,
        **extra,
    )


def _extract_relationship_evidence_entries(
    warehouse_doc: Dict[str, Any],
    datalake_docs: Sequence[Dict[str, Any]],
    limit: int = 12,
) -> List[Dict[str, Any]]:
    primary_indicator = _indicator_id(warehouse_doc.get("ioc_type", ""), warehouse_doc.get("ioc_value", ""))
    entries: List[Dict[str, Any]] = []
    seen: set = {primary_indicator}

    def add_entry(raw_value: Any, type_hint: Any, source_doc: Dict[str, Any], evidence_source: str) -> None:
        if len(entries) >= limit:
            return
        normalized_value = _refang_indicator_value(str(raw_value or "").strip())
        ioc_type = _relationship_infer_ioc_type(normalized_value, type_hint)
        if not ioc_type or not normalized_value:
            return
        if ioc_type == "cve":
            normalized_value = normalized_value.upper()
        indicator = _indicator_id(ioc_type, normalized_value)
        if indicator in seen:
            return
        seen.add(indicator)
        event_time = _pick_event_time(source_doc)
        observed = event_time.isoformat().replace("+00:00", "Z") if event_time else None
        entries.append(
            {
                "ioc_type": ioc_type,
                "ioc_value": normalized_value,
                "indicator": indicator,
                "relation": "correlated_with",
                "evidence_source": evidence_source,
                "first_seen": source_doc.get("first_seen") or source_doc.get("event_time") or observed,
                "last_seen": source_doc.get("last_seen") or source_doc.get("processed_at") or observed,
            }
        )

    source_docs = [warehouse_doc, *list(datalake_docs)]
    for source_doc in source_docs:
        for evidence in _iter_relationship_evidence_items(source_doc.get("source_evidence")):
            related_iocs = evidence.get("related_iocs")
            if isinstance(related_iocs, list):
                related_types = evidence.get("related_ioc_types")
                for index, raw_value in enumerate(related_iocs):
                    type_hint = related_types[index] if isinstance(related_types, list) and len(related_types) == len(related_iocs) else None
                    add_entry(raw_value, type_hint, source_doc, str(evidence.get("evidence_type") or "source_evidence"))

        correlations = source_doc.get("correlations")
        if not isinstance(correlations, dict):
            continue
        related_docs = correlations.get("related_docs")
        if not isinstance(related_docs, list):
            continue
        for related in related_docs:
            if not isinstance(related, dict):
                continue
            add_entry(
                related.get("original_ioc") or related.get("ioc_value") or related.get("value"),
                related.get("type") or related.get("ioc_type"),
                source_doc,
                "correlations.related_docs",
            )

    return entries


def _append_relationship(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    relationship_log: List[Dict[str, Any]],
    seen_nodes: set,
    seen_edges: set,
    source_node: Dict[str, Any],
    target_node: Dict[str, Any],
    relation: str,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
) -> None:
    for node in (source_node, target_node):
        if node["id"] not in seen_nodes:
            nodes.append(node)
            seen_nodes.add(node["id"])
    edge_key = (source_node["id"], target_node["id"], relation)
    if edge_key in seen_edges:
        return
    edges.append(_relationship_edge(source_node["id"], target_node["id"], relation))
    seen_edges.add(edge_key)
    relationship_log.append(
        {
            "source": source_node["label"],
            "source_type": source_node["type"],
            "relationship": relation,
            "target": target_node["label"],
            "target_type": target_node["type"],
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    )


def _build_ioc_relationship_graph(
    warehouse_doc: Dict[str, Any],
    datalake_docs: List[Dict[str, Any]],
    related_docs: Sequence[Dict[str, Any]],
    evidence_entries: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    relationship_log: List[Dict[str, Any]] = []
    seen_nodes: set = set()
    seen_edges: set = set()
    indicator = _indicator_id(warehouse_doc.get("ioc_type", ""), warehouse_doc.get("ioc_value", ""))
    ioc_node = _relationship_node(
        f"ioc:{indicator}",
        "ioc",
        warehouse_doc.get("ioc_value"),
        ioc_type=warehouse_doc.get("ioc_type"),
        severity=_severity_label(_source_severity(warehouse_doc)),
        risk_score=int(warehouse_doc.get("ai_risk_score") or 0),
    )
    if ioc_node["id"] not in seen_nodes:
        nodes.append(ioc_node)
        seen_nodes.add(ioc_node["id"])

    first_seen = warehouse_doc.get("first_seen") or warehouse_doc.get("event_time") or warehouse_doc.get("collect_time")
    last_seen = warehouse_doc.get("last_seen") or warehouse_doc.get("processed_at") or warehouse_doc.get("collect_time")
    for threat_type in warehouse_doc.get("ai_threat_types") or warehouse_doc.get("threat_type") or []:
        if not _is_displayable_relationship_threat_type(threat_type):
            continue
        target_node = _relationship_node(f"type:{threat_type}", "threat_type", threat_type)
        _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, ioc_node, target_node, "classified_as", first_seen, last_seen)

    for actor in _relationship_actors(warehouse_doc):
        if not str(actor).strip():
            continue
        actor_node = _relationship_node(f"actor:{actor}", "actor", actor)
        _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, actor_node, ioc_node, "uses", first_seen, last_seen)

    # source_evidence.related_iocs is correlation evidence, not direct actor
    # attribution. It may be used as an IOC -> IOC hop, but any actor/type shown
    # after that must come from the related IOC's own metadata.
    evidence_by_indicator: Dict[str, Dict[str, Any]] = {}
    for entry in evidence_entries or []:
        entry_indicator = entry.get("indicator") or _indicator_id(entry.get("ioc_type", ""), entry.get("ioc_value", ""))
        if entry_indicator and entry_indicator not in evidence_by_indicator:
            evidence_by_indicator[entry_indicator] = dict(entry)

    # Check if main IOC is a CVE pattern — create cve node instead
    _cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    ioc_value = warehouse_doc.get("ioc_value", "")
    if _cve_pattern.match(ioc_value):
        cve_node = _relationship_node(f"cve:{ioc_value.upper()}", "cve", ioc_value.upper())
        if cve_node["id"] not in seen_nodes:
            nodes.append(cve_node)
            seen_nodes.add(cve_node["id"])
        # Link actors to this CVE with "exploits"
        for actor in _relationship_actors(warehouse_doc):
            if not str(actor).strip():
                continue
            actor_node = _relationship_node(f"actor:{actor}", "actor", actor)
            _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, actor_node, cve_node, "exploits", first_seen, last_seen)

    for doc in datalake_docs:
        observed = (_pick_event_time(doc) or datetime.now(UTC)).isoformat().replace("+00:00", "Z")
        enrichment = doc.get("enrichment") or {}
        related = enrichment.get("related_entities") if isinstance(enrichment, dict) else {}
        if isinstance(related, dict):
            for malware in related.get("malware_family") or []:
                malware_node = _relationship_node(f"malware:{malware}", "malware", malware)
                _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, ioc_node, malware_node, "hosts", observed, observed)

        # Infrastructure nodes from WHOIS, ASN, and GeoIP owner data. These are
        # explicit enrichment fields, not fuzzy "similar IOC" links.
        whois = _doc_whois(doc)
        if isinstance(whois, dict):
            registrant_email = whois.get("registrant_email")
            if registrant_email and str(registrant_email).strip():
                infra_node = _relationship_node(f"infra:email:{registrant_email}", "infrastructure", registrant_email)
                _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, ioc_node, infra_node, "shares_infra", observed, observed)
            name_server = whois.get("name_server")
            if name_server and str(name_server).strip():
                ns_list = name_server if isinstance(name_server, list) else [name_server]
                for ns in ns_list:
                    if str(ns).strip():
                        infra_node = _relationship_node(f"infra:ns:{ns}", "infrastructure", str(ns))
                        _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, ioc_node, infra_node, "shares_infra", observed, observed)
        asn_data = _doc_asn_data(doc)
        geo_ip = _doc_geo_ip(doc)
        ip_info = _doc_ip_info(doc)
        asn_org = _first_detail_text(
            asn_data.get("org"),
            asn_data.get("asn_name"),
            ip_info.get("org"),
            ip_info.get("isp"),
            geo_ip.get("org"),
            geo_ip.get("isp"),
            geo_ip.get("as_org"),
        )
        asn_number = _first_detail_text(
            asn_data.get("asn"),
            asn_data.get("as_number"),
            ip_info.get("asn"),
            ip_info.get("as_number"),
            geo_ip.get("asn"),
            geo_ip.get("as_number"),
        )
        if asn_org:
            infra_label = f"{asn_org} (AS{asn_number})" if asn_number else asn_org
            infra_node = _relationship_node(f"infra:asn:{asn_number or asn_org}", "infrastructure", infra_label)
            _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, ioc_node, infra_node, "shares_infra", observed, observed)

        # CVE nodes from enrichment
        cve_info = enrichment.get("cve_info") if isinstance(enrichment, dict) else None
        if isinstance(cve_info, dict):
            cve_id = cve_info.get("cve_id") or cve_info.get("id")
            if cve_id and str(cve_id).strip():
                cve_node = _relationship_node(f"cve:{str(cve_id).upper()}", "cve", str(cve_id).upper())
                # actors exploit CVE
                for actor in _relationship_actors(warehouse_doc):
                    if not str(actor).strip():
                        continue
                    actor_node = _relationship_node(f"actor:{actor}", "actor", actor)
                    _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, actor_node, cve_node, "exploits", observed, observed)
                # CVE affects vendor
                vendor_name = cve_info.get("vendor") or enrichment.get("affected_vendor")
                if vendor_name and str(vendor_name).strip():
                    vendor_node = _relationship_node(f"vendor:{vendor_name}", "vendor", str(vendor_name))
                    _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, cve_node, vendor_node, "affects", observed, observed)
        elif isinstance(enrichment, dict) and enrichment.get("affected_vendor"):
            # Vendor from affected_vendor field without full cve_info
            vendor_name = enrichment["affected_vendor"]
            if str(vendor_name).strip():
                vendor_node = _relationship_node(f"vendor:{vendor_name}", "vendor", str(vendor_name))
                # If we have a CVE node from the main IOC, link it
                if _cve_pattern.match(ioc_value):
                    cve_node = _relationship_node(f"cve:{ioc_value.upper()}", "cve", ioc_value.upper())
                    _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, cve_node, vendor_node, "affects", observed, observed)

        if doc.get("cluster_label") is not None:
            campaign_label = f"cluster_{doc['cluster_label']}"
            campaign_node = _relationship_node(f"campaign:{doc['cluster_label']}", "campaign", campaign_label)
            _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges, ioc_node, campaign_node, "same_campaign", observed, observed)

    # Hop 2: related IOCs (max 10, sorted by risk score desc). Keep this
    # evidence-based: only related_docs discovered from source evidence or
    # documented campaign membership are eligible. Do not infer a direct
    # relationship from a generic shared threat type or actor label.
    MAX_RELATED = 10
    MAX_NODES = 50
    MAX_EDGES = 100
    sorted_related = sorted(
        related_docs,
        key=lambda d: int(d.get("ai_risk_score") or 0),
        reverse=True,
    )
    hop2_nodes: list = []
    for related_doc in sorted_related:
        if len(hop2_nodes) >= MAX_RELATED:
            break
        related_indicator = _indicator_id(related_doc.get("ioc_type", ""), related_doc.get("ioc_value", ""))
        if related_indicator == indicator:
            continue
        if related_indicator not in evidence_by_indicator and related_doc.get("cluster_label") is None:
            continue
        hop2_nodes.append(related_doc)

    for related_doc in hop2_nodes:
        if len(nodes) >= MAX_NODES or len(edges) >= MAX_EDGES:
            break
        related_indicator = _indicator_id(related_doc.get("ioc_type", ""), related_doc.get("ioc_value", ""))
        related_node = _relationship_node(
            f"ioc:{related_indicator}",
            "ioc",
            related_doc.get("ioc_value"),
            ioc_type=related_doc.get("ioc_type"),
            severity=_severity_label(_source_severity(related_doc)),
            risk_score=int(related_doc.get("ai_risk_score") or 0),
        )
        rel_first = related_doc.get("first_seen") or related_doc.get("event_time")
        rel_last = related_doc.get("last_seen") or related_doc.get("processed_at")
        cluster_label = related_doc.get("cluster_label")
        evidence_entry = evidence_by_indicator.get(related_indicator)

        if evidence_entry:
            evidence_first = evidence_entry.get("first_seen") or rel_first
            evidence_last = evidence_entry.get("last_seen") or rel_last
            _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges,
                                 ioc_node, related_node, "correlated_with", evidence_first, evidence_last)

            for threat_type in related_doc.get("ai_threat_types") or related_doc.get("threat_type") or []:
                if not _is_displayable_relationship_threat_type(threat_type):
                    continue
                target_node = _relationship_node(f"type:{threat_type}", "threat_type", threat_type)
                _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges,
                                     related_node, target_node, "classified_as", rel_first, rel_last)

            for actor in _relationship_actors(related_doc):
                if not str(actor).strip():
                    continue
                actor_node = _relationship_node(f"actor:{actor}", "actor", actor)
                _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges,
                                     actor_node, related_node, "uses", rel_first, rel_last)

        if cluster_label is not None:
            # The design document defines same_campaign as HDBSCAN cluster
            # membership. Do not use this relation for generic shared labels.
            campaign_label = f"cluster_{cluster_label}"
            campaign_node = _relationship_node(f"campaign:{cluster_label}", "campaign", campaign_label)
            _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges,
                                 ioc_node, campaign_node, "same_campaign", rel_first, rel_last)
            _append_relationship(nodes, edges, relationship_log, seen_nodes, seen_edges,
                                 related_node, campaign_node, "same_campaign", rel_first, rel_last)

    first_datalake = datalake_docs[0] if datalake_docs else {}
    detail = _build_ioc_detail(warehouse_doc, datalake_docs)
    return {
        "matched_ioc": _build_ioc_record(1, warehouse_doc),
        "key_attributes": {
            "asn": detail["asn_infrastructure"].get("asn"),
            "asn_name": detail["asn_infrastructure"].get("asn_name"),
            "country": detail["geo_location_owner"].get("country"),
            "city": detail["geo_location_owner"].get("city"),
            "reputation": first_datalake.get("reputation") or first_datalake.get("source_risk_score"),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "sources": _normalize_sources(warehouse_doc),
        },
        "relationship": {
            "nodes": nodes,
            "edges": edges,
            "capabilities": {
                "actors": any(node["type"] == "actor" for node in nodes),
                "campaigns": any(node["type"] == "campaign" for node in nodes),
                "malware": any(node["type"] == "malware" for node in nodes),
                "infrastructure": any(node["type"] == "infrastructure" for node in nodes),
                "cve": any(node["type"] == "cve" for node in nodes),
                "vendors": any(node["type"] == "vendor" for node in nodes),
            },
        },
        "relationship_log": relationship_log,
        "related_iocs": [_build_ioc_record(index + 1, doc) for index, doc in enumerate(related_docs[:20])],
    }


def _date_label_for_doc(doc: Dict[str, Any]) -> str:
    event_time = _pick_event_time(doc)
    if not event_time:
        return ""
    return event_time.astimezone(BANGKOK_TZ).date().isoformat()


def _build_threat_type_detail_payload(
    threat_type: str,
    docs: Sequence[Dict[str, Any]],
    page: int,
    page_size: int,
    es_total: Optional[int] = None,
) -> Dict[str, Any]:
    total = len(docs)
    display_total = max(es_total, total) if es_total is not None else total
    ioc_type_counts = Counter(str(doc.get("ioc_type") or "").lower() for doc in docs if doc.get("ioc_type"))
    sector_counts = Counter(_sector_info(doc)["sector_name"] for doc in docs if _sector_info(doc).get("sector_name"))
    actor_counts = Counter(actor for doc in docs for actor in (doc.get("ai_threat_actors") or []) if str(actor).strip())
    source_counts = Counter(source for doc in docs for source in _normalize_sources(doc))
    severity_counts = Counter(_source_severity(doc) for doc in docs)
    mitre_values = []
    for doc in docs:
        for technique in doc.get("ai_mitre_techniques") or []:
            if not technique:
                continue
            if isinstance(technique, dict):
                mitre_values.append(str(technique.get("external_id") or technique.get("name") or ""))
            else:
                mitre_values.append(str(technique))
    mitre_counts = Counter(value for value in mitre_values if value.strip())
    trend_counts = Counter(_date_label_for_doc(doc) for doc in docs)

    def _counter_items(counter: Counter, key_name: str = "name", limit: Optional[int] = None) -> List[Dict[str, Any]]:
        items = counter.most_common(limit)
        return [
            {
                key_name: key,
                "count": count,
                "percentage": _percentage(count, total),
            }
            for key, count in items
        ]

    return {
        "threat_type": threat_type,
        "summary": {
            "total_iocs": total,
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "clean": severity_counts.get("clean", 0),
        },
        "ioc_type_distribution": [
            {
                "ioc_type": key,
                "label": IOC_TYPE_LABELS.get(key, key.upper()),
                "count": count,
                "percentage": _percentage(count, total),
            }
            for key, count in ioc_type_counts.most_common()
        ],
        "trend": [
            {"date": key, "count": trend_counts[key]}
            for key in sorted(trend_counts.keys())
            if key != "unknown"
        ],
        "targeted_sectors": [
            {
                "sector": key,
                "count": count,
                "percentage": _percentage(count, total),
            }
            for key, count in sector_counts.most_common(10)
        ],
        "related_attackers": _counter_items(actor_counts, key_name="actor", limit=20),
        "related_mitre_techniques": _counter_items(mitre_counts, key_name="technique", limit=20),
        "sources": _counter_items(source_counts, key_name="source", limit=20),
        "related_iocs": _page_slice([_build_ioc_record(index + 1, doc) for index, doc in enumerate(docs)], page, page_size),
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": display_total,
        },
    }


def _doc_text_blob(doc: Dict[str, Any]) -> str:
    fields = [
        doc.get("ioc_value"),
        doc.get("title"),
        doc.get("description"),
        doc.get("reference"),
        doc.get("source_name"),
        doc.get("source_type"),
        doc.get("source_malware_family"),
        doc.get("source_campaigns"),
        doc.get("ai_threat_types"),
        doc.get("ai_threat_actors"),
        doc.get("ai_mitre_techniques"),
        doc.get("source_evidence"),
    ]
    return " ".join(json.dumps(item, ensure_ascii=False, default=str) if isinstance(item, (dict, list)) else str(item or "") for item in fields)


def _pick_processed_time(doc: Dict[str, Any]) -> Optional[datetime]:
    return _parse_dt(doc.get("processed_at") or doc.get("created_at")) or _pick_event_time(doc)


def _build_trend_event_rows(
    docs: Sequence[Dict[str, Any]],
    *,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    time_mode: str = TIME_MODE_OBSERVED,
) -> List[Dict[str, Any]]:
    grouped: Dict[tuple, Dict[str, Any]] = {}
    for doc in docs:
        severity = _source_severity(doc)
        if severity == "clean":
            continue
        display_time = _pick_display_time_in_range(doc, time_mode, start_date, end_date)
        if not display_time:
            continue
        hour_bucket = _start_bangkok_hour(display_time)
        sector = _sector_info(doc)
        sector_name = str(sector.get("sector_name") or "General/Multiple").strip() or "General/Multiple"
        threat_type = _primary_threat_type(doc) or "Other"
        key = (hour_bucket.isoformat(), sector_name, threat_type)
        row = grouped.setdefault(
            key,
            {
                "rank": 0,
                "event_id": f"trend::{hour_bucket.isoformat()}::{sector_name}::{threat_type}",
                "timestamp": hour_bucket.isoformat(),
                "sector": sector_name,
                "threat_types": [threat_type],
                "severity": "Low",
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
            },
        )
        row[severity] = int(row.get(severity) or 0) + 1
        row["total"] = int(row.get("total") or 0) + 1
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[_normalize_severity(str(row.get("severity") or "low"))]:
            row["severity"] = _severity_label(severity)

    rows = sorted(
        grouped.values(),
        key=lambda item: (
            _parse_dt(item.get("timestamp")) or datetime.min.replace(tzinfo=UTC),
            int(item.get("total") or 0),
        ),
        reverse=True,
    )
    for index, row in enumerate(rows, start=1):
        row["rank"] = index
    return rows


def _build_cve_records(
    warehouse_docs: Sequence[Dict[str, Any]],
    datalake_docs: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}

    def _append_doc(cve_id: str, doc: Dict[str, Any], source_kind: str) -> None:
        current = grouped.setdefault(cve_id, {"cve_id": cve_id, "warehouse_docs": [], "datalake_docs": []})
        current["warehouse_docs" if source_kind == "warehouse" else "datalake_docs"].append(doc)

    for doc in warehouse_docs:
        cves = _extract_cve_ids(doc.get("ioc_value"), doc.get("description"), doc.get("reference"), doc.get("ai_threat_types"), doc.get("source_evidence"))
        if str(doc.get("ioc_type") or "").lower() == "cve" and doc.get("ioc_value"):
            cves = _unique_list([str(doc["ioc_value"]).upper()] + cves)
        for cve_id in cves:
            _append_doc(cve_id, doc, "warehouse")

    for doc in datalake_docs:
        cves = _extract_cve_ids(doc.get("ioc_value"), doc.get("description"), doc.get("reference"), doc.get("threat_type"), doc.get("source_evidence"))
        if str(doc.get("ioc_type") or "").lower() == "cve" and doc.get("ioc_value"):
            cves = _unique_list([str(doc["ioc_value"]).upper()] + cves)
        for cve_id in cves:
            _append_doc(cve_id, doc, "datalake")

    records: List[Dict[str, Any]] = []
    exploit_markers = ("actively exploited", "known exploited", "kev", "rce", "remote code execution", "command injection", "arbitrary command")
    for cve_id, bucket in grouped.items():
        all_docs = bucket["warehouse_docs"] + bucket["datalake_docs"]
        if not all_docs:
            continue
        latest_time = max((_pick_event_time(doc) for doc in all_docs if _pick_event_time(doc)), default=None)
        earliest_time = min((_pick_event_time(doc) for doc in all_docs if _pick_event_time(doc)), default=None)
        warehouse_related = bucket["warehouse_docs"]
        risk_score = max((int(doc.get("ai_risk_score") or 0) for doc in warehouse_related), default=0)
        severity = max(
            (_source_severity(doc) for doc in all_docs),
            key=lambda item: SEVERITY_ORDER.get(item, 0),
            default="low",
        )
        text_blob = " ".join(_doc_text_blob(doc).lower() for doc in all_docs)
        records.append(
            {
                "cve_id": cve_id,
                "title": next((doc.get("title") or doc.get("description") for doc in all_docs if doc.get("title") or doc.get("description")), cve_id),
                "severity": _severity_label(severity),
                "risk_score": risk_score,
                "exploited_in_the_wild": any(marker in text_blob for marker in exploit_markers),
                "threat_types": _unique_list([item for doc in all_docs for item in _as_list(doc.get("ai_threat_types") or doc.get("threat_type"))]),
                "affected_sectors": _unique_list([_sector_info(doc)["sector_name"] for doc in warehouse_related if _sector_info(doc)["sector_name"]]),
                "sources": _unique_list([source for doc in all_docs for source in _normalize_sources(doc)]),
                "related_iocs": _unique_list([doc.get("ioc_value") for doc in warehouse_related if doc.get("ioc_value") and str(doc.get("ioc_value")).upper() != cve_id], limit=20),
                "first_seen": earliest_time.isoformat().replace("+00:00", "Z") if earliest_time else None,
                "last_seen": latest_time.isoformat().replace("+00:00", "Z") if latest_time else None,
                "warehouse_doc_count": len(bucket["warehouse_docs"]),
                "datalake_doc_count": len(bucket["datalake_docs"]),
            }
        )
    return sorted(records, key=lambda item: (item["risk_score"], item["last_seen"] or ""), reverse=True)


def _build_threat_landscape_payload(
    warehouse_docs: Sequence[Dict[str, Any]],
    datalake_docs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    threat_counts = Counter(threat for doc in warehouse_docs for threat in _as_list(doc.get("ai_threat_types") or doc.get("threat_type")))
    actor_counts = Counter(actor for doc in warehouse_docs for actor in (doc.get("ai_threat_actors") or []) if str(actor).strip())
    sector_counts = Counter(_sector_info(doc)["sector_name"] for doc in warehouse_docs if _sector_info(doc).get("sector_name"))
    source_counts = Counter(source for doc in list(warehouse_docs) + list(datalake_docs) for source in _normalize_sources(doc))
    country_counts = Counter(country for country in (_country_from_doc(doc) for doc in list(datalake_docs) + list(warehouse_docs)) if country)
    ioc_type_counts = Counter(str(doc.get("ioc_type") or "").lower() for doc in warehouse_docs if doc.get("ioc_type"))
    severity_counts = Counter(_source_severity(doc) for doc in warehouse_docs)
    total = len(warehouse_docs)
    high_risk = sum(1 for doc in warehouse_docs if int(doc.get("ai_risk_score") or 0) >= 80)
    return {
        "summary": {
            "total_iocs": total,
            "high_risk_iocs": high_risk,
            "critical_iocs": severity_counts.get("critical", 0),
            "active_threat_types": len(threat_counts),
            "active_actors": len(actor_counts),
            "observed_sources": len(source_counts),
        },
        "threat_types": _build_top_list(threat_counts, limit=10),
        "threat_actors": _build_top_list(actor_counts, limit=10),
        "target_sectors": _build_top_list(sector_counts, limit=10),
        "attack_origins": _build_top_list(country_counts, limit=10),
        "intelligence_sources": _build_top_list(source_counts, limit=10),
        "ioc_type_distribution": _build_top_list(ioc_type_counts, labels=IOC_TYPE_LABELS, limit=10),
        "severity_distribution": _build_severity_distribution(list(warehouse_docs)),
        "risk_distribution": [
            {"bucket": "0-19", "value": sum(1 for doc in warehouse_docs if int(doc.get("ai_risk_score") or 0) < 20)},
            {"bucket": "20-39", "value": sum(1 for doc in warehouse_docs if 20 <= int(doc.get("ai_risk_score") or 0) < 40)},
            {"bucket": "40-59", "value": sum(1 for doc in warehouse_docs if 40 <= int(doc.get("ai_risk_score") or 0) < 60)},
            {"bucket": "60-79", "value": sum(1 for doc in warehouse_docs if 60 <= int(doc.get("ai_risk_score") or 0) < 80)},
            {"bucket": "80-100", "value": high_risk},
        ],
    }


def _filter_news_docs(docs: List[Dict[str, Any]], query_text: Optional[str] = None, sources: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    allowed_sources = {item.lower() for item in NEWS_SOURCES}
    requested_sources = [item.lower() for item in (sources or [])]
    filtered = []
    for doc in docs:
        source_name = str(doc.get("source_name") or "").strip()
        source_type = str(doc.get("source_type") or "").strip().lower()
        if not source_name:
            continue
        if source_name.lower() not in allowed_sources and source_type not in {"news", "rss", "article"}:
            continue
        if requested_sources and not any(item in source_name.lower() for item in requested_sources):
            continue
        haystack = f"{doc.get('description', '')} {doc.get('reference', '')}".lower()
        if query_text and query_text.lower() not in haystack and query_text.lower() not in source_name.lower():
            continue
        filtered.append(doc)
    return filtered


def _search_news_docs(
    query_text: str = "*",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    client = get_elastic_client()
    filters: List[Dict[str, Any]] = [
        {
            "bool": {
                "should": [
                    {"terms": {"source_type": ["news", "rss", "article"]}},
                    {"terms": {"source_name": NEWS_SOURCES}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    if sources:
        filters.append(
            {
                "bool": {
                    "should": [{"match_phrase": {"source_name": source}} for source in sources],
                    "minimum_should_match": 1,
                }
            }
        )
    date_filter = _date_filter(_date_query_range(start_date, end_date), WAREHOUSE_TIME_FIELDS[TIME_MODE_PUBLISHED])
    if date_filter:
        filters.append(date_filter)
    return _search_documents(
        client.warehouse_index,
        query_text=query_text,
        filters=filters,
        limit=limit,
        sort=[{"published_at": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}],
        fields=["title^3", "description", "reference", "source_name", "ai_threat_types"],
    )


def _build_news_articles(docs: List[Dict[str, Any]], query_text: Optional[str] = None, sources: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    articles: Dict[str, Dict[str, Any]] = {}
    for doc in _filter_news_docs(docs, query_text=query_text, sources=sources):
        source_name = doc.get("source_name")
        event_time = _parse_dt(doc.get("published_at")) or _pick_event_time(doc)
        title_source = str(doc.get("title") or doc.get("description") or doc.get("reference") or doc.get("ioc_value") or "").strip()
        title = title_source.split(".")[0][:120]
        if not source_name or not title or not event_time:
            continue
        published_at = event_time.astimezone(UTC).isoformat().replace("+00:00", "Z")
        article_key = _hash_id(source_name, str(doc.get("reference") or title), _to_bangkok_date(event_time))
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


@router.post("/auth/sso/session", tags=["Auth"])
def dashboard_sso_session(
    request: SSOExchangeRequest,
    _: str = Depends(require_internal_api_key),
):
    request_data = (
        request.model_dump(exclude_none=True)
        if hasattr(request, "model_dump")
        else request.dict(exclude_none=True)
    )
    payload = get_dashboard_state().authenticate_sso(request_data)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid SSO identity")
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
    cache_key = _cache_key("lookups_threat_types", active=active, query=query)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    warehouse_aggs = _warehouse_dashboard_aggs(time_mode=TIME_MODE_OBSERVED)
    datalake_aggs = _datalake_dashboard_aggs(time_mode=TIME_MODE_OBSERVED)
    counts = Counter()
    for bucket in ((warehouse_aggs.get("threat_types") or {}).get("buckets") or []):
        counts[str(bucket.get("key") or "")] += int(bucket.get("doc_count") or 0)
    for bucket in ((datalake_aggs.get("threat_types") or {}).get("buckets") or []):
        counts[str(bucket.get("key") or "")] += int(bucket.get("doc_count") or 0)
    items = _lookup_items_from_counts(counts)
    if query:
        items = [item for item in items if query.lower() in item["label"].lower()]
    return _cache_set(cache_key, _success({"items": items}), ttl=300)


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
    cache_key = _cache_key("lookups_sources", active=active, query=query)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    warehouse_aggs = _warehouse_dashboard_aggs(time_mode=TIME_MODE_OBSERVED)
    datalake_aggs = _datalake_dashboard_aggs(time_mode=TIME_MODE_OBSERVED)
    counts = Counter()
    for bucket in ((warehouse_aggs.get("sources") or {}).get("buckets") or []):
        counts[str(bucket.get("key") or "")] += int(bucket.get("doc_count") or 0)
    for bucket in ((datalake_aggs.get("sources") or {}).get("buckets") or []):
        counts[str(bucket.get("key") or "")] += int(bucket.get("doc_count") or 0)
    items = _lookup_items_from_counts(counts)
    items = [{**item, "label": _source_display_name(item.get("label") or item.get("value"))} for item in items]
    if query:
        items = [item for item in items if query.lower() in item["label"].lower()]
    return _cache_set(cache_key, _success({"items": items}), ttl=300)


@router.get("/lookups/sectors", tags=["Lookups"])
def list_sectors(active: bool = True, query: Optional[str] = None, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    cache_key = _cache_key("lookups_sectors", active=active, query=query)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    warehouse_aggs = _warehouse_dashboard_aggs(time_mode=TIME_MODE_OBSERVED)
    items = []
    for bucket in ((warehouse_aggs.get("sectors") or {}).get("buckets") or []):
        raw_label = str(bucket.get("key") or "").strip()
        label = _sector_display_name(raw_label)
        if not label:
            continue
        items.append(
            {
                "value": raw_label,
                "label": label,
                "label_th": raw_label,
                "description": None,
                "active": active,
                "count": int(bucket.get("doc_count") or 0),
            }
        )
    if query:
        needle = query.lower()
        items = [item for item in items if needle in item["label"].lower() or needle in str(item.get("label_th", "")).lower()]
    return _cache_set(cache_key, _success({"items": items}), ttl=300)


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

    current_stats = _warehouse_summary_stats(start_date, end_date, time_mode=TIME_MODE_OBSERVED)
    current_aggs = _warehouse_dashboard_aggs(start_date=start_date, end_date=end_date, include_trend=True, time_mode=TIME_MODE_OBSERVED)
    previous_start_date, previous_end_date = _previous_date_window(start_date, end_date)
    previous_stats = _warehouse_summary_stats(previous_start_date, previous_end_date, time_mode=TIME_MODE_OBSERVED) if previous_start_date and previous_end_date else None
    severity_distribution = _build_severity_distribution_from_counts(current_stats.get("severity_counts") or {})
    treemap_nodes = _build_threat_volume_nodes_from_terms(current_stats.get("threat_types") or [])
    sector_treemap_nodes = _build_threat_volume_nodes_from_terms(current_stats.get("sector_terms") or [])
    threat_level = _build_threat_level_from_aggregations(current_stats, current_aggs, now=now)
    primary_sector = threat_level["top_sectors"][0] if threat_level["top_sectors"] else {"sector_name": "", "count": 0}
    attack_origin_map = _build_attack_origin_map_from_aggs(current_aggs)
    is_single_day = start_date == end_date
    today_bkk = _to_bangkok_date(datetime.now(UTC))
    include_forecast = is_single_day and end_date >= today_bkk
    if is_single_day:
        # Use ES date_histogram aggregation instead of scroll-all for hourly trend
        hourly_aggs = _warehouse_dashboard_aggs(
            start_date=(now - timedelta(hours=72)).isoformat(),
            end_date=now.isoformat(),
            include_trend=True,
            time_mode=TIME_MODE_OBSERVED,
        )
        hourly_buckets = (hourly_aggs.get("trend") or {}).get("buckets") or []
        historical_points = []
        for bucket in hourly_buckets:
            ts = bucket.get("key_as_string") or ""
            severity_buckets = (bucket.get("severity") or {}).get("buckets") or {}
            historical_points.append({
                "hour": ts,
                "timestamp": ts,
                "count": int(bucket.get("doc_count") or 0),
                "point_type": "historical",
                "critical": int((severity_buckets.get("critical") or {}).get("doc_count") or 0),
                "high": int((severity_buckets.get("high") or {}).get("doc_count") or 0),
                "medium": int((severity_buckets.get("medium") or {}).get("doc_count") or 0),
                "low": int((severity_buckets.get("low") or {}).get("doc_count") or 0),
            })
        attack_volume_trend = {
            "points": historical_points,
            "forecast_start_index": len(historical_points),
        }
        threat_volume_trend = attack_volume_trend
    else:
        forecast_days = 7 if end_date >= today_bkk else 0
        threat_volume_trend = _build_executive_attack_volume_trend_from_buckets(
            (current_aggs.get("trend") or {}).get("buckets") or [],
            forecast_days=forecast_days,
        )
        attack_volume_trend = threat_volume_trend
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
            current_stats=current_stats,
            previous_stats=previous_stats,
        ),
        "severity_distribution": severity_distribution,
        "threat_volume_severity": {"nodes": treemap_nodes},
        "sector_threat_volume_severity": {"nodes": sector_treemap_nodes},
        "threat_volume_trend": threat_volume_trend,
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
    aggs = _warehouse_dashboard_aggs(start_date=start_date, end_date=end_date, time_mode=TIME_MODE_OBSERVED)
    recent_start = _to_bangkok_date((anchor_end or datetime.now(UTC)) - timedelta(days=1))
    recent_end = _to_bangkok_date(anchor_end or datetime.now(UTC))
    recent_stats = _warehouse_summary_stats(recent_start, recent_end, time_mode=TIME_MODE_OBSERVED)
    payload = {
        "overview": _operations_overview_from_aggs(aggs, recent_stats=recent_stats),
        "incident_by_severity": _build_severity_distribution_from_counts(_severity_counts_from_filter_agg(aggs.get("severity_counts") or {})),
        "attack_time_heatmap": _build_attack_time_heatmap_from_aggs(start_date=start_date, end_date=end_date, time_mode=TIME_MODE_OBSERVED),
        "top_intelligence_sources": _terms_items_from_buckets((aggs.get("sources") or {}).get("buckets") or [], total=aggs.get("total"), limit=5),
        "top_threat_types": _terms_items_from_buckets((aggs.get("threat_types") or {}).get("buckets") or [], limit=5),
        "top_attack_origins": _terms_items_from_buckets((aggs.get("countries") or {}).get("buckets") or [], total=aggs.get("total"), limit=5),
        "target_sectors": _format_sector_terms(_terms_items_from_buckets((aggs.get("sectors") or {}).get("buckets") or [], total=aggs.get("total"), limit=5)),
    }
    return _success(payload)


@router.get("/operations/reports/threat-types/{threat_type:path}", tags=["Operations"])
def threat_type_report_detail(
    threat_type: str,
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    normalized_threat_type = str(threat_type or "").strip()
    if not normalized_threat_type:
        raise HTTPException(status_code=400, detail="Threat type is required")
    result = _search_warehouse_docs(
        query_text=query or "*",
        start_date=start_date,
        end_date=end_date,
        threat_types=[normalized_threat_type],
        sources=sources,
        severities=severities,
        sort_by="risk",
        limit=10000,
        offset=0,
        time_mode=TIME_MODE_OBSERVED,
    )
    es_total = _search_total(result)
    docs = _hits_to_docs(result)
    docs = sorted(
        docs,
        key=lambda item: (int(item.get("ai_risk_score") or 0), _pick_event_time(item) or datetime.min.replace(tzinfo=UTC)),
        reverse=True,
    )
    display_total = max(es_total, len(docs))
    return _success(_build_threat_type_detail_payload(normalized_threat_type, docs, page, page_size, es_total=display_total))


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
    cache_key = _cache_key(
        "operations_report",
        report_key=normalized_key,
        page=page,
        page_size=page_size,
        query=query,
        start_date=start_date,
        end_date=end_date,
        threat_types=threat_types,
        sources=sources,
        severities=severities,
    )
    cached = _cache_get(cache_key)
    if cached:
        return cached

    aggregated_payload = _build_aggregated_report_payload(
        normalized_key,
        page=page,
        page_size=page_size,
        query=query,
        start_date=start_date,
        end_date=end_date,
        threat_types=threat_types,
        sources=sources,
        severities=severities,
        time_mode=TIME_MODE_OBSERVED,
    )
    if aggregated_payload:
        return _cache_set(cache_key, _success(aggregated_payload))

    payload = _empty_operations_report_payload(
        normalized_key,
        page=page,
        page_size=page_size,
        query=query,
        start_date=start_date,
        end_date=end_date,
        threat_types=threat_types,
        sources=sources,
        severities=severities,
        reason="aggregation_unavailable",
    )
    return _cache_set(cache_key, _success(payload), ttl=15)


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


@router.get("/threat-intelligence/trend/events", tags=["Threat Intelligence"])
def threat_trend_events(
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
    cache_key = _cache_key("threat_trend_events", page=page, page_size=page_size, query=query, start_date=start_date, end_date=end_date, threat_types=threat_types, sources=sources, severities=severities)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    docs, es_total = _collect_ioc_docs(
        query=query,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        severities=severities,
        sort_by="time",
        return_es_total=True,
        time_mode=TIME_MODE_OBSERVED,
    )
    rows = _build_trend_event_rows(docs, start_date=start_date, end_date=end_date, time_mode=TIME_MODE_OBSERVED)
    severity_totals = {
        "critical": sum(int(item.get("critical") or 0) for item in rows),
        "high": sum(int(item.get("high") or 0) for item in rows),
        "medium": sum(int(item.get("medium") or 0) for item in rows),
        "low": sum(int(item.get("low") or 0) for item in rows),
    }
    total_threats = sum(severity_totals.values())
    payload = {
        "summary": {
            "total_events": total_threats,
            "critical": severity_totals["critical"],
            "high": severity_totals["high"],
            "medium": severity_totals["medium"],
            "low": severity_totals["low"],
            "raw_event_count": es_total,
            "grouped_row_count": len(rows),
        },
        "filters": {
            "query": query,
            "start_date": start_date,
            "end_date": end_date,
            "threat_types": threat_types or [],
            "sources": sources or [],
            "severities": severities or [],
        },
        "items": _page_slice(rows, page, page_size),
    }
    return _cache_set(cache_key, _paged(payload, page=page, page_size=page_size, total=len(rows)))


@router.get("/cve-intelligence", tags=["Threat Intelligence"])
def cve_intelligence(
    page: int = 1,
    page_size: int = 20,
    query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    sources: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    cache_key = _cache_key("cve_intelligence", page=page, page_size=page_size, query=query, start_date=start_date, end_date=end_date, sources=sources, severities=severities)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    wh_result = _search_warehouse_docs(
        query_text=query or "*",
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        severities=severities,
        sort_by="risk",
        limit=10000,
        offset=0,
        time_mode=TIME_MODE_PUBLISHED,
    )
    warehouse_docs = _hits_to_docs(wh_result)
    datalake_docs = _scroll_all_datalake_docs(start_date=start_date, end_date=end_date, sources=sources, severities=severities, time_mode=TIME_MODE_PUBLISHED)
    es_total_warehouse = _search_total(wh_result)
    es_total_datalake = len(datalake_docs)
    records = _build_cve_records(warehouse_docs, datalake_docs)
    if query and not CVE_PATTERN.search(query):
        needle = query.lower()
        records = [item for item in records if needle in item["cve_id"].lower() or needle in str(item.get("title") or "").lower()]
    es_total = max(es_total_warehouse, es_total_datalake)
    display_total = max(es_total, len(records))
    payload = {
        "summary": {
            "total_cves": display_total,
            "exploited_in_the_wild": sum(1 for item in records if item["exploited_in_the_wild"]),
            "critical": sum(1 for item in records if str(item["severity"]).lower() == "critical"),
            "high": sum(1 for item in records if str(item["severity"]).lower() == "high"),
        },
        "items": _page_slice(records, page, page_size),
    }
    return _cache_set(cache_key, _paged(payload, page=page, page_size=page_size, total=display_total))


@router.get("/cve-intelligence/{cve_id}", tags=["Threat Intelligence"])
def cve_intelligence_detail(cve_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    normalized_cve = str(cve_id or "").strip().upper()
    if not CVE_PATTERN.fullmatch(normalized_cve):
        raise HTTPException(status_code=400, detail="Invalid CVE identifier")
    warehouse_docs = _hits_to_docs(_search_warehouse_docs(query_text=normalized_cve, sort_by="risk", limit=10000))
    datalake_docs = _hits_to_docs(_search_datalake_docs(query_text=normalized_cve, limit=10000))
    records = _build_cve_records(warehouse_docs, datalake_docs)
    record = next((item for item in records if item["cve_id"] == normalized_cve), None)
    if not record:
        raise HTTPException(status_code=404, detail="CVE not found")
    related_ioc_docs = [
        _build_ioc_record(index + 1, doc)
        for index, doc in enumerate(warehouse_docs)
        if normalized_cve in _extract_cve_ids(doc.get("ioc_value"), doc.get("description"), doc.get("reference"), doc.get("source_evidence"))
    ]
    return _success({**record, "related_iocs_detail": related_ioc_docs})


@router.get("/threat-landscape", tags=["Threat Intelligence"])
def threat_landscape(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    query: Optional[str] = None,
    sources: Optional[List[str]] = Query(default=None),
    threat_types: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    cache_key = _cache_key("threat_landscape", start_date=start_date, end_date=end_date, query=query, sources=sources, threat_types=threat_types, severities=severities)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    warehouse_docs = _collect_ioc_docs(
        query=query,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        severities=severities,
        sort_by="risk",
        time_mode=TIME_MODE_OBSERVED,
    )
    datalake_docs = _scroll_all_datalake_docs(start_date=start_date, end_date=end_date, sources=sources, threat_types=threat_types, severities=severities, time_mode=TIME_MODE_OBSERVED)
    payload = _build_threat_landscape_payload(warehouse_docs, datalake_docs)
    payload["filters"] = {
        "query": query,
        "start_date": start_date,
        "end_date": end_date,
        "sources": sources or [],
        "threat_types": threat_types or [],
        "severities": severities or [],
    }
    return _cache_set(cache_key, _success(payload))


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
    docs, es_total_events = _collect_ioc_docs(
        query=query,
        start_date=start_date,
        end_date=end_date,
        threat_types=threat_types,
        sources=sources,
        severities=severities,
        sort_by="risk",
        sort_order="desc",
        return_es_total=True,
        time_mode=TIME_MODE_OBSERVED,
    )
    heatmap = _build_heatmap(docs, time_mode=TIME_MODE_OBSERVED, start_date=start_date, end_date=end_date)
    heatmap_peak = heatmap.get("peak") or {}
    if heatmap_peak and heatmap_peak.get("value", 0) > 0:
        peak_day = heatmap_peak.get("day") or heatmap_peak.get("label", "Monday")
        peak_time = heatmap_peak.get("hour", "00:00")
        peak_end = heatmap_peak.get("end_hour", "")
        peak_time_range = f"{peak_time} - {peak_end}" if peak_end else peak_time
    else:
        peak_day = "-"
        peak_time_range = "-"
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    by_day_hour: Dict[tuple, int] = {(day, hour): 0 for day in day_names for hour in range(24)}
    for doc in docs:
        event_time = _pick_display_time_in_range(doc, TIME_MODE_OBSERVED, start_date, end_date)
        if not event_time:
            continue
        local = event_time.astimezone(BANGKOK_TZ)
        by_day_hour[(local.strftime("%A"), local.hour)] = by_day_hour.get((local.strftime("%A"), local.hour), 0) + 1
    quiet = min(by_day_hour.items(), key=lambda item: item[1])[0] if any(v > 0 for v in by_day_hour.values()) else ("-", 0)
    total_events = max(es_total_events, len(docs))
    sorted_events = sorted(docs, key=lambda item: _pick_display_time_in_range(item, TIME_MODE_OBSERVED, start_date, end_date) or datetime.min.replace(tzinfo=UTC), reverse=True)
    paged_items = [_attack_time_event_row(event, TIME_MODE_OBSERVED, start_date, end_date) for event in _page_slice(sorted_events, page, page_size)]
    payload = {
        "summary": {
            "peak_attack_time": {"day": peak_day, "time_range": peak_time_range},
            "quietest_period": {"day": quiet[0], "time_range": "-" if quiet[0] == "-" else _hour_range_label((quiet[1] // 3) * 3, span=3)},
            "avg_attack_rate": _average_events_per_day(total_events, docs, start_date, end_date, TIME_MODE_OBSERVED),
            "highest_day": peak_day,
            "total_events": total_events,
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
        "events": {"items": paged_items, "total": total_events},
    }
    return _paged(payload, page=page, page_size=page_size, total=total_events)


@router.get("/operations/events/{event_id}", tags=["Operations"])
def operation_event_detail(event_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    client = get_elastic_client()
    document = client.get_index_document(client.warehouse_index, event_id) or client.get_index_document(client.datalake_index, event_id)
    if not document:
        raise HTTPException(status_code=404, detail="Event not found")
    formatted = _attack_time_event_row({"_id": event_id, **document}, TIME_MODE_OBSERVED)
    payload = {
        "event_id": event_id,
        "formatted": formatted,
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
    cache_key = _cache_key("list_actions", page=page, page_size=page_size, query=query, start_date=start_date, end_date=end_date, threat_types=threat_types, sources=sources, severities=severities, status=status)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    docs, es_total = _search_action_docs(
        query_text=query or "*",
        start_date=start_date,
        end_date=end_date,
        threat_types=threat_types,
        sources=sources,
        severities=severities,
        limit=2000,
        return_es_total=True,
    )
    state = get_dashboard_state()
    action_pairs = [(doc, _build_action_ticket(doc, state.get_action_assignment(doc["_id"]))) for doc in docs]
    if status:
        requested_statuses = {item.strip().lower() for item in status if str(item).strip()}
        action_pairs = [(doc, item) for doc, item in action_pairs if item["status"] in requested_statuses]
    filtered_docs = [doc for doc, _ in action_pairs]
    items = [item for _, item in action_pairs]
    display_total = max(es_total, len(items))
    facets = {
        "threat_types": [{"value": key, "label": key, "count": value} for key, value in Counter(threat for doc in filtered_docs for threat in (doc.get("ai_threat_types") or [])).most_common(10)],
        "sources": [{"value": key, "label": key, "count": value} for key, value in Counter(source for doc in filtered_docs for source in _normalize_sources(doc)).most_common(10)],
        "severities": [{"value": key, "label": _severity_label(key), "count": value} for key, value in Counter(_source_severity(doc) for doc in filtered_docs).most_common(5)],
        "statuses": [{"value": key, "label": key.replace("_", " ").title(), "count": value} for key, value in Counter(item["status"] for item in items).most_common()],
    }
    summary = {
        "total": display_total,
        "open": sum(1 for item in items if item["status"] == "open"),
        "in_progress": sum(1 for item in items if item["status"] == "in_progress"),
        "closed": sum(1 for item in items if item["status"] == "closed"),
    }
    paged_items = _page_slice(items, page, page_size)
    return _cache_set(cache_key, _paged({"summary": summary, "facets": facets, "items": paged_items}, page=page, page_size=page_size, total=display_total))


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


@router.post("/actions/{action_id}/notes", tags=["Actions"], status_code=201)
def create_action_note(action_id: str, request: ActionNoteRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    doc = _get_processed_doc(action_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Action not found")
    note = get_dashboard_state().append_action_note(action_id, current_user["name"], request.content.strip())
    return _success({"action_id": action_id, "note": note})


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
    cache_key = _cache_key("list_iocs", page=page, page_size=page_size, query=query, start_date=start_date, end_date=end_date, sources=sources, threat_types=threat_types, risk_levels=risk_levels, ioc_types=ioc_types, severities=severities, high_risk_only=high_risk_only, sort_by=sort_by, sort_order=sort_order)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    min_risk_score = 80 if high_risk_only else None
    search_result = _search_warehouse_docs(
        query_text=query or "*",
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        risk_levels=risk_levels,
        ioc_types=ioc_types,
        severities=severities,
        min_risk_score=min_risk_score,
        sort_by=sort_by,
        limit=page_size,
        offset=max(page - 1, 0) * page_size,
        time_mode=TIME_MODE_OBSERVED,
    )
    docs = _hits_to_docs(search_result)
    total = _search_total(search_result)
    aggs = _warehouse_dashboard_aggs(
        query=query,
        start_date=start_date,
        end_date=end_date,
        sources=sources,
        threat_types=threat_types,
        risk_levels=risk_levels,
        severities=severities,
        min_risk_score=min_risk_score,
        time_mode=TIME_MODE_OBSERVED,
    )
    items = [_build_ioc_record(index + 1, doc) for index, doc in enumerate(docs)]
    severity_facet_counts = _severity_counts_from_filter_agg(aggs.get("severity_counts") or {})
    risk_facet_counts = _severity_counts_from_filter_agg(aggs.get("risk_level_counts") or {})
    facets = {
        "sources": [{"value": item["key"], "label": item["label"], "count": item["value"]} for item in _terms_items_from_buckets((aggs.get("sources") or {}).get("buckets") or [], total=total, limit=10)],
        "threat_types": [{"value": item["key"], "label": item["label"], "count": item["value"]} for item in _terms_items_from_buckets((aggs.get("threat_types") or {}).get("buckets") or [], total=total, limit=10)],
        "risk_levels": [{"value": key, "label": _severity_label(key), "count": value} for key, value in risk_facet_counts.items() if value > 0],
        "ioc_types": [{"value": item["key"], "label": IOC_TYPE_LABELS.get(item["key"], item["key"].upper()), "count": item["value"]} for item in _terms_items_from_buckets((aggs.get("ioc_types") or {}).get("buckets") or [], total=total, limit=10)],
        "severities": [{"value": key, "label": _severity_label(key), "count": value} for key, value in severity_facet_counts.items() if value > 0],
    }
    quick_filters = {
        "ioc_types": [{"value": item["value"], "label": item["label"], "count": next((facet["count"] for facet in facets["ioc_types"] if facet["value"] == item["value"]), 0)} for item in IOC_TYPE_LOOKUPS],
        "severities": [{"value": item["value"], "label": item["label"], "count": next((facet["count"] for facet in facets["severities"] if facet["value"] == item["value"]), 0)} for item in RISK_LEVELS],
    }
    return _cache_set(cache_key, _paged({"summary": {"total_indicators": total}, "quick_filters": quick_filters, "facets": facets, "items": items}, page=page, page_size=page_size, total=total))


@router.get("/iocs/relationships", tags=["IOCs"])
def ioc_relationships(
    query: Optional[str] = None,
    ioc_type: Optional[str] = None,
    ioc_value: Optional[str] = None,
    ioc_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    target_type = str(ioc_type or "").strip().lower()
    target_value = _refang_indicator_value(ioc_value or "")
    if ioc_id:
        try:
            target_type, target_value = _split_indicator_id(ioc_id)
            target_value = _refang_indicator_value(target_value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if target_type and target_value:
        warehouse_doc = _get_warehouse_doc_by_indicator(target_type, target_value)
    else:
        search_text = _refang_indicator_value(query or "")
        if not search_text:
            raise HTTPException(status_code=400, detail="Provide query, ioc_id, or ioc_type and ioc_value")
        warehouse_doc = _get_warehouse_doc_by_value(search_text)
        if not warehouse_doc and _infer_ioc_type_from_value(search_text):
            # Never fall back to _collect_ioc_docs() here. That helper scrolls all
            # matching warehouse docs into Python and can stall the AI service for
            # a missing IOC on large datasets.
            matches = _hits_to_docs(
                _search_warehouse_docs(
                    query_text=search_text,
                    sort_by="risk",
                    limit=1,
                    time_mode=TIME_MODE_OBSERVED,
                )
            )
            warehouse_doc = matches[0] if matches else None
    if not warehouse_doc:
        raise HTTPException(status_code=404, detail="IOC not found")

    primary_indicator = (warehouse_doc.get("ioc_type", ""), warehouse_doc.get("ioc_value", ""))
    datalake_docs = _fetch_datalake_by_indicators([primary_indicator])
    primary_id = _indicator_id(*primary_indicator)
    seen_indicators: set = {primary_id}
    related_docs: list = []
    evidence_entries = _extract_relationship_evidence_entries(warehouse_doc, datalake_docs)

    for entry in evidence_entries:
        did = entry.get("indicator") or _indicator_id(entry.get("ioc_type", ""), entry.get("ioc_value", ""))
        if did in seen_indicators:
            continue
        wdoc = _get_warehouse_doc_by_indicator(entry.get("ioc_type", ""), entry.get("ioc_value", ""))
        if wdoc:
            seen_indicators.add(did)
            related_docs.append(wdoc)

    cluster_labels = [doc.get("cluster_label") for doc in datalake_docs if doc.get("cluster_label") is not None]
    if cluster_labels:
        cluster_indicators = [(doc.get("ioc_type", ""), doc.get("ioc_value", ""))
                              for doc in datalake_docs if doc.get("cluster_label") is not None]
        cluster_datalake = _fetch_datalake_by_cluster(cluster_labels[:5])
        for cdoc in cluster_datalake:
            cind = _indicator_id(cdoc.get("ioc_type", ""), cdoc.get("ioc_value", ""))
            if cind not in seen_indicators:
                seen_indicators.add(cind)
                wdoc = _get_warehouse_doc_by_indicator(cdoc.get("ioc_type", ""), cdoc.get("ioc_value", ""))
                if wdoc:
                    related_docs.append(wdoc)

    return _success(_build_ioc_relationship_graph(warehouse_doc, datalake_docs, related_docs, evidence_entries))


@router.get("/iocs/{ioc_id}", tags=["IOCs"])
def ioc_detail(ioc_id: str, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    ioc_type, ioc_value = _split_indicator_id(ioc_id)
    warehouse_doc = _get_warehouse_doc_by_indicator(ioc_type, ioc_value)
    if not warehouse_doc:
        raise HTTPException(status_code=404, detail="IOC not found")
    datalake_docs = _fetch_datalake_by_indicators([(ioc_type, ioc_value)])
    return _success(_build_ioc_detail(warehouse_doc, datalake_docs))


@router.get("/iocs/{ioc_id}/events", tags=["IOCs"])
def ioc_events(
    ioc_id: str,
    page: int = 1,
    page_size: int = 20,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    ioc_type, ioc_value = _split_indicator_id(ioc_id)
    raw_docs = _fetch_datalake_by_indicators([(ioc_type, ioc_value)])
    start_bound, end_bound = _resolve_date_bounds(start_date, end_date)
    docs = []
    for doc in raw_docs:
        observed_time = _datalake_event_time(doc)
        if start_bound or end_bound:
            if observed_time is None:
                continue
            if start_bound and observed_time < start_bound:
                continue
            if end_bound and observed_time > end_bound:
                continue
        docs.append(doc)
    docs = sorted(
        docs,
        key=lambda item: _datalake_event_time(item) or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    items = []
    for doc in _page_slice(docs, page, page_size):
        observed = _datalake_event_time(doc)
        items.append({
            "observed_at": observed.isoformat().replace("+00:00", "Z") if observed else None,
            "source": _datalake_event_source(doc),
            "severity": _datalake_event_severity(doc),
            "description": _datalake_event_description(doc),
        })
    return _paged({"items": items}, page=page, page_size=page_size, total=len(docs))


@router.get("/ioc-analytics", tags=["IOCs"])
def ioc_analytics(
    tab: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    cache_key = _cache_key("ioc_analytics", tab=tab, start_date=start_date, end_date=end_date)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    if tab == "ioc-summary":
        aggs = _warehouse_dashboard_aggs(start_date=start_date, end_date=end_date, time_mode=TIME_MODE_OBSERVED)
        total = int(aggs.get("total") or 0)
        severity_counts = _severity_counts_from_filter_agg(aggs.get("severity_counts") or {})
        by_source_breakdown = [
            {
                "source": str(bucket.get("key") or ""),
                **_severity_counts_from_filter_agg(bucket.get("severity") or {}),
            }
            for bucket in ((aggs.get("severity_by_source") or {}).get("buckets") or [])
            if str(bucket.get("key") or "").strip().lower() not in {"", "none", "null", "unknown"}
        ]
        by_type_breakdown = [
            {
                "type": IOC_TYPE_LABELS.get(str(bucket.get("key") or "").lower(), str(bucket.get("key") or "").upper()),
                **_severity_counts_from_filter_agg(bucket.get("severity") or {}),
            }
            for bucket in ((aggs.get("severity_by_type") or {}).get("buckets") or [])
            if str(bucket.get("key") or "").strip().lower() not in {"", "none", "null", "unknown"}
        ]
        risk_counts = _range_counts_from_agg(aggs.get("risk_score_ranges") or {}, ["0-19", "20-39", "40-59", "60-79", "80-100"])
        risk_distribution = [{"bucket": key, "value": value} for key, value in risk_counts.items()]
        unique_iocs = int((aggs.get("active_iocs") or {}).get("value") or total)
        critical_unique_iocs = int(((aggs.get("critical_active") or {}).get("active_iocs") or {}).get("value") or 0)
        payload = {
            "tab": "ioc-summary",
            "cards": {
                "total_ioc": total,
                "clean_ioc": severity_counts.get("clean", 0),
                # Backward compatible alias: the UI now presents this as "New IOCs"
                # for the selected observed date range.
                "active_ioc": unique_iocs,
                "new_ioc": unique_iocs,
                "critical_ioc": critical_unique_iocs,
                "critical_ioc_docs": severity_counts.get("critical", 0),
                "risk_ioc": int((aggs.get("high_risk") or {}).get("doc_count") or 0),
                "avg_risk_score": round(float((aggs.get("avg_risk_score") or {}).get("value") or 0), 1),
            },
            "charts": {
                "ioc_by_type": _terms_items_from_buckets((aggs.get("ioc_types") or {}).get("buckets") or [], total=total, labels=IOC_TYPE_LABELS, limit=25),
                "ioc_by_severity": _build_severity_distribution_from_counts(severity_counts),
                "threat_type_distribution": _terms_items_from_buckets((aggs.get("threat_types") or {}).get("buckets") or [], limit=25),
                "severity_by_source": by_source_breakdown,
                "severity_by_type": by_type_breakdown,
                "risk_score_distribution": risk_distribution,
            },
        }
        return _cache_set(cache_key, _success(payload))

    if tab == "statistics-import":
        aggs = _datalake_dashboard_aggs(start_date=start_date, end_date=end_date, time_mode=TIME_MODE_OBSERVED)
        total = int(aggs.get("total") or 0)
        using_warehouse_fallback = False
        if total == 0:
            # The UAT target keeps processed warehouse docs, but may not retain a
            # raw datalake mirror. Show actual imported warehouse data instead of
            # a misleading all-zero import dashboard.
            aggs = _warehouse_dashboard_aggs(start_date=start_date, end_date=end_date, include_trend=True, time_mode=TIME_MODE_OBSERVED)
            total = int(aggs.get("total") or 0)
            using_warehouse_fallback = True
        timeline_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: {"value": 0, "trusted": 0, "news": 0, "other": 0})
        timeline_buckets = (
            ((aggs.get("trend") or {}).get("buckets") or [])
            if using_warehouse_fallback
            else ((aggs.get("import_timeline") or {}).get("buckets") or [])
        )
        for bucket in timeline_buckets:
            parsed = _parse_dt(bucket.get("key_as_string"))
            timestamp = parsed.astimezone(BANGKOK_TZ).date().isoformat() if parsed else str(bucket.get("key_as_string") or "")
            bucket_total = int(bucket.get("doc_count") or 0)
            row = timeline_counts[timestamp]
            row["value"] += bucket_total
            source_buckets = ((bucket.get("sources") or {}).get("buckets") or [])
            source_total = 0
            for source_bucket in source_buckets:
                value = int(source_bucket.get("doc_count") or 0)
                source_total += value
                row[_source_category(source_bucket.get("key"))] += value
            if not source_buckets or source_total < bucket_total:
                row["other"] += max(0, bucket_total - source_total)
        timeline_points = [
            {"timestamp": timestamp, **values}
            for timestamp, values in sorted(timeline_counts.items())
        ]
        active_days = len([point for point in timeline_points if int(point.get("value") or 0) > 0]) or 1
        severity_counts = _severity_counts_from_filter_agg(aggs.get("severity_counts") or {})
        quality_complete = int((aggs.get("quality_complete") or {}).get("doc_count") or 0)
        data_quality_score = round((quality_complete / total) * 100) if total > 0 else 0
        source_items = _format_source_terms(_terms_items_from_buckets((aggs.get("sources") or {}).get("buckets") or [], total=total, limit=25))
        failed_import = total - quality_complete
        payload = {
            "tab": "statistics-import",
            "cards": {
                "total_import": total,
                "successful_import": quality_complete,
                "failed_import": failed_import,
                "avg_import_per_day": round(total / active_days, 2),
                "data_quality_score": data_quality_score,
            },
            "charts": {
                "import_volume_over_time": {"points": timeline_points},
                "ioc_by_intelligence_source": source_items,
                "ioc_by_type": _terms_items_from_buckets((aggs.get("ioc_types") or {}).get("buckets") or [], total=total, labels=IOC_TYPE_LABELS, limit=25),
                "threat_type_distribution": _terms_items_from_buckets((aggs.get("threat_types") or {}).get("buckets") or [], limit=25),
                "ioc_by_severity": _build_severity_distribution_from_counts(severity_counts),
                "import_by_source": [{"key": item["key"], "label": item["label"], "value": item["value"]} for item in source_items],
                "import_by_type": [{"key": item["key"], "label": item["label"], "value": item["value"]} for item in _terms_items_from_buckets((aggs.get("ioc_types") or {}).get("buckets") or [], total=total, labels=IOC_TYPE_LABELS, limit=25)],
                "import_by_severity": [{"key": key, "label": _severity_label(key), "value": value} for key, value in severity_counts.items()],
            },
        }
        return _cache_set(cache_key, _success(payload))

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
        time_mode=TIME_MODE_OBSERVED,
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
            "high_risk_count": sum(
                1 for doc in docs
                if _normalize_severity(doc.get("severity")) in ("critical", "high")
            ),
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
        time_mode=TIME_MODE_OBSERVED,
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
    datalake_docs = _scroll_all_datalake_docs(
        start_date=request.start_date.isoformat(),
        end_date=request.end_date.isoformat(),
        threat_types=request.threat_types or None,
        severities=request.severities or request.risk_levels or None,
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
        if doc.get("source_name"):
            item["sources"].add(doc.get("source_name"))
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
    cache_key = _cache_key("list_news", page=page, page_size=page_size, query=query, start_date=start_date, end_date=end_date, sources=sources, sort_by=sort_by)
    cached = _cache_get(cache_key)
    if cached:
        return cached
    docs = _scroll_all_news_docs(start_date=start_date, end_date=end_date, sources=sources)
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
    return _cache_set(cache_key, _paged({"items": _page_slice(items, page, page_size)}, page=page, page_size=page_size, total=len(items)))


@router.get("/news/{article_id}", tags=["News"])
def news_detail(
    article_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    docs = _scroll_all_news_docs(start_date=start_date, end_date=end_date)
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


@router.post("/ml/feedback", tags=["ML Feedback"], status_code=201)
def create_ml_feedback(request: MLFeedbackRequest, current_user: Dict[str, Any] = Depends(require_dashboard_user)):
    reviewer = current_user.get("email") or current_user.get("name") or current_user.get("user_id")
    if not reviewer:
        raise HTTPException(status_code=400, detail="Reviewer identity is required")
    payload = request.model_dump()
    payload["reviewer"] = str(reviewer)
    feedback_id = get_elastic_client().save_ml_feedback(payload)
    if not feedback_id:
        raise HTTPException(status_code=500, detail="Failed to save ML feedback")
    return _success({"feedback_id": feedback_id, "status": "open"})


@router.get("/ml/feedback", tags=["ML Feedback"])
def list_ml_feedback(
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    offset = max(page - 1, 0) * page_size
    result = get_elastic_client().search_ml_feedback(status=status, limit=page_size, offset=offset)
    hits = result.get("hits", {})
    total_raw = hits.get("total", 0)
    total = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw or 0)
    items = _hits_to_docs(result)
    return _paged({"items": items}, page=page, page_size=page_size, total=total)


@router.get("/diagnostics/data-sources", tags=["Diagnostics"])
def data_source_diagnostics(
    current_user: Dict[str, Any] = Depends(require_dashboard_user),
):
    """Return document counts and connectivity status for each ES index."""
    from elastic_client import DATALAKE_INDEX, WAREHOUSE_INDEX, PROCESSED_INDEX, QUARANTINE_INDEX

    client = get_elastic_client()
    indices_info: Dict[str, Any] = {}
    for label, index in [
        ("datalake", client.datalake_index),
        ("warehouse", client.warehouse_index),
        ("processed", PROCESSED_INDEX),
        ("quarantine", QUARANTINE_INDEX),
    ]:
        try:
            count = client.count_documents(index)
            indices_info[label] = {
                "index_name": index,
                "status": "available",
                "document_count": count,
            }
        except Exception as exc:
            indices_info[label] = {
                "index_name": index,
                "status": "error",
                "error": str(exc),
                "document_count": 0,
            }

    # Quick datalake search test (no date filters)
    datalake_test: Dict[str, Any] = {}
    try:
        test_body = {"size": 0, "track_total_hits": True, "query": {"match_all": {}}}
        test_result = client.search_index(client.datalake_index, test_body)
        datalake_test = {
            "status": "ok",
            "total_hits": _search_total(test_result),
        }
    except Exception as exc:
        datalake_test = {"status": "error", "error": str(exc)}

    return _success({
        "indices": indices_info,
        "datalake_search_test": datalake_test,
        "datalake_url": client.datalake_url,
        "warehouse_url": client.warehouse_url,
    })
