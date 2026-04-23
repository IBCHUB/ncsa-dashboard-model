"""
External threat sharing API routes for partner organizations.

This router exposes a REST/JSON v1 interface for:
- partner metadata and lookups
- outbound threat feed / incremental sync
- inbound IOC and event submissions
- export jobs for machine-consumable feeds
"""

from __future__ import annotations

import csv
from datetime import date, datetime
import io
import json
import logging
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from elastic_client import get_elastic_client
from services import dashboard_router
from services.external_sharing_bootstrap import (
    DEFAULT_EXPORT_FORMATS,
    TLP_LEVELS,
    get_external_state,
    reset_external_state,
)
from utils.sanitizer import sanitize_observation_fields, sanitize_text

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/external")

TLP_RANK = {value: index for index, value in enumerate(TLP_LEVELS)}
SEVERITY_BASE_SCORE = {
    "critical": 90,
    "high": 75,
    "medium": 50,
    "low": 25,
    "clean": 0,
}


class PartnerProfile(BaseModel):
    partner_id: str
    partner_name: str
    permissions: List[str]
    max_tlp: str
    allowed_ioc_types: List[str]
    allowed_formats: List[str]
    rate_limit: int


class SharedIndicator(BaseModel):
    indicator_id: str
    ioc_value: str
    ioc_type: str
    severity: str
    risk_score: int
    confidence: int
    threat_types: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    tlp: str
    submission_source: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    published_at: Optional[str] = None
    last_shared_at: Optional[str] = None
    revoked_at: Optional[str] = None
    sharing_status: str


class SharedObservation(BaseModel):
    observation_id: str
    observed_at: Optional[str] = None
    collected_at: Optional[str] = None
    source_name: str
    source_type: Optional[str] = None
    severity: str
    confidence: int
    tlp: str
    reference: Optional[str] = None
    description: Optional[str] = None


class ChangeEvent(BaseModel):
    change_type: Literal["created", "updated", "revoked"]
    changed_at: str
    indicator: SharedIndicator


class ExternalIndicatorSubmission(BaseModel):
    ioc_value: str
    ioc_type: str
    title: str = ""
    description: str = ""
    threat_types: List[str] = Field(default_factory=list)
    severity: str = "medium"
    confidence: int = Field(default=50, ge=0, le=100)
    tlp: str = "amber"
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    observed_at: Optional[datetime] = None


class ExternalIndicatorReference(BaseModel):
    ioc_value: str
    ioc_type: str


class ExternalEventSubmission(BaseModel):
    event_type: str
    title: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: int = Field(default=50, ge=0, le=100)
    tlp: str = "amber"
    observed_at: Optional[datetime] = None
    indicators: List[ExternalIndicatorReference] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    source_context: Dict[str, Any] = Field(default_factory=dict)


class ExternalBulkItem(BaseModel):
    kind: Literal["indicator", "event"]
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    title: str = ""
    description: str = ""
    threat_types: List[str] = Field(default_factory=list)
    severity: str = "medium"
    confidence: int = Field(default=50, ge=0, le=100)
    tlp: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    observed_at: Optional[datetime] = None
    event_type: Optional[str] = None
    indicators: List[ExternalIndicatorReference] = Field(default_factory=list)
    source_context: Dict[str, Any] = Field(default_factory=dict)


class ExternalBulkSubmissionRequest(BaseModel):
    items: List[ExternalBulkItem]
    default_tlp: str = "amber"
    dedupe_strategy: str = "indicator_id"


class SubmissionReceipt(BaseModel):
    submission_id: str
    submission_type: str
    status: str
    normalized_indicator_ids: List[str] = Field(default_factory=list)
    validation_errors: List[Dict[str, Any]] = Field(default_factory=list)
    accepted_count: int = 0
    rejected_count: int = 0
    created_at: str
    updated_at: str
    revoked_at: Optional[str] = None


class BulkSubmissionResult(BaseModel):
    submission_id: str
    status: str
    accepted_count: int
    rejected_count: int
    normalized_indicator_ids: List[str] = Field(default_factory=list)
    validation_errors: List[Dict[str, Any]] = Field(default_factory=list)


class ExportRequest(BaseModel):
    query: Optional[str] = None
    ioc_types: List[str] = Field(default_factory=list)
    threat_types: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    min_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    tlp: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    format: str


class ExportJob(BaseModel):
    export_id: str
    status: str
    format: str
    file_name: str
    download_url: Optional[str] = None
    expires_at: str
    record_count: int


def _normalize_tlp(value: Optional[str]) -> str:
    normalized = str(value or "amber").strip().lower()
    return normalized if normalized in TLP_RANK else "amber"


def _normalize_permissions(partner: Dict[str, Any]) -> List[str]:
    return [str(item).strip() for item in partner.get("permissions") or [] if str(item).strip()]


def _require_partner(permission: Optional[str] = None):
    def dependency(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> Dict[str, Any]:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing API Key. Include 'X-API-Key' header.")
        partner = get_external_state().get_partner(x_api_key)
        if not partner:
            raise HTTPException(status_code=403, detail="Invalid API Key.")
        if permission and permission not in _normalize_permissions(partner):
            raise HTTPException(status_code=403, detail=f"Partner does not have '{permission}' permission.")
        return partner

    return dependency


def _tlp_cap(partner: Dict[str, Any], requested_tlp: Optional[str]) -> str:
    partner_rank = TLP_RANK[_normalize_tlp(partner.get("max_tlp"))]
    requested = _normalize_tlp(requested_tlp or partner.get("max_tlp"))
    requested_rank = TLP_RANK[requested]
    return TLP_LEVELS[min(partner_rank, requested_rank)]


def _is_tlp_allowed(partner: Dict[str, Any], doc_tlp: str, requested_tlp: Optional[str] = None) -> bool:
    cap = _tlp_cap(partner, requested_tlp)
    return TLP_RANK[_normalize_tlp(doc_tlp)] <= TLP_RANK[cap]


def _parse_dt(value: Any) -> Optional[datetime]:
    return dashboard_router._parse_dt(value)


def _to_iso(value: Any) -> Optional[str]:
    parsed = _parse_dt(value)
    return parsed.isoformat().replace("+00:00", "Z") if parsed else None


def _utcnow_z() -> str:
    return datetime.now(dashboard_router.UTC).isoformat().replace("+00:00", "Z")


def _safe_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    sanitized = sanitize_text(str(value))
    cleaned = str(sanitized.get("text") or "").strip()
    return cleaned or None


def _normalize_reference_list(values: Sequence[Any]) -> List[str]:
    sanitized = []
    for value in values:
        cleaned = _safe_text(value)
        if cleaned and cleaned not in sanitized:
            sanitized.append(cleaned)
    return sanitized


def _derive_doc_tlp(doc: Dict[str, Any]) -> str:
    return _normalize_tlp(doc.get("tlp") or doc.get("sharing_tlp") or doc.get("traffic_light_protocol"))


def _derive_sharing_status(doc: Dict[str, Any]) -> str:
    status = str(doc.get("sharing_status") or "").strip().lower()
    if status in {"active", "revoked"}:
        return status
    return "revoked" if doc.get("revoked_at") else "active"


def _derive_published_at(doc: Dict[str, Any]) -> Optional[str]:
    return _to_iso(doc.get("published_at") or doc.get("processed_at") or doc.get("created_at") or doc.get("first_seen") or doc.get("event_time"))


def _derive_last_shared_at(doc: Dict[str, Any]) -> Optional[str]:
    return _to_iso(doc.get("last_shared_at") or doc.get("published_at") or doc.get("processed_at") or doc.get("last_seen") or doc.get("updated_at"))


def _derive_change_timestamp(doc: Dict[str, Any]) -> Optional[datetime]:
    return _parse_dt(doc.get("revoked_at") or doc.get("last_shared_at") or doc.get("published_at") or doc.get("processed_at") or doc.get("created_at"))


def _derive_change_type(doc: Dict[str, Any]) -> str:
    if _derive_sharing_status(doc) == "revoked" or doc.get("revoked_at"):
        return "revoked"
    published_at = _parse_dt(doc.get("published_at") or doc.get("processed_at") or doc.get("created_at"))
    last_shared_at = _parse_dt(doc.get("last_shared_at") or doc.get("updated_at"))
    if published_at and last_shared_at and last_shared_at > published_at:
        return "updated"
    return "created"


def _risk_score_from_submission(severity: str, confidence: int) -> int:
    normalized = dashboard_router._normalize_severity(severity)
    base = SEVERITY_BASE_SCORE.get(normalized, 50)
    return max(0, min(100, round((base * 0.7) + (int(confidence) * 0.3))))


def _build_reference_index(datalake_docs: Sequence[Dict[str, Any]]) -> Dict[str, List[str]]:
    references: Dict[str, List[str]] = {}
    for doc in datalake_docs:
        indicator_id = dashboard_router._indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", ""))
        bucket = references.setdefault(indicator_id, [])
        reference = _safe_text(doc.get("reference") or doc.get("source_url"))
        if reference and reference not in bucket:
            bucket.append(reference)
    return references


def _is_doc_shareable(
    doc: Dict[str, Any],
    partner: Dict[str, Any],
    *,
    requested_tlp: Optional[str] = None,
    include_revoked: bool = False,
) -> bool:
    if str(doc.get("validation_status") or "validated").strip().lower() != "validated":
        return False
    if bool(doc.get("warehouse_eligible", True)) is False:
        return False
    if str(doc.get("ioc_type") or "").lower() not in set(partner.get("allowed_ioc_types") or []):
        return False
    status = _derive_sharing_status(doc)
    if status == "revoked" and not include_revoked:
        return False
    return _is_tlp_allowed(partner, _derive_doc_tlp(doc), requested_tlp=requested_tlp)


def _shared_indicator_payload(
    doc: Dict[str, Any],
    datalake_docs: Sequence[Dict[str, Any]],
    partner: Dict[str, Any],
) -> Dict[str, Any]:
    indicator_id = dashboard_router._indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", ""))
    references = _build_reference_index(datalake_docs).get(indicator_id, [])
    return {
        "indicator_id": indicator_id,
        "ioc_value": str(doc.get("ioc_value") or ""),
        "ioc_type": str(doc.get("ioc_type") or "").lower(),
        "severity": dashboard_router._severity_label(dashboard_router._normalize_severity(doc.get("ai_severity") or doc.get("severity"))),
        "risk_score": dashboard_router._safe_int(doc.get("ai_risk_score")),
        "confidence": max(0, min(100, round(float(doc.get("confidence") or (float(doc.get("ai_classification_confidence") or 0.5) * 100))))),
        "threat_types": [str(item) for item in (doc.get("ai_threat_types") or doc.get("threat_type") or []) if str(item).strip()],
        "threat_actors": [str(item) for item in (doc.get("ai_threat_actors") or []) if str(item).strip()],
        "mitre_techniques": [str(item) for item in (doc.get("ai_mitre_techniques") or []) if str(item).strip()],
        "sources": dashboard_router._normalize_sources(doc) or [partner["partner_name"]],
        "references": references,
        "description": _safe_text(doc.get("description")) or _safe_text(doc.get("reference")),
        "tlp": _derive_doc_tlp(doc),
        "submission_source": str(doc.get("submitted_by_partner") or doc.get("partner_id") or ""),
        "first_seen": _to_iso(doc.get("first_seen") or doc.get("event_time") or doc.get("collect_time")),
        "last_seen": _to_iso(doc.get("last_seen") or doc.get("processed_at") or doc.get("collect_time")),
        "published_at": _derive_published_at(doc),
        "last_shared_at": _derive_last_shared_at(doc),
        "revoked_at": _to_iso(doc.get("revoked_at")),
        "sharing_status": _derive_sharing_status(doc),
    }


def _collect_active_warehouse_docs(
    partner: Dict[str, Any],
    *,
    query: str = "*",
    ioc_types: Optional[List[str]] = None,
    threat_types: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    min_risk_score: Optional[int] = None,
    requested_tlp: Optional[str] = None,
    include_revoked: bool = False,
) -> List[Dict[str, Any]]:
    result = dashboard_router._search_warehouse_docs(
        query_text=query or "*",
        ioc_types=ioc_types,
        threat_types=threat_types,
        severities=severities,
        start_date=start_date,
        end_date=end_date,
        warehouse_eligible_only=None,
        limit=5000,
        offset=0,
    )
    docs = dashboard_router._hits_to_docs(result)
    filtered: List[Dict[str, Any]] = []
    for doc in docs:
        if not _is_doc_shareable(doc, partner, requested_tlp=requested_tlp, include_revoked=include_revoked):
            continue
        if min_risk_score is not None and dashboard_router._safe_int(doc.get("ai_risk_score")) < min_risk_score:
            continue
        filtered.append(doc)
    filtered.sort(
        key=lambda item: (
            dashboard_router._safe_int(item.get("ai_risk_score")),
            _derive_change_timestamp(item) or datetime.min.replace(tzinfo=dashboard_router.UTC),
        ),
        reverse=True,
    )
    return filtered


def _partner_submission_doc_base(
    *,
    partner: Dict[str, Any],
    severity: str,
    confidence: int,
    tlp: str,
    observed_at: Optional[datetime],
    description: str,
    title: str,
    references: Sequence[str],
) -> Dict[str, Any]:
    observed = observed_at.isoformat().replace("+00:00", "Z") if observed_at else _utcnow_z()
    created_at = _utcnow_z()
    return {
        "source_name": partner["partner_name"],
        "source_type": "partner_submission",
        "confidence": int(confidence),
        "severity": dashboard_router._normalize_severity(severity),
        "description": description or title,
        "reference": references[0] if references else None,
        "source_url": references[0] if references else None,
        "event_time": observed,
        "collect_time": created_at,
        "created_at": created_at,
        "ai_processed": True,
        "partner_id": partner["partner_id"],
        "submitted_by_partner": partner["partner_name"],
        "tlp": _normalize_tlp(tlp),
        "published_at": created_at,
        "last_shared_at": created_at,
        "revoked_at": None,
        "sharing_status": "active",
    }


def _build_partner_submission_documents(
    *,
    partner: Dict[str, Any],
    ioc_value: str,
    ioc_type: str,
    title: str,
    description: str,
    threat_types: Sequence[str],
    severity: str,
    confidence: int,
    tlp: str,
    tags: Sequence[str],
    references: Sequence[str],
    observed_at: Optional[datetime],
    source_context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    safe_title = _safe_text(title) or ""
    safe_description = _safe_text(description) or safe_title
    sanitized_fields = sanitize_observation_fields(
        [safe_description],
        list(references),
        list(tags),
    )
    clean_description = str((sanitized_fields.get("descriptions") or [safe_description])[0] or "").strip()
    clean_references = _normalize_reference_list(sanitized_fields.get("references") or references)
    clean_tags = [str(item).strip() for item in (sanitized_fields.get("tags") or tags) if str(item).strip()]
    normalized_ioc_type = str(ioc_type).strip().lower()
    normalized_threat_types = [str(item).strip() for item in threat_types if str(item).strip()]
    normalized_severity = dashboard_router._normalize_severity(severity)
    risk_score = _risk_score_from_submission(normalized_severity, confidence)
    base = _partner_submission_doc_base(
        partner=partner,
        severity=normalized_severity,
        confidence=confidence,
        tlp=tlp,
        observed_at=observed_at,
        description=clean_description,
        title=safe_title,
        references=clean_references,
    )
    datalake_doc = {
        **base,
        "ioc_value": str(ioc_value).strip(),
        "ioc_type": normalized_ioc_type,
        "threat_type": normalized_threat_types,
        "tags": clean_tags,
    }
    warehouse_doc = {
        "ioc_value": str(ioc_value).strip(),
        "ioc_type": normalized_ioc_type,
        "sources": [partner["partner_name"]],
        "source_types": ["partner_submission"],
        "source_count": 1,
        "source_urls": clean_references,
        "source_name": partner["partner_name"],
        "source_type": "partner_submission",
        "description": clean_description,
        "threat_type": normalized_threat_types,
        "severity": normalized_severity,
        "tags": clean_tags,
        "reference": clean_references[0] if clean_references else None,
        "event_time": base["event_time"],
        "first_seen": base["event_time"],
        "last_seen": base["event_time"],
        "collect_time": base["collect_time"],
        "ai_risk_score": risk_score,
        "ai_severity": normalized_severity,
        "ai_threat_types": normalized_threat_types,
        "ai_threat_actors": [],
        "ai_mitre_techniques": [],
        "ai_classification_confidence": round(confidence / 100.0, 4),
        "confidence": confidence,
        "credibility_score": confidence,
        "impact_score": SEVERITY_BASE_SCORE.get(normalized_severity, 50),
        "operational_risk_score": risk_score,
        "ai_score_breakdown": {
            "submission_source": {
                "partner_id": partner["partner_id"],
                "partner_name": partner["partner_name"],
                "source_context": source_context or {},
            },
            "sanitization_summary": sanitized_fields.get("summary") or {},
        },
        "ai_top_factors": [
            {
                "factor": "partner_confidence",
                "score": confidence,
                "weighted_score": confidence,
                "label": "Partner Confidence",
            },
            {
                "factor": "severity_signal",
                "score": SEVERITY_BASE_SCORE.get(normalized_severity, 50),
                "weighted_score": SEVERITY_BASE_SCORE.get(normalized_severity, 50),
                "label": "Severity Signal",
            },
        ],
        "validation_status": "validated",
        "validation_reasons": [],
        "warehouse_eligible": True,
        "cleaning_flags": sanitized_fields.get("summary", {}).get("flags") or [],
        "sanitization_summary": sanitized_fields.get("summary") or {},
        "partner_id": partner["partner_id"],
        "submitted_by_partner": partner["partner_name"],
        "tlp": _normalize_tlp(tlp),
        "published_at": base["published_at"],
        "last_shared_at": base["last_shared_at"],
        "revoked_at": None,
        "sharing_status": "active",
        "processed_at": base["created_at"],
        "created_at": base["created_at"],
    }
    return datalake_doc, warehouse_doc


def _submission_receipt_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "submission_id": payload["submission_id"],
        "submission_type": payload["submission_type"],
        "status": payload["status"],
        "normalized_indicator_ids": payload.get("normalized_indicator_ids") or [],
        "validation_errors": payload.get("validation_errors") or [],
        "accepted_count": int(payload.get("accepted_count") or 0),
        "rejected_count": int(payload.get("rejected_count") or 0),
        "created_at": payload["created_at"],
        "updated_at": payload["updated_at"],
        "revoked_at": payload.get("revoked_at"),
    }


def _public_export_job(job: Dict[str, Any], request: Request) -> Dict[str, Any]:
    payload = dict(job)
    if get_external_state().get_export_file(str(job.get("export_id"))):
        payload["download_url"] = str(request.url_for("external_export_download", export_id=str(job["export_id"])))
    return payload


def _render_export_content(items: Sequence[Dict[str, Any]], export_format: str) -> Tuple[bytes, str]:
    normalized = export_format.lower()
    if normalized == "json":
        return json.dumps(list(items), ensure_ascii=False, indent=2).encode("utf-8"), "application/json"
    if normalized == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["indicator_id", "ioc_value", "ioc_type", "severity", "risk_score", "tlp", "threat_types", "sources"])
        for item in items:
            writer.writerow(
                [
                    item.get("indicator_id"),
                    item.get("ioc_value"),
                    item.get("ioc_type"),
                    item.get("severity"),
                    item.get("risk_score"),
                    item.get("tlp"),
                    " | ".join(item.get("threat_types") or []),
                    " | ".join(item.get("sources") or []),
                ]
            )
        return buffer.getvalue().encode("utf-8"), "text/csv"
    if normalized == "plain_text":
        lines = [f"{item.get('ioc_type')}::{item.get('ioc_value')}" for item in items]
        return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"), "text/plain"
    if normalized in {"suricata", "snort"}:
        lines: List[str] = []
        for index, item in enumerate(items, start=1):
            sid = 1000000 + index
            ioc_type = str(item.get("ioc_type") or "").lower()
            ioc_value = str(item.get("ioc_value") or "")
            if ioc_type == "ip":
                lines.append(f'alert ip any any -> {ioc_value} any (msg:"TCTI IOC {ioc_value}"; sid:{sid}; rev:1;)')
            elif ioc_type == "domain":
                lines.append(f'alert http any any -> any any (msg:"TCTI IOC {ioc_value}"; http.host; content:"{ioc_value}"; nocase; sid:{sid}; rev:1;)')
            elif ioc_type == "url":
                lines.append(f'# Unsupported direct URL rule for {ioc_value}')
            else:
                lines.append(f'# Unsupported {ioc_type} IOC {ioc_value}')
        return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"), "text/plain"
    raise HTTPException(status_code=400, detail=f"Unsupported export format: {export_format}")


def _lookup_threat_types() -> List[Dict[str, Any]]:
    warehouse = dashboard_router._hits_to_docs(dashboard_router._search_warehouse_docs(limit=5000))
    datalake = dashboard_router._hits_to_docs(dashboard_router._search_datalake_docs(limit=5000))
    values = []
    for doc in warehouse:
        values.extend(doc.get("ai_threat_types") or [])
        values.extend(doc.get("threat_type") or [])
    for doc in datalake:
        values.extend(doc.get("threat_type") or [])
    return dashboard_router._lookup_items(values)


def _lookup_ioc_types(partner: Dict[str, Any]) -> List[Dict[str, Any]]:
    allowed = set(partner.get("allowed_ioc_types") or [])
    return [
        {
            "value": item["value"],
            "label": item["label"],
            "description": item.get("description"),
            "active": True,
        }
        for item in dashboard_router.IOC_TYPE_LOOKUPS
        if item["value"] in allowed
    ]


def _lookup_severities() -> List[Dict[str, Any]]:
    return [
        {"value": item["value"], "label": item["label"], "description": None, "active": True}
        for item in dashboard_router.RISK_LEVELS
    ]


def _lookup_tlp_levels() -> List[Dict[str, Any]]:
    return [
        {"value": value, "label": value.upper(), "description": None, "active": True}
        for value in TLP_LEVELS
    ]


def _lookup_export_formats(partner: Dict[str, Any]) -> List[Dict[str, Any]]:
    allowed = set(partner.get("allowed_formats") or [])
    return [
        {"value": value, "label": value.upper(), "description": None, "active": True}
        for value in DEFAULT_EXPORT_FORMATS
        if value in allowed
    ]


@router.get("/profile", tags=["ExternalSharing"])
def external_profile(partner: Dict[str, Any] = Depends(_require_partner())):
    return dashboard_router._success(get_external_state().public_partner(partner))


@router.get("/lookups/ioc-types", tags=["ExternalSharing"])
def external_ioc_types(partner: Dict[str, Any] = Depends(_require_partner("read_feed"))):
    return dashboard_router._success({"items": _lookup_ioc_types(partner)})


@router.get("/lookups/threat-types", tags=["ExternalSharing"])
def external_threat_types(partner: Dict[str, Any] = Depends(_require_partner("read_feed"))):
    return dashboard_router._success({"items": _lookup_threat_types()})


@router.get("/lookups/severities", tags=["ExternalSharing"])
def external_severities(partner: Dict[str, Any] = Depends(_require_partner("read_feed"))):
    return dashboard_router._success({"items": _lookup_severities()})


@router.get("/lookups/tlp-levels", tags=["ExternalSharing"])
def external_tlp_levels(partner: Dict[str, Any] = Depends(_require_partner("read_feed"))):
    return dashboard_router._success({"items": _lookup_tlp_levels()})


@router.get("/lookups/export-formats", tags=["ExternalSharing"])
def external_export_formats(partner: Dict[str, Any] = Depends(_require_partner("export_feed"))):
    return dashboard_router._success({"items": _lookup_export_formats(partner)})


@router.get("/changes", tags=["ExternalSharing"])
def external_changes(
    cursor: Optional[str] = None,
    since: Optional[str] = None,
    page_size: int = Query(default=100, ge=1, le=500),
    tlp: Optional[str] = None,
    ioc_types: Optional[List[str]] = Query(default=None),
    threat_types: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    updated_after: Optional[str] = None,
    partner: Dict[str, Any] = Depends(_require_partner("read_feed")),
):
    effective_cursor = cursor or updated_after or since
    cursor_dt = _parse_dt(effective_cursor) if effective_cursor else None
    docs = _collect_active_warehouse_docs(
        partner,
        query="*",
        ioc_types=ioc_types,
        threat_types=threat_types,
        severities=severities,
        requested_tlp=tlp,
        include_revoked=True,
    )
    datalake_docs = dashboard_router._fetch_datalake_by_indicators(
        [(doc.get("ioc_type", ""), doc.get("ioc_value", "")) for doc in docs],
        limit=5000,
    )
    items: List[Dict[str, Any]] = []
    for doc in docs:
        change_ts = _derive_change_timestamp(doc)
        if cursor_dt and change_ts and change_ts <= cursor_dt:
            continue
        indicator = _shared_indicator_payload(doc, datalake_docs, partner)
        changed_at = change_ts.isoformat().replace("+00:00", "Z") if change_ts else _utcnow_z()
        items.append(
            {
                "change_type": _derive_change_type(doc),
                "changed_at": changed_at,
                "indicator": indicator,
            }
        )
    items.sort(key=lambda item: item["changed_at"])
    page_items = items[:page_size]
    next_cursor = page_items[-1]["changed_at"] if page_items else effective_cursor
    payload = {"created": [], "updated": [], "revoked": []}
    for item in page_items:
        payload[item["change_type"]].append(item)
    return dashboard_router._success(payload, next_cursor=next_cursor, returned=len(page_items))


@router.get("/indicators", tags=["ExternalSharing"])
def external_indicators(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    query: Optional[str] = None,
    ioc_types: Optional[List[str]] = Query(default=None),
    threat_types: Optional[List[str]] = Query(default=None),
    severities: Optional[List[str]] = Query(default=None),
    min_risk_score: Optional[int] = Query(default=None, ge=0, le=100),
    tlp: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    partner: Dict[str, Any] = Depends(_require_partner("read_feed")),
):
    docs = _collect_active_warehouse_docs(
        partner,
        query=query or "*",
        ioc_types=ioc_types,
        threat_types=threat_types,
        severities=severities,
        start_date=start_date,
        end_date=end_date,
        min_risk_score=min_risk_score,
        requested_tlp=tlp,
    )
    indicator_slice = docs[(page - 1) * page_size: page * page_size]
    datalake_docs = dashboard_router._fetch_datalake_by_indicators(
        [(doc.get("ioc_type", ""), doc.get("ioc_value", "")) for doc in indicator_slice],
        limit=max(page_size * 20, 200),
    )
    items = [_shared_indicator_payload(doc, datalake_docs, partner) for doc in indicator_slice]
    return dashboard_router._paged({"items": items}, page=page, page_size=page_size, total=len(docs))


@router.get("/indicators/{indicator_id:path}/observations", tags=["ExternalSharing"])
def external_indicator_observations(
    indicator_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    partner: Dict[str, Any] = Depends(_require_partner("read_feed")),
):
    try:
        ioc_type, ioc_value = dashboard_router._split_indicator_id(indicator_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    warehouse_doc = dashboard_router._get_warehouse_doc_by_indicator(ioc_type, ioc_value)
    if not warehouse_doc or not _is_doc_shareable(warehouse_doc, partner):
        raise HTTPException(status_code=404, detail="Indicator not found")
    datalake_docs = dashboard_router._fetch_datalake_by_indicators([(ioc_type, ioc_value)], limit=1000)
    observations: List[Dict[str, Any]] = []
    for doc in datalake_docs:
        if not _is_tlp_allowed(partner, _derive_doc_tlp(doc)):
            continue
        observations.append(
            {
                "observation_id": str(doc.get("_id") or dashboard_router._hash_id(ioc_type, ioc_value, doc.get("collect_time"))),
                "observed_at": _to_iso(doc.get("event_time")),
                "collected_at": _to_iso(doc.get("collect_time")),
                "source_name": str(doc.get("source_name") or "unknown"),
                "source_type": doc.get("source_type"),
                "severity": dashboard_router._severity_label(dashboard_router._normalize_severity(doc.get("severity"))),
                "confidence": dashboard_router._safe_int(doc.get("confidence"), default=50),
                "tlp": _derive_doc_tlp(doc),
                "reference": _safe_text(doc.get("reference") or doc.get("source_url")),
                "description": _safe_text(doc.get("description")),
            }
        )
    observations.sort(key=lambda item: item.get("observed_at") or "", reverse=True)
    sliced = observations[(page - 1) * page_size: page * page_size]
    return dashboard_router._paged({"items": sliced}, page=page, page_size=page_size, total=len(observations))


@router.get("/indicators/{indicator_id:path}/relationships", tags=["ExternalSharing"])
def external_indicator_relationships(
    indicator_id: str,
    partner: Dict[str, Any] = Depends(_require_partner("read_feed")),
):
    try:
        ioc_type, ioc_value = dashboard_router._split_indicator_id(indicator_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    warehouse_doc = dashboard_router._get_warehouse_doc_by_indicator(ioc_type, ioc_value)
    if not warehouse_doc or not _is_doc_shareable(warehouse_doc, partner):
        raise HTTPException(status_code=404, detail="Indicator not found")
    datalake_docs = dashboard_router._fetch_datalake_by_indicators([(ioc_type, ioc_value)], limit=500)
    detail = dashboard_router._build_ioc_detail(warehouse_doc, datalake_docs)
    related_docs = _collect_active_warehouse_docs(
        partner,
        query="*",
        threat_types=list(warehouse_doc.get("ai_threat_types") or warehouse_doc.get("threat_type") or []),
        requested_tlp=_derive_doc_tlp(warehouse_doc),
    )
    related_indicator_docs = [
        doc for doc in related_docs
        if dashboard_router._indicator_id(doc.get("ioc_type", ""), doc.get("ioc_value", "")) != indicator_id
    ][:10]
    related_datalake = dashboard_router._fetch_datalake_by_indicators(
        [(doc.get("ioc_type", ""), doc.get("ioc_value", "")) for doc in related_indicator_docs],
        limit=1000,
    )
    relationship_graph = detail.get("relationship") or {"nodes": [], "edges": [], "capabilities": {}}
    payload = {
        "indicator_id": indicator_id,
        "threat_types": detail["key_identifiers"]["threat_types"],
        "threat_actors": warehouse_doc.get("ai_threat_actors") or [],
        "mitre_techniques": warehouse_doc.get("ai_mitre_techniques") or [],
        "campaigns": [node["label"] for node in relationship_graph["nodes"] if node.get("type") == "campaign"],
        "related_indicators": [_shared_indicator_payload(doc, related_datalake, partner) for doc in related_indicator_docs],
        "graph_summary": relationship_graph,
    }
    return dashboard_router._success(payload)


@router.get("/indicators/{indicator_id:path}", tags=["ExternalSharing"])
def external_indicator_detail(
    indicator_id: str,
    partner: Dict[str, Any] = Depends(_require_partner("read_feed")),
):
    try:
        ioc_type, ioc_value = dashboard_router._split_indicator_id(indicator_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    warehouse_doc = dashboard_router._get_warehouse_doc_by_indicator(ioc_type, ioc_value)
    if not warehouse_doc or not _is_doc_shareable(warehouse_doc, partner):
        raise HTTPException(status_code=404, detail="Indicator not found")
    datalake_docs = dashboard_router._fetch_datalake_by_indicators([(ioc_type, ioc_value)], limit=500)
    return dashboard_router._success(_shared_indicator_payload(warehouse_doc, datalake_docs, partner))


def _store_submission(
    *,
    partner: Dict[str, Any],
    submission_type: str,
    datalake_docs: List[Dict[str, Any]],
    warehouse_docs: List[Dict[str, Any]],
    normalized_indicator_ids: List[str],
    validation_errors: List[Dict[str, Any]],
    raw_payload: Dict[str, Any],
) -> Dict[str, Any]:
    client = get_elastic_client()
    if datalake_docs:
        client.bulk_index_datalake(datalake_docs)
    warehouse_doc_ids = [doc_id for doc_id in (client.save_to_warehouse(doc) for doc in warehouse_docs) if doc_id]
    status = "accepted" if warehouse_doc_ids else "rejected"
    accepted_count = len(warehouse_doc_ids)
    rejected_count = len(validation_errors)
    return get_external_state().create_submission(
        partner=partner,
        submission_type=submission_type,
        status=status,
        normalized_indicator_ids=normalized_indicator_ids,
        validation_errors=validation_errors,
        warehouse_doc_ids=warehouse_doc_ids,
        datalake_count=len(datalake_docs),
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        raw_payload=raw_payload,
    )


@router.post("/indicators", tags=["ExternalSharing"])
def submit_external_indicator(
    request: ExternalIndicatorSubmission,
    partner: Dict[str, Any] = Depends(_require_partner("submit_data")),
):
    allowed_ioc_types = set(partner.get("allowed_ioc_types") or [])
    normalized_ioc_type = str(request.ioc_type).strip().lower()
    validation_errors: List[Dict[str, Any]] = []
    if normalized_ioc_type not in allowed_ioc_types:
        validation_errors.append({"field": "ioc_type", "message": f"IOC type '{normalized_ioc_type}' is not allowed for this partner"})
    if not str(request.ioc_value).strip():
        validation_errors.append({"field": "ioc_value", "message": "IOC value is required"})
    datalake_docs: List[Dict[str, Any]] = []
    warehouse_docs: List[Dict[str, Any]] = []
    normalized_indicator_ids: List[str] = []
    if not validation_errors:
        datalake_doc, warehouse_doc = _build_partner_submission_documents(
            partner=partner,
            ioc_value=request.ioc_value,
            ioc_type=normalized_ioc_type,
            title=request.title,
            description=request.description,
            threat_types=request.threat_types,
            severity=request.severity,
            confidence=request.confidence,
            tlp=request.tlp,
            tags=request.tags,
            references=request.references,
            observed_at=request.observed_at,
        )
        datalake_docs.append(datalake_doc)
        warehouse_docs.append(warehouse_doc)
        normalized_indicator_ids.append(dashboard_router._indicator_id(request.ioc_type, request.ioc_value))
    submission = _store_submission(
        partner=partner,
        submission_type="indicator",
        datalake_docs=datalake_docs,
        warehouse_docs=warehouse_docs,
        normalized_indicator_ids=normalized_indicator_ids,
        validation_errors=validation_errors,
        raw_payload=request.model_dump(mode="json"),
    )
    return dashboard_router._success(_submission_receipt_payload(submission))


@router.post("/events", tags=["ExternalSharing"])
def submit_external_event(
    request: ExternalEventSubmission,
    partner: Dict[str, Any] = Depends(_require_partner("submit_data")),
):
    allowed_ioc_types = set(partner.get("allowed_ioc_types") or [])
    validation_errors: List[Dict[str, Any]] = []
    if not request.indicators:
        validation_errors.append({"field": "indicators", "message": "At least one indicator is required"})
    datalake_docs: List[Dict[str, Any]] = []
    warehouse_docs: List[Dict[str, Any]] = []
    normalized_indicator_ids: List[str] = []
    for index, indicator in enumerate(request.indicators):
        normalized_ioc_type = str(indicator.ioc_type).strip().lower()
        if normalized_ioc_type not in allowed_ioc_types:
            validation_errors.append({"field": f"indicators[{index}].ioc_type", "message": f"IOC type '{normalized_ioc_type}' is not allowed for this partner"})
            continue
        if not str(indicator.ioc_value).strip():
            validation_errors.append({"field": f"indicators[{index}].ioc_value", "message": "IOC value is required"})
            continue
        datalake_doc, warehouse_doc = _build_partner_submission_documents(
            partner=partner,
            ioc_value=indicator.ioc_value,
            ioc_type=normalized_ioc_type,
            title=request.title or request.event_type,
            description=request.description or request.title,
            threat_types=[],
            severity=request.severity,
            confidence=request.confidence,
            tlp=request.tlp,
            tags=[],
            references=request.references,
            observed_at=request.observed_at,
            source_context={"event_type": request.event_type, **(request.source_context or {})},
        )
        datalake_doc["event_type"] = request.event_type
        warehouse_doc["event_type"] = request.event_type
        datalake_docs.append(datalake_doc)
        warehouse_docs.append(warehouse_doc)
        normalized_indicator_ids.append(dashboard_router._indicator_id(indicator.ioc_type, indicator.ioc_value))
    submission = _store_submission(
        partner=partner,
        submission_type="event",
        datalake_docs=datalake_docs,
        warehouse_docs=warehouse_docs,
        normalized_indicator_ids=dashboard_router._unique_list(normalized_indicator_ids),
        validation_errors=validation_errors,
        raw_payload=request.model_dump(mode="json"),
    )
    return dashboard_router._success(_submission_receipt_payload(submission))


@router.post("/bulk", tags=["ExternalSharing"])
def submit_external_bulk(
    request: ExternalBulkSubmissionRequest,
    partner: Dict[str, Any] = Depends(_require_partner("submit_data")),
):
    validation_errors: List[Dict[str, Any]] = []
    datalake_docs: List[Dict[str, Any]] = []
    warehouse_docs: List[Dict[str, Any]] = []
    normalized_indicator_ids: List[str] = []
    allowed_ioc_types = set(partner.get("allowed_ioc_types") or [])
    for index, item in enumerate(request.items):
        item_tlp = item.tlp or request.default_tlp
        if item.kind == "indicator":
            normalized_ioc_type = str(item.ioc_type or "").strip().lower()
            if not str(item.ioc_value or "").strip():
                validation_errors.append({"field": f"items[{index}].ioc_value", "message": "IOC value is required"})
                continue
            if normalized_ioc_type not in allowed_ioc_types:
                validation_errors.append({"field": f"items[{index}].ioc_type", "message": f"IOC type '{normalized_ioc_type}' is not allowed for this partner"})
                continue
            datalake_doc, warehouse_doc = _build_partner_submission_documents(
                partner=partner,
                ioc_value=str(item.ioc_value or ""),
                ioc_type=normalized_ioc_type,
                title=item.title,
                description=item.description,
                threat_types=item.threat_types,
                severity=item.severity,
                confidence=item.confidence,
                tlp=item_tlp,
                tags=item.tags,
                references=item.references,
                observed_at=item.observed_at,
            )
            datalake_docs.append(datalake_doc)
            warehouse_docs.append(warehouse_doc)
            normalized_indicator_ids.append(dashboard_router._indicator_id(normalized_ioc_type, str(item.ioc_value or "")))
            continue
        if item.kind == "event":
            if not item.indicators:
                validation_errors.append({"field": f"items[{index}].indicators", "message": "At least one indicator is required for event items"})
                continue
            for indicator_index, indicator in enumerate(item.indicators):
                normalized_ioc_type = str(indicator.ioc_type).strip().lower()
                if normalized_ioc_type not in allowed_ioc_types:
                    validation_errors.append({"field": f"items[{index}].indicators[{indicator_index}].ioc_type", "message": f"IOC type '{normalized_ioc_type}' is not allowed for this partner"})
                    continue
                datalake_doc, warehouse_doc = _build_partner_submission_documents(
                    partner=partner,
                    ioc_value=indicator.ioc_value,
                    ioc_type=normalized_ioc_type,
                    title=item.title or item.event_type or "Partner event",
                    description=item.description,
                    threat_types=item.threat_types,
                    severity=item.severity,
                    confidence=item.confidence,
                    tlp=item_tlp,
                    tags=item.tags,
                    references=item.references,
                    observed_at=item.observed_at,
                    source_context={"event_type": item.event_type, **(item.source_context or {})},
                )
                datalake_doc["event_type"] = item.event_type
                warehouse_doc["event_type"] = item.event_type
                datalake_docs.append(datalake_doc)
                warehouse_docs.append(warehouse_doc)
                normalized_indicator_ids.append(dashboard_router._indicator_id(normalized_ioc_type, indicator.ioc_value))
    if request.dedupe_strategy == "indicator_id":
        deduped: Dict[str, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
        for datalake_doc, warehouse_doc in zip(datalake_docs, warehouse_docs):
            indicator_id = dashboard_router._indicator_id(datalake_doc.get("ioc_type", ""), datalake_doc.get("ioc_value", ""))
            deduped[indicator_id] = (datalake_doc, warehouse_doc)
        datalake_docs = [item[0] for item in deduped.values()]
        warehouse_docs = [item[1] for item in deduped.values()]
        normalized_indicator_ids = list(deduped.keys())
    else:
        normalized_indicator_ids = dashboard_router._unique_list(normalized_indicator_ids)
    submission = _store_submission(
        partner=partner,
        submission_type="bulk",
        datalake_docs=datalake_docs,
        warehouse_docs=warehouse_docs,
        normalized_indicator_ids=normalized_indicator_ids,
        validation_errors=validation_errors,
        raw_payload=request.model_dump(mode="json"),
    )
    return dashboard_router._success(
        {
            "submission_id": submission["submission_id"],
            "status": submission["status"],
            "accepted_count": submission["accepted_count"],
            "rejected_count": submission["rejected_count"],
            "normalized_indicator_ids": submission["normalized_indicator_ids"],
            "validation_errors": submission["validation_errors"],
        }
    )


@router.get("/submissions/{submission_id}", tags=["ExternalSharing"])
def external_submission_status(
    submission_id: str,
    partner: Dict[str, Any] = Depends(_require_partner("submit_data")),
):
    submission = get_external_state().get_submission(submission_id)
    if not submission or submission.get("partner_id") != partner["partner_id"]:
        raise HTTPException(status_code=404, detail="Submission not found")
    return dashboard_router._success(_submission_receipt_payload(submission))


@router.post("/submissions/{submission_id}/revoke", tags=["ExternalSharing"])
def external_revoke_submission(
    submission_id: str,
    partner: Dict[str, Any] = Depends(_require_partner("submit_data")),
):
    state = get_external_state()
    submission = state.get_submission(submission_id)
    if not submission or submission.get("partner_id") != partner["partner_id"]:
        raise HTTPException(status_code=404, detail="Submission not found")
    if submission.get("status") == "revoked":
        return dashboard_router._success({"submission_id": submission_id, "status": "revoked", "updated_count": 0})
    revoked_at = _utcnow_z()
    updated_count = 0
    for doc_id in submission.get("warehouse_doc_ids") or []:
        if get_elastic_client().update_warehouse_document(
            doc_id,
            {
                "sharing_status": "revoked",
                "revoked_at": revoked_at,
                "last_shared_at": revoked_at,
            },
        ):
            updated_count += 1
    updated_submission = state.revoke_submission(submission_id)
    return dashboard_router._success(
        {
            "submission_id": submission_id,
            "status": updated_submission["status"] if updated_submission else "revoked",
            "updated_count": updated_count,
            "revoked_at": revoked_at,
        }
    )


@router.post("/exports", tags=["ExternalSharing"])
def external_export(
    request: ExportRequest,
    http_request: Request,
    partner: Dict[str, Any] = Depends(_require_partner("export_feed")),
):
    normalized_format = str(request.format or "").strip().lower()
    if normalized_format not in set(partner.get("allowed_formats") or []):
        raise HTTPException(status_code=400, detail=f"Export format '{normalized_format}' is not allowed for this partner")
    docs = _collect_active_warehouse_docs(
        partner,
        query=request.query or "*",
        ioc_types=request.ioc_types or None,
        threat_types=request.threat_types or None,
        severities=request.severities or None,
        start_date=request.start_date.isoformat() if request.start_date else None,
        end_date=request.end_date.isoformat() if request.end_date else None,
        min_risk_score=request.min_risk_score,
        requested_tlp=request.tlp,
    )
    datalake_docs = dashboard_router._fetch_datalake_by_indicators(
        [(doc.get("ioc_type", ""), doc.get("ioc_value", "")) for doc in docs],
        limit=5000,
    )
    items = [_shared_indicator_payload(doc, datalake_docs, partner) for doc in docs]
    content, media_type = _render_export_content(items, normalized_format)
    job = get_external_state().create_export_job(
        partner=partner,
        export_format=normalized_format,
        file_prefix=f"external-feed-{partner['partner_id']}",
        filters=request.model_dump(mode="json"),
        file_content=content,
        media_type=media_type,
        record_count=len(items),
    )
    return dashboard_router._success(_public_export_job(job, http_request))


@router.get("/exports/{export_id}", tags=["ExternalSharing"])
def external_export_status(
    export_id: str,
    request: Request,
    partner: Dict[str, Any] = Depends(_require_partner("export_feed")),
):
    job = get_external_state().get_export_job(export_id)
    if not job or job.get("partner_id") != partner["partner_id"]:
        raise HTTPException(status_code=404, detail="Export job not found")
    return dashboard_router._success(_public_export_job(job, request))


@router.get("/exports/{export_id}/download", name="external_export_download", tags=["ExternalSharing"])
def external_export_download(
    export_id: str,
    partner: Dict[str, Any] = Depends(_require_partner("export_feed")),
):
    job = get_external_state().get_export_job(export_id)
    if not job or job.get("partner_id") != partner["partner_id"]:
        raise HTTPException(status_code=404, detail="Export job not found")
    export_file = get_external_state().get_export_file(export_id)
    if not export_file:
        raise HTTPException(status_code=404, detail="Export file not found")
    return Response(
        content=export_file["content"],
        media_type=export_file["media_type"],
        headers={"Content-Disposition": f'attachment; filename="{job["file_name"]}"'},
    )


__all__ = ["router", "reset_external_state"]
