"""
Bootstrap state for external threat sharing partners.

This module keeps lightweight in-process state for:
- partner registry loaded from environment
- submission receipts
- export jobs and generated files
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import secrets
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

UTC = timezone.utc
TLP_LEVELS = ["clear", "green", "amber", "red"]
DEFAULT_IOC_TYPES = ["ip", "domain", "url", "hash", "sha256", "sha1", "md5", "cve"]
DEFAULT_EXPORT_FORMATS = ["json", "csv", "plain_text", "suricata", "snort"]
DEFAULT_PERMISSIONS = ["read_feed", "submit_data", "export_feed"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _normalize_tlp(value: Optional[str]) -> str:
    normalized = str(value or "amber").strip().lower()
    return normalized if normalized in TLP_LEVELS else "amber"


def _normalize_permissions(values: Any) -> List[str]:
    allowed = {"read_feed", "submit_data", "export_feed"}
    items = []
    for value in values or []:
        permission = str(value).strip()
        if permission and permission in allowed and permission not in items:
            items.append(permission)
    return items or ["read_feed"]


def _normalize_str_list(values: Any, *, default: Optional[List[str]] = None, lowercase: bool = False) -> List[str]:
    items: List[str] = []
    for value in values or []:
        normalized = str(value).strip()
        if lowercase:
            normalized = normalized.lower()
        if normalized and normalized not in items:
            items.append(normalized)
    if items:
        return items
    return list(default or [])


def _partner_from_payload(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    api_key = str(payload.get("api_key") or "").strip()
    partner_id = str(payload.get("partner_id") or "").strip()
    partner_name = str(payload.get("partner_name") or payload.get("name") or partner_id).strip()
    if not api_key or not partner_id or not partner_name:
        return None
    return {
        "api_key": api_key,
        "partner_id": partner_id,
        "partner_name": partner_name,
        "permissions": _normalize_permissions(payload.get("permissions") or DEFAULT_PERMISSIONS),
        "max_tlp": _normalize_tlp(payload.get("max_tlp")),
        "allowed_ioc_types": _normalize_str_list(payload.get("allowed_ioc_types"), default=DEFAULT_IOC_TYPES, lowercase=True),
        "allowed_formats": _normalize_str_list(payload.get("allowed_formats"), default=DEFAULT_EXPORT_FORMATS, lowercase=True),
        "rate_limit": int(payload.get("rate_limit") or 60),
        "active": bool(payload.get("active", True)),
    }


def _load_partners_from_env() -> Dict[str, Dict[str, Any]]:
    raw = os.getenv("EXTERNAL_PARTNER_REGISTRY_JSON", "").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse EXTERNAL_PARTNER_REGISTRY_JSON: %s", exc)
        return {}
    if not isinstance(payload, list):
        logger.error("EXTERNAL_PARTNER_REGISTRY_JSON must be a JSON array")
        return {}
    partners: Dict[str, Dict[str, Any]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        partner = _partner_from_payload(item)
        if not partner:
            continue
        partners[partner["api_key"]] = partner
    return partners


@dataclass
class ExternalSharingState:
    partners_by_key: Dict[str, Dict[str, Any]]
    submissions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    export_jobs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    export_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_env(cls) -> "ExternalSharingState":
        return cls(partners_by_key=_load_partners_from_env())

    def get_partner(self, api_key: str) -> Optional[Dict[str, Any]]:
        partner = self.partners_by_key.get(api_key)
        if not partner or not partner.get("active", True):
            return None
        return deepcopy(partner)

    def public_partner(self, partner: Dict[str, Any]) -> Dict[str, Any]:
        payload = deepcopy(partner)
        payload.pop("api_key", None)
        return payload

    def create_submission(
        self,
        *,
        partner: Dict[str, Any],
        submission_type: str,
        status: str,
        normalized_indicator_ids: List[str],
        validation_errors: List[Dict[str, Any]],
        warehouse_doc_ids: Optional[List[str]] = None,
        datalake_count: int = 0,
        accepted_count: int = 0,
        rejected_count: int = 0,
        raw_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self.lock:
            submission_id = f"sub-{secrets.token_hex(4)}"
            created_at = _isoformat(_utcnow())
            payload = {
                "submission_id": submission_id,
                "partner_id": partner["partner_id"],
                "partner_name": partner["partner_name"],
                "submission_type": submission_type,
                "status": status,
                "normalized_indicator_ids": list(normalized_indicator_ids),
                "validation_errors": deepcopy(validation_errors),
                "warehouse_doc_ids": list(warehouse_doc_ids or []),
                "datalake_count": datalake_count,
                "accepted_count": accepted_count,
                "rejected_count": rejected_count,
                "created_at": created_at,
                "updated_at": created_at,
                "revoked_at": None,
                "raw_payload": deepcopy(raw_payload or {}),
            }
            self.submissions[submission_id] = payload
            return deepcopy(payload)

    def get_submission(self, submission_id: str) -> Optional[Dict[str, Any]]:
        payload = self.submissions.get(submission_id)
        return deepcopy(payload) if payload else None

    def revoke_submission(self, submission_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            payload = self.submissions.get(submission_id)
            if not payload:
                return None
            revoked_at = _isoformat(_utcnow())
            payload["status"] = "revoked"
            payload["revoked_at"] = revoked_at
            payload["updated_at"] = revoked_at
            return deepcopy(payload)

    def create_export_job(
        self,
        *,
        partner: Dict[str, Any],
        export_format: str,
        file_prefix: str,
        filters: Optional[Dict[str, Any]] = None,
        file_content: Optional[bytes] = None,
        media_type: Optional[str] = None,
        record_count: int = 0,
    ) -> Dict[str, Any]:
        with self.lock:
            export_id = f"ext-exp-{secrets.token_hex(4)}"
            created_at = _utcnow()
            payload = {
                "export_id": export_id,
                "partner_id": partner["partner_id"],
                "partner_name": partner["partner_name"],
                "status": "completed",
                "format": export_format,
                "file_name": f"{file_prefix}-{created_at.strftime('%Y%m%d%H%M%S')}.{export_format}",
                "created_at": _isoformat(created_at),
                "completed_at": _isoformat(created_at),
                "expires_at": _isoformat(created_at),
                "record_count": int(record_count),
                "filters": deepcopy(filters or {}),
                "download_url": None,
            }
            if file_content is not None:
                self.export_files[export_id] = {
                    "content": bytes(file_content),
                    "media_type": media_type or "application/octet-stream",
                }
            self.export_jobs[export_id] = payload
            return deepcopy(payload)

    def get_export_job(self, export_id: str) -> Optional[Dict[str, Any]]:
        payload = self.export_jobs.get(export_id)
        return deepcopy(payload) if payload else None

    def get_export_file(self, export_id: str) -> Optional[Dict[str, Any]]:
        payload = self.export_files.get(export_id)
        if not payload:
            return None
        return {
            "content": bytes(payload["content"]),
            "media_type": payload["media_type"],
        }


_state: Optional[ExternalSharingState] = None


def get_external_state() -> ExternalSharingState:
    global _state
    if _state is None:
        _state = ExternalSharingState.from_env()
    return _state


def reset_external_state() -> None:
    global _state
    _state = None
