"""
Review queue service helpers.

Keeps manual-review workflow logic out of the FastAPI module so it can be
tested without importing classifier/model dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from models.validation import REJECTED_MANUAL, VALIDATED_MANUAL


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def to_review_queue_item(document: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "doc_id": str(document.get("_id", "")),
        "ioc_value": str(document.get("ioc_value", "")),
        "ioc_type": str(document.get("ioc_type", "unknown")),
        "validation_status": str(document.get("validation_status", "unknown")),
        "review_state": str(document.get("review_state", "not_required")),
        "warehouse_eligible": bool(document.get("warehouse_eligible", False)),
        "review_required": bool(document.get("review_required", False)),
        "validation_reasons": [str(item) for item in document.get("validation_reasons", []) or []],
        "ai_risk_score": int(document.get("ai_risk_score", 0) or 0),
        "ai_severity": str(document.get("ai_severity", "low")),
        "ai_classification_confidence": float(document.get("ai_classification_confidence", 0.0) or 0.0),
        "source_name": str(document.get("source_name", "unknown")),
        "processed_at": document.get("processed_at"),
        "reviewed_by": document.get("reviewed_by"),
        "reviewed_at": document.get("reviewed_at"),
        "review_notes": document.get("review_notes"),
    }


def build_review_queue_response(search_result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "total": int(search_result.get("total", 0) or 0),
        "items": [to_review_queue_item(item) for item in search_result.get("data", [])],
    }


def approve_review_document(es_client: Any, doc_id: str, reviewer: str, notes: str = "") -> Dict[str, Any]:
    document = es_client.get_warehouse_document(doc_id)
    if not document:
        raise LookupError("Warehouse document not found")

    reviewed_at = utc_now_iso()
    updated_fields = {
        "validation_status": VALIDATED_MANUAL,
        "warehouse_eligible": True,
        "review_required": False,
        "review_state": "approved",
        "reviewed_by": reviewer,
        "reviewed_at": reviewed_at,
        "review_notes": notes or None,
    }

    if not es_client.update_warehouse_document(doc_id, updated_fields):
        raise RuntimeError("Failed to update warehouse review state")

    return {
        "success": True,
        "doc_id": doc_id,
        "validation_status": VALIDATED_MANUAL,
        "review_state": "approved",
        "warehouse_saved": True,
        "message": "IOC approved in warehouse",
    }


def reject_review_document(es_client: Any, doc_id: str, reviewer: str, notes: str = "") -> Dict[str, Any]:
    document = es_client.get_warehouse_document(doc_id)
    if not document:
        raise LookupError("Warehouse document not found")

    updated_fields = {
        "validation_status": REJECTED_MANUAL,
        "warehouse_eligible": False,
        "review_required": False,
        "review_state": "rejected",
        "reviewed_by": reviewer,
        "reviewed_at": utc_now_iso(),
        "review_notes": notes or None,
    }

    if not es_client.update_warehouse_document(doc_id, updated_fields):
        raise RuntimeError("Failed to update warehouse review state")

    return {
        "success": True,
        "doc_id": doc_id,
        "validation_status": REJECTED_MANUAL,
        "review_state": "rejected",
        "warehouse_saved": False,
        "message": "IOC rejected during manual review",
    }
