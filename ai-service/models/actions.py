"""
Action metadata helpers for dashboard-facing operational tickets.

The dashboard models actions as operational tickets with statuses like
`open`, `in_progress`, and `closed`. These helpers derive that metadata from
warehouse IOC documents without coupling the UI contract to internal
validation-state terminology.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional


ACTION_OPEN = "open"
ACTION_IN_PROGRESS = "in_progress"
ACTION_CLOSED = "closed"
ACTIONABLE_SEVERITIES = {"critical", "high"}
ACTIONABLE_RISK_THRESHOLD = int(os.getenv("ACTION_RISK_THRESHOLD", "10"))
ACTIONABLE_SOURCE_COUNT_THRESHOLD = int(os.getenv("ACTION_SOURCE_COUNT_THRESHOLD", "2"))
ZONEH_ACTION_RISK_THRESHOLD = int(os.getenv("ZONEH_ACTION_RISK_THRESHOLD", "10"))
EDITORIAL_ACTION_RISK_THRESHOLD = int(os.getenv("EDITORIAL_ACTION_RISK_THRESHOLD", "10"))
EDITORIAL_SOURCES = {"TheHackerNews", "DarkReading", "BleepingComputer", "SecurityWeek", "Cyber News"}
DEFACEMENT_SOURCES = {"Zone-H"}


def normalize_severity(value: Optional[str]) -> str:
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


def normalize_action_status(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip().lower()
    if text in {ACTION_OPEN, ACTION_IN_PROGRESS, ACTION_CLOSED}:
        return text
    return None


def default_action_title(document: Dict[str, Any]) -> str:
    severity = normalize_severity(document.get("ai_severity") or document.get("severity"))
    source_count = int(document.get("source_count", 0) or 0)
    ioc_type = str(document.get("ioc_type", "")).strip().lower()
    source_names = {item.strip() for item in str(document.get("source_name", "")).split(",") if item.strip()}

    if severity == "critical":
        return "Review Critical Threat"
    if ioc_type == "cve":
        return "Review Vulnerability Intelligence"
    if source_names & DEFACEMENT_SOURCES:
        return "Investigate Website Defacement Indicator"
    if source_count >= ACTIONABLE_SOURCE_COUNT_THRESHOLD:
        return "Validate Intelligence Source"
    if source_count <= 1 and ioc_type in {"ip", "domain", "url", "hash", "cve"}:
        return "Validate Intelligence Source"
    if severity == "high":
        return "Investigate High-Risk IOC"
    return "Security Action Detail"


def default_action_reason(document: Dict[str, Any]) -> str:
    severity = normalize_severity(document.get("ai_severity") or document.get("severity"))
    ioc_type = str(document.get("ioc_type", "")).strip().lower()
    source_names = {item.strip() for item in str(document.get("source_name", "")).split(",") if item.strip()}
    if severity == "critical":
        return "critical_threat"
    if ioc_type == "cve":
        return "vulnerability_intelligence"
    if source_names & DEFACEMENT_SOURCES:
        return "defacement_follow_up"
    if int(document.get("source_count", 0) or 0) >= ACTIONABLE_SOURCE_COUNT_THRESHOLD:
        return "multi_source_validation"
    if severity == "high":
        return "high_risk_ioc"
    return "ioc_follow_up"


def derive_action_metadata(document: Dict[str, Any]) -> Dict[str, Any]:
    explicit_status = normalize_action_status(document.get("action_status"))
    action_required = bool(document.get("action_required", False))

    if explicit_status is None and should_open_action(document):
        action_required = True
        explicit_status = ACTION_OPEN

    if explicit_status == ACTION_CLOSED:
        action_required = False

    if explicit_status is None:
        return {
            "action_required": False,
            "action_status": None,
            "action_title": None,
            "action_reason": None,
            "action_opened_at": None,
            "action_updated_at": document.get("action_updated_at"),
            "action_closed_at": document.get("action_closed_at"),
            "action_closed_reason": document.get("action_closed_reason"),
        }

    opened_at = (
        document.get("action_opened_at")
        or document.get("processed_at")
        or document.get("last_seen")
        or document.get("first_seen")
        or document.get("event_time")
        or document.get("collect_time")
    )
    updated_at = document.get("action_updated_at") or document.get("action_closed_at") or opened_at

    return {
        "action_required": action_required,
        "action_status": explicit_status,
        "action_title": document.get("action_title") or default_action_title(document),
        "action_reason": document.get("action_reason") or default_action_reason(document),
        "action_opened_at": opened_at,
        "action_updated_at": updated_at,
        "action_closed_at": document.get("action_closed_at"),
        "action_closed_reason": document.get("action_closed_reason"),
    }


def should_open_action(document: Dict[str, Any]) -> bool:
    severity = normalize_severity(document.get("ai_severity") or document.get("severity"))
    risk_score = int(document.get("ai_risk_score", 0) or 0)
    source_count = int(document.get("source_count", 0) or 0)
    ioc_type = str(document.get("ioc_type", "")).strip().lower()
    source_names = {item.strip() for item in str(document.get("source_name", "")).split(",") if item.strip()}

    if severity in ACTIONABLE_SEVERITIES:
        return True
    if risk_score >= ACTIONABLE_RISK_THRESHOLD:
        return True
    if source_count >= ACTIONABLE_SOURCE_COUNT_THRESHOLD and (source_names & EDITORIAL_SOURCES):
        return True
    if ioc_type in {"domain", "url"} and (source_names & DEFACEMENT_SOURCES) and risk_score >= ZONEH_ACTION_RISK_THRESHOLD:
        return True
    if ioc_type == "cve" and (source_names & EDITORIAL_SOURCES) and risk_score >= EDITORIAL_ACTION_RISK_THRESHOLD:
        return True
    return False
