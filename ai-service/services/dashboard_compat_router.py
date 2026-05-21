"""
Flat compatibility routes for `ncsa-dashboard-web`.

These routes preserve the original PoC path names and response casing while
reusing the canonical `/api/v1` service logic underneath.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from services.dashboard_bootstrap import get_dashboard_state
from services import dashboard_router

router = APIRouter()

COMPAT_DASHBOARD_USER = {
    "user_id": "compat-client",
    "username": "compat-client",
    "name": "Compat Client",
}

COMPAT_HEATMAP_DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def _compat_result(payload: Any) -> Dict[str, Any]:
    return {"res_result": payload}


def _compat_overview(overview: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    safe = overview or {}
    return {
        "ActiveIOC": int(safe.get("active_ioc") or 0),
        "CriticalIOCActive": int(safe.get("critical_ioc_active") or 0),
        "NewIOC": int(safe.get("new_ioc") or 0),
        "SourcesActive": int(safe.get("sources_active") or 0),
    }


def _compat_severity_rows(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [
        {
            "Color": str(item.get("color") or "#667085"),
            "Name": str(item.get("label") or item.get("key") or "Unknown"),
            "Value": int(item.get("value") or 0),
            "Percentage": round(float(item.get("percentage") or 0.0), 2),
        }
        for item in (items or [])
    ]


def _compat_top_rows(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [
        {
            "Name": str(item.get("label") or item.get("key") or "Unknown"),
            "Value": int(item.get("value") or 0),
        }
        for item in (items or [])
    ]


def _compat_lookup_items(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    output = []
    for index, item in enumerate(items or [], start=1):
        name = str(item.get("label") or item.get("Name") or item.get("value") or item.get("Value") or f"Item {index}")
        raw_value = str(item.get("value") or item.get("Value") or name)
        value = raw_value.lower() if raw_value else raw_value
        output.append({"Id": index, "Name": name, "Value": value})
    return output


def _compat_heatmap(heatmap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    safe = heatmap or {}
    raw_x_axis = safe.get("x_axis") or []
    normalized_x_axis = [str(item).split(":", 1)[0] for item in raw_x_axis]
    x_index_map = {value: index for index, value in enumerate(normalized_x_axis)}
    y_index_map = {value: index for index, value in enumerate(COMPAT_HEATMAP_DAYS)}

    data = []
    for cell in safe.get("cells") or []:
        x_label = str(cell.get("x") or "").split(":", 1)[0]
        y_label = str(cell.get("y") or "")
        if x_label not in x_index_map or y_label not in y_index_map:
            continue
        data.append([x_index_map[x_label], y_index_map[y_label], int(cell.get("value") or 0)])

    return {
        "mode": str(safe.get("mode") or "day-hour"),
        "xAxis": normalized_x_axis,
        "yAxis": list(COMPAT_HEATMAP_DAYS),
        "data": data,
    }


def _operations_payload(start_date: Optional[str], end_date: Optional[str]) -> Dict[str, Any]:
    response = dashboard_router.operations_dashboard(
        start_date=start_date,
        end_date=end_date,
        current_user=COMPAT_DASHBOARD_USER,
    )
    return response["data"]


def _attack_time_payload(start_date: Optional[str], end_date: Optional[str]) -> Dict[str, Any]:
    response = dashboard_router.attack_time_report(
        page=1,
        page_size=20,
        query=None,
        start_date=start_date,
        end_date=end_date,
        threat_types=None,
        sources=None,
        severities=None,
        current_user=COMPAT_DASHBOARD_USER,
    )
    return response["data"]


@router.post("/login")
def compat_login(request: dashboard_router.LoginRequest):
    payload = get_dashboard_state().authenticate(request.username, request.password)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response_payload = {
        "token": payload["access_token"],
        "token_type": payload["token_type"],
        "expires_in": payload["expires_in"],
        "user": payload["user"],
    }
    response = JSONResponse(response_payload)
    response.set_cookie("token", payload["access_token"], httponly=True, samesite="strict")
    return response


@router.get("/dashboard")
def compat_dashboard(start_date: Optional[str] = None, end_date: Optional[str] = None):
    payload = _operations_payload(start_date, end_date)
    return _compat_result(_compat_overview(payload.get("overview")))


@router.get("/incidentbyseverity")
def compat_incident_by_severity(start_date: Optional[str] = None, end_date: Optional[str] = None):
    payload = _operations_payload(start_date, end_date)
    return _compat_result(_compat_severity_rows(payload.get("incident_by_severity")))


@router.get("/attacktime")
def compat_attack_time(start_date: Optional[str] = None, end_date: Optional[str] = None):
    payload = _attack_time_payload(start_date, end_date)
    return _compat_result(_compat_heatmap(payload.get("heatmap")))


@router.get("/intelligencesources")
def compat_intelligence_sources(start_date: Optional[str] = None, end_date: Optional[str] = None):
    payload = _operations_payload(start_date, end_date)
    return _compat_result(_compat_top_rows(payload.get("top_intelligence_sources")))


@router.get("/threattype")
def compat_threat_type_chart(start_date: Optional[str] = None, end_date: Optional[str] = None):
    payload = _operations_payload(start_date, end_date)
    return _compat_result(_compat_top_rows(payload.get("top_threat_types")))


@router.get("/countriesbythreatassociation")
def compat_countries_by_threat_association(start_date: Optional[str] = None, end_date: Optional[str] = None):
    payload = _operations_payload(start_date, end_date)
    return _compat_result(_compat_top_rows(payload.get("top_attack_origins")))


@router.get("/targetsectors")
def compat_target_sectors(start_date: Optional[str] = None, end_date: Optional[str] = None):
    payload = _operations_payload(start_date, end_date)
    return _compat_result(_compat_top_rows(payload.get("target_sectors")))


@router.get("/threat-type")
def compat_threat_type_lookup():
    payload = dashboard_router.list_threat_types(current_user=COMPAT_DASHBOARD_USER)
    return _compat_result(_compat_lookup_items(payload["data"]["items"]))


@router.get("/source")
def compat_source_lookup():
    payload = dashboard_router.list_sources(current_user=COMPAT_DASHBOARD_USER)
    return _compat_result(_compat_lookup_items(payload["data"]["items"]))


@router.get("/severity")
def compat_severity_lookup():
    payload = dashboard_router.list_severities(current_user=COMPAT_DASHBOARD_USER)
    return _compat_result(_compat_lookup_items(payload["data"]["items"]))


@router.get("/rick-level")
def compat_risk_level_lookup():
    payload = dashboard_router.list_risk_levels(current_user=COMPAT_DASHBOARD_USER)
    return _compat_result(_compat_lookup_items(payload["data"]["items"]))


@router.get("/export-type")
def compat_export_type_lookup():
    payload = dashboard_router.list_export_formats(current_user=COMPAT_DASHBOARD_USER)
    return _compat_result(_compat_lookup_items(payload["data"]["items"]))
