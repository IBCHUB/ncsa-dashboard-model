"""
Bootstrap state for dashboard-facing APIs.

This module provides lightweight in-process storage for domains that do not
yet have a dedicated backend service, such as auth, users, groups,
notifications, enforcement points, and export jobs.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import secrets
import threading
from typing import Any, Dict, List, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


def _b64encode_json(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode_json(value: str) -> Dict[str, Any]:
    padded = value + ("=" * (-len(value) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    decoded = json.loads(raw.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def _group_permissions() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "grp-super-admin": [
            {"module": "Executive Dashboard", "read": True, "edit": True},
            {"module": "Threat Intelligence", "read": True, "edit": True},
            {"module": "IOC Data Lake", "read": True, "edit": True},
            {"module": "Reports & Export", "read": True, "edit": True},
            {"module": "Setting", "read": True, "edit": True},
        ],
        "grp-admin": [
            {"module": "Executive Dashboard", "read": True, "edit": True},
            {"module": "Threat Intelligence", "read": True, "edit": False},
            {"module": "IOC Data Lake", "read": True, "edit": False},
            {"module": "Reports & Export", "read": True, "edit": True},
            {"module": "Setting", "read": True, "edit": False},
        ],
        "grp-general": [
            {"module": "Executive Dashboard", "read": True, "edit": False},
            {"module": "Threat Intelligence", "read": True, "edit": False},
            {"module": "IOC Data Lake", "read": False, "edit": False},
            {"module": "Reports & Export", "read": False, "edit": False},
            {"module": "Setting", "read": False, "edit": False},
        ],
    }


def _default_groups() -> Dict[str, Dict[str, Any]]:
    permissions = _group_permissions()
    return {
        "grp-super-admin": {
            "group_id": "grp-super-admin",
            "name": "Super Admin",
            "permissions": permissions["grp-super-admin"],
        },
        "grp-admin": {
            "group_id": "grp-admin",
            "name": "Admin",
            "permissions": permissions["grp-admin"],
        },
        "grp-general": {
            "group_id": "grp-general",
            "name": "General",
            "permissions": permissions["grp-general"],
        },
    }


def _require_env_password(env_var: str) -> str:
    """Load password from env var. Generates an unusable random value if unset, preventing silent default login."""
    import logging as _logging
    value = os.getenv(env_var, "")
    if not value:
        random_value = secrets.token_urlsafe(32)
        _logging.getLogger(__name__).warning(
            "%s is not set. Account will be inaccessible until the env var is configured.", env_var
        )
        return random_value
    return value


def _default_users() -> Dict[str, Dict[str, Any]]:
    admin_username = os.getenv("DASHBOARD_BOOTSTRAP_USERNAME", "admin")
    admin_password = _require_env_password("DASHBOARD_BOOTSTRAP_PASSWORD")
    superadmin_password = _require_env_password("DASHBOARD_SUPERADMIN_PASSWORD")
    analyst_password = _require_env_password("DASHBOARD_ANALYST_PASSWORD")
    now = _utcnow()
    return {
        "usr-admin": {
            "user_id": "usr-admin",
            "username": admin_username,
            "password": admin_password,
            "name": "Natakarn Kanjanamas",
            "role_name": "Admin",
            "email": "natakarn@example.com",
            "group_id": "grp-admin",
            "user_group": "Admin",
            "national_id": "X-XXXX-XXXXX-XX-1234",
            "phone_number": "088-888-8888",
            "avatar_url": "/user.png",
            "status": "active",
            "last_password_reset_at": _isoformat(now - timedelta(days=12)),
        },
        "usr-super-admin": {
            "user_id": "usr-super-admin",
            "username": "superadmin",
            "password": superadmin_password,
            "name": "Napat Pongpai",
            "role_name": "Super Admin",
            "email": "napat@example.com",
            "group_id": "grp-super-admin",
            "user_group": "Super Admin",
            "national_id": "X-XXXX-XXXXX-XX-0001",
            "phone_number": "081-234-5670",
            "avatar_url": "/user.png",
            "status": "active",
            "last_password_reset_at": _isoformat(now - timedelta(days=20)),
        },
        "usr-general": {
            "user_id": "usr-general",
            "username": "analyst",
            "password": analyst_password,
            "name": "Kenika Krajangwong",
            "role_name": "General",
            "email": "kenika@example.com",
            "group_id": "grp-general",
            "user_group": "General",
            "national_id": "X-XXXX-XXXXX-XX-1452",
            "phone_number": "086-789-0125",
            "avatar_url": "/user.png",
            "status": "active",
            "last_password_reset_at": _isoformat(now - timedelta(days=4)),
        },
    }


def _default_notifications() -> List[Dict[str, Any]]:
    created_at = _utcnow() - timedelta(minutes=5)
    return [
        {
            "notification_id": "ntf-001",
            "title": "New Match: IOC Data Lake",
            "message": "Detected critical IOC in Zone-H feed",
            "created_at": _isoformat(created_at),
            "relative_time": "5 minutes",
            "type": "ioc_match",
            "unread": True,
            "linked_resource_type": "ioc",
            "linked_resource_id": "ip::http://malicious-site.example",
            "ioc_summary": {
                "ioc_value": "http://malicious-site.example",
                "ioc_type": "url",
                "severity": "Critical",
                "risk_score": 90,
                "threat_types": ["Malware"],
            },
        },
        {
            "notification_id": "ntf-002",
            "title": "Action Ticket Updated",
            "message": "Review queue item requires analyst confirmation",
            "created_at": _isoformat(created_at - timedelta(minutes=12)),
            "relative_time": "17 minutes",
            "type": "action_update",
            "unread": True,
            "linked_resource_type": "action",
            "linked_resource_id": "pending-review",
            "ioc_summary": None,
        },
    ]


def _default_enforcement_points() -> List[Dict[str, Any]]:
    return [
        {"enforcement_point_id": "fw-bkk-01", "name": "Bangkok Firewall 01", "type": "firewall", "location": "Bangkok", "active": True},
        {"enforcement_point_id": "waf-bkk-02", "name": "Bangkok WAF 02", "type": "waf", "location": "Bangkok", "active": True},
        {"enforcement_point_id": "proxy-cdc-01", "name": "CDC Secure Proxy 01", "type": "proxy", "location": "CDC", "active": True},
    ]


@dataclass
class DashboardState:
    token_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("DASHBOARD_ACCESS_TOKEN_TTL_SECONDS", "3600")))
    users: Dict[str, Dict[str, Any]] = field(default_factory=_default_users)
    groups: Dict[str, Dict[str, Any]] = field(default_factory=_default_groups)
    notifications: List[Dict[str, Any]] = field(default_factory=_default_notifications)
    enforcement_points: List[Dict[str, Any]] = field(default_factory=_default_enforcement_points)
    sessions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    export_jobs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    export_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    action_assignments: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    action_notes: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def _session_secret(self) -> str:
        return os.getenv("DASHBOARD_SESSION_SECRET") or os.getenv("JWT_SECRET") or ""

    def _cleanup_sessions(self) -> None:
        now = _utcnow()
        expired = [
            token
            for token, session in self.sessions.items()
            if session.get("expires_at") and session["expires_at"] <= now
        ]
        for token in expired:
            self.sessions.pop(token, None)

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for user in self.users.values():
                if user["username"] == username and user["password"] == password and user["status"] == "active":
                    return self._create_session_locked(user)
        return None

    def _create_session_locked(self, user: Dict[str, Any]) -> Dict[str, Any]:
        expires_at = _utcnow() + timedelta(seconds=self.token_ttl_seconds)
        token = self._create_signed_session_token(user, expires_at) or secrets.token_urlsafe(24)
        self.sessions[token] = {
            "user_id": user["user_id"],
            "expires_at": expires_at,
        }
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.token_ttl_seconds,
            "user": self.public_user(user),
        }

    def _create_signed_session_token(self, user: Dict[str, Any], expires_at: datetime) -> Optional[str]:
        secret = self._session_secret()
        if not secret:
            return None
        user_payload = {
            key: user.get(key)
            for key in (
                "user_id",
                "sso_id",
                "username",
                "name",
                "role_name",
                "email",
                "group_id",
                "user_group",
                "national_id",
                "phone_number",
                "avatar_url",
                "status",
                "last_password_reset_at",
            )
        }
        payload = {
            "typ": "dashboard-session",
            "exp": int(expires_at.timestamp()),
            "iat": int(_utcnow().timestamp()),
            "nonce": secrets.token_hex(8),
            "user": user_payload,
        }
        body = _b64encode_json(payload)
        signature = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return f"ds1.{body}.{encoded_signature}"

    def _verify_signed_session_token(self, token: str) -> Optional[Dict[str, Any]]:
        secret = self._session_secret()
        if not secret or not token.startswith("ds1."):
            return None
        try:
            _, body, encoded_signature = token.split(".", 2)
            expected = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
            actual = base64.urlsafe_b64decode((encoded_signature + "=" * (-len(encoded_signature) % 4)).encode("ascii"))
            if not hmac.compare_digest(actual, expected):
                return None
            payload = _b64decode_json(body)
            if str(payload.get("typ") or "") != "dashboard-session":
                return None
            if int(payload.get("exp") or 0) <= int(_utcnow().timestamp()):
                return None
            user = payload.get("user")
            if not isinstance(user, dict) or user.get("status") != "active":
                return None
            return user
        except Exception:
            return None

    def authenticate_sso(self, identity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sso_id = str(identity.get("sso_id") or identity.get("id") or identity.get("sub") or "").strip()
        email = str(identity.get("email") or "").strip()
        if not sso_id and not email:
            return None

        with self.lock:
            user = self._find_sso_user_locked(sso_id, email)
            if not user:
                user = self._create_sso_user_locked(identity, sso_id, email)
            else:
                self._update_sso_user_locked(user, identity, email)

            if user.get("status") != "active":
                return None
            return self._create_session_locked(user)

    def _find_sso_user_locked(self, sso_id: str, email: str) -> Optional[Dict[str, Any]]:
        for user in self.users.values():
            if sso_id and str(user.get("sso_id") or "") == sso_id:
                return user
            if email and str(user.get("email") or "").lower() == email.lower():
                return user
        return None

    def _resolve_sso_group_locked(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        requested_group_id = str(identity.get("group_id") or "").strip()
        if requested_group_id in self.groups:
            return self.groups[requested_group_id]

        requested_role = str(identity.get("role_name") or identity.get("user_group") or identity.get("role") or "").strip().lower()
        for group in self.groups.values():
            if str(group.get("name") or "").strip().lower() == requested_role:
                return group

        default_group_id = os.getenv("DASHBOARD_SSO_DEFAULT_GROUP_ID", "grp-general")
        return self.groups.get(default_group_id) or self.groups["grp-general"]

    def _create_sso_user_locked(self, identity: Dict[str, Any], sso_id: str, email: str) -> Dict[str, Any]:
        group = self._resolve_sso_group_locked(identity)
        stable_id = sso_id or email.lower()
        user_id = f"usr-sso-{secrets.token_hex(4)}"
        username = str(identity.get("username") or email.split("@")[0] or stable_id or user_id).strip()
        user = {
            "user_id": user_id,
            "sso_id": sso_id or None,
            "username": username,
            "password": "",
            "name": str(identity.get("name") or identity.get("display_name") or username or "SSO User").strip(),
            "role_name": group["name"],
            "email": email or f"{user_id}@sso.local",
            "group_id": group["group_id"],
            "user_group": group["name"],
            "national_id": identity.get("national_id") or identity.get("pid"),
            "phone_number": identity.get("phone_number") or identity.get("phone"),
            "avatar_url": identity.get("avatar_url") or "/user.png",
            "status": "active",
            "last_password_reset_at": None,
        }
        self.users[user_id] = user
        return user

    def _update_sso_user_locked(self, user: Dict[str, Any], identity: Dict[str, Any], email: str) -> None:
        for field, source_keys in {
            "sso_id": ["sso_id", "id", "sub"],
            "name": ["name", "display_name"],
            "national_id": ["national_id", "pid"],
            "phone_number": ["phone_number", "phone"],
            "avatar_url": ["avatar_url"],
        }.items():
            for source_key in source_keys:
                value = identity.get(source_key)
                if value:
                    user[field] = value
                    break
        if email:
            user["email"] = email

    def logout(self, token: str) -> bool:
        with self.lock:
            return self.sessions.pop(token, None) is not None

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            self._cleanup_sessions()
            session = self.sessions.get(token)
            if session:
                user = self.users.get(session["user_id"])
            else:
                user = self._verify_signed_session_token(token)
            if not user or user.get("status") != "active":
                return None
            return deepcopy(user)

    def public_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "user_id": user["user_id"],
            "username": user["username"],
            "name": user["name"],
            "role_name": user["role_name"],
            "avatar_url": user.get("avatar_url"),
        }

    def profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        user = self.users.get(user_id)
        if not user:
            return None
        return {
            "user_id": user["user_id"],
            "username": user["username"],
            "name": user["name"],
            "role_name": user["role_name"],
            "national_id": user.get("national_id"),
            "phone_number": user.get("phone_number"),
            "email": user["email"],
            "avatar_url": user.get("avatar_url"),
            "last_password_reset_at": user.get("last_password_reset_at"),
            "status": user["status"],
        }

    def update_profile(self, user_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.lock:
            user = self.users.get(user_id)
            if not user:
                return None
            for field in ["name", "national_id", "phone_number", "email", "avatar_url"]:
                if field in payload and payload[field] is not None:
                    user[field] = payload[field]
            return self.profile(user_id)

    def verify_password(self, user_id: str, password: str) -> bool:
        with self.lock:
            user = self.users.get(user_id)
            if not user or not password:
                return False
            return user.get("password") == password

    def reset_password(self, user_id: str, new_password: Optional[str] = None) -> bool:
        with self.lock:
            user = self.users.get(user_id)
            if not user:
                return False
            if new_password:
                user["password"] = new_password
            user["last_password_reset_at"] = _isoformat(_utcnow())
            return True

    def delete_user(self, user_id: str) -> bool:
        with self.lock:
            existed = self.users.pop(user_id, None)
            if not existed:
                return False
            self.sessions = {
                token: session
                for token, session in self.sessions.items()
                if session.get("user_id") != user_id
            }
            return True

    def list_users(self) -> List[Dict[str, Any]]:
        return [
            {
                "user_id": user["user_id"],
                "name": user["name"],
                "email": user["email"],
                "user_group": user["user_group"],
                "group_id": user["group_id"],
                "national_id": user.get("national_id"),
                "phone_number": user.get("phone_number"),
                "status": user["status"],
            }
            for user in self.users.values()
        ]

    def create_user(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            user_id = f"usr-{secrets.token_hex(4)}"
            group = self.groups.get(payload["group_id"])
            user = {
                "user_id": user_id,
                "username": payload.get("username") or payload["email"].split("@")[0],
                "password": payload["password"],
                "name": payload["name"],
                "role_name": group["name"] if group else "General",
                "email": payload["email"],
                "group_id": payload["group_id"],
                "user_group": group["name"] if group else "General",
                "national_id": payload.get("national_id"),
                "phone_number": payload.get("phone_number"),
                "avatar_url": payload.get("avatar_url"),
                "status": payload["status"],
                "last_password_reset_at": _isoformat(_utcnow()),
            }
            self.users[user_id] = user
            return self.list_users()[-1]

    def update_user(self, user_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.lock:
            user = self.users.get(user_id)
            if not user:
                return None
            for field in ["name", "email", "national_id", "phone_number", "status", "avatar_url"]:
                if field in payload and payload[field] is not None:
                    user[field] = payload[field]
            if payload.get("password"):
                user["password"] = payload["password"]
                user["last_password_reset_at"] = _isoformat(_utcnow())
            if payload.get("group_id"):
                group = self.groups.get(payload["group_id"])
                user["group_id"] = payload["group_id"]
                if group:
                    user["user_group"] = group["name"]
                    user["role_name"] = group["name"]
            for item in self.list_users():
                if item["user_id"] == user_id:
                    return item
        return None

    def list_groups(self) -> List[Dict[str, Any]]:
        return [deepcopy(group) for group in self.groups.values()]

    def create_group(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            group_id = f"grp-{secrets.token_hex(4)}"
            group = {
                "group_id": group_id,
                "name": payload["name"],
                "permissions": deepcopy(payload["permissions"]),
            }
            self.groups[group_id] = group
            return deepcopy(group)

    def update_group(self, group_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.lock:
            group = self.groups.get(group_id)
            if not group:
                return None
            if payload.get("name"):
                group["name"] = payload["name"]
            if payload.get("permissions") is not None:
                group["permissions"] = deepcopy(payload["permissions"])
            for user in self.users.values():
                if user.get("group_id") == group_id:
                    user["user_group"] = group["name"]
                    user["role_name"] = group["name"]
            return deepcopy(group)

    def delete_group(self, group_id: str) -> bool:
        with self.lock:
            if group_id not in self.groups:
                return False
            for user in self.users.values():
                if user.get("group_id") == group_id:
                    user["group_id"] = "grp-general"
                    user["user_group"] = "General"
                    user["role_name"] = "General"
            self.groups.pop(group_id, None)
            return True

    @staticmethod
    def _notification_visible_to(notification: Dict[str, Any], user_id: Optional[str]) -> bool:
        """Notifications without an explicit recipient are broadcast to everyone.

        When a notification carries a `recipient_user_id`, only that user
        sees it — preventing other users from reading or mutating it.
        """
        recipient = notification.get("recipient_user_id")
        if recipient is None:
            return True
        return user_id is not None and recipient == user_id

    def list_notifications(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [
            deepcopy(item)
            for item in self.notifications
            if self._notification_visible_to(item, user_id)
        ]

    def mark_notification_read(
        self,
        notification_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        with self.lock:
            for notification in self.notifications:
                if notification["notification_id"] != notification_id:
                    continue
                if not self._notification_visible_to(notification, user_id):
                    return None
                notification["unread"] = False
                return deepcopy(notification)
        return None

    def mark_all_notifications_read(
        self,
        notification_type: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, int]:
        with self.lock:
            count = 0
            for notification in self.notifications:
                if not self._notification_visible_to(notification, user_id):
                    continue
                if notification_type and notification.get("type") != notification_type:
                    continue
                if notification.get("unread"):
                    notification["unread"] = False
                    count += 1
            unread_count = sum(
                1
                for item in self.notifications
                if self._notification_visible_to(item, user_id) and item.get("unread")
            )
            return {"marked_count": count, "unread_count": unread_count}

    def list_assignees(self, query: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = []
        for user in self.users.values():
            if status and user["status"] != status:
                continue
            haystack = f"{user['name']} {user['email']} {user['role_name']}".lower()
            if query and query.lower() not in haystack:
                continue
            items.append(
                {
                    "user_id": user["user_id"],
                    "name": user["name"],
                    "role_name": user["role_name"],
                    "avatar_url": user.get("avatar_url"),
                    "status": user["status"],
                }
            )
        return items

    def list_enforcement_points(self, query: Optional[str] = None, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        items = []
        for point in self.enforcement_points:
            if kind and point["type"] != kind:
                continue
            haystack = f"{point['name']} {point.get('location', '')}".lower()
            if query and query.lower() not in haystack:
                continue
            items.append(deepcopy(point))
        return items

    def create_export_job(
        self,
        export_format: str,
        file_prefix: str,
        report_type: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        file_content: Optional[bytes] = None,
        media_type: Optional[str] = None,
        owner_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self.lock:
            export_id = f"exp-{secrets.token_hex(4)}"
            created_at = _utcnow()
            job = {
                "export_id": export_id,
                "status": "completed",
                "format": export_format,
                "export_format": export_format,
                "file_name": f"{file_prefix}-{created_at.strftime('%Y%m%d%H%M%S')}.{export_format.lower()}",
                "download_url": None,
                "created_at": _isoformat(created_at),
                "completed_at": _isoformat(created_at),
                "report_type": report_type or file_prefix,
                "filters": deepcopy(filters or {}),
                "owner_user_id": owner_user_id,
            }
            if file_content is not None:
                self.export_files[export_id] = {
                    "content": bytes(file_content),
                    "media_type": media_type or "application/octet-stream",
                }
            self.export_jobs[export_id] = job
            return deepcopy(job)

    def get_export_job(self, export_id: str) -> Optional[Dict[str, Any]]:
        job = self.export_jobs.get(export_id)
        return deepcopy(job) if job else None

    def delete_export_job(self, export_id: str) -> None:
        with self.lock:
            self.export_jobs.pop(export_id, None)
            self.export_files.pop(export_id, None)

    def get_export_file(self, export_id: str) -> Optional[Dict[str, Any]]:
        export_file = self.export_files.get(export_id)
        if not export_file:
            return None
        return {
            "content": bytes(export_file["content"]),
            "media_type": export_file["media_type"],
        }

    def get_action_assignment(self, action_id: str) -> Optional[Dict[str, Any]]:
        item = self.action_assignments.get(action_id)
        return deepcopy(item) if item else None

    def assign_action(self, action_id: str, assignee: Dict[str, Any], handover_note: str = "") -> Dict[str, Any]:
        with self.lock:
            payload = {
                "assignee": deepcopy(assignee),
                "handover_note": handover_note,
                "assigned_at": _isoformat(_utcnow()),
            }
            self.action_assignments[action_id] = payload
            return deepcopy(payload)

    def append_action_note(self, action_id: str, author_name: str, content: str) -> Dict[str, Any]:
        with self.lock:
            note = {
                "note_id": f"note-{secrets.token_hex(4)}",
                "author_name": author_name,
                "created_at": _isoformat(_utcnow()),
                "content": content,
            }
            self.action_notes.setdefault(action_id, []).append(note)
            return deepcopy(note)

    def get_action_notes(self, action_id: str) -> List[Dict[str, Any]]:
        return deepcopy(self.action_notes.get(action_id, []))


_state: Optional[DashboardState] = None


def get_dashboard_state() -> DashboardState:
    global _state
    if _state is None:
        _state = DashboardState()
    return _state
