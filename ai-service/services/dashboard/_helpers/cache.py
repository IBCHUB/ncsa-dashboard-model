"""In-memory TTL cache for dashboard endpoints.

Extracted from dashboard_router.py (Phase A.2). All dashboard endpoints
that opt into caching share this single process-local store. It is NOT
shared across worker processes — restarting a worker drops its cache.

Public API:
    - DASHBOARD_CACHE_TTL_SECONDS  (configured via env)
    - cache_key(name, **params)
    - cache_get(key)
    - cache_set(key, payload, ttl=None)

Backwards-compatibility aliases (`_cache_key`, `_cache_get`, `_cache_set`)
are also exported so existing call sites need no changes in this phase.

Behaviour preserved verbatim from the original implementation:
    - TTL == 0 disables caching entirely (get returns None, set is a no-op)
    - Hits past their `expires_at` are evicted on read
    - When the store exceeds 512 entries, the 128 oldest entries are dropped
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple


DASHBOARD_CACHE_TTL_SECONDS = int(os.getenv("DASHBOARD_CACHE_TTL_SECONDS", "120"))

_DASHBOARD_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_DASHBOARD_CACHE_LOCK = threading.Lock()


def cache_key(name: str, **params: Any) -> str:
    """Build a stable cache key from an endpoint name + its params."""
    return json.dumps(
        {"name": name, "params": params},
        sort_keys=True,
        default=str,
        ensure_ascii=True,
    )


def cache_get(key: str) -> Optional[Dict[str, Any]]:
    """Return the cached payload if present and not expired, else ``None``."""
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


def cache_set(
    key: str,
    payload: Dict[str, Any],
    ttl: Optional[int] = None,
) -> Dict[str, Any]:
    """Store *payload* under *key* with the given TTL (or the default).

    Returns *payload* so callers can write ``return cache_set(key, payload)``.
    """
    effective_ttl = DASHBOARD_CACHE_TTL_SECONDS if ttl is None else ttl
    if effective_ttl > 0:
        with _DASHBOARD_CACHE_LOCK:
            _DASHBOARD_CACHE[key] = (time.monotonic() + effective_ttl, payload)
            if len(_DASHBOARD_CACHE) > 512:
                oldest_keys = sorted(
                    _DASHBOARD_CACHE,
                    key=lambda item: _DASHBOARD_CACHE[item][0],
                )[:128]
                for old_key in oldest_keys:
                    _DASHBOARD_CACHE.pop(old_key, None)
    return payload


# Backwards-compatibility aliases — existing dashboard_router code calls the
# underscore-prefixed names. Keep both bindings until Phase B migration.
_cache_key = cache_key
_cache_get = cache_get
_cache_set = cache_set


__all__ = [
    "DASHBOARD_CACHE_TTL_SECONDS",
    "cache_key",
    "cache_get",
    "cache_set",
    "_cache_key",
    "_cache_get",
    "_cache_set",
]
