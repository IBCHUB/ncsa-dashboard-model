from __future__ import annotations

from typing import Iterable, List


DEFAULT_CORS_ORIGINS = [
    "https://ctidashboard.worldinfinity.co.th",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


def build_cors_origins(origin_setting: str | None, defaults: Iterable[str] = DEFAULT_CORS_ORIGINS) -> List[str]:
    setting = (origin_setting or "").strip()
    if setting == "*":
        return ["*"]

    origins = []
    seen = set()
    for origin in [item.strip() for item in setting.split(",") if item.strip()] + list(defaults):
        if origin not in seen:
            origins.append(origin)
            seen.add(origin)

    return origins or ["*"]
