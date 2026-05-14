import os
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.cors import build_cors_origins  # noqa: E402


def test_cors_origins_preserve_explicit_origin_and_add_uat_dev_defaults():
    origins = build_cors_origins("http://192.168.100.44:9001")

    assert origins == [
        "http://192.168.100.44:9001",
        "https://ctidashboard.worldinfinity.co.th",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def test_cors_origins_keep_wildcard_for_open_dev_mode():
    assert build_cors_origins("*") == ["*"]


def test_cors_preflight_allows_localhost_dev_origin():
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=build_cors_origins("http://192.168.100.44:9001"),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    response = TestClient(app).options(
        "/api/v1/executive/dashboard",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
