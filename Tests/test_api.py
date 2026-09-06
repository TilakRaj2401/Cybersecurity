"""API tests for the NIDS service.

These tests gracefully skip when FastAPI or the application module
is not available in the current environment.
"""

import pytest

try:
    from fastapi.testclient import TestClient
    from main_api import app
    _API_MISSING = None
except ImportError as _err:
    TestClient = None
    app = None
    _API_MISSING = str(_err)


if TestClient and app:
    CLIENT = TestClient(app)
else:
    CLIENT = None


def test_health_endpoint():
    """GET /api/v1/health should return operational status."""
    if _API_MISSING:
        pytest.skip(f"API dependencies missing: {_API_MISSING}")

    response = CLIENT.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "operational", "engine": "running"}
