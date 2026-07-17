"""
Tests for URL model config — verifies SHORT_URL_BASE is used correctly.
Run with: pytest tests/test_config.py
"""

import pytest
from datetime import datetime
from app import app
from models import URL


@pytest.fixture
def app_context():
    with app.app_context():
        yield


def test_short_url_uses_base_config(app_context):
    """short_url in to_dict() must be built from SHORT_URL_BASE config."""
    short_url_base = app.config.get("SHORT_URL_BASE", "http://localhost:5000")
    test_code = "testcode123"

    url = URL(
        original_url="https://www.example.com/test",
        short_code=test_code,
        user_id=None,
        threat_score=0.0,
        threat_verdict="SAFE",
        created_at=datetime.utcnow(),
    )

    result = url.to_dict()
    expected = f"{short_url_base}/{test_code}"
    assert result["short_url"] == expected, (
        f"Expected '{expected}', got '{result['short_url']}'"
    )


def test_config_has_required_keys(app_context):
    """Essential config keys must be present and non-empty."""
    required_keys = ["SHORT_URL_BASE", "API_BASE_URL", "FRONTEND_URL"]
    for key in required_keys:
        value = app.config.get(key)
        assert value, f"Config key '{key}' is missing or empty"
