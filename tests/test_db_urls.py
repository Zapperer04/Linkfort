"""
Tests for URL database entries and threat verdict distribution.
Run with: pytest tests/test_db_urls.py
"""

import pytest
from app import app
from models import db, URL


@pytest.fixture
def app_context():
    with app.app_context():
        yield


def test_url_table_accessible(app_context):
    """Ensure the URL table is reachable and returns a list."""
    urls = URL.query.all()
    assert isinstance(urls, list)


def test_threat_verdicts_are_valid(app_context):
    """All stored URLs must have a recognised threat verdict."""
    valid_verdicts = {"SAFE", "WARN", "BLOCK"}
    urls = URL.query.all()
    for url in urls:
        assert url.threat_verdict in valid_verdicts, (
            f"Unexpected verdict '{url.threat_verdict}' for URL id={url.id}"
        )


def test_verdict_counts(app_context):
    """Smoke-check that verdict counts sum to total row count."""
    total = URL.query.count()
    safe = URL.query.filter_by(threat_verdict="SAFE").count()
    warn = URL.query.filter_by(threat_verdict="WARN").count()
    block = URL.query.filter_by(threat_verdict="BLOCK").count()
    assert safe + warn + block == total
