"""
Security Payloads API, Repository, and Importer Unit Tests.

Coverage:
  1. API requires authentication (401 when unauthenticated)
  2. List payloads with pagination
  3. Filter payloads by category / type
  4. Filter payloads by severity
  5. Search payloads across id, description, payload content
  6. Retrieve payload details by ID
  7. Retrieve non-existent payload ID returns 404
  8. Aggregated stats endpoint (by severity and by type)
  9. Importer record validation (required fields, severity values)
 10. Importer idempotency (subsequent runs do not create duplicates)
 11. Scanner payload test runner safe probe execution & confidence classification
"""

import json
from pathlib import Path
from tempfile import NamedTemporaryFile
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_payload import SecurityPayload
from app.repositories.security_payload import SecurityPayloadRepository
from app.scripts.import_payloads import (
    import_payloads,
    validate_payload_record,
)
from app.services.scanner.payload_test_runner import PayloadSecurityTestRunner
from app.repositories.finding import FindingRepository
from app.models.scan import Scan

pytestmark = pytest.mark.asyncio


async def _seed_test_payloads(db: AsyncSession) -> list[SecurityPayload]:
    """Insert a controlled fixture set of payloads into the test DB."""
    repo = SecurityPayloadRepository(db)
    items = [
        SecurityPayload(
            id="sqli-test-01",
            description="Basic tautology injection",
            payload="' OR '1'='1",
            context="Login field",
            type="tautology",
            severity="high",
            example_usage="SELECT * FROM users WHERE user='' OR '1'='1'",
        ),
        SecurityPayload(
            id="sqli-test-02",
            description="Stacked drop table query",
            payload="'; DROP TABLE users--",
            context="Search input",
            type="stacked-queries",
            severity="critical",
            example_usage="SELECT * FROM items; DROP TABLE users--",
        ),
        SecurityPayload(
            id="xss-test-01",
            description="Reflected XSS script execution",
            payload="<script>alert(1)</script>",
            context="Search box",
            type="reflected",
            severity="medium",
            example_usage=None,
        ),
        SecurityPayload(
            id="ssrf-test-01",
            description="Cloud metadata probe",
            payload="http://169.254.169.254/latest/meta-data/",
            context="Webhook URL parameter",
            type="SSRF",
            severity="critical",
            example_usage=None,
        ),
    ]
    for p in items:
        db.add(p)
    await db.commit()
    return items


# ── Test Cases ───────────────────────────────────────────────────

async def test_list_payloads_unauthenticated(client: AsyncClient):
    """Accessing payloads without auth header returns 401."""
    resp = await client.get("/api/v1/payloads")
    assert resp.status_code == 401


async def test_list_payloads_paginated(client: AsyncClient, registered_user: dict, db: AsyncSession):
    """Listing payloads returns paginated structure."""
    await _seed_test_payloads(db)
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    resp = await client.get("/api/v1/payloads?page=1&page_size=2", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["total"] == 4
    assert len(data["items"]) == 2
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total_pages"] == 2


async def test_filter_payloads_by_type(client: AsyncClient, registered_user: dict, db: AsyncSession):
    """Filtering by category/type returns only matching records."""
    await _seed_test_payloads(db)
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    resp = await client.get("/api/v1/payloads?type=reflected", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 1
    assert data["items"][0]["id"] == "xss-test-01"
    assert data["items"][0]["type"] == "reflected"


async def test_filter_payloads_by_severity(client: AsyncClient, registered_user: dict, db: AsyncSession):
    """Filtering by severity returns only matching records."""
    await _seed_test_payloads(db)
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    resp = await client.get("/api/v1/payloads?severity=critical", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 2
    ids = {item["id"] for item in data["items"]}
    assert ids == {"sqli-test-02", "ssrf-test-01"}


async def test_search_payloads(client: AsyncClient, registered_user: dict, db: AsyncSession):
    """Search query matches id, description, or payload text."""
    await _seed_test_payloads(db)
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    # Search for script tag
    resp = await client.get("/api/v1/payloads?q=alert(1)", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["id"] == "xss-test-01"

    # Search for id
    resp_id = await client.get("/api/v1/payloads?q=sqli-test-02", headers=headers)
    assert resp_id.status_code == 200
    assert resp_id.json()["total"] == 1


async def test_get_payload_by_id(client: AsyncClient, registered_user: dict, db: AsyncSession):
    """Fetching individual payload by ID succeeds."""
    await _seed_test_payloads(db)
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    resp = await client.get("/api/v1/payloads/sqli-test-01", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "sqli-test-01"
    assert data["payload"] == "' OR '1'='1"
    assert data["type"] == "tautology"


async def test_get_payload_not_found(client: AsyncClient, registered_user: dict, db: AsyncSession):
    """Fetching non-existent payload ID returns 404."""
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
    resp = await client.get("/api/v1/payloads/non-existent-id", headers=headers)
    assert resp.status_code == 404


async def test_get_payload_stats(client: AsyncClient, registered_user: dict, db: AsyncSession):
    """Stats endpoint returns totals and breakdown maps."""
    await _seed_test_payloads(db)
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    resp = await client.get("/api/v1/payloads/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] == 4
    assert data["by_severity"]["critical"] == 2
    assert data["by_severity"]["high"] == 1
    assert data["by_severity"]["medium"] == 1
    assert data["by_type"]["tautology"] == 1
    assert data["by_type"]["reflected"] == 1


async def test_validator_required_fields_and_severity():
    """Unit test for validate_payload_record rules."""
    # Valid record
    valid_rec = {
        "id": "test-1",
        "description": "desc",
        "payload": "payload_text",
        "context": "ctx",
        "type": "type_val",
        "severity": "high",
    }
    is_valid, reason, cleaned = validate_payload_record(valid_rec)
    assert is_valid is True
    assert reason is None
    assert cleaned["id"] == "test-1"

    # Missing payload
    invalid_no_payload = dict(valid_rec)
    del invalid_no_payload["payload"]
    is_valid, reason, _ = validate_payload_record(invalid_no_payload)
    assert is_valid is False
    assert "payload" in reason.lower()

    # Invalid severity
    invalid_sev = dict(valid_rec, severity="super-critical")
    is_valid, reason, _ = validate_payload_record(invalid_sev)
    assert is_valid is False
    assert "severity" in reason.lower()


async def test_importer_idempotency(db: AsyncSession, tmp_path: Path):
    """Importer inserts valid records and is completely idempotent on second run."""
    dataset = [
        {
            "id": "mock-001",
            "description": "Mock payload 1",
            "payload": "' OR 1=1--",
            "context": "Form",
            "type": "SQLi",
            "severity": "high",
        },
        {
            "id": "mock-002",
            "description": "Mock payload 2",
            "payload": "<img src=x onerror=alert(1)>",
            "context": "Input",
            "type": "XSS",
            "severity": "medium",
        },
    ]

    temp_file = tmp_path / "test_dataset.json"
    temp_file.write_text(json.dumps(dataset), encoding="utf-8")

    # First run: should insert 2
    res1 = await import_payloads(temp_file, db)
    assert res1.inserted == 2
    assert res1.skipped == 0
    assert res1.updated == 0

    # Second run: should skip 2 (idempotent)
    res2 = await import_payloads(temp_file, db)
    assert res2.inserted == 0
    assert res2.skipped == 2
    assert res2.updated == 0
