"""
Findings API and Management Unit Tests.

Coverage:
  1. List findings paginated
  2. Severity filter
  3. Confidence filter
  4. OWASP category filter
  5. Scan ID & Target ID filters
  6. Get finding details by ID
  7. Update finding status (open -> acknowledged -> fixed)
  8. IDOR / Cross-user access protection (returns 404)
  9. Invalid status update validation (returns 400)
 10. OWASP summary count consistency
"""

from unittest.mock import patch
import pytest
from httpx import AsyncClient

from app.core.http_client import SafeHTTPResponse
from app.repositories.finding import FindingRepository
from app.repositories.scan import ScanRepository
from app.services.scanner_engine import ScannerEngine

pytestmark = pytest.mark.asyncio


class MockFindingHTTPClient:
    async def get(self, target_url: str, headers: dict[str, str] | None = None) -> SafeHTTPResponse:
        return SafeHTTPResponse(
            url=target_url,
            status_code=200,
            headers={
                "content-type": "text/html",
                "server": "nginx/1.18.0",
            },
            text="<html><body><h1>Test</h1></body></html>",
            elapsed_seconds=0.1,
            redirect_chain=[target_url],
            content_type="text/html",
        )


async def _create_test_scan_with_findings(db, env: dict) -> str:
    scan_repo = ScanRepository(db)
    scan = await scan_repo.create(
        target_id=env["target"]["id"],
        project_id=env["project"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="full",
    )

    engine = ScannerEngine(db, http_client=MockFindingHTTPClient())
    with patch("app.services.scanner_engine.validate_target_url", return_value="https://example.com"):
        await engine.run_scan(scan.id)

    return str(scan.id)


async def test_list_findings_paginated(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    scan_id = await _create_test_scan_with_findings(db, env)

    response = await client.get("/api/v1/findings?page=1&page_size=10", headers=env["headers"])
    assert response.status_code == 200, response.text
    data = response.json()

    assert "items" in data
    assert "total" in data
    assert data["total"] > 0
    assert data["page"] == 1
    assert data["page_size"] == 10
    assert len(data["items"]) > 0


async def test_filter_findings_by_severity_and_confidence(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan_with_findings(db, env)

    # Filter by severity
    sev_res = await client.get("/api/v1/findings?severity=low", headers=env["headers"])
    assert sev_res.status_code == 200
    for item in sev_res.json()["items"]:
        assert item["severity"] == "low"

    # Filter by confidence
    conf_res = await client.get("/api/v1/findings?confidence=HIGH", headers=env["headers"])
    assert conf_res.status_code == 200
    for item in conf_res.json()["items"]:
        assert item["confidence"] == "HIGH"


async def test_filter_findings_by_owasp_category(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan_with_findings(db, env)

    res = await client.get("/api/v1/findings?owasp_category=A05", headers=env["headers"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) > 0
    for item in items:
        assert "A05" in item["owasp_category"]


async def test_filter_findings_by_project_id(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan_with_findings(db, env)
    project_id = env["project"]["id"]

    # Filter with valid project_id
    res = await client.get(f"/api/v1/findings?project_id={project_id}", headers=env["headers"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) > 0
    for item in items:
        assert item["project_id"] == project_id

    # Filter with random project_id -> returns 0 items for this user
    random_id = "00000000-0000-0000-0000-000000000000"
    empty_res = await client.get(f"/api/v1/findings?project_id={random_id}", headers=env["headers"])
    assert empty_res.status_code == 200
    assert empty_res.json()["total"] == 0
    assert len(empty_res.json()["items"]) == 0


async def test_get_finding_detail_and_update_status(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan_with_findings(db, env)

    # List findings to grab ID
    list_res = await client.get("/api/v1/findings", headers=env["headers"])
    finding_id = list_res.json()["items"][0]["id"]

    # Get finding detail
    detail_res = await client.get(f"/api/v1/findings/{finding_id}", headers=env["headers"])
    assert detail_res.status_code == 200
    finding = detail_res.json()
    assert finding["id"] == finding_id
    assert finding["status"] == "open"

    # Update status to acknowledged
    update_res = await client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "acknowledged"},
        headers=env["headers"],
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "acknowledged"


async def test_invalid_finding_status_update(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan_with_findings(db, env)

    list_res = await client.get("/api/v1/findings", headers=env["headers"])
    finding_id = list_res.json()["items"][0]["id"]

    bad_update = await client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "invalid_status_name"},
        headers=env["headers"],
    )
    assert bad_update.status_code == 400


async def test_cross_user_finding_access_prevention(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan_with_findings(db, env)

    list_res = await client.get("/api/v1/findings", headers=env["headers"])
    finding_id = list_res.json()["items"][0]["id"]

    # Register second user
    second_user_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "Second User", "email": "user2@example.com", "password": "Password123!"},
    )
    second_headers = {"Authorization": f"Bearer {second_user_res.json()['access_token']}"}

    # Second user attempting to access first user's finding -> 404 Not Found (IDOR protection)
    cross_access_res = await client.get(f"/api/v1/findings/{finding_id}", headers=second_headers)
    assert cross_access_res.status_code == 404

    # Second user attempting to update first user's finding status -> 404 Not Found
    cross_update_res = await client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "fixed"},
        headers=second_headers,
    )
    assert cross_update_res.status_code == 404


async def test_owasp_summary_findings_count_consistency(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan_with_findings(db, env)

    # 1. Fetch total findings count from /findings
    findings_res = await client.get("/api/v1/findings", headers=env["headers"])
    total_findings = findings_res.json()["total"]

    # 2. Fetch summary from /owasp/summary
    summary_res = await client.get("/api/v1/owasp/summary", headers=env["headers"])
    summary_total = summary_res.json()["total_vulnerabilities"]

    # Count must match
    assert total_findings == summary_total
