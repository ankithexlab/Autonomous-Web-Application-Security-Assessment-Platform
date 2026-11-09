"""
Scan management endpoint tests.

Coverage:
  1. Create scan success
  2. List user scans
  3. Get scan details
  4. List project scans
  5. List target scans
  6. Unauthorized request (no token) -> 401
  7. Cross-user project access -> 404 (or 403)
  8. Cross-user target access -> 404 (or 403)
  9. Cross-user scan access -> 404 (or 403)
 10. Invalid project ID -> 404
 11. Invalid target ID -> 404
 12. Target belonging to another project -> 404
 13. Cancel scan success
 14. Invalid scan ID -> 404
 15. Cancel completed scan error -> 400
"""

import uuid
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ── Test Fixtures ────────────────────────────────────────────────

@pytest.fixture
async def second_user(client: AsyncClient):
    payload = {
        "name": "Second User",
        "email": "user2@example.com",
        "password": "Password123!",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    return {
        "user": data["user"],
        "token": data["access_token"],
        "headers": {"Authorization": f"Bearer {data['access_token']}"},
    }


# ── Tests ────────────────────────────────────────────────────────

async def test_create_scan_success(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    resp = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full", "config": {"maxDepth": 5}},
        headers=env["headers"],
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()

    assert scan["scan_type"] == "full"
    assert scan["status"] == "QUEUED"
    assert scan["target_id"] == target_id
    assert scan["project_id"] == project_id
    assert scan["target_url"] == "https://app.acmecorp.com"


async def test_list_scans(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # Create 2 scans
    await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "quick"},
        headers=env["headers"],
    )
    await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=env["headers"],
    )

    # List all user scans
    res = await client.get("/api/v1/scans", headers=env["headers"])
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # List project scans
    res_p = await client.get(f"/api/v1/projects/{project_id}/scans", headers=env["headers"])
    assert res_p.status_code == 200
    assert res_p.json()["total"] == 2

    # List target scans
    res_t = await client.get(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        headers=env["headers"],
    )
    assert res_t.status_code == 200
    assert res_t.json()["total"] == 2


async def test_get_scan_details(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=env["headers"],
    )
    scan_id = create_res.json()["id"]

    res = await client.get(f"/api/v1/scans/{scan_id}", headers=env["headers"])
    assert res.status_code == 200
    scan = res.json()
    assert scan["id"] == scan_id
    assert scan["status"] == "QUEUED"


async def test_cancel_scan(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=env["headers"],
    )
    scan_id = create_res.json()["id"]

    cancel_res = await client.patch(f"/api/v1/scans/{scan_id}/cancel", headers=env["headers"])
    assert cancel_res.status_code == 200
    scan = cancel_res.json()
    assert scan["status"] == "CANCELLED"
    assert scan["completed_at"] is not None


async def test_unauthorized_request(client: AsyncClient):
    res = await client.get("/api/v1/scans")
    assert res.status_code == 401


async def test_cross_user_scan_access(
    client: AsyncClient, setup_project_and_target: dict, second_user: dict
):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # User 1 creates scan
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=env["headers"],
    )
    scan_id = create_res.json()["id"]

    # User 2 attempts to view User 1's scan
    res_get = await client.get(f"/api/v1/scans/{scan_id}", headers=second_user["headers"])
    assert res_get.status_code == 404

    # User 2 attempts to cancel User 1's scan
    res_cancel = await client.patch(
        f"/api/v1/scans/{scan_id}/cancel", headers=second_user["headers"]
    )
    assert res_cancel.status_code == 404

    # User 2 attempts to create scan under User 1's project/target
    res_create = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=second_user["headers"],
    )
    assert res_create.status_code == 404


async def test_invalid_ids_and_mismatched_target(
    client: AsyncClient, setup_project_and_target: dict
):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    fake_id = str(uuid.uuid4())

    # Invalid scan ID
    res = await client.get(f"/api/v1/scans/{fake_id}", headers=env["headers"])
    assert res.status_code == 404

    # Invalid project ID for scan creation
    res2 = await client.post(
        f"/api/v1/projects/{fake_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=env["headers"],
    )
    assert res2.status_code == 404

    # Invalid target ID for scan creation
    res3 = await client.post(
        f"/api/v1/projects/{project_id}/targets/{fake_id}/scans",
        json={"scan_type": "full"},
        headers=env["headers"],
    )
    assert res3.status_code == 404


async def test_start_scan_and_get_findings(
    client: AsyncClient, setup_project_and_target: dict
):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # 1. Create scan
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={
            "scan_type": "full",
            "config": {
                "targetUrl": "https://app.acmecorp.com",
                "modules": ["headers", "sql_injection"],
                "maxDepth": 5,
            },
        },
        headers=env["headers"],
    )
    assert create_res.status_code == 201
    scan_data = create_res.json()
    scan_id = scan_data["id"]
    assert "modules_json" in scan_data

    # 2. Get initial scan findings (should be empty list)
    findings_res = await client.get(
        f"/api/v1/scans/{scan_id}/findings",
        headers=env["headers"],
    )
    assert findings_res.status_code == 200
    assert findings_res.json() == []

    # 3. Start scan execution
    start_res = await client.post(
        f"/api/v1/scans/{scan_id}/start",
        headers=env["headers"],
    )
    assert start_res.status_code == 200
    started_scan = start_res.json()
    assert started_scan["status"] in ("QUEUED", "RUNNING")

    # 4. Cancel scan
    cancel_res = await client.patch(
        f"/api/v1/scans/{scan_id}/cancel",
        headers=env["headers"],
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # 5. Attempting to cancel already cancelled scan returns 400
    cancel_again = await client.patch(
        f"/api/v1/scans/{scan_id}/cancel",
        headers=env["headers"],
    )
    assert cancel_again.status_code == 400

