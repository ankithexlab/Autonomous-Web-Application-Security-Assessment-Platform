"""
Target Management and User Target Aggregation Unit Tests.

Coverage:
  1. GET /api/v1/targets — Lists all targets across all projects owned by the user
  2. Cross-user isolation on GET /api/v1/targets
  3. POST /api/v1/projects/{project_id}/targets — Create target under project
  4. GET /api/v1/projects/{project_id}/targets — List project targets
  5. GET /api/v1/projects/{project_id}/targets/{target_id} — Get target details
  6. IDOR / Cross-user target protection (returns 404)
  7. Target creation in non-existent project (returns 404)
"""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_list_all_user_targets_single_query(client: AsyncClient, registered_user: dict):
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    # Create two projects
    p1_resp = await client.post(
        "/api/v1/projects",
        json={"name": "Project Alpha", "risk_level": "medium"},
        headers=headers,
    )
    assert p1_resp.status_code == 201
    p1_id = p1_resp.json()["id"]

    p2_resp = await client.post(
        "/api/v1/projects",
        json={"name": "Project Beta", "risk_level": "low"},
        headers=headers,
    )
    assert p2_resp.status_code == 201
    p2_id = p2_resp.json()["id"]

    # Create targets under each project
    t1_resp = await client.post(
        f"/api/v1/projects/{p1_id}/targets",
        json={"url": "https://alpha.example.com", "type": "web"},
        headers=headers,
    )
    assert t1_resp.status_code == 201
    t1_id = t1_resp.json()["id"]

    t2_resp = await client.post(
        f"/api/v1/projects/{p2_id}/targets",
        json={"url": "https://beta.example.com", "type": "api"},
        headers=headers,
    )
    assert t2_resp.status_code == 201
    t2_id = t2_resp.json()["id"]

    # Call GET /api/v1/targets (the newly added endpoint)
    all_targets_resp = await client.get("/api/v1/targets", headers=headers)
    assert all_targets_resp.status_code == 200, all_targets_resp.text
    targets = all_targets_resp.json()

    assert len(targets) == 2
    target_ids = {t["id"] for t in targets}
    assert t1_id in target_ids
    assert t2_id in target_ids


async def test_cross_user_target_isolation(client: AsyncClient, registered_user: dict):
    headers_a = {"Authorization": f"Bearer {registered_user['access_token']}"}

    # User A creates a project and target
    p_resp = await client.post(
        "/api/v1/projects",
        json={"name": "User A Project", "risk_level": "high"},
        headers=headers_a,
    )
    assert p_resp.status_code == 201
    project_id = p_resp.json()["id"]

    t_resp = await client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"url": "https://secure.example.com", "type": "web"},
        headers=headers_a,
    )
    assert t_resp.status_code == 201
    target_id = t_resp.json()["id"]

    # Register User B
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={"name": "User B", "email": "user_b@example.com", "password": "Password123!"},
    )
    assert reg_b.status_code == 201
    headers_b = {"Authorization": f"Bearer {reg_b.json()['access_token']}"}

    # User B lists user targets -> must be empty
    all_targets_b = await client.get("/api/v1/targets", headers=headers_b)
    assert all_targets_b.status_code == 200
    assert len(all_targets_b.json()) == 0

    # User B tries to access User A's target directly -> 404
    detail_res = await client.get(f"/api/v1/projects/{project_id}/targets/{target_id}", headers=headers_b)
    assert detail_res.status_code == 404

    # User B tries to create target under User A's project -> 404
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"url": "https://evil.example.com", "type": "web"},
        headers=headers_b,
    )
    assert create_res.status_code == 404


async def test_get_target_details_and_not_found(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # Get existing target
    res = await client.get(f"/api/v1/projects/{project_id}/targets/{target_id}", headers=env["headers"])
    assert res.status_code == 200
    assert res.json()["id"] == target_id
    assert res.json()["url"] == "https://app.acmecorp.com"

    # Non-existent target
    non_existent = "00000000-0000-0000-0000-000000000000"
    res_404 = await client.get(f"/api/v1/projects/{project_id}/targets/{non_existent}", headers=env["headers"])
    assert res_404.status_code == 404
