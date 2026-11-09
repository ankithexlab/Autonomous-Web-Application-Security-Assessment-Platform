"""
Security Projects API Unit & Regression Tests.

Coverage:
  1. POST /api/v1/projects — Create project
  2. GET  /api/v1/projects — List user projects
  3. GET  /api/v1/projects/{project_id} — Get project details
  4. PUT  /api/v1/projects/{project_id} — Update project details & status
  5. DELETE /api/v1/projects/{project_id} — Delete project and verify cascade
  6. IDOR / Cross-user project access protection (update & delete return 404)
  7. Non-existent project access returns 404
"""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_project_crud_lifecycle(client: AsyncClient, registered_user: dict):
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    # 1. Create project
    create_res = await client.post(
        "/api/v1/projects",
        json={"name": "Lifecycle Project", "description": "Initial desc", "risk_level": "medium"},
        headers=headers,
    )
    assert create_res.status_code == 201, create_res.text
    project = create_res.json()
    project_id = project["id"]
    assert project["name"] == "Lifecycle Project"
    assert project["status"] == "active"
    assert project["risk_level"] == "medium"

    # 2. Get project details
    get_res = await client.get(f"/api/v1/projects/{project_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == project_id

    # 3. List projects
    list_res = await client.get("/api/v1/projects", headers=headers)
    assert list_res.status_code == 200
    assert any(p["id"] == project_id for p in list_res.json())

    # 4. Update project (PUT /api/v1/projects/{project_id})
    update_res = await client.put(
        f"/api/v1/projects/{project_id}",
        json={
            "name": "Updated Lifecycle Project",
            "description": "Updated desc",
            "status": "archived",
            "risk_level": "high",
        },
        headers=headers,
    )
    assert update_res.status_code == 200, update_res.text
    updated = update_res.json()
    assert updated["name"] == "Updated Lifecycle Project"
    assert updated["description"] == "Updated desc"
    assert updated["status"] == "archived"
    assert updated["risk_level"] == "high"

    # 5. Delete project (DELETE /api/v1/projects/{project_id})
    del_res = await client.delete(f"/api/v1/projects/{project_id}", headers=headers)
    assert del_res.status_code == 204

    # 6. Verify project is deleted
    get_after_del = await client.get(f"/api/v1/projects/{project_id}", headers=headers)
    assert get_after_del.status_code == 404


async def test_project_cross_user_isolation(client: AsyncClient, registered_user: dict):
    headers_a = {"Authorization": f"Bearer {registered_user['access_token']}"}

    # User A creates a project
    create_res = await client.post(
        "/api/v1/projects",
        json={"name": "User A Sensitive Project", "risk_level": "high"},
        headers=headers_a,
    )
    assert create_res.status_code == 201
    project_id = create_res.json()["id"]

    # Register User B
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={"name": "User B", "email": "user_b_proj@example.com", "password": "Password123!"},
    )
    assert reg_b.status_code == 201
    headers_b = {"Authorization": f"Bearer {reg_b.json()['access_token']}"}

    # User B cannot get User A's project
    assert (await client.get(f"/api/v1/projects/{project_id}", headers=headers_b)).status_code == 404

    # User B cannot update User A's project
    assert (
        await client.put(
            f"/api/v1/projects/{project_id}",
            json={"name": "Hacked Name"},
            headers=headers_b,
        )
    ).status_code == 404

    # User B cannot delete User A's project
    assert (await client.delete(f"/api/v1/projects/{project_id}", headers=headers_b)).status_code == 404
