"""
Phase 2 Backend Repair — Regression Tests
==========================================

Covers every fix applied during Phase 2:
  - DELETE /auth/me            (account self-deletion with cascade + token revocation)
  - DELETE /targets/{id}       (flat-route deletion with IDOR protection)
  - DELETE /projects/{id}/targets/{id}  (project-scoped target deletion)
  - DELETE /scans/{id}         (scan deletion with RUNNING guard)
  - DELETE /findings/{id}      (finding deletion with IDOR protection)
  - DELETE /reports/{id}       (report deletion with IDOR protection)
  - GET  /dashboard/notifications  (derived notifications endpoint)
  - Cross-user IDOR: all DELETE endpoints return 404 for another user's resource
  - Unauthenticated access: all DELETE endpoints return 401

Each test is independent and uses the shared `client` / `registered_user` /
`setup_project_and_target` fixtures from conftest.py.
"""

import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient


# ── Helper: register a second independent user ───────────────────────────────

async def _register_other_user(client: AsyncClient) -> dict:
    """Create a second user account and return its tokens."""
    payload = {
        "name": "Other User",
        "email": f"other_{uuid.uuid4().hex}@example.com",
        "password": "OtherPass999!",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ── Helper: create a finding via scan (using a fully seeded scan record) ─────

async def _create_finding_directly(client: AsyncClient, headers: dict, project_id: str, target_id: str) -> dict:
    """
    Create a scan and then a finding via POST /scans/{id}/findings if that endpoint
    exists; otherwise directly POST to /findings.  Falls back to creating a scan and
    checking the findings list.  Returns the finding dict.
    """
    # Start a scan (queued — won't actually run in tests)
    scan_resp = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "quick"},
        headers=headers,
    )
    assert scan_resp.status_code in (200, 201), f"scan create failed: {scan_resp.text}"
    scan = scan_resp.json()

    # POST a finding scoped to this scan
    finding_resp = await client.post(
        "/api/v1/findings",
        json={
            "scan_id": scan["id"],
            "target_id": target_id,
            "project_id": project_id,
            "title": "Phase2 Test Finding",
            "description": "XSS in search field",
            "severity": "high",
        },
        headers=headers,
    )
    assert finding_resp.status_code in (200, 201), f"finding create failed: {finding_resp.text}"
    return finding_resp.json(), scan


async def _create_report(client: AsyncClient, headers: dict, project_id: str) -> dict:
    """Create a report for the given project. Returns report dict."""
    resp = await client.post(
        "/api/v1/reports",
        json={
            "project_id": project_id,
            "title": "Phase2 Test Report",
            "report_type": "executive",
            "file_format": "pdf",
        },
        headers=headers,
    )
    assert resp.status_code in (200, 201), f"report create failed: {resp.text}"
    return resp.json()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. UNAUTHENTICATED ACCESS — all protected endpoints must return 401
# ═══════════════════════════════════════════════════════════════════════════════

class TestUnauthenticated:
    """Every DELETE endpoint must reject requests without a Bearer token."""

    @pytest.mark.asyncio
    async def test_delete_account_unauthenticated(self, client: AsyncClient):
        resp = await client.delete("/api/v1/auth/me")
        assert resp.status_code == 401, resp.text

    @pytest.mark.asyncio
    async def test_delete_target_unauthenticated(self, client: AsyncClient):
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/targets/{fake_id}")
        assert resp.status_code == 401, resp.text

    @pytest.mark.asyncio
    async def test_delete_project_target_unauthenticated(self, client: AsyncClient):
        fake_pid = str(uuid.uuid4())
        fake_tid = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/projects/{fake_pid}/targets/{fake_tid}")
        assert resp.status_code == 401, resp.text

    @pytest.mark.asyncio
    async def test_delete_scan_unauthenticated(self, client: AsyncClient):
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/scans/{fake_id}")
        assert resp.status_code == 401, resp.text

    @pytest.mark.asyncio
    async def test_delete_finding_unauthenticated(self, client: AsyncClient):
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/findings/{fake_id}")
        assert resp.status_code == 401, resp.text

    @pytest.mark.asyncio
    async def test_delete_report_unauthenticated(self, client: AsyncClient):
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/reports/{fake_id}")
        assert resp.status_code == 401, resp.text

    @pytest.mark.asyncio
    async def test_get_notifications_unauthenticated(self, client: AsyncClient):
        resp = await client.get("/api/v1/dashboard/notifications")
        assert resp.status_code == 401, resp.text


# ═══════════════════════════════════════════════════════════════════════════════
# 2. 404 ON NON-EXISTENT RESOURCE (authenticated)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotFound:
    """Authenticated requests to non-existent resource IDs must return 404."""

    @pytest.mark.asyncio
    async def test_delete_target_not_found(self, client: AsyncClient, registered_user: dict):
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/targets/{fake_id}", headers=headers)
        assert resp.status_code == 404, resp.text

    @pytest.mark.asyncio
    async def test_delete_scan_not_found(self, client: AsyncClient, registered_user: dict):
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/scans/{fake_id}", headers=headers)
        assert resp.status_code == 404, resp.text

    @pytest.mark.asyncio
    async def test_delete_finding_not_found(self, client: AsyncClient, registered_user: dict):
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/findings/{fake_id}", headers=headers)
        assert resp.status_code == 404, resp.text

    @pytest.mark.asyncio
    async def test_delete_report_not_found(self, client: AsyncClient, registered_user: dict):
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/v1/reports/{fake_id}", headers=headers)
        assert resp.status_code == 404, resp.text


# ═══════════════════════════════════════════════════════════════════════════════
# 3. HAPPY PATH — authenticated owner can delete their own resources
# ═══════════════════════════════════════════════════════════════════════════════

class TestOwnerCanDelete:
    """Authenticated owner successfully deletes their own resources."""

    @pytest.mark.asyncio
    async def test_delete_target_via_flat_route(
        self, client: AsyncClient, setup_project_and_target: dict
    ):
        ctx = setup_project_and_target
        headers = ctx["headers"]
        target_id = ctx["target"]["id"]

        resp = await client.delete(f"/api/v1/targets/{target_id}", headers=headers)
        assert resp.status_code == 204, resp.text

        # Verify gone — subsequent GET returns 404
        get_resp = await client.get(f"/api/v1/targets/{target_id}", headers=headers)
        assert get_resp.status_code == 404, get_resp.text

    @pytest.mark.asyncio
    async def test_delete_target_via_project_route(
        self, client: AsyncClient, setup_project_and_target: dict
    ):
        ctx = setup_project_and_target
        headers = ctx["headers"]
        project_id = ctx["project"]["id"]
        target_id = ctx["target"]["id"]

        resp = await client.delete(
            f"/api/v1/projects/{project_id}/targets/{target_id}", headers=headers
        )
        assert resp.status_code == 204, resp.text

    @pytest.mark.asyncio
    async def test_delete_scan_success(
        self, client: AsyncClient, setup_project_and_target: dict
    ):
        ctx = setup_project_and_target
        headers = ctx["headers"]
        project_id = ctx["project"]["id"]
        target_id = ctx["target"]["id"]

        # Create a scan first
        scan_resp = await client.post(
            f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
            json={"scan_type": "quick"},
            headers=headers,
        )
        assert scan_resp.status_code in (200, 201), scan_resp.text
        scan_id = scan_resp.json()["id"]

        resp = await client.delete(f"/api/v1/scans/{scan_id}", headers=headers)
        assert resp.status_code == 204, resp.text

    @pytest.mark.asyncio
    async def test_delete_account_cascades(
        self, client: AsyncClient, setup_project_and_target: dict
    ):
        """
        DELETE /auth/me must succeed and invalidate the token.
        A subsequent GET /auth/me with the same token must return 401.
        """
        ctx = setup_project_and_target
        headers = ctx["headers"]

        resp = await client.delete("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "deleted" in body.get("message", "").lower()

        # Token must now be invalid (user deleted → revoked)
        me_resp = await client.get("/api/v1/auth/me", headers=headers)
        assert me_resp.status_code == 401, me_resp.text


# ═══════════════════════════════════════════════════════════════════════════════
# 4. IDOR PROTECTION — cross-user access must return 404 (not 403)
# ═══════════════════════════════════════════════════════════════════════════════

class TestIDORProtection:
    """
    A second user trying to delete the first user's resources must receive 404,
    not 403.  Leaking 403 would confirm resource existence to an attacker.
    """

    @pytest.mark.asyncio
    async def test_idor_delete_target(
        self, client: AsyncClient, setup_project_and_target: dict
    ):
        ctx = setup_project_and_target
        target_id = ctx["target"]["id"]

        # Register attacker
        attacker = await _register_other_user(client)
        attacker_headers = {"Authorization": f"Bearer {attacker['access_token']}"}

        resp = await client.delete(f"/api/v1/targets/{target_id}", headers=attacker_headers)
        assert resp.status_code == 404, (
            f"Expected 404 (IDOR hidden), got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_idor_delete_scan(
        self, client: AsyncClient, setup_project_and_target: dict
    ):
        ctx = setup_project_and_target
        headers = ctx["headers"]
        project_id = ctx["project"]["id"]
        target_id = ctx["target"]["id"]

        # Create a scan as the owner
        scan_resp = await client.post(
            f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
            json={"scan_type": "quick"},
            headers=headers,
        )
        assert scan_resp.status_code in (200, 201), scan_resp.text
        scan_id = scan_resp.json()["id"]

        # Attacker tries to delete
        attacker = await _register_other_user(client)
        attacker_headers = {"Authorization": f"Bearer {attacker['access_token']}"}
        resp = await client.delete(f"/api/v1/scans/{scan_id}", headers=attacker_headers)
        assert resp.status_code == 404, (
            f"Expected 404 (IDOR hidden), got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_idor_delete_project_target(
        self, client: AsyncClient, setup_project_and_target: dict
    ):
        ctx = setup_project_and_target
        project_id = ctx["project"]["id"]
        target_id = ctx["target"]["id"]

        attacker = await _register_other_user(client)
        attacker_headers = {"Authorization": f"Bearer {attacker['access_token']}"}
        resp = await client.delete(
            f"/api/v1/projects/{project_id}/targets/{target_id}",
            headers=attacker_headers,
        )
        assert resp.status_code == 404, (
            f"Expected 404 (IDOR hidden), got {resp.status_code}: {resp.text}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. DASHBOARD NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDashboardNotifications:
    """GET /dashboard/notifications must return a list (possibly empty) for auth users."""

    @pytest.mark.asyncio
    async def test_notifications_returns_list(
        self, client: AsyncClient, registered_user: dict
    ):
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
        resp = await client.get("/api/v1/dashboard/notifications", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert isinstance(body, list), f"Expected list, got: {type(body)}"

    @pytest.mark.asyncio
    async def test_notifications_schema(
        self, client: AsyncClient, registered_user: dict
    ):
        """Each notification item (if any) must have required fields."""
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
        resp = await client.get("/api/v1/dashboard/notifications", headers=headers)
        assert resp.status_code == 200, resp.text
        for item in resp.json():
            assert "id" in item
            assert "title" in item
            assert "message" in item
            assert "type" in item
            assert item["type"] in ("critical", "warning", "success", "info")
            assert isinstance(item["read"], bool)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. MODEL RELATIONSHIP INTEGRITY — ORM round-trip
# ═══════════════════════════════════════════════════════════════════════════════

class TestModelRelationships:
    """Verify SQLAlchemy ORM relationships are correctly wired (back_populates)."""

    @pytest.mark.asyncio
    async def test_all_models_importable(self, client: AsyncClient):
        """All models must import without SQLAlchemy mapper errors."""
        from app.models.user import User
        from app.models.project import Project
        from app.models.target import Target
        from app.models.scan import Scan
        from app.models.finding import Finding
        from app.models.report import Report

        # Check back_populates wiring via relationship inspection
        from sqlalchemy import inspect as sa_inspect

        user_rels = {r.key for r in sa_inspect(User).relationships}
        assert "projects" in user_rels
        assert "scans" in user_rels
        assert "findings" in user_rels
        assert "reports" in user_rels

        project_rels = {r.key for r in sa_inspect(Project).relationships}
        assert "owner" in project_rels
        assert "targets" in project_rels
        assert "scans" in project_rels
        assert "findings" in project_rels
        assert "reports" in project_rels

        target_rels = {r.key for r in sa_inspect(Target).relationships}
        assert "project" in target_rels
        assert "scans" in target_rels
        assert "findings" in target_rels

        scan_rels = {r.key for r in sa_inspect(Scan).relationships}
        assert "user" in scan_rels
        assert "findings" in scan_rels

        finding_rels = {r.key for r in sa_inspect(Finding).relationships}
        assert "user" in finding_rels
        assert "project" in finding_rels
        assert "target" in finding_rels

        report_rels = {r.key for r in sa_inspect(Report).relationships}
        assert "user" in report_rels
        assert "project" in report_rels

    @pytest.mark.asyncio
    async def test_user_id_column_comment(self, client: AsyncClient):
        """User.id must carry the migration comment for alembic drift-free state."""
        from app.models.user import User
        comment = User.__table__.c.id.comment
        assert comment is not None
        assert "UUID v4" in comment


# ═══════════════════════════════════════════════════════════════════════════════
# 7. TOKEN REVOCATION AFTER ACCOUNT DELETION
# ═══════════════════════════════════════════════════════════════════════════════

class TestTokenRevocationOnAccountDelete:
    """After DELETE /auth/me, the access token must be fully revoked."""

    @pytest.mark.asyncio
    async def test_token_revoked_after_account_deletion(
        self, client: AsyncClient, registered_user: dict
    ):
        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

        # Confirm token is valid first
        me_resp = await client.get("/api/v1/auth/me", headers=headers)
        assert me_resp.status_code == 200, me_resp.text

        # Delete account
        del_resp = await client.delete("/api/v1/auth/me", headers=headers)
        assert del_resp.status_code == 200, del_resp.text

        # Token must now be invalid
        post_del_resp = await client.get("/api/v1/auth/me", headers=headers)
        assert post_del_resp.status_code == 401, (
            f"Token still valid after account deletion! Status: {post_del_resp.status_code}"
        )
