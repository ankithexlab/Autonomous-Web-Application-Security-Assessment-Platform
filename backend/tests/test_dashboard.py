"""
Dashboard API Unit Tests.

Coverage:
  1. Authenticated user dashboard summary (GET /api/v1/dashboard/summary)
  2. Unauthenticated request returns 401 Unauthorized
  3. User data isolation (IDOR / cross-user metric segregation)
  4. Project, target, scan, and finding counts verification
  5. Running, completed, and failed scan count breakdown
  6. Finding severity breakdown (critical, high, medium, low, info)
  7. OWASP category counts (A01 - A10)
  8. Overall security posture score calculation
  9. Recent scans, findings, reports, and activity feed synthesis
  10. Empty database handling & multi-project multi-target support
"""

from uuid import UUID
from unittest.mock import patch
import pytest
from httpx import AsyncClient

from app.core.http_client import SafeHTTPResponse
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.repositories.scan import ScanRepository
from app.services.scanner_engine import ScannerEngine

pytestmark = pytest.mark.asyncio


class MockDashboardHTTPClient:
    async def get(
        self,
        target_url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> SafeHTTPResponse:
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


async def test_unauthenticated_dashboard_request(client: AsyncClient):
    res = await client.get("/api/v1/dashboard/summary")
    assert res.status_code == 401


async def test_empty_user_dashboard_summary(client: AsyncClient):
    # Register brand new user with empty workspace
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "Empty User", "email": "empty_user@example.com", "password": "Password123!"},
    )
    headers = {"Authorization": f"Bearer {reg_res.json()['access_token']}"}

    res = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["total_projects"] == 0
    assert data["total_targets"] == 0
    assert data["total_scans"] == 0
    assert data["running_scans"] == 0
    assert data["completed_scans"] == 0
    assert data["failed_scans"] == 0
    assert data["total_findings"] == 0
    assert data["critical_findings"] == 0
    assert data["high_findings"] == 0
    assert data["medium_findings"] == 0
    assert data["low_findings"] == 0
    assert data["info_findings"] == 0
    assert data["overall_security_score"] == 100.0
    assert data["recent_scans"] == []
    assert data["recent_findings"] == []
    assert data["recent_reports"] == []
    assert len(data["owasp_distribution"]) == 10
    assert data["recent_activities"] == []


async def test_dashboard_summary_with_scans_and_findings(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target

    # Create and run a scan to populate findings
    scan_repo = ScanRepository(db)
    scan = await scan_repo.create(
        target_id=env["target"]["id"],
        project_id=env["project"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="full",
    )

    engine = ScannerEngine(db, http_client=MockDashboardHTTPClient())
    with patch("app.services.scanner_engine.validate_target_url", return_value="https://example.com"):
        await engine.run_scan(scan.id)

    # Fetch dashboard summary
    res = await client.get("/api/v1/dashboard/summary", headers=env["headers"])
    assert res.status_code == 200
    data = res.json()

    assert data["total_scans"] >= 1
    assert data["total_findings"] >= 1
    assert data["completed_scans"] >= 1
    assert len(data["recent_scans"]) > 0
    assert len(data["recent_findings"]) > 0
    assert len(data["recent_activities"]) > 0


async def test_user_data_isolation(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target

    # Register second user
    second_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "User B", "email": "user_b@example.com", "password": "Password123!"},
    )
    second_headers = {"Authorization": f"Bearer {second_res.json()['access_token']}"}

    # Fetch summary for User B (must have 0 projects/targets/scans/findings)
    b_res = await client.get("/api/v1/dashboard/summary", headers=second_headers)
    assert b_res.status_code == 200
    b_data = b_res.json()

    assert b_data["total_projects"] == 0
    assert b_data["total_targets"] == 0
    assert b_data["total_scans"] == 0
    assert b_data["total_findings"] == 0
    assert b_data["overall_security_score"] == 100.0


async def test_multi_project_multi_target_summary_breakdown(client: AsyncClient, db):
    # 1. Register User C
    reg = await client.post(
        "/api/v1/auth/register",
        json={"name": "User C", "email": "user_c@example.com", "password": "Password123!"},
    )
    user_id = UUID(reg.json()["user"]["id"])
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}

    # 2. Add 2 projects & 3 targets directly
    p1 = Project(name="Project One", user_id=user_id, status="active")
    p2 = Project(name="Project Two", user_id=user_id, status="active")
    db.add_all([p1, p2])
    await db.flush()

    t1 = Target(project_id=p1.id, url="https://app1.example.com", type="web")
    t2 = Target(project_id=p1.id, url="https://api1.example.com", type="api")
    t3 = Target(project_id=p2.id, url="https://app2.example.com", type="web")
    db.add_all([t1, t2, t3])
    await db.flush()

    # 3. Add scans with different statuses
    s1 = Scan(target_id=t1.id, project_id=p1.id, user_id=user_id, scan_type="full", status="completed", findings_count=2, critical_count=1, high_count=1)
    s2 = Scan(target_id=t2.id, project_id=p1.id, user_id=user_id, scan_type="quick", status="running")
    s3 = Scan(target_id=t3.id, project_id=p2.id, user_id=user_id, scan_type="full", status="failed")
    db.add_all([s1, s2, s3])
    await db.flush()

    # 4. Add findings with OWASP categories and severities
    f1 = Finding(
        scan_id=s1.id, target_id=t1.id, project_id=p1.id, user_id=user_id,
        title="SQL Injection Vector", description="Unparameterized query",
        severity="critical", confidence="HIGH", category="Injection", owasp_category="A03:2021-Injection",
        cvss_score=9.8, affected_url="https://app1.example.com/api/users",
    )
    f2 = Finding(
        scan_id=s1.id, target_id=t1.id, project_id=p1.id, user_id=user_id,
        title="Broken Access Control", description="BOLA flaw",
        severity="high", confidence="HIGH", category="Access Control", owasp_category="A01:2021-Broken Access Control",
        cvss_score=8.5, affected_url="https://app1.example.com/api/orders",
    )
    db.add_all([f1, f2])
    await db.flush()

    # 5. Add Report
    r1 = Report(project_id=p1.id, user_id=user_id, target_id=t1.id, scan_id=s1.id, title="Exec Summary", report_type="executive", file_format="pdf", status="COMPLETED")
    db.add(r1)
    await db.commit()

    # 6. Call API
    res = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total_projects"] == 2
    assert data["total_targets"] == 3
    assert data["total_scans"] == 3
    assert data["running_scans"] == 1
    assert data["completed_scans"] == 1
    assert data["failed_scans"] == 1

    assert data["total_findings"] == 2
    assert data["critical_findings"] == 1
    assert data["high_findings"] == 1
    assert data["medium_findings"] == 0

    # Score calculation: 100 - (1*25 + 1*15) = 60.0
    assert data["overall_security_score"] == 60.0

    # OWASP breakdown check
    owasp_map = {item["category"]: item["count"] for item in data["owasp_distribution"]}
    assert owasp_map.get("A01:2021") == 1
    assert owasp_map.get("A03:2021") == 1
    assert owasp_map.get("A02:2021") == 0

    # Recent items
    assert len(data["recent_scans"]) == 3
    assert data["recent_scans"][0]["project_name"] in ["Project One", "Project Two"]
    assert len(data["recent_findings"]) == 2
    assert len(data["recent_reports"]) == 1
    assert data["recent_reports"][0]["title"] == "Exec Summary"
    assert len(data["recent_activities"]) >= 3

    # Scan activity & trends mapping verification
    assert len(data["scan_activity"]) == 7
    for day_item in data["scan_activity"]:
        assert "day" in day_item
        assert "completed" in day_item
        assert "failed" in day_item
        assert isinstance(day_item["completed"], int)
        assert isinstance(day_item["failed"], int)

    assert len(data["vulnerability_trend"]) == 6
    for v_item in data["vulnerability_trend"]:
        assert "date" in v_item
        assert "critical" in v_item
        assert "high" in v_item
        assert "medium" in v_item
        assert "low" in v_item

    assert len(data["threat_trend"]) == 7
    for t_item in data["threat_trend"]:
        assert "period" in t_item
        assert "velocity" in t_item
        assert "exploitsPrevented" in t_item
        assert "activeThreats" in t_item

    assert len(data["risk_factors"]) == 4
    rf_labels = [rf["label"] for rf in data["risk_factors"]]
    assert "Exploitability Index" in rf_labels
    assert "Attack Surface Exposure" in rf_labels
    assert "Remediation Velocity" in rf_labels
    assert "Asset Criticality Weight" in rf_labels


async def test_dashboard_activity_types_and_resilience(client: AsyncClient, db):
    """
    Regression test for dashboard activity stream resilience.
    Verifies that:
      - 'scan_completed' is generated for completed scans
      - 'scan_failed' is generated for failed scans
      - 'scan_cancelled' is generated for cancelled scans
      - 'scan_started' is generated for running / pending scans
      - 'finding_discovered' is generated for findings
      - All activity objects contain required fields (id, type, title, description, timestamp)
      - The feed safely processes varied scan statuses without runtime errors
    """
    # 1. Register a dedicated test user
    reg = await client.post(
        "/api/v1/auth/register",
        json={"name": "Activity Tester", "email": "activity_tester@example.com", "password": "Password123!"},
    )
    assert reg.status_code == 201
    user_id = UUID(reg.json()["user"]["id"])
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}

    # 2. Add project & target
    p = Project(name="Activity Project", user_id=user_id, status="active")
    db.add(p)
    await db.flush()

    t = Target(project_id=p.id, url="https://resilience.example.com", type="web")
    db.add(t)
    await db.flush()

    # 3. Add scans with all distinct lifecycle statuses
    s_completed = Scan(target_id=t.id, project_id=p.id, user_id=user_id, scan_type="full", status="completed")
    s_failed = Scan(target_id=t.id, project_id=p.id, user_id=user_id, scan_type="quick", status="failed")
    s_cancelled = Scan(target_id=t.id, project_id=p.id, user_id=user_id, scan_type="custom", status="cancelled")
    s_running = Scan(target_id=t.id, project_id=p.id, user_id=user_id, scan_type="quick", status="running")
    db.add_all([s_completed, s_failed, s_cancelled, s_running])
    await db.flush()

    # 4. Add finding
    f = Finding(
        scan_id=s_completed.id, target_id=t.id, project_id=p.id, user_id=user_id,
        title="Cross-Site Scripting (Reflected)", description="XSS in query param",
        severity="high", confidence="HIGH", category="Cross-Site Scripting",
        owasp_category="A03:2021-Injection", cvss_score=7.5,
        affected_url="https://resilience.example.com/search",
    )
    db.add(f)
    await db.commit()

    # 5. Fetch dashboard summary
    res = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert res.status_code == 200
    data = res.json()

    activities = data.get("recent_activities", [])
    assert len(activities) >= 5, f"Expected at least 5 activities, got {len(activities)}"

    # Check that expected types are present in synthesized activity stream
    types = {item["type"] for item in activities}
    assert "scan_completed" in types, f"Missing scan_completed in {types}"
    assert "scan_failed" in types, f"Missing scan_failed in {types}"
    assert "scan_cancelled" in types, f"Missing scan_cancelled in {types}"
    assert "scan_started" in types, f"Missing scan_started in {types}"
    assert "finding_discovered" in types, f"Missing finding_discovered in {types}"

    # Verify structural integrity of every activity item
    for act in activities:
        assert "id" in act and act["id"], f"Activity missing id: {act}"
        assert "type" in act and act["type"], f"Activity missing type: {act}"
        assert "title" in act and act["title"], f"Activity missing title: {act}"
        assert "description" in act and act["description"], f"Activity missing description: {act}"
        assert "timestamp" in act, f"Activity missing timestamp key: {act}"


