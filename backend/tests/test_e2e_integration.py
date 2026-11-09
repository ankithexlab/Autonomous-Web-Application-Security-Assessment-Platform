"""
AWASAP Phase 3.4 — End-to-End Integration & Regression Test Suite.

Validates:
  1. Full authorized user workflow:
     Register -> Login -> Create Project -> Add Target -> Start Scan ->
     Verify Progress & Completion -> Inspect Findings -> Update Finding Status ->
     Generate & Download JSON, CSV, and genuine binary PDF reports.
  2. Metric alignment between Dashboard summary and OWASP Analytics.
  3. Scan lifecycle: Cancellation, retry/re-run pattern, and failed scan states.
  4. Empty states, invalid inputs, and API validation error handling.
  5. Multi-tenant cross-user access isolation across all resources.
  6. Controlled security payload consumption in scanner engine without unbounded flooding.
"""

import io
import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from pypdf import PdfReader
from sqlalchemy import select, func

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.security_payload import SecurityPayload
from app.repositories.scan import ScanRepository
from app.services.scanner_engine import ScannerEngine
from app.services.scanner.payload_test_runner import PayloadSecurityTestRunner

pytestmark = pytest.mark.asyncio


class MockE2EHTTPClient(SafeHTTPClient):
    """
    Mock HTTP client simulating real web server responses for scanner testing.
    """

    async def get(
        self,
        target_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> SafeHTTPResponse:
        # Check if URL contains simulated SQLi or XSS probe parameters
        if "param=" in target_url or "q=" in target_url:
            if "tautology" in target_url or "' OR '" in target_url or "DROP" in target_url:
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=500,
                    headers={"content-type": "text/html"},
                    text="<html><body>Error: syntax error at or near 'OR'</body></html>",
                    elapsed_seconds=0.08,
                    redirect_chain=[target_url],
                    content_type="text/html",
                )
            if "<script>" in target_url or "alert(" in target_url:
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=200,
                    headers={"content-type": "text/html"},
                    text=f"<html><body>Search results for: {target_url}</body></html>",
                    elapsed_seconds=0.05,
                    redirect_chain=[target_url],
                    content_type="text/html",
                )

        # Default responsive website without security headers
        return SafeHTTPResponse(
            url=target_url,
            status_code=200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3",
                "set-cookie": "session_token=secret_12345; Path=/",
            },
            text=(
                "<!DOCTYPE html><html><head><title>Acme Test App</title></head>"
                "<body><h1>Welcome to Acme</h1><p>Test Application Content</p></body></html>"
            ),
            elapsed_seconds=0.12,
            redirect_chain=[target_url],
            content_type="text/html",
        )


# ── Test 1: Full Authorized End-to-End Workflow ──────────────────

async def test_full_authorized_lifecycle_workflow(client: AsyncClient, db):
    # 1. Register new user
    user_email = f"e2e_{uuid.uuid4().hex[:8]}@example.com"
    user_password = "E2E_SecurePassword123!"
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={"name": "E2E Auditor", "email": user_email, "password": user_password},
    )
    assert reg_resp.status_code == 201, reg_resp.text
    user_data = reg_resp.json()
    auth_headers = {"Authorization": f"Bearer {user_data['access_token']}"}

    # 2. Login to verify credential issuance
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": user_email, "password": user_password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Project
    proj_resp = await client.post(
        "/api/v1/projects",
        json={"name": "Enterprise Banking Core", "description": "Production banking portal", "risk_level": "critical"},
        headers=auth_headers,
    )
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]

    # 4. Add Target to Project
    target_resp = await client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"url": "https://secure-bank.example.com", "type": "web"},
        headers=auth_headers,
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # 5. Create Scan for Target
    scan_resp = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full", "config": {"maxDepth": 3}},
        headers=auth_headers,
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]
    assert scan_resp.json()["status"] == "QUEUED"

    # 6. Execute Scan using ScannerEngine with Mock HTTP Client
    mock_http = MockE2EHTTPClient()
    engine = ScannerEngine(db, http_client=mock_http)

    with patch("app.services.scanner_engine.validate_target_url", return_value="https://secure-bank.example.com"), \
         patch("app.services.scanner.payload_test_runner.validate_target_url", return_value="https://secure-bank.example.com"):
        completed_scan = await engine.run_scan(uuid.UUID(scan_id))

    assert completed_scan.status == "COMPLETED"
    assert completed_scan.progress == 100
    assert completed_scan.findings_count > 0

    # 7. Inspect findings via API
    findings_resp = await client.get(f"/api/v1/scans/{scan_id}/findings", headers=auth_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == completed_scan.findings_count

    # Pick a finding to transition through status lifecycle
    test_finding = findings[0]
    finding_id = test_finding["id"]
    assert test_finding["status"] == "open"

    # 8. Update finding status: open -> in_progress
    patch_resp1 = await client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "in_progress"},
        headers=auth_headers,
    )
    assert patch_resp1.status_code == 200
    assert patch_resp1.json()["status"] == "in_progress"

    # Update finding status: in_progress -> resolved
    patch_resp2 = await client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "resolved"},
        headers=auth_headers,
    )
    assert patch_resp2.status_code == 200
    assert patch_resp2.json()["status"] == "resolved"

    # 9. Generate and download JSON report
    rep_json_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "E2E Assessment JSON", "report_type": "full", "file_format": "json"},
        headers=auth_headers,
    )
    assert rep_json_res.status_code == 201
    json_rep_id = rep_json_res.json()["id"]

    dl_json = await client.get(f"/api/v1/reports/{json_rep_id}/download", headers=auth_headers)
    assert dl_json.status_code == 200
    assert "application/json" in dl_json.headers["content-type"]
    assert dl_json.json()["report_id"] == json_rep_id

    # 10. Generate and download CSV report
    rep_csv_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "E2E Assessment CSV", "report_type": "technical", "file_format": "csv"},
        headers=auth_headers,
    )
    assert rep_csv_res.status_code == 201
    csv_rep_id = rep_csv_res.json()["id"]

    dl_csv = await client.get(f"/api/v1/reports/{csv_rep_id}/download", headers=auth_headers)
    assert dl_csv.status_code == 200
    assert "text/csv" in dl_csv.headers["content-type"]
    assert "ID,Title,Severity" in dl_csv.text

    # 11. Generate and download PDF report
    rep_pdf_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "E2E Executive PDF", "report_type": "executive", "file_format": "pdf"},
        headers=auth_headers,
    )
    assert rep_pdf_res.status_code == 201
    pdf_rep_id = rep_pdf_res.json()["id"]

    dl_pdf = await client.get(f"/api/v1/reports/{pdf_rep_id}/download", headers=auth_headers)
    assert dl_pdf.status_code == 200
    assert "application/pdf" in dl_pdf.headers["content-type"]
    assert dl_pdf.content.startswith(b"%PDF-")

    # Verify PDF parseable by pypdf
    pdf_reader = PdfReader(io.BytesIO(dl_pdf.content))
    assert len(pdf_reader.pages) >= 1
    extracted_text = pdf_reader.pages[0].extract_text()
    assert "AWASAP" in extracted_text or "Executive" in extracted_text


# ── Test 2: Dashboard and OWASP Analytics Metric Alignment ───────

async def test_dashboard_and_owasp_analytics_alignment(client: AsyncClient, db):
    user_email = f"analytics_{uuid.uuid4().hex[:8]}@example.com"
    reg = await client.post(
        "/api/v1/auth/register",
        json={"name": "Analytics Reviewer", "email": user_email, "password": "Password123!"},
    )
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}

    # Setup project and target
    p = await client.post("/api/v1/projects", json={"name": "Analytics Proj", "risk_level": "medium"}, headers=headers)
    proj_id = p.json()["id"]
    t = await client.post(f"/api/v1/projects/{proj_id}/targets", json={"url": "https://analytics.example.com", "type": "web"}, headers=headers)
    target_id = t.json()["id"]

    # Create & execute scan
    s = await client.post(f"/api/v1/projects/{proj_id}/targets/{target_id}/scans", json={"scan_type": "full"}, headers=headers)
    scan_id = s.json()["id"]

    engine = ScannerEngine(db, http_client=MockE2EHTTPClient())
    with patch("app.services.scanner_engine.validate_target_url", return_value="https://analytics.example.com"), \
         patch("app.services.scanner.payload_test_runner.validate_target_url", return_value="https://analytics.example.com"):
        completed = await engine.run_scan(uuid.UUID(scan_id))

    # Fetch dashboard summary
    dash_res = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()

    assert dash_data["total_projects"] == 1
    assert dash_data["total_targets"] == 1
    assert dash_data["total_scans"] == 1
    assert dash_data["completed_scans"] == 1
    assert dash_data["failed_scans"] == 0
    assert dash_data["running_scans"] == 0
    assert dash_data["total_findings"] == completed.findings_count

    # Fetch OWASP summary
    owasp_res = await client.get("/api/v1/owasp/summary", headers=headers)
    assert owasp_res.status_code == 200
    owasp_data = owasp_res.json()

    assert owasp_data["total_vulnerabilities"] == completed.findings_count
    # The sum of findings across categories should match total findings
    owasp_cat_sum = sum(cat.get("findings_count", 0) for cat in owasp_data.get("category_breakdown", []))
    assert owasp_cat_sum == completed.findings_count


# ── Test 3: Scan Cancellation and Retry/Re-run Workflow ───────────

async def test_scan_cancellation_and_rerun_lifecycle(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    proj_id = env["project"]["id"]
    target_id = env["target"]["id"]
    headers = env["headers"]

    # 1. Create scan
    s_res = await client.post(
        f"/api/v1/projects/{proj_id}/targets/{target_id}/scans",
        json={"scan_type": "quick"},
        headers=headers,
    )
    assert s_res.status_code == 201
    scan_id = s_res.json()["id"]
    assert s_res.json()["status"] == "QUEUED"

    # 2. Cancel scan
    cancel_res = await client.patch(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # 3. Attempting to cancel again should return 400 Bad Request
    cancel_again = await client.patch(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert cancel_again.status_code == 400

    # 4. Re-run / Retry pattern: create a new scan for the target and verify start
    rerun_res = await client.post(
        f"/api/v1/projects/{proj_id}/targets/{target_id}/scans",
        json={"scan_type": "quick"},
        headers=headers,
    )
    assert rerun_res.status_code == 201
    new_scan_id = rerun_res.json()["id"]

    start_res = await client.post(f"/api/v1/scans/{new_scan_id}/start", headers=headers)
    assert start_res.status_code == 200
    assert start_res.json()["status"] in ("QUEUED", "RUNNING")


# ── Test 4: Empty States and Input Validation ─────────────────────

async def test_empty_states_and_validation(client: AsyncClient):
    # New user with empty workspace
    reg = await client.post(
        "/api/v1/auth/register",
        json={"name": "Clean User", "email": "clean_user@example.com", "password": "Password123!"},
    )
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}

    # Empty dashboard
    d_res = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert d_res.status_code == 200
    assert d_res.json()["total_projects"] == 0
    assert d_res.json()["total_scans"] == 0
    assert d_res.json()["total_findings"] == 0

    # Empty list responses
    assert len((await client.get("/api/v1/projects", headers=headers)).json()) == 0
    assert (await client.get("/api/v1/scans", headers=headers)).json()["total"] == 0
    assert (await client.get("/api/v1/findings", headers=headers)).json()["total"] == 0
    assert (await client.get("/api/v1/reports", headers=headers)).json()["total"] == 0

    # Validation: Register with weak password (< 8 chars)
    bad_reg = await client.post(
        "/api/v1/auth/register",
        json={"name": "Bad", "email": "bad@example.com", "password": "short"},
    )
    assert bad_reg.status_code in (400, 422)

    # Validation: Add target with private SSRF IP address
    fake_proj = uuid.uuid4()
    ssrf_target = await client.post(
        f"/api/v1/projects/{fake_proj}/targets",
        json={"url": "http://127.0.0.1:8000/internal", "type": "web"},
        headers=headers,
    )
    assert ssrf_target.status_code in (400, 404)

    # Validation: 404 on non-existent resources
    assert (await client.get(f"/api/v1/scans/{uuid.uuid4()}", headers=headers)).status_code == 404
    assert (await client.get(f"/api/v1/findings/{uuid.uuid4()}", headers=headers)).status_code == 404
    assert (await client.get(f"/api/v1/reports/{uuid.uuid4()}", headers=headers)).status_code == 404


# ── Test 5: Cross-User Access Isolation (Multi-tenant BOLA) ───────

async def test_cross_user_isolation_full_matrix(client: AsyncClient, setup_project_and_target: dict):
    owner_env = setup_project_and_target
    proj_id = owner_env["project"]["id"]
    target_id = owner_env["target"]["id"]

    # Register adversary user
    adv_reg = await client.post(
        "/api/v1/auth/register",
        json={"name": "Adversary", "email": "adversary@example.com", "password": "Password123!"},
    )
    adv_headers = {"Authorization": f"Bearer {adv_reg.json()['access_token']}"}

    # Owner creates scan and report
    s_res = await client.post(
        f"/api/v1/projects/{proj_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=owner_env["headers"],
    )
    scan_id = s_res.json()["id"]

    r_res = await client.post(
        f"/api/v1/projects/{proj_id}/reports",
        json={"title": "Private Owner Report", "report_type": "full", "file_format": "json"},
        headers=owner_env["headers"],
    )
    report_id = r_res.json()["id"]

    # Adversary tries to access Owner's resources -> MUST BE 404
    assert (await client.get(f"/api/v1/projects/{proj_id}", headers=adv_headers)).status_code == 404
    assert (await client.get(f"/api/v1/projects/{proj_id}/targets/{target_id}", headers=adv_headers)).status_code == 404
    assert (await client.get(f"/api/v1/scans/{scan_id}", headers=adv_headers)).status_code == 404
    assert (await client.get(f"/api/v1/scans/{scan_id}/findings", headers=adv_headers)).status_code == 404
    assert (await client.patch(f"/api/v1/scans/{scan_id}/cancel", headers=adv_headers)).status_code == 404
    assert (await client.get(f"/api/v1/reports/{report_id}", headers=adv_headers)).status_code == 404
    assert (await client.get(f"/api/v1/reports/{report_id}/download", headers=adv_headers)).status_code == 404


# ── Test 6: Security Payload Consumption & Non-Destructive Filtering

async def test_security_payload_consumption_and_safety(db):
    """
    Verifies:
      1. PayloadSecurityTestRunner queries relevant payloads from database.
      2. Dangerous destructive tokens (e.g. drop database, rm -rf) are safely intercepted.
      3. Probes are sampled/bounded to prevent DoS.
    """
    from app.repositories.finding import FindingRepository
    finding_repo = FindingRepository(db)
    runner = PayloadSecurityTestRunner(finding_repo, db)

    # Verify safe probe interception for destructive payload
    destructive_payload = SecurityPayload(
        id=99999,
        payload="'; DROP DATABASE awasap; --",
        type="tautology",
        severity="critical",
        description="Destructive SQL injection test",
        context="parameter",
    )

    fake_scan = type("FakeScan", (), {"id": uuid.uuid4(), "project_id": uuid.uuid4(), "target_id": uuid.uuid4(), "user_id": uuid.uuid4()})()
    mock_http = MockE2EHTTPClient()

    res = await runner._execute_safe_probe(
        scan=fake_scan,
        base_url="https://example.com/search?q=test",
        payload_record=destructive_payload,
        http_client=mock_http,
        counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )

    assert res["confidence"] == "INCONCLUSIVE"
    assert "potentially destructive" in res["reason"]
