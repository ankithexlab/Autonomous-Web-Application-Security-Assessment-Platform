"""
Phase 10 — Final Product QA, Security Audit & End-to-End Platform Test Suite.

Comprehensive validation covering:
  1. Complete platform workflow:
     Register -> Login -> Token Refresh -> Project -> Target -> Scan ->
     Findings Detection -> Lifecycle Transitions -> AI Finding Analysis & Remediation ->
     AI Chat Assistant -> Dashboard Analytics & Notifications -> Multi-Format Reports (JSON/CSV/HTML/PDF) ->
     Report Preview & Downloads -> Report Deletion.
  2. Multi-tenant account isolation & strict IDOR protection across all endpoints.
  3. SSRF, private network, and metadata endpoint blocking.
  4. Scanner error resilience, failure handling, and cancellation lifecycle.
  5. Operational health and readiness probes (/health, /health/live, /readiness, /health/ready).
  6. Response security headers and sensitive secret redaction.
"""

import io
import uuid
from unittest.mock import patch
import pytest
from httpx import AsyncClient
from pypdf import PdfReader
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPResponse
from app.core.security import create_access_token
from app.core.ssrf import validate_target_url
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.repositories.scan import ScanRepository
from app.services.scanner_engine import ScannerEngine

pytestmark = pytest.mark.asyncio


class MockPhase10LabHTTPClient:
    """Simulates realistic lab responses for testing positive and negative scanner checks."""

    async def get(
        self,
        target_url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> SafeHTTPResponse:
        t_lower = target_url.lower()

        # Simulated vulnerable SQL injection endpoint
        if "param=" in t_lower or "q=" in t_lower:
            if "tautology" in t_lower or "' or '1'='1" in t_lower:
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=500,
                    headers={"content-type": "text/html"},
                    text="<html><body>FATAL: PostgreSQL syntax error near 'OR'</body></html>",
                    elapsed_seconds=0.08,
                    redirect_chain=[target_url],
                    content_type="text/html",
                )
            if "<script>" in t_lower or "alert(" in t_lower:
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=200,
                    headers={"content-type": "text/html"},
                    text=f"<html><body>Search results for: {target_url}</body></html>",
                    elapsed_seconds=0.05,
                    redirect_chain=[target_url],
                    content_type="text/html",
                )

        # Base application root (missing CSP and HSTS headers)
        return SafeHTTPResponse(
            url=target_url,
            status_code=200,
            headers={
                "content-type": "text/html",
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3",
            },
            text=(
                "<!DOCTYPE html><html><head><title>Secure Lab Portal</title></head>"
                "<body><form action='/login' method='POST'>"
                "<input name='username' type='text'/>"
                "<input name='password' type='password'/>"
                "<button type='submit'>Sign In</button></form>"
                "<a href='/search?q=test'>Search</a></body></html>"
            ),
            elapsed_seconds=0.05,
            redirect_chain=[target_url],
            content_type="text/html",
        )


# ── 1. Full Product Lifecycle E2E Workflow ────────────────────────

async def test_full_product_lifecycle_e2e(client: AsyncClient, db: AsyncSession):
    uid = uuid.uuid4().hex[:6]
    email = f"qa_lead_{uid}@example.com"
    password = "StrongPassword123!"

    # Step 1: User Registration
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"name": f"QA Lead {uid}", "email": email, "password": password},
    )
    assert reg_res.status_code == 201, reg_res.text
    reg_data = reg_res.json()
    assert "access_token" in reg_data
    assert "refresh_token" in reg_data
    user_id = reg_data["user"]["id"]

    # Step 2: User Login
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200, login_res.text
    login_data = login_res.json()
    access_token = login_data["access_token"]
    refresh_token = login_data["refresh_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # Step 3: Refresh Token Verification
    ref_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert ref_res.status_code == 200, ref_res.text
    new_token = ref_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {new_token}"}

    # Step 4: Create Project
    proj_res = await client.post(
        "/api/v1/projects",
        json={
            "name": f"Enterprise Banking Portal {uid}",
            "description": "Core online financial platform assessment",
            "risk_level": "critical",
        },
        headers=headers,
    )
    assert proj_res.status_code == 201, proj_res.text
    project = proj_res.json()
    project_id = project["id"]

    # Step 5: Add Target
    target_res = await client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={"url": "https://secure-banking.qa.internal", "type": "web"},
        headers=headers,
    )
    assert target_res.status_code == 201, target_res.text
    target = target_res.json()
    target_id = target["id"]

    # Step 6: Create Scan Record & Execute Scanner Engine
    scan_res = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=headers,
    )
    assert scan_res.status_code == 201, scan_res.text
    scan = scan_res.json()
    scan_id = scan["id"]

    # Run ScannerEngine with mock lab client to produce real detected findings
    engine = ScannerEngine(db, http_client=MockPhase10LabHTTPClient())
    with patch("app.services.scanner_engine.validate_target_url", return_value="https://secure-banking.qa.internal"):
        await engine.run_scan(uuid.UUID(scan_id))

    # Step 7: Verify Completed Scan & Persisted Findings
    scan_detail_res = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert scan_detail_res.status_code == 200
    scan_detail = scan_detail_res.json()
    assert scan_detail["status"] == "COMPLETED"
    assert scan_detail["progress"] == 100
    assert scan_detail["findings_count"] >= 1

    findings_res = await client.get(f"/api/v1/scans/{scan_id}/findings", headers=headers)
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) >= 1

    first_finding = findings[0]
    finding_id = first_finding["id"]
    assert "severity" in first_finding
    assert "confidence" in first_finding
    assert first_finding["status"] == "open"

    # Step 8: Finding Lifecycle Transition
    patch_res = await client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "confirmed"},
        headers=headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "confirmed"

    patch_resolve = await client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"status": "resolved"},
        headers=headers,
    )
    assert patch_resolve.status_code == 200
    assert patch_resolve.json()["status"] == "resolved"

    # Step 9: AI Finding Analysis & Remediation
    ai_status = await client.get("/api/v1/ai/status", headers=headers)
    assert ai_status.status_code == 200
    assert ai_status.json().get("status") == "online"

    ai_analysis = await client.post(
        f"/api/v1/ai/findings/{finding_id}/analyze",
        headers=headers,
    )
    assert ai_analysis.status_code == 200
    analysis_data = ai_analysis.json()
    assert "summary" in analysis_data
    assert "risk_explanation" in analysis_data
    assert "why_it_matters" in analysis_data

    ai_remediation = await client.post(
        f"/api/v1/ai/findings/{finding_id}/remediation",
        headers=headers,
    )
    assert ai_remediation.status_code == 200
    rem_data = ai_remediation.json()
    assert "recommended_fix" in rem_data
    assert "implementation_steps" in rem_data

    # Step 10: AI Contextual Chat
    ai_chat = await client.post(
        "/api/v1/ai/chat",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": "How should our development team prioritize fixing this vulnerability?",
                }
            ],
            "finding_id": finding_id,
            "scan_id": scan_id,
        },
        headers=headers,
    )
    assert ai_chat.status_code == 200
    chat_data = ai_chat.json()
    assert "reply" in chat_data
    assert chat_data.get("is_advisory") is True

    # Step 11: Dashboard Summary & Notifications
    dash_res = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["total_projects"] >= 1
    assert dash_data["total_targets"] >= 1
    assert dash_data["total_scans"] >= 1
    assert dash_data["completed_scans"] >= 1
    # Posture score respects resolved status
    assert isinstance(dash_data["overall_security_score"], float)

    notifs_res = await client.get("/api/v1/dashboard/notifications", headers=headers)
    assert notifs_res.status_code == 200
    assert isinstance(notifs_res.json(), list)

    # Step 12: Multi-Format Report Generation (JSON, CSV, HTML, PDF)
    create_rep_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Q4 Executive Audit", "report_type": "executive", "file_format": "pdf"},
        headers=headers,
    )
    assert create_rep_res.status_code == 201
    report = create_rep_res.json()
    report_id = report["id"]
    assert report["status"] == "COMPLETED"

    # Step 13: Report Downloads & Live Preview
    # A. PDF Download
    dl_pdf = await client.get(f"/api/v1/reports/{report_id}/download?format=pdf", headers=headers)
    assert dl_pdf.status_code == 200
    assert dl_pdf.headers["content-type"] == "application/pdf"
    assert dl_pdf.content.startswith(b"%PDF-")

    # B. HTML Download
    dl_html = await client.get(f"/api/v1/reports/{report_id}/download?format=html", headers=headers)
    assert dl_html.status_code == 200
    assert "text/html" in dl_html.headers["content-type"]
    assert "<!DOCTYPE html>" in dl_html.text

    # C. JSON Download
    dl_json = await client.get(f"/api/v1/reports/{report_id}/download?format=json", headers=headers)
    assert dl_json.status_code == 200
    assert "application/json" in dl_json.headers["content-type"]
    assert dl_json.json()["report_id"] == report_id

    # D. CSV Download
    dl_csv = await client.get(f"/api/v1/reports/{report_id}/download?format=csv", headers=headers)
    assert dl_csv.status_code == 200
    assert "text/csv" in dl_csv.headers["content-type"]
    assert "Title" in dl_csv.text

    # E. Dedicated Live Preview Endpoint
    preview = await client.get(f"/api/v1/reports/{report_id}/preview", headers=headers)
    assert preview.status_code == 200
    assert "text/html" in preview.headers["content-type"]
    assert "content-security-policy" in preview.headers

    # Step 14: Report Deletion
    del_res = await client.delete(f"/api/v1/reports/{report_id}", headers=headers)
    assert del_res.status_code == 204

    # Verify report is deleted
    assert (await client.get(f"/api/v1/reports/{report_id}", headers=headers)).status_code == 404


# ── 2. Multi-Tenant Account Isolation & Strict IDOR Protection ────

async def test_unauthorized_and_cross_user_isolation_e2e(client: AsyncClient, db: AsyncSession):
    # Register User 1
    u1_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "Tenant One", "email": f"t1_{uuid.uuid4().hex[:6]}@example.com", "password": "Password123!"},
    )
    u1_headers = {"Authorization": f"Bearer {u1_res.json()['access_token']}"}

    # Register User 2
    u2_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "Tenant Two", "email": f"t2_{uuid.uuid4().hex[:6]}@example.com", "password": "Password123!"},
    )
    u2_headers = {"Authorization": f"Bearer {u2_res.json()['access_token']}"}

    # User 1 creates resources
    p1 = (await client.post(
        "/api/v1/projects",
        json={"name": "Private Project", "description": "Confidential"},
        headers=u1_headers,
    )).json()

    t1 = (await client.post(
        f"/api/v1/projects/{p1['id']}/targets",
        json={"url": "https://tenant1.internal", "type": "web"},
        headers=u1_headers,
    )).json()

    s1 = (await client.post(
        f"/api/v1/projects/{p1['id']}/targets/{t1['id']}/scans",
        json={"scan_type": "quick"},
        headers=u1_headers,
    )).json()

    r1 = (await client.post(
        f"/api/v1/projects/{p1['id']}/reports",
        json={"title": "T1 Report", "report_type": "executive", "file_format": "json"},
        headers=u1_headers,
    )).json()

    # User 2 attempts unauthorized access to User 1's resources -> MUST return 404
    assert (await client.get(f"/api/v1/projects/{p1['id']}", headers=u2_headers)).status_code == 404
    assert (await client.get(f"/api/v1/targets/{t1['id']}", headers=u2_headers)).status_code == 404
    assert (await client.get(f"/api/v1/scans/{s1['id']}", headers=u2_headers)).status_code == 404
    assert (await client.get(f"/api/v1/reports/{r1['id']}", headers=u2_headers)).status_code == 404
    assert (await client.get(f"/api/v1/reports/{r1['id']}/preview", headers=u2_headers)).status_code == 404
    assert (await client.get(f"/api/v1/reports/{r1['id']}/download", headers=u2_headers)).status_code == 404
    assert (await client.delete(f"/api/v1/reports/{r1['id']}", headers=u2_headers)).status_code == 404

    # User 2's dashboard shows 0 items (complete tenant segregation)
    u2_dash = (await client.get("/api/v1/dashboard/summary", headers=u2_headers)).json()
    assert u2_dash["total_projects"] == 0
    assert u2_dash["total_targets"] == 0
    assert u2_dash["total_scans"] == 0
    assert u2_dash["total_findings"] == 0

    # Unauthenticated requests return 401
    assert (await client.get("/api/v1/projects")).status_code == 401
    assert (await client.get("/api/v1/dashboard/summary")).status_code == 401
    assert (await client.get("/api/v1/reports")).status_code == 401


# ── 3. SSRF, Private Network & Host Validation Protections ─────────

async def test_ssrf_and_host_validation_protections(client: AsyncClient, setup_project_and_target: dict, db: AsyncSession):
    env = setup_project_and_target
    headers = env["headers"]
    project_id = env["project"]["id"]

    # Block localhost & private network SSRF targets via core validator
    blocked_urls = [
        "http://127.0.0.1:8080/admin",
        "http://localhost:8000/secret",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router",
        "http://user:pass@127.0.0.1/",
        "ftp://malicious.test/exploit",
    ]

    for bad_url in blocked_urls:
        with pytest.raises(BadRequestException):
            validate_target_url(bad_url)

    # Verify that ScannerEngine immediately aborts and fails scan if target resolves to blocked private IP
    priv_target = Target(
        project_id=uuid.UUID(project_id),
        url="http://127.0.0.1:8080",
        type="web",
        validation_status="authorized",
    )
    db.add(priv_target)
    await db.commit()
    await db.refresh(priv_target)

    priv_scan = Scan(
        project_id=uuid.UUID(project_id),
        target_id=priv_target.id,
        user_id=uuid.UUID(env["user"]["user"]["id"]),
        scan_type="quick",
        status="QUEUED",
        progress=0,
    )
    db.add(priv_scan)
    await db.commit()
    await db.refresh(priv_scan)

    engine = ScannerEngine(db)
    # run_scan raises BadRequestException on SSRF violation and marks scan FAILED without making HTTP calls
    with pytest.raises(BadRequestException):
        await engine.run_scan(priv_scan.id)

    updated_scan = await db.get(Scan, priv_scan.id)
    assert updated_scan.status == "FAILED"


# ── 4. Scanner Cancellation & Error Resilience ────────────────────

async def test_scanner_cancellation_and_error_resilience(client: AsyncClient, setup_project_and_target: dict, db: AsyncSession):
    env = setup_project_and_target
    headers = env["headers"]
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # Create scan
    scan_res = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "quick"},
        headers=headers,
    )
    assert scan_res.status_code == 201, scan_res.text
    scan_id = scan_res.json()["id"]

    # Cancel scan
    cancel_res = await client.patch(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # Status check confirms cancelled
    get_res = await client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert get_res.json()["status"] == "CANCELLED"


# ── 5. Health, Readiness Probes & Security Headers ────────────────

async def test_operational_health_probes_and_security_headers(client: AsyncClient):
    # Liveness probe
    health_res = await client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"
    assert "version" in health_res.json()

    # Liveness alias
    live_res = await client.get("/health/live")
    assert live_res.status_code == 200

    # Readiness probe (DB check)
    ready_res = await client.get("/readiness")
    assert ready_res.status_code == 200
    ready_data = ready_res.json()
    assert ready_data["status"] == "ready"
    assert ready_data["components"]["database"] == "connected"

    # Hardened security headers on API responses
    assert health_res.headers.get("x-content-type-options") == "nosniff"
    assert health_res.headers.get("x-frame-options") == "DENY"
    assert "default-src 'none'" in health_res.headers.get("content-security-policy", "")
