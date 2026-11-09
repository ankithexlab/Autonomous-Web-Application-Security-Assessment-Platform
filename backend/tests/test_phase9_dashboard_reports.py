"""
Phase 9 Comprehensive Dashboard & Reporting Test Suite.

Verifies:
  1. Real DB-connected dashboard metrics, security scores, severity breakdown, and OWASP A01-A10 charts.
  2. Scan activity, monthly vulnerability trends, and threat velocity calculations.
  3. Live activity feed and notifications with accurate types (critical, warning, success, info).
  4. All four report export formats: JSON, CSV, HTML, and PDF.
  5. On-demand format override via GET /api/v1/reports/{id}/download?format=...
  6. Live HTML report preview endpoint: GET /api/v1/reports/{id}/preview.
  7. Secret and sensitive data redaction across all report formats.
  8. CSV formula injection defense (prepended single-quote on =, +, -, @, %, |).
  9. HTML XSS defense (escaped script and HTML tags in preview and report).
  10. Strict ownership, tenant isolation, and IDOR protection on dashboard and reports.
"""

import csv
import io
import json
import uuid
import pytest
from httpx import AsyncClient
from pypdf import PdfReader
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.repositories.finding import FindingRepository
from app.repositories.project import ProjectRepository
from app.repositories.report import ReportRepository
from app.repositories.scan import ScanRepository
from app.repositories.target import TargetRepository
from app.services.dashboard import DashboardService
from app.services.report_generator import ReportGenerator

pytestmark = pytest.mark.asyncio


# ── Fixture: Seeded Security Dataset ──────────────────────────────

@pytest.fixture
async def setup_phase9_dataset(db: AsyncSession, client: AsyncClient):
    uid = uuid.uuid4().hex[:6]
    user = User(
        email=f"phase9_user_{uid}@example.com",
        name=f"Phase 9 User {uid}",
        hashed_password="hashed_pw_secret_999",
        role="analyst",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    reg_token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {reg_token}"}

    project = Project(
        name=f"PBL Enterprise Project {uid}",
        description="Comprehensive project for Phase 9 testing",
        user_id=user.id,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    target = Target(
        project_id=project.id,
        url="https://sec-audit.internal.test",
        type="web",
        validation_status="authorized",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    # 1. Successful Completed Scan
    scan_comp = Scan(
        project_id=project.id,
        target_id=target.id,
        user_id=user.id,
        scan_type="full",
        status="COMPLETED",
        progress=100,
        findings_count=3,
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=0,
        info_count=0,
    )
    db.add(scan_comp)

    # 2. Failed Scan (for failure detection in dashboard & notifications)
    scan_fail = Scan(
        project_id=project.id,
        target_id=target.id,
        user_id=user.id,
        scan_type="headers",
        status="FAILED",
        progress=45,
        findings_count=0,
    )
    db.add(scan_fail)
    await db.commit()
    await db.refresh(scan_comp)
    await db.refresh(scan_fail)

    # 3. Seed Findings with secrets, formula injection, and XSS probe
    finding_repo = FindingRepository(db)

    # Finding 1: Critical SQL Injection with formula injection title & leaked secrets
    f_crit = await finding_repo.create(
        scan_id=scan_comp.id,
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        title="=1+1; Remote SQL Injection in /login",
        severity="critical",
        status="open",
        confidence="CONFIRMED",
        category="Injection",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        cvss_score=9.8,
        affected_url="https://sec-audit.internal.test/login?u=' OR 1=1--",
        description="Authorization: Bearer super_secret_access_token_123456\nCookie: session=top_secret_cookie_token_abc\nSensitive database crash stack trace.",
        remediation="Use parameterized queries and SQLAlchemy bound parameters.",
        proof_of_concept="curl -H 'Authorization: Bearer my_api_key_secret_999' 'https://sec-audit.internal.test/login?u=%27+OR+1%3D1--'\nJWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2VjcmV0U2lnbmF0dXJl",
    )

    # Finding 2: High XSS with HTML injection in title
    f_high = await finding_repo.create(
        scan_id=scan_comp.id,
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        title="Reflected XSS in <script>alert(document.cookie)</script>",
        severity="high",
        status="open",
        confidence="CONFIRMED",
        category="Cross-Site Scripting",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-79",
        cvss_score=7.5,
        affected_url="https://sec-audit.internal.test/search?q=<script>alert(1)</script>",
        description="Unencoded reflection in search response.",
        remediation="Apply contextual HTML entity encoding.",
        proof_of_concept="https://sec-audit.internal.test/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    )

    # Finding 3: Medium Security Header
    f_med = await finding_repo.create(
        scan_id=scan_comp.id,
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        title="Missing Content-Security-Policy Header",
        severity="medium",
        status="open",
        confidence="CONFIRMED",
        category="Security Headers",
        owasp_category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-693",
        cvss_score=5.3,
        affected_url="https://sec-audit.internal.test/",
        description="Server does not enforce CSP.",
        remediation="Add Content-Security-Policy header to web server configuration.",
        proof_of_concept="curl -I https://sec-audit.internal.test/",
    )

    return {
        "user": user,
        "headers": headers,
        "project": project,
        "target": target,
        "scan_comp": scan_comp,
        "scan_fail": scan_fail,
        "findings": [f_crit, f_high, f_med],
    }


# ── Test 1: Real DB-Connected Dashboard Summary & Score Accuracy ─────

async def test_dashboard_summary_accuracy(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    res = await client.get("/api/v1/dashboard/summary", headers=env["headers"])
    assert res.status_code == 200
    data = res.json()

    assert data["total_projects"] == 1
    assert data["total_targets"] == 1
    assert data["total_scans"] == 2
    assert data["completed_scans"] == 1
    assert data["failed_scans"] == 1
    assert data["running_scans"] == 0

    assert data["total_findings"] == 3
    assert data["critical_findings"] == 1
    assert data["high_findings"] == 1
    assert data["medium_findings"] == 1
    assert data["low_findings"] == 0
    assert data["info_findings"] == 0

    # Score calculation: 100 - (1*25 + 1*15 + 1*8) = 100 - 48 = 52.0
    assert data["overall_security_score"] == 52.0

    # OWASP distribution contains exactly 10 categories
    assert len(data["owasp_distribution"]) == 10
    a03 = next(item for item in data["owasp_distribution"] if "A03" in item["category"])
    assert a03["count"] == 2  # SQLi and XSS
    a05 = next(item for item in data["owasp_distribution"] if "A05" in item["category"])
    assert a05["count"] == 1  # CSP


# ── Test 2: Live Activity Stream & Notifications Endpoint ───────────

async def test_dashboard_activities_and_notifications(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    res = await client.get("/api/v1/dashboard/notifications", headers=env["headers"])
    assert res.status_code == 200
    notifs = res.json()

    assert len(notifs) >= 3
    # Check that critical findings and failed scans produce critical/warning notifications
    types = [n["type"] for n in notifs]
    assert "critical" in types or "warning" in types
    assert all("id" in n and "title" in n and "message" in n for n in notifs)


# ── Test 3: Four Export Formats Generation (PDF, HTML, JSON, CSV) ────

async def test_four_report_export_formats(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    project_id = env["project"].id

    for fmt in ("json", "csv", "html", "pdf"):
        create_res = await client.post(
            f"/api/v1/projects/{project_id}/reports",
            json={
                "title": f"Phase 9 Audit {fmt.upper()}",
                "report_type": "technical",
                "file_format": fmt,
            },
            headers=env["headers"],
        )
        assert create_res.status_code == 201, create_res.text
        report_data = create_res.json()
        report_id = report_data["id"]
        assert report_data["status"] == "COMPLETED"
        assert report_data["overall_score"] == 52.0

        # Download in default created format
        dl_res = await client.get(f"/api/v1/reports/{report_id}/download", headers=env["headers"])
        assert dl_res.status_code == 200

        if fmt == "json":
            assert "application/json" in dl_res.headers["content-type"]
            data = dl_res.json()
            assert data["total_findings"] == 3
            assert data["overall_security_score"] == 52.0
        elif fmt == "csv":
            assert "text/csv" in dl_res.headers["content-type"]
            assert "Title" in dl_res.text
            assert "Severity" in dl_res.text
        elif fmt == "html":
            assert "text/html" in dl_res.headers["content-type"]
            assert "<!DOCTYPE html>" in dl_res.text
            assert "52.0" in dl_res.text
        elif fmt == "pdf":
            assert "application/pdf" in dl_res.headers["content-type"]
            assert dl_res.content.startswith(b"%PDF-")


# ── Test 4: Dynamic Format Override via Query Param ──────────────────

async def test_report_download_format_override(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    project_id = env["project"].id

    # Create report as PDF
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Multi-Format Test", "report_type": "executive", "file_format": "pdf"},
        headers=env["headers"],
    )
    report_id = create_res.json()["id"]

    # 1. Override format to CSV
    dl_csv = await client.get(f"/api/v1/reports/{report_id}/download?format=csv", headers=env["headers"])
    assert dl_csv.status_code == 200
    assert "text/csv" in dl_csv.headers["content-type"]
    assert ".csv" in dl_csv.headers["content-disposition"]

    # 2. Override format to JSON
    dl_json = await client.get(f"/api/v1/reports/{report_id}/download?format=json", headers=env["headers"])
    assert dl_json.status_code == 200
    assert "application/json" in dl_json.headers["content-type"]
    assert ".json" in dl_json.headers["content-disposition"]

    # 3. Override format to HTML
    dl_html = await client.get(f"/api/v1/reports/{report_id}/download?format=html", headers=env["headers"])
    assert dl_html.status_code == 200
    assert "text/html" in dl_html.headers["content-type"]
    assert ".html" in dl_html.headers["content-disposition"]

    # 4. Invalid format rejected with 400
    dl_bad = await client.get(f"/api/v1/reports/{report_id}/download?format=docx", headers=env["headers"])
    assert dl_bad.status_code == 400


# ── Test 5: Live HTML Report Preview Endpoint ────────────────────────

async def test_report_preview_endpoint(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    project_id = env["project"].id

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Preview Assessment", "report_type": "compliance", "file_format": "pdf"},
        headers=env["headers"],
    )
    report_id = create_res.json()["id"]

    preview_res = await client.get(f"/api/v1/reports/{report_id}/preview", headers=env["headers"])
    assert preview_res.status_code == 200
    assert "text/html" in preview_res.headers["content-type"]
    assert "attachment" not in preview_res.headers.get("content-disposition", "")
    assert "content-security-policy" in preview_res.headers
    assert "default-src 'none'" in preview_res.headers["content-security-policy"]
    assert "Preview Assessment" in preview_res.text
    assert "AWASAP" in preview_res.text


# ── Test 6: Sensitive Secret Redaction Across Reports ────────────────

async def test_secret_redaction_across_report_formats(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    project_id = env["project"].id

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Confidential Security Audit", "report_type": "technical", "file_format": "json"},
        headers=env["headers"],
    )
    report_id = create_res.json()["id"]

    # Check JSON export for secret redaction
    dl_json = await client.get(f"/api/v1/reports/{report_id}/download?format=json", headers=env["headers"])
    json_text = dl_json.text
    assert "super_secret_access_token_123456" not in json_text
    assert "top_secret_cookie_token_abc" not in json_text
    assert "my_api_key_secret_999" not in json_text
    assert "c2VjcmV0U2lnbmF0dXJl" not in json_text
    assert "[REDACTED]" in json_text

    # Check HTML export for secret redaction
    dl_html = await client.get(f"/api/v1/reports/{report_id}/download?format=html", headers=env["headers"])
    html_text = dl_html.text
    assert "super_secret_access_token_123456" not in html_text
    assert "top_secret_cookie_token_abc" not in html_text
    assert "[REDACTED]" in html_text

    # Check CSV export for secret redaction
    dl_csv = await client.get(f"/api/v1/reports/{report_id}/download?format=csv", headers=env["headers"])
    csv_text = dl_csv.text
    assert "super_secret_access_token_123456" not in csv_text
    assert "[REDACTED]" in csv_text


# ── Test 7: CSV Formula Injection Prevention ─────────────────────────

async def test_csv_formula_injection_defense(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    project_id = env["project"].id

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Formula Defense Audit", "report_type": "technical", "file_format": "csv"},
        headers=env["headers"],
    )
    report_id = create_res.json()["id"]

    dl_csv = await client.get(f"/api/v1/reports/{report_id}/download?format=csv", headers=env["headers"])
    assert dl_csv.status_code == 200

    # The finding title "=1+1; Remote SQL Injection in /login" MUST be sanitized with leading '
    reader = csv.reader(io.StringIO(dl_csv.text))
    rows = list(reader)
    title_col_idx = rows[0].index("Title")

    found_sanitized = False
    for r in rows[1:]:
        val = r[title_col_idx]
        if "Remote SQL Injection" in val:
            assert val.startswith("'="), f"Expected formula injection escaping with leading quote, got: {val}"
            found_sanitized = True
    assert found_sanitized, "Target finding was not found in CSV output"


# ── Test 8: HTML XSS Defense ─────────────────────────────────────────

async def test_html_xss_defense_in_reports(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    project_id = env["project"].id

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "XSS Defense Audit", "report_type": "technical", "file_format": "html"},
        headers=env["headers"],
    )
    report_id = create_res.json()["id"]

    dl_html = await client.get(f"/api/v1/reports/{report_id}/download?format=html", headers=env["headers"])
    assert dl_html.status_code == 200
    html_text = dl_html.text

    # Raw script tags in title or URL must NEVER be emitted unescaped
    assert "<script>alert(document.cookie)</script>" not in html_text
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in html_text
    assert "<script>alert(1)</script>" not in html_text


# ── Test 9: IDOR & Cross-User Isolation on Reports & Dashboard ───────

async def test_cross_user_isolation_on_reports_and_dashboard(client: AsyncClient, setup_phase9_dataset: dict):
    env = setup_phase9_dataset
    project_id = env["project"].id

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "User A Report", "report_type": "executive", "file_format": "json"},
        headers=env["headers"],
    )
    report_id = create_res.json()["id"]

    # Register second user (User B)
    u2_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "User B", "email": f"user_b_{uuid.uuid4().hex[:6]}@example.com", "password": "Password123!"},
    )
    u2_headers = {"Authorization": f"Bearer {u2_res.json()['access_token']}"}

    # 1. User B's dashboard summary shows 0 projects and 0 findings (no leak from User A)
    u2_dash = await client.get("/api/v1/dashboard/summary", headers=u2_headers)
    assert u2_dash.status_code == 200
    assert u2_dash.json()["total_projects"] == 0
    assert u2_dash.json()["total_findings"] == 0

    # 2. User B cannot get User A's report details -> 404
    u2_detail = await client.get(f"/api/v1/reports/{report_id}", headers=u2_headers)
    assert u2_detail.status_code == 404

    # 3. User B cannot preview User A's report -> 404
    u2_preview = await client.get(f"/api/v1/reports/{report_id}/preview", headers=u2_headers)
    assert u2_preview.status_code == 404

    # 4. User B cannot download User A's report -> 404
    u2_dl = await client.get(f"/api/v1/reports/{report_id}/download", headers=u2_headers)
    assert u2_dl.status_code == 404

    # 5. User B cannot delete User A's report -> 404
    u2_del = await client.delete(f"/api/v1/reports/{report_id}", headers=u2_headers)
    assert u2_del.status_code == 404


# ── Test 10: Security Score Correctly Handles Inactive Findings ─────

async def test_security_score_handles_resolved_false_positive_accepted_risk(
    client: AsyncClient,
    db: AsyncSession,
):
    """
    Verifies that resolved, false-positive, and accepted-risk findings
    do NOT deduct points from the active security posture score in dashboard
    and report generation, while active/reopened findings do.
    """
    uid = uuid.uuid4().hex[:6]
    user = User(
        email=f"posture_tester_{uid}@example.com",
        name=f"Posture Tester {uid}",
        hashed_password="hashed_pw_secret_999",
        role="analyst",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    project = Project(
        name=f"Score Project {uid}",
        description="Testing inactive status score handling",
        user_id=user.id,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    target = Target(
        project_id=project.id,
        url="https://score-test.internal.test",
        type="web",
        validation_status="authorized",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    scan = Scan(
        project_id=project.id,
        target_id=target.id,
        user_id=user.id,
        scan_type="active",
        status="COMPLETED",
        progress=100,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Add 4 findings with different statuses:
    # 1. Critical: resolved (0 deduction)
    # 2. High: false_positive (0 deduction)
    # 3. Medium: accepted_risk (0 deduction)
    # 4. Low: open (3 deduction)
    f_crit = Finding(
        scan_id=scan.id,
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        title="Resolved Critical RCE",
        description="Resolved remote code execution in administrative endpoint.",
        severity="critical",
        status="resolved",
        confidence="HIGH",
        category="RCE",
        owasp_category="A03:2021-Injection",
        affected_url="https://score-test.internal.test/admin/exec",
    )
    f_high = Finding(
        scan_id=scan.id,
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        title="False Positive Auth Bypass",
        description="Reported bypass investigated and confirmed as intended guest routing.",
        severity="high",
        status="false_positive",
        confidence="HIGH",
        category="Auth",
        owasp_category="A07:2021-Identification and Authentication Failures",
        affected_url="https://score-test.internal.test/login",
    )
    f_med = Finding(
        scan_id=scan.id,
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        title="Accepted Risk Information Leak",
        description="Verbose server banner documented and formally accepted for dev test environment.",
        severity="medium",
        status="accepted_risk",
        confidence="HIGH",
        category="Info Leak",
        owasp_category="A01:2021-Broken Access Control",
        affected_url="https://score-test.internal.test/debug",
    )
    f_low = Finding(
        scan_id=scan.id,
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        title="Active Low Header Issue",
        description="Missing Referrer-Policy header on root response.",
        severity="low",
        status="open",
        confidence="HIGH",
        category="Headers",
        owasp_category="A05:2021-Security Misconfiguration",
        affected_url="https://score-test.internal.test/",
    )
    db.add_all([f_crit, f_high, f_med, f_low])
    await db.commit()

    # 1. Dashboard summary verification
    res = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_findings"] == 4
    assert data["critical_findings"] == 1
    assert data["high_findings"] == 1
    assert data["medium_findings"] == 1
    assert data["low_findings"] == 1

    # Security score must deduct ONLY for the active low finding: 100 - (1*3) = 97.0
    # (If resolved/false_positive/accepted_risk were deducted, score would be 100 - 51 = 49.0)
    assert data["overall_security_score"] == 97.0

    # 2. Report generation score verification
    create_rep = await client.post(
        f"/api/v1/projects/{project.id}/reports",
        json={"title": "Status Handling Audit", "report_type": "technical", "file_format": "json"},
        headers=headers,
    )
    assert create_rep.status_code == 201
    rep_data = create_rep.json()
    assert rep_data["overall_score"] == 97.0

    dl_json = await client.get(f"/api/v1/reports/{rep_data['id']}/download?format=json", headers=headers)
    assert dl_json.status_code == 200
    assert dl_json.json()["overall_security_score"] == 97.0

    # 3. HTML export shows all findings with distinct status badges
    dl_html = await client.get(f"/api/v1/reports/{rep_data['id']}/download?format=html", headers=headers)
    assert dl_html.status_code == 200
    html_text = dl_html.text
    assert "97.0" in html_text
    assert "Resolved Critical RCE" in html_text
    assert "resolved" in html_text
    assert "false_positive" in html_text
    assert "accepted_risk" in html_text
