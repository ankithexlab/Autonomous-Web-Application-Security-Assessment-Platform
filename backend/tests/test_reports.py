"""
Reports API and Generator Unit Tests.

Coverage:
  1. Create report (JSON/HTML/CSV/PDF)
  2. List user reports
  3. Get report details by ID
  4. Download report file payload
  5. IDOR / Cross-user report access protection (returns 404)
  6. Invalid project ID error handling
"""

import io
import pytest
from httpx import AsyncClient
from pypdf import PdfReader
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.finding import FindingRepository
from app.repositories.scan import ScanRepository

pytestmark = pytest.mark.asyncio


async def test_create_and_download_report_json(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]

    # 1. Create report
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Q3 Executive Summary", "report_type": "executive", "file_format": "json"},
        headers=env["headers"],
    )
    assert create_res.status_code == 201, create_res.text
    report = create_res.json()
    assert report["title"] == "Q3 Executive Summary"
    assert report["file_format"] == "json"
    assert report["status"] == "COMPLETED"
    report_id = report["id"]

    # 2. Download report content
    download_res = await client.get(f"/api/v1/reports/{report_id}/download", headers=env["headers"])
    assert download_res.status_code == 200
    assert download_res.headers["content-type"] == "application/json"
    data = download_res.json()
    assert data["report_id"] == report_id


async def test_create_and_download_report_csv(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Technical Audit CSV", "report_type": "technical", "file_format": "csv"},
        headers=env["headers"],
    )
    assert create_res.status_code == 201
    report_id = create_res.json()["id"]

    download_res = await client.get(f"/api/v1/reports/{report_id}/download", headers=env["headers"])
    assert download_res.status_code == 200
    assert "text/csv" in download_res.headers["content-type"]
    assert "ID,Title,Severity" in download_res.text


async def test_list_and_get_reports(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]

    await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Audit Report 1", "report_type": "compliance", "file_format": "html"},
        headers=env["headers"],
    )

    list_res = await client.get("/api/v1/reports", headers=env["headers"])
    assert list_res.status_code == 200
    reports = list_res.json()["items"]
    assert len(reports) > 0

    report_id = reports[0]["id"]
    detail_res = await client.get(f"/api/v1/reports/{report_id}", headers=env["headers"])
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == report_id


async def test_cross_user_report_access_prevention(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={"title": "Confidential Report", "report_type": "full", "file_format": "json"},
        headers=env["headers"],
    )
    report_id = create_res.json()["id"]

    # Register second user
    second_user_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "Attacker", "email": "attacker@example.com", "password": "Password123!"},
    )
    second_headers = {"Authorization": f"Bearer {second_user_res.json()['access_token']}"}

    # Attempt cross-user access -> 404 Not Found (IDOR protection)
    cross_detail_res = await client.get(f"/api/v1/reports/{report_id}", headers=second_headers)
    assert cross_detail_res.status_code == 404

    cross_download_res = await client.get(f"/api/v1/reports/{report_id}/download", headers=second_headers)
    assert cross_download_res.status_code == 404


async def test_create_and_download_report_pdf(
    client: AsyncClient, setup_project_and_target: dict
):
    env = setup_project_and_target
    project_id = env["project"]["id"]

    # 1. Create PDF Report
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={
            "title": "Executive Security Assessment Report",
            "report_type": "executive",
            "file_format": "pdf",
        },
        headers=env["headers"],
    )
    assert create_res.status_code == 201, create_res.text
    report = create_res.json()
    assert report["file_format"] == "pdf"
    assert report["status"] == "COMPLETED"
    report_id = report["id"]

    # 2. Download PDF file payload
    download_res = await client.get(
        f"/api/v1/reports/{report_id}/download",
        headers=env["headers"],
    )
    assert download_res.status_code == 200
    assert download_res.headers["content-type"] == "application/pdf"
    content = download_res.content

    # 3. Verify PDF signature bytes
    assert content.startswith(b"%PDF-"), "Response does not start with %PDF- signature bytes"

    # 4. Verify PDF structure with pypdf
    reader = PdfReader(io.BytesIO(content))
    assert len(reader.pages) >= 1
    page_text = reader.pages[0].extract_text()
    assert "AWASAP" in page_text
    assert "Executive Security Assessment Report" in page_text
    assert "Security Posture Score" in page_text


async def test_create_and_download_report_pdf_with_findings(
    client: AsyncClient, setup_project_and_target: dict, db: AsyncSession
):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]
    user_id = env["user"]["user"]["id"]

    # 1. Create a Scan
    scan_repo = ScanRepository(db)
    scan = await scan_repo.create(
        target_id=target_id,
        project_id=project_id,
        user_id=user_id,
        scan_type="full",
    )

    # 2. Add realistic security findings to the scan
    finding_repo = FindingRepository(db)
    await finding_repo.create(
        scan_id=scan.id,
        target_id=target_id,
        project_id=project_id,
        user_id=user_id,
        title="Remote Command Injection in Search Endpoint",
        description="Unsanitized user query string passed directly to OS shell execution.",
        severity="critical",
        status="open",
        confidence="HIGH",
        category="Command Injection",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-78",
        cvss_score=9.8,
        affected_url="https://app.acmecorp.com/search?q=test",
        remediation="Ensure input validation and avoid shell execution wrappers.",
        proof_of_concept="curl 'https://app.acmecorp.com/search?q=%3Bwhoami'",
    )
    await finding_repo.create(
        scan_id=scan.id,
        target_id=target_id,
        project_id=project_id,
        user_id=user_id,
        title="Missing Strict-Transport-Security Header",
        description="HSTS header missing from HTTP response headers.",
        severity="low",
        status="open",
        confidence="HIGH",
        category="Security Headers",
        owasp_category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-319",
        cvss_score=3.5,
        affected_url="https://app.acmecorp.com/",
        remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    )
    await db.commit()

    # 3. Create PDF report targeted to this scan
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={
            "title": "Comprehensive Technical Assessment",
            "report_type": "technical",
            "file_format": "pdf",
            "scan_id": str(scan.id),
            "target_id": target_id,
        },
        headers=env["headers"],
    )
    assert create_res.status_code == 201
    report = create_res.json()
    assert report["file_format"] == "pdf"
    report_id = report["id"]

    # 4. Download and inspect PDF content
    download_res = await client.get(
        f"/api/v1/reports/{report_id}/download",
        headers=env["headers"],
    )
    assert download_res.status_code == 200
    assert download_res.headers["content-type"] == "application/pdf"
    content = download_res.content

    # 5. Validate genuine binary PDF format
    assert content.startswith(b"%PDF-")

    # 6. Parse and verify findings content inside the PDF
    reader = PdfReader(io.BytesIO(content))
    assert len(reader.pages) >= 1
    full_text = " ".join([page.extract_text() for page in reader.pages])

    assert "AWASAP" in full_text
    assert "Comprehensive Technical Assessment" in full_text
    assert "Remote Command Injection" in full_text
    assert "CRITICAL" in full_text
    assert "CWE-78" in full_text
    assert "Strict-Transport-Security" in full_text


async def test_create_and_download_report_html(
    client: AsyncClient, setup_project_and_target: dict
):
    env = setup_project_and_target
    project_id = env["project"]["id"]

    create_res = await client.post(
        f"/api/v1/projects/{project_id}/reports",
        json={
            "title": "HTML Audit Report",
            "report_type": "compliance",
            "file_format": "html",
        },
        headers=env["headers"],
    )
    assert create_res.status_code == 201
    report_id = create_res.json()["id"]

    download_res = await client.get(
        f"/api/v1/reports/{report_id}/download",
        headers=env["headers"],
    )
    assert download_res.status_code == 200
    assert "text/html" in download_res.headers["content-type"]
    assert "<!DOCTYPE html>" in download_res.text
    assert "HTML Audit Report" in download_res.text


async def test_report_scope_validation_mismatched_target(
    client: AsyncClient, setup_project_and_target: dict
):
    env = setup_project_and_target
    target_id = env["target"]["id"]

    # 1. Create a second independent project
    proj2_resp = await client.post(
        "/api/v1/projects",
        json={"name": "Second Isolated Project", "risk_level": "low"},
        headers=env["headers"],
    )
    assert proj2_resp.status_code == 201
    project_b_id = proj2_resp.json()["id"]

    # 2. Attempting to create report under Project B referencing Target A from Project A -> 404
    res = await client.post(
        f"/api/v1/projects/{project_b_id}/reports",
        json={
            "title": "Mismatched Target Scope Report",
            "report_type": "technical",
            "file_format": "json",
            "target_id": target_id,
        },
        headers=env["headers"],
    )
    assert res.status_code == 404


async def test_report_scope_validation_mismatched_scan(
    client: AsyncClient, setup_project_and_target: dict, db: AsyncSession
):
    env = setup_project_and_target
    project_a_id = env["project"]["id"]
    target_a_id = env["target"]["id"]
    user_id = env["user"]["user"]["id"]

    # 1. Create Scan under Project A
    scan_repo = ScanRepository(db)
    scan_a = await scan_repo.create(
        target_id=target_a_id,
        project_id=project_a_id,
        user_id=user_id,
        scan_type="full",
    )
    await db.commit()

    # 2. Create Project B
    proj2_resp = await client.post(
        "/api/v1/projects",
        json={"name": "Second Isolated Project B", "risk_level": "medium"},
        headers=env["headers"],
    )
    assert proj2_resp.status_code == 201
    project_b_id = proj2_resp.json()["id"]

    # 3. Attempting to create report under Project B referencing Scan A from Project A -> 404
    res = await client.post(
        f"/api/v1/projects/{project_b_id}/reports",
        json={
            "title": "Mismatched Scan Scope Report",
            "report_type": "technical",
            "file_format": "json",
            "scan_id": str(scan_a.id),
        },
        headers=env["headers"],
    )
    assert res.status_code == 404


async def test_target_project_mapping_and_isolation(
    client: AsyncClient, setup_project_and_target: dict
):
    env = setup_project_and_target
    project_a_id = env["project"]["id"]
    target_a_id = env["target"]["id"]

    # 1. Create Project B
    proj2_resp = await client.post(
        "/api/v1/projects",
        json={"name": "Project B for Target Isolation", "risk_level": "low"},
        headers=env["headers"],
    )
    assert proj2_resp.status_code == 201
    project_b_id = proj2_resp.json()["id"]

    # 2. List targets for Project B -> empty list
    list_b_resp = await client.get(
        f"/api/v1/projects/{project_b_id}/targets",
        headers=env["headers"],
    )
    assert list_b_resp.status_code == 200
    assert list_b_resp.json() == []

    # 3. Create Target B explicitly under Project B
    target_b_resp = await client.post(
        f"/api/v1/projects/{project_b_id}/targets",
        json={"url": "https://service-b.internal.net", "type": "api"},
        headers=env["headers"],
    )
    assert target_b_resp.status_code == 201
    target_b = target_b_resp.json()
    assert target_b["project_id"] == project_b_id
    assert target_b["url"] == "https://service-b.internal.net"

    # 4. Target A cannot be fetched under Project B's route -> 404
    get_mismatched_resp = await client.get(
        f"/api/v1/projects/{project_b_id}/targets/{target_a_id}",
        headers=env["headers"],
    )
    assert get_mismatched_resp.status_code == 404


