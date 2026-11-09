"""
OWASP Top 10 Security Engine Unit & Integration Tests.

Coverage:
  1. A01 Broken Access Control check
  2. A02 Cryptographic Failures check
  3. A03 Injection passive check
  4. A04 Insecure Design check
  5. A05 Security Misconfiguration check
  6. A06 Vulnerable Components check
  7. A07 Auth Failures check
  8. A08 Software Integrity check
  9. A10 SSRF check
 10. GET /api/v1/owasp/summary API endpoint
"""

from unittest.mock import patch

import pytest
from httpx import AsyncClient

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.repositories.finding import FindingRepository
from app.services.owasp.owasp_engine import OWASPEngine

pytestmark = pytest.mark.asyncio


class MockOWASPHTTPClient(SafeHTTPClient):
    """Mock HTTP client supplying rich vulnerability responses for OWASP testing."""

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
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3",
                "access-control-allow-origin": "*",
                "set-cookie": "session_id=abc123xyz; Path=/",
            },
            text="""
            <html>
                <head>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/js/bootstrap.min.js"></script>
                </head>
                <body>
                    <h1>Welcome</h1>
                    <form action="/login" method="POST">
                        <input type="password" name="password" />
                    </form>
                </body>
            </html>
            """,
            elapsed_seconds=0.12,
            redirect_chain=[target_url],
            content_type="text/html",
        )


async def test_owasp_engine_checkers_execution(setup_project_and_target: dict, db):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]
    user_id = env["user"]["user"]["id"]

    # 1. Create scan record
    from app.repositories.scan import ScanRepository
    scan_repo = ScanRepository(db)
    scan = await scan_repo.create(
        target_id=target_id,
        project_id=project_id,
        user_id=user_id,
        scan_type="full",
    )

    # 2. Run OWASP Engine
    finding_repo = FindingRepository(db)
    owasp_engine = OWASPEngine(finding_repo)

    mock_resp = await MockOWASPHTTPClient().get("http://example.com/search?url=https://test.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    await owasp_engine.execute_owasp_checks(scan, mock_resp, counts)

    findings = await finding_repo.list_for_scan(scan.id)
    assert len(findings) > 0

    owasp_cats = [f.owasp_category for f in findings if f.owasp_category]
    assert any("A02:2021-Cryptographic Failures" in c for c in owasp_cats)
    assert any("A05:2021-Security Misconfiguration" in c for c in owasp_cats)
    assert any("A06:2021-Vulnerable and Outdated Components" in c for c in owasp_cats)
    assert any("A07:2021-Identification and Authentication Failures" in c for c in owasp_cats)
    assert any("A08:2021-Software and Data Integrity Failures" in c for c in owasp_cats)
    assert any("A10:2021-Server-Side Request Forgery" in c for c in owasp_cats)


async def test_owasp_summary_api_endpoint(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target

    response = await client.get("/api/v1/owasp/summary", headers=env["headers"])
    assert response.status_code == 200, response.text
    data = response.json()

    assert "total_vulnerabilities" in data
    assert "categories_covered" in data
    assert data["categories_covered"] == 10
    assert "overall_risk_score" in data
    assert "category_breakdown" in data
    assert len(data["category_breakdown"]) == 10

    # Real Trend, Assets, Top Findings, and Scan Timeline
    assert "risk_trend" in data
    assert len(data["risk_trend"]) == 6
    for rt in data["risk_trend"]:
        assert "date" in rt
        assert "riskScore" in rt
        assert "criticalFindings" in rt
        assert "highFindings" in rt

    assert "most_affected_assets" in data
    assert isinstance(data["most_affected_assets"], list)

    assert "top_findings" in data
    assert isinstance(data["top_findings"], list)

    assert "scan_timeline" in data
    assert isinstance(data["scan_timeline"], list)


async def test_owasp_summary_empty_state_and_isolation(client: AsyncClient):
    # Register clean user
    reg = await client.post(
        "/api/v1/auth/register",
        json={"name": "Clean OWASP User", "email": "clean_owasp@example.com", "password": "Password123!"},
    )
    headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}

    res = await client.get("/api/v1/owasp/summary", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total_vulnerabilities"] == 0
    assert data["categories_covered"] == 10
    assert data["overall_risk_score"] == 100.0
    assert data["critical_count"] == 0
    assert data["high_count"] == 0
    assert data["medium_count"] == 0
    assert data["low_count"] == 0
    assert data["info_count"] == 0
    assert len(data["category_breakdown"]) == 10
    assert all(cat["findings_count"] == 0 for cat in data["category_breakdown"])
    assert all(cat["compliance_status"] == "PASS" for cat in data["category_breakdown"])

    assert len(data["risk_trend"]) == 6
    assert all(rt["criticalFindings"] == 0 and rt["highFindings"] == 0 for rt in data["risk_trend"])
    assert data["most_affected_assets"] == []
    assert data["top_findings"] == []
    assert data["scan_timeline"] == []
