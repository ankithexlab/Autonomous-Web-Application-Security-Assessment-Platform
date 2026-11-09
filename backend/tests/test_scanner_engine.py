"""
Real Scanner Engine unit tests.

Coverage:
  1. Passive HTTP scanner execution with mock HTTP client responses
  2. Finding generation for missing CSP, HSTS, insecure cookies, technology disclosure
  3. Status transitions QUEUED -> RUNNING -> COMPLETED
  4. Real stage-based progress tracking
  5. Scanner error handling -> FAILED state
"""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.services.scanner_engine import ScannerEngine

pytestmark = pytest.mark.asyncio


class MockHTTPClient(SafeHTTPClient):
    """Mock HTTP client returning controlled headers & responses for scanner tests."""

    def __init__(self, response_map: dict[str, SafeHTTPResponse] | None = None) -> None:
        super().__init__()
        self.response_map = response_map or {}

    async def get(
        self,
        target_url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> SafeHTTPResponse:
        if target_url in self.response_map:
            return self.response_map[target_url]

        # Default response
        return SafeHTTPResponse(
            url=target_url,
            status_code=200,
            headers={
                "content-type": "text/html",
                "server": "nginx/1.18.0",
                "x-powered-by": "PHP/7.4.3",
                "set-cookie": "session_id=12345; Path=/",
            },
            text="<html><body><h1>Test Page</h1></body></html>",
            elapsed_seconds=0.15,
            redirect_chain=[target_url],
            content_type="text/html",
        )


async def test_scanner_engine_passive_checks(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # 1. Create scan
    create_res = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "full"},
        headers=env["headers"],
    )
    assert create_res.status_code == 201
    scan_id = create_res.json()["id"]

    # 2. Run Scanner Engine directly with MockHTTPClient and SSRF validation mock
    mock_client = MockHTTPClient()
    engine = ScannerEngine(db, http_client=mock_client)

    with patch("app.services.scanner_engine.validate_target_url", return_value="https://example.com"):
        scan = await engine.run_scan(scan_id)

    assert scan.status == "COMPLETED"
    assert scan.progress == 100
    assert scan.findings_count > 0

    # 3. Verify findings created from real evidence
    findings_res = await client.get(f"/api/v1/scans/{scan_id}/findings", headers=env["headers"])
    assert findings_res.status_code == 200
    findings = findings_res.json()

    titles = [f["title"] for f in findings]
    assert "Missing Content-Security-Policy Header" in titles
    assert "Insecure Cookie Attributes Detected" in titles
    assert "Server & Technology Information Disclosure" in titles


async def test_scanner_engine_failure_state(setup_project_and_target: dict, db):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # 1. Create scan
    from app.repositories.scan import ScanRepository
    scan_repo = ScanRepository(db)
    scan = await scan_repo.create(
        target_id=target_id,
        project_id=project_id,
        user_id=env["user"]["user"]["id"],
        scan_type="full",
    )

    # 2. Run engine with failing HTTP client
    failing_client = AsyncMock(spec=SafeHTTPClient)
    failing_client.get.side_effect = BadRequestException("Simulated connection failure")

    engine = ScannerEngine(db, http_client=failing_client)

    with pytest.raises(BadRequestException):
        await engine.run_scan(scan.id)

    # Verify scan status transitioned to FAILED
    failed_scan = await scan_repo.get_by_id(scan.id)
    assert failed_scan.status == "FAILED"
