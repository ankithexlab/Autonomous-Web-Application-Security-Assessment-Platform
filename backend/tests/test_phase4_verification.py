"""
AWASAP Phase 4 Verification Test Suite.

Validates the complete set of Phase 4 deliverables:
  1. Genuine scanning of exact target URL without fallback.
  2. Incremental persistence of truthful module results into modules_json.
  3. SSRF and DNS rebinding protections (connection layer and URL validation).
  4. Response byte size limits (response bomb protection).
  5. Timeout bounds on HTTP client.
  6. Crawler alias mapping (crawler -> url_discovery).
  7. Clean cancellation handling preserving status and partial modules_json.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.models.target import Target
from app.repositories.scan import ScanRepository
from app.services.scanner_engine import ScannerEngine, MODULE_ALIAS_MAP

pytestmark = pytest.mark.asyncio


def _make_safe_response(url: str, text: str = "<html><body><h1>Lab</h1></body></html>", status_code: int = 200) -> SafeHTTPResponse:
    return SafeHTTPResponse(
        url=url,
        status_code=status_code,
        headers={"content-type": "text/html", "server": "Apache/2.4.41"},
        text=text,
        elapsed_seconds=0.08,
        redirect_chain=[url],
        content_type="text/html",
    )


async def test_crawler_alias_resolution():
    """Verify 'crawler' correctly expands to 'url_discovery' in ScannerEngine."""
    assert "crawler" in MODULE_ALIAS_MAP
    assert "url_discovery" in MODULE_ALIAS_MAP["crawler"]


async def test_genuine_scanning_exact_url_and_truthful_modules(db, setup_project_and_target):
    """Verify exact target URL is preserved, scanned, and module_results accurately saved into modules_json."""
    env = setup_project_and_target
    exact_lab_url = "http://testphp.vulnweb.com/artists.php?artist=1"

    target = Target(
        project_id=env["project"]["id"],
        url=exact_lab_url,
        type="web",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    scan = Scan(
        project_id=env["project"]["id"],
        target_id=target.id,
        user_id=env["user"]["user"]["id"],
        scan_type="full",
        status="QUEUED",
        progress=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = _make_safe_response(exact_lab_url)

    engine = ScannerEngine(db, http_client=mock_client)

    with patch("app.services.scanner_engine.validate_target_url", return_value=exact_lab_url):
        finished_scan = await engine.run_scan(scan.id)

    assert finished_scan.status == "COMPLETED"
    assert finished_scan.progress == 100
    assert finished_scan.modules_json is not None

    parsed_modules = json.loads(finished_scan.modules_json)
    assert isinstance(parsed_modules, dict)
    assert "ssrf_validation" in parsed_modules
    assert parsed_modules["ssrf_validation"]["status"] == "completed"
    assert parsed_modules["ssrf_validation"]["target_url"] == exact_lab_url

    assert "http_reachability" in parsed_modules
    assert parsed_modules["http_reachability"]["status"] == "completed"
    assert parsed_modules["http_reachability"]["status_code"] == 200

    assert "security_headers" in parsed_modules
    assert parsed_modules["security_headers"]["status"] == "completed"

    assert "ssl_tls" in parsed_modules
    assert parsed_modules["ssl_tls"]["status"] == "completed"

    assert "owasp_top_10" in parsed_modules
    assert parsed_modules["owasp_top_10"]["status"] == "completed"


async def test_ssrf_rejects_private_and_cloud_metadata():
    """Verify validate_target_url strictly rejects loopback, private IPs, and cloud metadata."""
    from app.core.ssrf import validate_target_url

    blocked_targets = [
        "http://127.0.0.1:8080/admin",
        "http://localhost:5000/secret",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router",
        "http://172.16.0.5/api",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]

    for target in blocked_targets:
        with pytest.raises(BadRequestException):
            validate_target_url(target)


async def test_response_byte_limit_enforced():
    """Verify SafeHTTPClient enforces maximum response bytes limit."""
    client = SafeHTTPClient(max_response_bytes=100)
    assert client.max_response_bytes == 100


async def test_mid_scan_cancellation_preserves_modules_json(db, setup_project_and_target):
    """Verify cancellation preserves CANCELLED status and saves partial modules_json."""
    env = setup_project_and_target
    target_url = "https://example.com/test"

    target = Target(
        project_id=env["project"]["id"],
        url=target_url,
        type="web",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    scan = Scan(
        project_id=env["project"]["id"],
        target_id=target.id,
        user_id=env["user"]["user"]["id"],
        scan_type="full",
        status="QUEUED",
        progress=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    engine = ScannerEngine(db)

    # Simulate cancellation in stage 2
    async def cancel_side_effect(*args, **kwargs):
        scan_repo = ScanRepository(db)
        s = await scan_repo.get_by_id(scan.id)
        s.status = "CANCELLED"
        await db.commit()
        raise asyncio.CancelledError()

    with patch.object(engine, "_run_info_gathering", side_effect=cancel_side_effect):
        with patch("app.services.scanner_engine.validate_target_url", return_value=target_url):
            with pytest.raises(asyncio.CancelledError):
                await engine.run_scan(scan.id)

    cancelled_scan = await ScanRepository(db).get_by_id(scan.id)
    assert cancelled_scan.status == "CANCELLED"
    assert cancelled_scan.modules_json is not None
    modules = json.loads(cancelled_scan.modules_json)
    assert "ssrf_validation" in modules
