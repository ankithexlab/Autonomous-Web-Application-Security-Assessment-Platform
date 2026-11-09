"""
Integration tests for Phase 4.4.1 Minimal Scanner Integration Fixes.

Validates:
  1. POST body testing is invoked during PayloadSecurityTestRunner.run() when eligible.
  2. Blind SQLi timing analysis is invoked during PayloadSecurityTestRunner.run() when query params exist.
  3. Negative test: Timing and POST testing are safely skipped for ineligible/static targets without schemas.
  4. Negative test: POST testing is safely blocked for sensitive/state-changing routes (/delete, /logout).
  5. Crawler redirect origin boundary: Crawler discards response bodies redirected outside target origin.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.models.security_payload import SecurityPayload
from app.repositories.finding import FindingRepository
from app.services.scanner.crawler import SameOriginCrawlerModule
from app.services.scanner.payload_test_runner import PayloadSecurityTestRunner


def _make_response(url: str, text: str = "<html><body>OK</body></html>", status_code: int = 200, elapsed: float = 0.05, content_type: str = "text/html") -> SafeHTTPResponse:
    return SafeHTTPResponse(
        url=url,
        status_code=status_code,
        headers={"content-type": content_type},
        text=text,
        elapsed_seconds=elapsed,
        redirect_chain=[url],
        content_type=content_type,
    )


async def _seed_test_payload(db):
    for pid, desc, val, ctx, ptype, sev in [
        ("p441-tautology", "Tautology probe", "' OR '1'='1", "Search", "tautology", "high"),
        ("p441-xss", "Reflected XSS", "<script>alert(1)</script>", "Search", "reflected", "medium"),
    ]:
        existing = await db.get(SecurityPayload, pid)
        if not existing:
            db.add(SecurityPayload(
                id=pid,
                description=desc,
                payload=val,
                context=ctx,
                type=ptype,
                severity=sev,
            ))
    await db.commit()


# ── 1. Eligible Target: Both Timing & POST Probes Invoked in run() ────────────


@pytest.mark.asyncio
async def test_payload_runner_invokes_timing_and_post_for_eligible_target(db, setup_project_and_target):
    """When target has query parameters, run() invokes GET probes, blind timing analysis, and safe POST testing."""
    await _seed_test_payload(db)
    env = setup_project_and_target
    scan = Scan(
        project_id=env["project"]["id"],
        target_id=env["target"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="web",
        status="running",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    repo = FindingRepository(db)
    runner = PayloadSecurityTestRunner(repo, db)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    mock_client = AsyncMock(spec=SafeHTTPClient)
    # Default fast responses for all GET and POST requests
    mock_client.get.return_value = _make_response("https://example.com/api/search?q=test", "No errors", elapsed=0.04)
    mock_client.post.return_value = _make_response("https://example.com/api/search?q=test", '{"status": "clean"}', elapsed=0.04, content_type="application/json")

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        results = await runner.run(
            scan=scan,
            target_url="https://example.com/api/search?q=test",
            main_resp=None,
            http_client=mock_client,
            counts=counts,
        )

    # Both categories must be tested and present in results
    assert "blind-sqli-timing" in results["tested_categories"]
    assert "post-json-testing" in results["tested_categories"]
    assert results["total_probes"] >= 2
    # Verify mock client received both GET and POST calls
    assert mock_client.get.called
    assert mock_client.post.called


# ── 2. Ineligible Target: Timing & POST Safely Skipped ────────────────────────


@pytest.mark.asyncio
async def test_payload_runner_skips_ineligible_targets(db, setup_project_and_target):
    """Targets without query params or API paths safely skip timing and arbitrary POST probing."""
    env = setup_project_and_target
    scan = Scan(
        project_id=env["project"]["id"],
        target_id=env["target"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="web",
        status="running",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    repo = FindingRepository(db)
    runner = PayloadSecurityTestRunner(repo, db)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    mock_client = AsyncMock(spec=SafeHTTPClient)

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        results = await runner.run(
            scan=scan,
            target_url="https://example.com/static-page",
            main_resp=None,
            http_client=mock_client,
            counts=counts,
        )

    # Timing analysis skipped
    timing_details = [d for d in results["details"] if d.get("category") == "blind-sqli-timing"]
    assert len(timing_details) == 1
    assert timing_details[0]["status"] == "skipped"
    assert "no query parameters" in timing_details[0]["reason"]

    # POST testing skipped due to no candidate schema
    post_details = [d for d in results["details"] if d.get("category") == "post-body-testing"]
    assert len(post_details) == 1
    assert post_details[0]["status"] == "skipped"
    assert "No established request schema" in post_details[0]["reason"]

    # No POST requests should have been dispatched
    assert not mock_client.post.called


# ── 3. State-Changing Route Exclusion for POST Probes ─────────────────────────


@pytest.mark.asyncio
async def test_payload_runner_blocks_post_on_sensitive_routes(db, setup_project_and_target):
    """State-changing routes like /delete or /logout are skipped from POST body probing."""
    env = setup_project_and_target
    scan = Scan(
        project_id=env["project"]["id"],
        target_id=env["target"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="web",
        status="running",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    repo = FindingRepository(db)
    runner = PayloadSecurityTestRunner(repo, db)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = _make_response("https://example.com/account/delete?confirm=yes", "Are you sure?")

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        results = await runner.run(
            scan=scan,
            target_url="https://example.com/account/delete?confirm=yes",
            main_resp=None,
            http_client=mock_client,
            counts=counts,
        )

    post_details = [d for d in results["details"] if d.get("category") == "post-body-testing"]
    assert len(post_details) == 1
    assert post_details[0]["status"] == "skipped"
    assert "state-changing route policy" in post_details[0]["reason"]
    assert not mock_client.post.called


# ── 4. Crawler Redirect Origin Boundary Check ────────────────────────────────


@pytest.mark.asyncio
async def test_crawler_discards_off_origin_redirect_destination(db, setup_project_and_target):
    """Crawler refuses to parse or harvest links from responses that redirected to an external origin."""
    env = setup_project_and_target
    scan = Scan(
        project_id=env["project"]["id"],
        target_id=env["target"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="web",
        status="running",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    repo = FindingRepository(db)
    crawler = SameOriginCrawlerModule(repo)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Root page links to /sso-login
    root_html = '<html><body><a href="/sso-login">SSO</a><a href="/internal-page">Internal</a></body></html>'
    # External redirected page contains external links that must NOT be parsed or crawled
    external_html = '<html><body><a href="/external-secret-page">External Leak</a></body></html>'

    mock_client = AsyncMock(spec=SafeHTTPClient)

    async def mock_get(url, timeout=None):
        if url == "https://example.com/":
            return _make_response("https://example.com/", root_html)
        elif url == "https://example.com/sso-login":
            # Response URL redirected off-origin to auth.external-corp.com
            return SafeHTTPResponse(
                url="https://auth.external-corp.com/oauth/authorize",
                status_code=200,
                headers={"content-type": "text/html"},
                text=external_html,
                elapsed_seconds=0.08,
                redirect_chain=["https://example.com/sso-login", "https://auth.external-corp.com/oauth/authorize"],
                content_type="text/html",
            )
        elif url == "https://example.com/internal-page":
            return _make_response("https://example.com/internal-page", '<html><body>Hello</body></html>')
        return _make_response(url, "404", 404)

    mock_client.get.side_effect = mock_get

    with patch("app.services.scanner.crawler.validate_target_url", side_effect=lambda u: u):
        res = await crawler.run(
            scan=scan,
            target_url="https://example.com/",
            main_resp=None,
            http_client=mock_client,
            counts=counts,
        )

    discovered = res["discovered_urls"]
    # Same origin pages are discovered
    assert "https://example.com/sso-login" in discovered
    assert "https://example.com/internal-page" in discovered

    # External redirect destination body was rejected; external links are NEVER parsed or crawled
    assert "https://auth.external-corp.com/oauth/authorize" not in discovered
    assert not any("external-secret-page" in u for u in discovered)
    assert not any("external-corp.com" in u for u in discovered)
