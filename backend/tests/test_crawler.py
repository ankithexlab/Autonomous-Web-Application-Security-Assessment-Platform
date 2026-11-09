"""
Unit and regression tests for Phase 4.4 Step 2: Same-Origin URL Discovery & Crawler.

Validates:
  1. Breadth-first crawl respects maximum depth of 2.
  2. Maximum 25 discovered URLs cap is strictly enforced.
  3. External domains and subdomains are rejected (strictly same-origin).
  4. Sensitive and state-changing routes (/logout, /delete, /pay, /upload, etc.) are excluded.
  5. URLs failing SSRF protection are skipped.
  6. Static assets (.css, .png, .pdf, etc.) are not queued.
  7. URL fragments and redundant trailing slashes are normalized and deduplicated.
  8. Informational finding is created when endpoints are discovered.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.repositories.finding import FindingRepository
from app.services.scanner.crawler import SameOriginCrawlerModule


# ── 1. Same-Origin & Normalization Tests ────────────────────────────────────


def test_crawler_url_normalization():
    """URL normalization strips fragments and standardizes paths."""
    assert SameOriginCrawlerModule.normalize_url("https://example.com/about/#team") == "https://example.com/about"
    assert SameOriginCrawlerModule.normalize_url("https://example.com/about/") == "https://example.com/about"
    assert SameOriginCrawlerModule.normalize_url("https://example.com/") == "https://example.com/"
    assert SameOriginCrawlerModule.normalize_url("https://example.com") == "https://example.com/"
    assert SameOriginCrawlerModule.normalize_url("https://example.com/search?q=1#top") == "https://example.com/search?q=1"


def test_crawler_state_changing_route_exclusion():
    """Identifies and rejects dangerous or state-changing routes."""
    dangerous = [
        "https://example.com/auth/logout",
        "https://example.com/users/123/delete",
        "https://example.com/checkout/pay",
        "https://example.com/account/billing",
        "https://example.com/files/upload",
        "https://example.com/reset-password",
        "https://example.com/sub/terminate",
        "https://example.com/action?do=cancel",
    ]
    for url in dangerous:
        assert SameOriginCrawlerModule.is_state_changing_or_sensitive(url) is True

    safe = [
        "https://example.com/about",
        "https://example.com/products",
        "https://example.com/blog/2026/security",
        "https://example.com/contact-us",
        "https://example.com/pricing",
    ]
    for url in safe:
        assert SameOriginCrawlerModule.is_state_changing_or_sensitive(url) is False


def test_crawler_ignored_static_assets():
    """Filters out binary and media extensions."""
    assert SameOriginCrawlerModule.is_ignored_asset("/static/logo.png") is True
    assert SameOriginCrawlerModule.is_ignored_asset("/styles/main.css") is True
    assert SameOriginCrawlerModule.is_ignored_asset("/docs/guide.pdf") is True
    assert SameOriginCrawlerModule.is_ignored_asset("/page.html") is False
    assert SameOriginCrawlerModule.is_ignored_asset("/api/v1/items") is False


# ── 2. Breadth-First Crawl Limits (Depth & URL Count) ───────────────────────


@pytest.mark.asyncio
async def test_crawler_respects_max_depth_and_url_cap(db, setup_project_and_target):
    """Crawler visits depth 1 and 2, but does not crawl depth 3 links, and caps at MAX_URLS."""
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

    # Generate pages:
    # Root (depth 0): links to /page1, /page2
    # /page1 (depth 1): links to /page1-sub1, /page1-sub2
    # /page1-sub1 (depth 2): links to /page1-sub1-subsub (depth 3 - should not be visited)
    responses = {
        "https://example.com/": (
            '<html><body>'
            '<a href="/page1">Page 1</a>'
            '<a href="/page2">Page 2</a>'
            '<a href="https://external.com/out">External</a>'
            '<a href="/account/logout">Logout</a>'
            '</body></html>'
        ),
        "https://example.com/page1": (
            '<html><body>'
            '<a href="/page1-sub1">Sub 1</a>'
            '<a href="/page1-sub2">Sub 2</a>'
            '</body></html>'
        ),
        "https://example.com/page2": (
            '<html><body>'
            '<a href="/page2-sub1">Page 2 Sub 1</a>'
            '</body></html>'
        ),
        "https://example.com/page1-sub1": (
            '<html><body>'
            '<a href="/page1-sub1-depth3">Depth 3 Page</a>'
            '</body></html>'
        ),
        "https://example.com/page1-sub2": '<html><body>No links</body></html>',
        "https://example.com/page2-sub1": '<html><body>No links</body></html>',
    }

    mock_client = AsyncMock(spec=SafeHTTPClient)

    async def mock_get(url, timeout=None):
        content = responses.get(url, '<html><body>Not found</body></html>')
        return SafeHTTPResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            text=content,
            elapsed_seconds=0.05,
            redirect_chain=[url],
            content_type="text/html",
        )

    mock_client.get.side_effect = mock_get

    with patch("app.services.scanner.crawler.validate_target_url", side_effect=lambda u: u):
        res = await crawler.run(
            scan=scan,
            target_url="https://example.com/",
            main_resp=None,
            http_client=mock_client,
            counts=counts,
        )

    assert res["total_discovered"] >= 5
    discovered = res["discovered_urls"]

    # Must contain depth 1 and depth 2 URLs
    assert "https://example.com/page1" in discovered
    assert "https://example.com/page2" in discovered
    assert "https://example.com/page1-sub1" in discovered
    assert "https://example.com/page1-sub2" in discovered
    assert "https://example.com/page2-sub1" in discovered

    # Must NOT contain depth 3 URL
    assert "https://example.com/page1-sub1-depth3" not in discovered

    # Must NOT contain external URL or dangerous route
    assert "https://external.com/out" not in discovered
    assert "https://example.com/account/logout" not in discovered

    # Check finding creation
    findings = await repo.list_for_scan(scan.id)
    assert any("Discovered" in f.title and f.cwe_id == "CWE-200" for f in findings)
    assert counts["info"] >= 1


@pytest.mark.asyncio
async def test_crawler_max_urls_cap(db, setup_project_and_target):
    """Crawler terminates immediately when MAX_URLS (25) is reached."""
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

    # Generate 40 unique links on root page
    links_html = "".join(f'<a href="/item-{i}">Item {i}</a>' for i in range(40))
    root_html = f"<html><body>{links_html}</body></html>"

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = SafeHTTPResponse(
        url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        text=root_html,
        elapsed_seconds=0.05,
        redirect_chain=["https://example.com/"],
        content_type="text/html",
    )

    with patch("app.services.scanner.crawler.validate_target_url", side_effect=lambda u: u):
        res = await crawler.run(
            scan=scan,
            target_url="https://example.com/",
            main_resp=None,
            http_client=mock_client,
            counts=counts,
        )

    # Strictly capped at MAX_URLS (25)
    assert res["total_discovered"] == 25
    assert len(res["discovered_urls"]) == 25


@pytest.mark.asyncio
async def test_crawler_skips_ssrf_violating_candidates(db, setup_project_and_target):
    """Candidate links resolving to internal or private IP ranges are rejected by validate_target_url."""
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

    root_html = (
        '<html><body>'
        '<a href="/safe-page">Safe</a>'
        '<a href="/internal-admin">SSRF Blocked</a>'
        '</body></html>'
    )

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = SafeHTTPResponse(
        url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        text=root_html,
        elapsed_seconds=0.05,
        redirect_chain=["https://example.com/"],
        content_type="text/html",
    )

    def ssrf_validator(url: str):
        if "internal-admin" in url:
            raise BadRequestException("Target resolves to private network")
        return url

    with patch("app.services.scanner.crawler.validate_target_url", side_effect=ssrf_validator):
        res = await crawler.run(
            scan=scan,
            target_url="https://example.com/",
            main_resp=None,
            http_client=mock_client,
            counts=counts,
        )

    assert "https://example.com/safe-page" in res["discovered_urls"]
    assert "https://example.com/internal-admin" not in res["discovered_urls"]
