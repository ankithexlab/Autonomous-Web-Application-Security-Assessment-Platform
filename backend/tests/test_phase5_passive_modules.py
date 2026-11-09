"""
Phase 5 — Passive Scanner Modules Test Suite.

Verifies independent, genuine, defensive passive security analysis:
  1. Security headers analysis (SecurityHeadersModule).
  2. SSL/TLS observations (SslTlsModule).
  3. Cookie security attributes (CookieSecurityModule).
  4. HTTP/HTTPS configuration (HttpConfigModule).
  5. Redirect analysis (RedirectAnalysisModule).
  6. Technology fingerprinting (TechDetectionModule).
  7. robots.txt and sitemap.xml analysis (RobotsSitemapModule).
  8. Bounded same-origin crawling (SameOriginCrawlerModule).
  9. Endpoint and parameter discovery (EndpointParamDiscoveryModule).
  10. Publicly exposed configuration checks (ExposedConfigCheckerModule).
  11. End-to-end passive engine execution with modules_json persistence and error handling.
"""

import asyncio
from datetime import datetime, timezone
import json
import pytest
from unittest.mock import AsyncMock, patch

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.repositories.finding import FindingRepository
from app.repositories.scan import ScanRepository
from app.services.scanner_engine import ScannerEngine, MODULE_ALIAS_MAP

# Phase 5 Modules
from app.services.scanner.security_headers import SecurityHeadersModule
from app.services.scanner.ssl_tls import SslTlsModule
from app.services.scanner.cookie_security import CookieSecurityModule
from app.services.scanner.http_config import HttpConfigModule
from app.services.scanner.redirect_analysis import RedirectAnalysisModule
from app.services.scanner.tech_detection import TechDetectionModule
from app.services.scanner.robots_sitemap import RobotsSitemapModule
from app.services.scanner.crawler import SameOriginCrawlerModule
from app.services.scanner.endpoint_param_discovery import EndpointParamDiscoveryModule
from app.services.scanner.exposed_config_checker import ExposedConfigCheckerModule

pytestmark = pytest.mark.asyncio


def _make_response(
    url: str,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    text: str = "",
    redirect_chain: list[str] | None = None,
) -> SafeHTTPResponse:
    hdrs = headers or {}
    return SafeHTTPResponse(
        url=url,
        status_code=status_code,
        headers=hdrs,
        text=text,
        elapsed_seconds=0.05,
        redirect_chain=redirect_chain or [url],
        content_type=hdrs.get("content-type", "text/html"),
    )


async def _create_test_scan(db, setup_project_and_target, target_url: str = "https://example.com") -> tuple[Scan, FindingRepository]:
    env = setup_project_and_target
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
        scan_type="passive",
        status="RUNNING",
        progress=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan, FindingRepository(db)


# ── 1. Security Headers Analysis ─────────────────────────────────────

async def test_security_headers_missing_and_unsafe_directives(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = SecurityHeadersModule(repo)

    # Insecure response missing all headers and with unsafe CSP
    resp = _make_response(
        "https://example.com",
        headers={
            "content-security-policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "server": "nginx/1.18.0",
        },
    )

    result = await module.run(scan, "https://example.com", resp, AsyncMock(), counts)
    assert result["status"] == "completed"
    assert "Strict-Transport-Security" in result["headers_missing"]
    assert "X-Frame-Options" in result["headers_missing"]
    assert "X-Content-Type-Options" in result["headers_missing"]
    assert result["findings_count"] >= 3

    # Verify findings were persisted into DB
    findings = await repo.list_for_scan(scan.id)
    titles = [f.title for f in findings]
    assert any("unsafe-inline" in t for t in titles)
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("nosniff" in t for t in titles)


async def test_security_headers_fully_hardened(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = SecurityHeadersModule(repo)

    hardened_resp = _make_response(
        "https://example.com",
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "same-origin",
        },
    )

    result = await module.run(scan, "https://example.com", hardened_resp, AsyncMock(), counts)
    assert result["status"] == "completed"
    assert len(result["headers_missing"]) == 0
    assert result["findings_count"] == 0


# ── 2. SSL/TLS Observations ──────────────────────────────────────────

async def test_ssl_tls_http_and_https_observations(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "http://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = SslTlsModule(repo)

    # 1. Plain HTTP target
    http_result = await module.run(scan, "http://example.com", None, AsyncMock(), counts)
    assert http_result["status"] == "completed"
    assert http_result["is_https"] is False
    assert "no SSL/TLS layer present" in http_result["note"]

    # 2. HTTPS target with mock TLS inspection
    mock_tls_info = {
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "cert_subject": "CN=example.com",
        "cert_issuer": "CN=Let's Encrypt Authority",
        "cert_expires": "Dec 31 23:59:59 2026 GMT",
        "days_until_expiry": 120,
        "sans": ["example.com", "www.example.com"],
    }
    with patch.object(module, "_inspect_ssl", return_value=mock_tls_info):
        https_result = await module.run(scan, "https://example.com", None, AsyncMock(), counts)
        assert https_result["status"] == "completed"
        assert https_result["tls_version"] == "TLSv1.3"
        assert https_result["days_until_expiry"] == 120
        assert https_result["findings_count"] == 0


async def test_ssl_tls_expired_and_deprecated_protocol(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://expired.badssl.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = SslTlsModule(repo)

    mock_expired_tls = {
        "tls_version": "TLSv1.0",
        "cipher": "DES-CBC3-SHA",
        "cipher_bits": 112,
        "cert_subject": "CN=expired.badssl.com",
        "cert_issuer": "CN=BadSSL Untrusted CA",
        "cert_expires": "Jan 01 00:00:00 2020 GMT",
        "days_until_expiry": -500,
        "sans": [],
    }
    with patch.object(module, "_inspect_ssl", return_value=mock_expired_tls):
        res = await module.run(scan, "https://expired.badssl.com", None, AsyncMock(), counts)
        assert res["status"] == "completed"
        assert res["findings_count"] >= 3  # Deprecated TLS, Expired cert, Weak cipher

    findings = await repo.list_for_scan(scan.id)
    titles = [f.title for f in findings]
    assert any("Deprecated TLS" in t for t in titles)
    assert any("Expired" in t for t in titles)
    assert any("Weak SSL/TLS Cipher" in t for t in titles)


# ── 3. Cookie Security Attributes ────────────────────────────────────

async def test_cookie_security_missing_flags_and_redaction(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = CookieSecurityModule(repo)

    resp = _make_response(
        "https://example.com",
        headers={
            # Insecure cookie: no Secure, no HttpOnly, no SameSite
            "set-cookie": "session_id=SUPER_SECRET_SESSION_TOKEN_XYZ; Path=/",
        },
    )

    result = await module.run(scan, "https://example.com", resp, AsyncMock(), counts)
    assert result["status"] == "completed"
    assert result["cookies_analyzed"] == 1
    assert result["cookies_with_issues"] == 1

    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 1
    poc = findings[0].proof_of_concept
    # Verify cookie value is redacted in proof of concept
    assert "SUPER_SECRET_SESSION_TOKEN_XYZ" not in poc
    assert "<redacted>" in poc


# ── 4. HTTP/HTTPS Configuration ──────────────────────────────────────

async def test_http_config_cleartext_and_mixed_content(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "http://plain.example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = HttpConfigModule(repo)

    # 1. Plain HTTP target without HTTPS redirect
    resp = _make_response("http://plain.example.com", text="<html><body>Welcome</body></html>")
    res = await module.run(scan, "http://plain.example.com", resp, AsyncMock(), counts)
    assert res["status"] == "completed"
    assert res["enforces_https"] is False
    assert res["findings_count"] == 1

    # 2. HTTPS page with mixed content
    scan_https, repo_https = await _create_test_scan(db, setup_project_and_target, "https://secure.example.com")
    https_resp = _make_response(
        "https://secure.example.com",
        text='<html><body><img src="http://cdn.example.com/logo.png"><script src="http://api.example.com/app.js"></script></body></html>',
    )
    res_https = await module.run(scan_https, "https://secure.example.com", https_resp, AsyncMock(), counts)
    assert res_https["status"] == "completed"
    assert res_https["mixed_content_count"] == 2
    assert res_https["findings_count"] == 1


# ── 5. Redirect Analysis ─────────────────────────────────────────────

async def test_redirect_analysis_downgrade_and_excessive_hops(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com/start")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = RedirectAnalysisModule(repo)

    # Downgrade chain: https -> http with 4 hops (excessive)
    chain = [
        "https://example.com/start",
        "https://example.com/redirect1",
        "http://example.com/redirect2",
        "http://example.com/redirect3",
        "http://example.com/final",
    ]
    resp = _make_response("http://example.com/final", redirect_chain=chain)

    result = await module.run(scan, "https://example.com/start", resp, AsyncMock(), counts)
    assert result["status"] == "completed"
    assert result["has_downgrade"] is True
    assert result["hops_count"] == 4

    findings = await repo.list_for_scan(scan.id)
    titles = [f.title for f in findings]
    assert any("Downgrade" in t for t in titles)
    assert any("Excessive" in t for t in titles)


# ── 6. Technology Fingerprinting ─────────────────────────────────────

async def test_tech_detection_headers_and_outdated_jquery(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = TechDetectionModule(repo)

    resp = _make_response(
        "https://example.com",
        headers={
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/7.4.3",
        },
        text='<html><head><script src="/js/jquery-1.12.4.min.js"></script></head><body></body></html>',
    )

    result = await module.run(scan, "https://example.com", resp, AsyncMock(), counts)
    assert result["count"] >= 3
    tech_names = [t["name"] for t in result["technologies"]]
    assert "PHP" in tech_names
    assert "Apache" in tech_names
    assert "jQuery" in tech_names

    findings = await repo.list_for_scan(scan.id)
    assert any("Outdated jQuery" in f.title for f in findings)


# ── 7. robots.txt and sitemap.xml Analysis ───────────────────────────

async def test_robots_sitemap_disclosed_admin_paths(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = RobotsSitemapModule(repo)

    mock_client = AsyncMock(spec=SafeHTTPClient)

    def _client_get(url, *args, **kwargs):
        if url.endswith("/robots.txt"):
            return _make_response(
                url,
                text="User-agent: *\nDisallow: /admin/\nDisallow: /backups/db.sql\nSitemap: https://example.com/sitemap.xml\n",
            )
        elif url.endswith("/sitemap.xml"):
            return _make_response(
                url,
                text='<?xml version="1.0"?><urlset><loc>https://example.com/home</loc><loc>https://example.com/admin/login</loc></urlset>',
            )
        return _make_response(url, status_code=404)

    mock_client.get.side_effect = _client_get

    result = await module.run(scan, "https://example.com", None, mock_client, counts)
    assert result["status"] == "completed"
    assert result["robots_found"] is True
    assert result["sitemap_found"] is True
    assert len(result["sensitive_disallowed_paths"]) >= 2
    assert result["sitemap_url_count"] == 2

    findings = await repo.list_for_scan(scan.id)
    titles = [f.title for f in findings]
    assert any("Sensitive Administrative Paths" in t for t in titles)
    assert any("Sensitive URLs Advertised" in t for t in titles)


# ── 8. Bounded Same-Origin Crawling ──────────────────────────────────

async def test_bounded_crawler_enforces_depth_and_origin(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = SameOriginCrawlerModule(repo)

    mock_client = AsyncMock(spec=SafeHTTPClient)

    root_html = """
    <html>
      <body>
        <a href="/about">About</a>
        <a href="/contact">Contact</a>
        <a href="https://evil.com/phish">External Link</a>
        <a href="/logout">Logout Action</a>
        <a href="/image.png">Logo Image</a>
      </body>
    </html>
    """

    def _get_page(url, *args, **kwargs):
        if url == "https://example.com" or url == "https://example.com/":
            return _make_response(url, text=root_html)
        elif url == "https://example.com/about":
            return _make_response(url, text='<a href="/team">Team</a>')
        elif url == "https://example.com/contact":
            return _make_response(url, text='<p>Contact Us</p>')
        elif url == "https://example.com/team":
            return _make_response(url, text='<p>Our Team</p>')
        return _make_response(url, status_code=404)

    mock_client.get.side_effect = _get_page

    result = await module.run(scan, "https://example.com", None, mock_client, counts)
    assert result["total_discovered"] >= 2
    discovered = result["discovered_urls"]

    # Verify origin boundary: evil.com must never be crawled
    assert not any("evil.com" in u for u in discovered)
    # Verify sensitive token exclusion: /logout must be skipped
    assert not any("logout" in u for u in discovered)
    # Verify static image exclusion: /image.png must be skipped
    assert not any("image.png" in u for u in discovered)


# ── 9. Endpoint and Parameter Discovery ──────────────────────────────

async def test_endpoint_and_param_discovery_redacts_values(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Simulate crawler having populated modules_json with discovered URLs
    crawler_output = {
        "url_discovery": {
            "discovered_urls": [
                "https://example.com/items/12345",
                "https://example.com/search?token=SECRET_VALUE_DO_NOT_LEAK&admin=true",
                "https://example.com/legacy/script.php",
            ]
        }
    }
    scan.modules_json = json.dumps(crawler_output)
    await db.commit()

    module = EndpointParamDiscoveryModule(repo)
    result = await module.run(scan, "https://example.com", None, AsyncMock(), counts)

    assert result["status"] == "completed"
    assert "token" in result["sensitive_params"]
    assert result["numeric_id_url_count"] >= 1
    assert result["legacy_extension_count"] >= 1

    findings = await repo.list_for_scan(scan.id)
    poc_text = "\n".join(f.proof_of_concept or "" for f in findings)

    # Ensure secret parameter value is completely redacted in proof of concept
    assert "SECRET_VALUE_DO_NOT_LEAK" not in poc_text
    assert "<redacted>" in poc_text


# ── 10. Publicly Exposed Configuration Checks ────────────────────────

async def test_exposed_config_checker_identifies_env_and_git(db, setup_project_and_target):
    scan, repo = await _create_test_scan(db, setup_project_and_target, "https://example.com")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module = ExposedConfigCheckerModule(repo)

    mock_client = AsyncMock(spec=SafeHTTPClient)

    def _probe_files(url, *args, **kwargs):
        if url.endswith("/.env"):
            return _make_response(url, text="DB_PASSWORD=SuperSecretPass123\nAPP_KEY=base64:xyz")
        elif url.endswith("/.git/HEAD"):
            return _make_response(url, text="ref: refs/heads/main\n")
        return _make_response(url, status_code=404, text="Not Found")

    mock_client.get.side_effect = _probe_files

    result = await module.run(scan, "https://example.com", None, mock_client, counts)
    assert result["status"] == "completed"
    assert result["exposed_count"] == 2
    assert result["findings_count"] == 2

    findings = await repo.list_for_scan(scan.id)
    poc_text = "\n".join(f.proof_of_concept or "" for f in findings)
    # Ensure sensitive database password in .env is NOT leaked in PoC
    assert "SuperSecretPass123" not in poc_text
    assert any(".env" in f.title for f in findings)
    assert any(".git/HEAD" in f.title for f in findings)


# ── 11. Full End-to-End Scanner Engine Integration ───────────────────

async def test_full_passive_scanner_engine_integration(db, setup_project_and_target):
    """Verify ScannerEngine executes all 10 passive modules and saves comprehensive modules_json."""
    env = setup_project_and_target
    target_url = "https://example.com/test-lab"

    target = Target(
        project_id=env["project"]["id"],
        url=target_url,
        type="web",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    # Configure scan with 'passive' preset
    scan = Scan(
        project_id=env["project"]["id"],
        target_id=target.id,
        user_id=env["user"]["user"]["id"],
        scan_type="passive",
        status="QUEUED",
        progress=0,
        config_json=json.dumps({"modules": ["passive"]}),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = _make_response(
        target_url,
        headers={
            "content-type": "text/html",
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
            "set-cookie": "session_id=abc; Path=/",
        },
        text='<html><body><h1>Lab</h1><a href="/contact">Contact</a></body></html>',
    )

    engine = ScannerEngine(db, http_client=mock_client)

    with patch("app.services.scanner_engine.validate_target_url", return_value=target_url):
        finished_scan = await engine.run_scan(scan.id)

    assert finished_scan.status == "COMPLETED"
    assert finished_scan.progress == 100
    assert finished_scan.modules_json is not None

    modules = json.loads(finished_scan.modules_json)

    # Verify all 10 passive module keys are tracked with truthful statuses
    expected_passive_keys = [
        "security_headers",
        "ssl_tls",
        "cookie_security",
        "http_config",
        "redirect_analysis",
        "tech_detection",
        "robots_sitemap",
        "url_discovery",
        "endpoint_discovery",
        "exposed_config",
    ]

    for key in expected_passive_keys:
        assert key in modules, f"Expected module '{key}' missing from scan.modules_json"
        assert modules[key]["status"] in ("completed", "skipped", "error")
        assert modules[key]["status"] != "running"
        assert modules[key]["status"] != "pending"

    # Verify findings count matches sum of severities
    total_severities = (
        finished_scan.critical_count
        + finished_scan.high_count
        + finished_scan.medium_count
        + finished_scan.low_count
        + finished_scan.info_count
    )
    assert finished_scan.findings_count == total_severities
