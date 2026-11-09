"""
Regression and verification tests for AWASAP Phase 4.2 Scanner Engine Bug Fixes.

Covered issues:
  1. SafeHTTPClient.get timeout argument support & payload runner execution
  2. Subresource Integrity (SRI) checker attribute parsing (vulnerable vs secure)
  3. Directory discovery soft-404 baseline & content-type/signature validation
  4. Finding deduplication (security headers, cookies, identical findings) & count integrity
  5. Offloaded async DNS, WHOIS, and reverse-DNS resolution with bounded timeouts
"""

import asyncio
import socket
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.repositories.finding import FindingRepository
from app.services.owasp.checkers.a08_software_integrity import A08SoftwareIntegrityChecker
from app.services.scanner.directory_discovery import DirectoryDiscoveryModule
from app.services.scanner.dns_lookup import DNSLookupModule
from app.services.scanner.ip_detection import IPDetectionModule
from app.services.scanner.whois_lookup import WHOISLookupModule

pytestmark = pytest.mark.asyncio


# ── Issue 1: SafeHTTPClient.get timeout argument ─────────────────────────────


async def test_safe_http_client_accepts_timeout_parameter():
    """Verify SafeHTTPClient.get accepts timeout kwarg without raising TypeError."""
    client = SafeHTTPClient(timeout=10.0, connect_timeout=3.0)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.content = b"OK"
    mock_resp.text = "OK"
    mock_resp.elapsed.total_seconds.return_value = 0.05
    mock_resp.is_redirect = False
    mock_resp.url = "http://example.com/api/test"

    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_resp
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client_instance) as mock_httpx_cls:
        with patch("app.core.http_client.validate_target_url", return_value="http://example.com/api/test"):
            resp = await client.get("http://example.com/api/test", timeout=4.5)
            assert resp.status_code == 200
            assert resp.text == "OK"
            assert mock_httpx_cls.called
            call_kwargs = mock_httpx_cls.call_args[1]
            assert "timeout" in call_kwargs
            assert call_kwargs["timeout"].read == 4.5


# ── Issue 2: SRI Checker Tag Attribute Parsing ───────────────────────────────


async def test_sri_checker_vulnerable_cdn_script_without_integrity(db, setup_project_and_target):
    """Vulnerable case: CDN script lacking integrity attribute triggers finding."""
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

    checker = A08SoftwareIntegrityChecker(FindingRepository(db))
    counts = {"low": 0}

    # CDN script without integrity attribute
    vulnerable_html = """
    <html>
      <head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
      </head>
      <body><h1>App</h1></body>
    </html>
    """
    resp = SafeHTTPResponse(
        url="https://app.example.com",
        status_code=200,
        headers={"content-type": "text/html"},
        text=vulnerable_html,
        elapsed_seconds=0.1,
        redirect_chain=["https://app.example.com"],
        content_type="text/html",
    )

    await checker.run_check(scan, resp, counts)
    assert counts["low"] == 1

    repo = FindingRepository(db)
    findings = await repo.list_for_scan(scan.id)
    assert any("Subresource Integrity" in f.title for f in findings)


async def test_sri_checker_secure_cdn_script_with_valid_integrity(db, setup_project_and_target):
    """Secure case: CDN script with valid integrity attribute does not trigger finding."""
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

    checker = A08SoftwareIntegrityChecker(FindingRepository(db))
    counts = {"low": 0}

    # CDN script with valid integrity attribute
    secure_html = """
    <html>
      <head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"
                integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4iflP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
                crossorigin="anonymous"></script>
      </head>
      <body><h1>App</h1></body>
    </html>
    """
    resp = SafeHTTPResponse(
        url="https://app.example.com",
        status_code=200,
        headers={"content-type": "text/html"},
        text=secure_html,
        elapsed_seconds=0.1,
        redirect_chain=["https://app.example.com"],
        content_type="text/html",
    )

    await checker.run_check(scan, resp, counts)
    assert counts["low"] == 0

    repo = FindingRepository(db)
    findings = await repo.list_for_scan(scan.id)
    assert not any("Subresource Integrity" in f.title for f in findings)


async def test_sri_checker_ignores_local_scripts(db, setup_project_and_target):
    """Local first-party script tags without CDN hosts do not trigger SRI finding."""
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

    checker = A08SoftwareIntegrityChecker(FindingRepository(db))
    counts = {"low": 0}

    local_html = """
    <html>
      <head>
        <script src="/static/js/bundle.js"></script>
        <script src="https://app.example.com/assets/main.js"></script>
      </head>
      <body><h1>App</h1></body>
    </html>
    """
    resp = SafeHTTPResponse(
        url="https://app.example.com",
        status_code=200,
        headers={"content-type": "text/html"},
        text=local_html,
        elapsed_seconds=0.1,
        redirect_chain=["https://app.example.com"],
        content_type="text/html",
    )

    await checker.run_check(scan, resp, counts)
    assert counts["low"] == 0


# ── Issue 3: Directory Discovery False-Positive Filtering ───────────────────


async def test_directory_discovery_suppresses_soft_404_spa_catch_all(db, setup_project_and_target):
    """Soft-404 SPA returning 200 for random probe must not trigger findings for /.env or /.git."""
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

    module = DirectoryDiscoveryModule(FindingRepository(db))
    counts = {"high": 0, "critical": 0, "medium": 0, "low": 0, "info": 0}

    spa_shell = "<!DOCTYPE html><html><head><title>SPA</title></head><body><div id='root'></div></body></html>"

    class SPAMockClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            return SafeHTTPResponse(
                url=target_url,
                status_code=200,
                headers={"content-type": "text/html; charset=utf-8"},
                text=spa_shell,
                elapsed_seconds=0.05,
                redirect_chain=[target_url],
                content_type="text/html",
            )

    client = SPAMockClient()
    main_resp = await client.get("https://spa.example.com")
    res = await module.run(scan, "https://spa.example.com", main_resp, client, counts)

    # Discovered paths should be empty due to soft-404 baseline detection
    assert res["discovered_count"] == 0
    assert counts["critical"] == 0
    assert counts["high"] == 0

    repo = FindingRepository(db)
    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 0


async def test_directory_discovery_real_env_file_exposure(db, setup_project_and_target):
    """Real exposed .env file containing credentials must be flagged."""
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

    module = DirectoryDiscoveryModule(FindingRepository(db))
    counts = {"high": 0, "critical": 0, "medium": 0, "low": 0, "info": 0}

    class RealEnvMockClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            if "awasap_404_probe" in target_url:
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=404,
                    headers={"content-type": "text/html"},
                    text="Not Found",
                    elapsed_seconds=0.05,
                    redirect_chain=[target_url],
                    content_type="text/html",
                )
            if target_url.endswith("/.env"):
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=200,
                    headers={"content-type": "text/plain"},
                    text="DB_HOST=localhost\nDB_PASSWORD=SuperSecretPass123!\nSECRET_KEY=abcdef123456",
                    elapsed_seconds=0.05,
                    redirect_chain=[target_url],
                    content_type="text/plain",
                )
            return SafeHTTPResponse(
                url=target_url,
                status_code=404,
                headers={"content-type": "text/html"},
                text="Not Found",
                elapsed_seconds=0.05,
                redirect_chain=[target_url],
                content_type="text/html",
            )

    client = RealEnvMockClient()
    main_resp = await client.get("https://app.example.com")
    res = await module.run(scan, "https://app.example.com", main_resp, client, counts)

    assert res["discovered_count"] >= 1
    assert any(p["path"] == "/.env" for p in res["discovered"])
    assert counts["critical"] >= 1

    repo = FindingRepository(db)
    findings = await repo.list_for_scan(scan.id)
    assert any("/.env" in f.title for f in findings)


async def test_directory_discovery_rejects_html_on_env_even_without_soft_404(db, setup_project_and_target):
    """Negative case: /.env returning HTML custom 404 page (no env key pattern) is rejected."""
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

    module = DirectoryDiscoveryModule(FindingRepository(db))
    counts = {"high": 0, "critical": 0, "medium": 0, "low": 0, "info": 0}

    class FakeEnvMockClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            if "awasap_404_probe" in target_url:
                # Baseline 404
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=404,
                    headers={"content-type": "text/plain"},
                    text="404",
                    elapsed_seconds=0.05,
                    redirect_chain=[target_url],
                    content_type="text/plain",
                )
            if target_url.endswith("/.env"):
                # Returns 200 but text is generic HTML without any KEY= patterns
                return SafeHTTPResponse(
                    url=target_url,
                    status_code=200,
                    headers={"content-type": "text/html"},
                    text="<html><body><h1>Sorry, could not find resource</h1></body></html>",
                    elapsed_seconds=0.05,
                    redirect_chain=[target_url],
                    content_type="text/html",
                )
            return SafeHTTPResponse(
                url=target_url,
                status_code=404,
                headers={"content-type": "text/plain"},
                text="404",
                elapsed_seconds=0.05,
                redirect_chain=[target_url],
                content_type="text/plain",
            )

    client = FakeEnvMockClient()
    main_resp = await client.get("https://app.example.com")
    res = await module.run(scan, "https://app.example.com", main_resp, client, counts)

    # Should NOT be counted as an exposed .env file
    assert not any(p["path"] == "/.env" for p in res["discovered"])
    assert counts["critical"] == 0


# ── Issue 4: Finding Deduplication & Count Integrity ─────────────────────────


async def test_finding_repository_deduplicates_identical_and_canonical_findings(db, setup_project_and_target):
    """Duplicate calls to create() for the same scan return None and avoid duplicate records."""
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

    # 1. Create initial CSP finding
    f1 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Missing Content-Security-Policy Header",
        description="CSP header is missing.",
        severity="low",
        cwe_id="CWE-693",
        affected_url="https://app.example.com",
    )
    assert f1 is not None

    # 2. Duplicate CSP finding for same scan
    f2 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Missing Content-Security-Policy (CSP) Header",
        description="CSP header is missing.",
        severity="low",
        cwe_id="CWE-693",
        affected_url="https://app.example.com",
    )
    assert f2 is None, "Duplicate CSP finding must return None"

    # 3. Duplicate cookie finding
    c1 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Insecure Cookie Attributes: session_id",
        description="Cookie missing secure flags.",
        severity="medium",
        cwe_id="CWE-614",
        affected_url="https://app.example.com",
    )
    assert c1 is not None

    c2 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Insecure Session Cookie Attributes",
        description="Cookie missing secure flags.",
        severity="medium",
        cwe_id="CWE-614",
        affected_url="https://app.example.com",
    )
    assert c2 is None, "Duplicate cookie finding must return None"

    # 4. Distinct finding (e.g. HSTS CWE-523) MUST be persisted
    h1 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Missing HTTP Strict-Transport-Security (HSTS)",
        description="HSTS header missing.",
        severity="medium",
        cwe_id="CWE-523",
        affected_url="https://app.example.com",
    )
    assert h1 is not None, "Distinct finding must be created"

    # Verify database contains exactly 3 findings (f1, c1, h1)
    all_findings = await repo.list_for_scan(scan.id)
    assert len(all_findings) == 3


# ── Issue 5: Non-Blocking DNS, WHOIS, and IP Detection ──────────────────────


async def test_dns_lookup_module_non_blocking_and_timeout_handling(db, setup_project_and_target):
    """DNS lookup runs asynchronously and handles resolver timeout gracefully."""
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

    module = DNSLookupModule(FindingRepository(db))
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}

    # Simulate slow/hanging DNS resolver that exceeds bounded timeout
    def slow_resolve(name, rtype):
        import time
        time.sleep(0.05)
        raise TimeoutError("DNS query timed out")

    with patch("dns.resolver.resolve", side_effect=slow_resolve):
        results = await module.run(
            scan=scan,
            target_url="https://test-timeout.example.com",
            main_resp=None,
            http_client=SafeHTTPClient(),
            counts=counts,
        )
        assert results["hostname"] == "test-timeout.example.com"
        assert "records" in results
        # Should complete gracefully without raising unhandled exception


async def test_whois_lookup_module_non_blocking_timeout_handling(db, setup_project_and_target):
    """WHOIS lookup offloads blocking query and handles errors/timeouts safely."""
    import sys
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

    module = WHOISLookupModule(FindingRepository(db))
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}

    mock_whois_mod = MagicMock()
    mock_whois_mod.whois.side_effect = TimeoutError("WHOIS query timed out")

    with patch.dict(sys.modules, {"whois": mock_whois_mod}):
        results = await module.run(
            scan=scan,
            target_url="https://test-whois.example.com",
            main_resp=None,
            http_client=SafeHTTPClient(),
            counts=counts,
        )
        assert results["hostname"] == "test-whois.example.com"
        assert "error" in results or "data" in results


async def test_ip_detection_module_non_blocking_execution(db, setup_project_and_target):
    """IP detection offloads getaddrinfo and reverse DNS lookups asynchronously."""
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

    module = IPDetectionModule(FindingRepository(db))
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}

    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 80)),
    ]

    with patch("socket.getaddrinfo", return_value=mock_addrinfo), \
         patch("socket.gethostbyaddr", return_value=("example.com", [], ["93.184.216.34"])):
        results = await module.run(
            scan=scan,
            target_url="https://example.com",
            main_resp=None,
            http_client=SafeHTTPClient(),
            counts=counts,
        )
        assert "93.184.216.34" in results["ipv4"]
        assert "2606:2800:220:1:248:1893:25c8:1946" in results["ipv6"]
        assert len(results["reverse_dns"]) == 1
        assert results["reverse_dns"][0]["hostname"] == "example.com"
