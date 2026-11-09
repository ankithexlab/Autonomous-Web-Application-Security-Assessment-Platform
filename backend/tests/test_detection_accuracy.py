"""
AWASAP Phase 4.3: Scanner Detection Accuracy Validation Test Suite.

Validates detection quality, false-positive suppression, confidence differentiation,
evidence collection, CWE mapping, and safety guardrails across all 8 required domains:
  1. SQL Injection: positive (passive error reflection, active probe) & negative (clean/sanitized).
  2. XSS: heuristic patterns (DOM sinks/sources) vs confirmed unescaped reflections.
  3. SSRF: URL/IP guardrails (RFC1918, loopback, cloud metadata, protocols) & passive vector detection.
  4. Directory Discovery: signature & content-type validation vs SPA/soft-404 catch-alls.
  5. SRI: external CDN scripts with valid integrity vs missing integrity vs local scripts.
  6. Headers, Cookies, and CORS: accurate findings and duplicate suppression.
  7. Finding Metadata: evidence, severity, CVSS, CWE mapping, and confidence levels.
  8. Active Payloads: rate limiting, non-destructive safety filter, timeout handling, INCONCLUSIVE states.
"""

import asyncio
import re
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.models.security_payload import SecurityPayload
from app.repositories.finding import FindingRepository
from app.services.owasp.checkers.a01_access_control import A01AccessControlChecker
from app.services.owasp.checkers.a02_crypto_failures import A02CryptoFailuresChecker
from app.services.owasp.checkers.a03_injection import A03InjectionChecker
from app.services.owasp.checkers.a05_misconfiguration import A05MisconfigurationChecker
from app.services.owasp.checkers.a07_auth_failures import A07AuthFailuresChecker
from app.services.owasp.checkers.a08_software_integrity import A08SoftwareIntegrityChecker
from app.services.owasp.checkers.a10_ssrf import A10SSRFChecker
from app.services.scanner.directory_discovery import DirectoryDiscoveryModule
from app.services.scanner.payload_test_runner import PayloadSecurityTestRunner
from app.services.scanner.sqli_detector import SQLInjectionDetectorModule
from app.services.scanner.xss_detector import XSSDetectorModule

pytestmark = pytest.mark.asyncio


# ── Area 1: SQL Injection Detection ──────────────────────────────────────────


async def test_sqli_detection_positive_passive_errors(db, setup_project_and_target):
    """Positive: Response body disclosing database error strings triggers CWE-89 finding."""
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
    module = SQLInjectionDetectorModule(repo)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Disclose PostgreSQL syntax error
    resp = SafeHTTPResponse(
        url="https://app.example.com/items?id=1",
        status_code=500,
        headers={"content-type": "text/html"},
        text="<html><body>ERROR: syntax error at or near 'SELECT' in query</body></html>",
        elapsed_seconds=0.1,
        redirect_chain=["https://app.example.com/items?id=1"],
        content_type="text/html",
    )

    results = await module.run(scan, "https://app.example.com/items?id=1", resp, SafeHTTPClient(), counts)
    assert len(results["error_messages_found"]) >= 1
    assert results["error_messages_found"][0]["database"] == "PostgreSQL"
    assert counts["critical"] == 1

    findings = await repo.list_for_scan(scan.id)
    sqli_findings = [f for f in findings if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 1
    assert "PostgreSQL" in sqli_findings[0].title
    assert sqli_findings[0].severity == "critical"
    assert sqli_findings[0].cvss_score == 9.8


async def test_sqli_detection_negative_clean_response(db, setup_project_and_target):
    """Negative: Clean response without SQL errors or injection parameters creates no findings."""
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
    module = SQLInjectionDetectorModule(repo)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    resp = SafeHTTPResponse(
        url="https://app.example.com/about",
        status_code=200,
        headers={"content-type": "text/html"},
        text="<html><body><h1>About Us</h1><p>Normal clean page</p></body></html>",
        elapsed_seconds=0.08,
        redirect_chain=["https://app.example.com/about"],
        content_type="text/html",
    )

    results = await module.run(scan, "https://app.example.com/about", resp, SafeHTTPClient(), counts)
    assert len(results["error_messages_found"]) == 0
    assert len(results["suspicious_params"]) == 0
    assert counts["critical"] == 0

    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 0


# ── Area 2: XSS Detection (Heuristics vs Confirmed Reflection) ────────────────


async def test_xss_detection_heuristic_dom_sinks_vs_confirmed_reflection(db, setup_project_and_target):
    """Heuristic: DOM sinks + sources flag potential DOM XSS (High)."""
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
    module = XSSDetectorModule(repo)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Page with DOM sink (innerHTML) and source (location.search)
    dom_xss_html = """
    <html>
      <body>
        <script>
          const query = location.search;
          document.getElementById('output').innerHTML = query;
        </script>
      </body>
    </html>
    """
    resp = SafeHTTPResponse(
        url="https://app.example.com/search",
        status_code=200,
        headers={"content-type": "text/html", "x-xss-protection": "1; mode=block"},
        text=dom_xss_html,
        elapsed_seconds=0.08,
        redirect_chain=["https://app.example.com/search"],
        content_type="text/html",
    )

    results = await module.run(scan, "https://app.example.com/search", resp, SafeHTTPClient(), counts)
    assert len(results["dom_sinks_found"]) >= 1
    assert len(results["dom_sources_found"]) >= 1
    assert counts["high"] == 1

    findings = await repo.list_for_scan(scan.id)
    assert any("Potential DOM-Based XSS" in f.title for f in findings)


async def test_xss_detection_active_confirmed_unescaped_reflection(db, setup_project_and_target):
    """Confirmed Evidence: Active probe reflected verbatim in response body produces CONFIRMED status."""
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

    payload = SecurityPayload(
        payload="<script>alert(1)</script>",
        description="Basic reflected XSS vector",
        type="reflected",
        severity="High",
        context="html_body",
    )

    class ReflectiveClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            # Target reflects input directly without HTML encoding
            return SafeHTTPResponse(
                url=target_url,
                status_code=200,
                headers={"content-type": "text/html"},
                text="<html><body>Search result for: <script>alert(1)</script></body></html>",
                elapsed_seconds=0.05,
                redirect_chain=[target_url],
                content_type="text/html",
            )

    probe_res = await runner._execute_safe_probe(
        scan=scan,
        base_url="https://app.example.com/search?q=test",
        payload_record=payload,
        http_client=ReflectiveClient(),
        counts=counts,
    )

    assert probe_res["confidence"] == "CONFIRMED"
    assert "reflected unescaped" in probe_res["evidence"]
    assert counts["high"] == 1

    findings = await repo.list_for_scan(scan.id)
    assert any("Reflected" in f.title and f.cwe_id == "CWE-79" for f in findings)


async def test_xss_detection_negative_html_escaped_reflection(db, setup_project_and_target):
    """Negative: HTML-escaped output (&lt;script&gt;) does not trigger CONFIRMED XSS finding."""
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

    payload = SecurityPayload(
        payload="<script>alert(1)</script>",
        description="Basic reflected XSS vector",
        type="reflected",
        severity="High",
        context="html_body",
    )

    class SanitizedClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            # Target properly HTML-encodes payload
            return SafeHTTPResponse(
                url=target_url,
                status_code=200,
                headers={"content-type": "text/html"},
                text="<html><body>Search result for: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
                elapsed_seconds=0.05,
                redirect_chain=[target_url],
                content_type="text/html",
            )

    probe_res = await runner._execute_safe_probe(
        scan=scan,
        base_url="https://app.example.com/search?q=test",
        payload_record=payload,
        http_client=SanitizedClient(),
        counts=counts,
    )

    assert probe_res["confidence"] == "INCONCLUSIVE"
    assert counts["high"] == 0

    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 0


# ── Area 3: SSRF Guardrails & Passive Vector Detection ───────────────────────


async def test_ssrf_guardrails_blocks_forbidden_destinations():
    """SSRF guardrail strictly blocks private IP ranges, localhost, and cloud metadata."""
    blocked_targets = [
        "http://127.0.0.1:8000/admin",
        "http://localhost:3000/internal",
        "http://10.0.0.5/confidential",
        "http://172.16.0.10/database",
        "http://192.168.1.1/router",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
        "ftp://internal.corp/data",
        "gopher://127.0.0.1:25",
    ]

    for target in blocked_targets:
        with pytest.raises(BadRequestException):
            validate_target_url(target)


async def test_ssrf_guardrails_allows_safe_external_urls():
    """SSRF guardrail allows valid HTTP/HTTPS targets with external hostnames."""
    safe_targets = [
        "https://example.com",
        "https://api.github.com/v1",
        "http://testapp.securehost.org:8080/portal",
    ]
    with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.215.14", 80))]):
        for target in safe_targets:
            validated = validate_target_url(target)
            assert validated.startswith("http")


async def test_ssrf_passive_vector_detection(db, setup_project_and_target):
    """Passive SSRF detector flags URL acceptor parameters (dest=, redirect_to=) as potential vectors."""
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
    checker = A10SSRFChecker(repo)
    counts = {"low": 0}

    resp = SafeHTTPResponse(
        url="https://app.example.com/proxy?dest=https://external.service.com/feed&url=http://api.remote.com",
        status_code=200,
        headers={"content-type": "application/json"},
        text="{}",
        elapsed_seconds=0.05,
        redirect_chain=["https://app.example.com/proxy?dest=https://external.service.com/feed&url=http://api.remote.com"],
        content_type="application/json",
    )

    await checker.run_check(scan, resp, counts)
    assert counts["low"] == 1

    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-918"
    assert "SSRF" in findings[0].title


# ── Area 4: Directory Discovery Accuracy ─────────────────────────────────────


async def test_directory_discovery_spa_catchall_suppression(db, setup_project_and_target):
    """SPA catch-all router returning 200 on all paths must be suppressed via soft-404 baseline."""
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
    module = DirectoryDiscoveryModule(repo)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    spa_index_html = "<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div><script src='/bundle.js'></script></body></html>"

    class CatchAllClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            return SafeHTTPResponse(
                url=target_url,
                status_code=200,
                headers={"content-type": "text/html; charset=utf-8"},
                text=spa_index_html,
                elapsed_seconds=0.04,
                redirect_chain=[target_url],
                content_type="text/html",
            )

    client = CatchAllClient()
    main_resp = await client.get("https://spa.example.com")
    res = await module.run(scan, "https://spa.example.com", main_resp, client, counts)

    # All paths suppressed; zero false positives
    assert res["discovered_count"] == 0
    assert counts["critical"] == 0
    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 0


async def test_directory_discovery_genuine_file_signatures(db, setup_project_and_target):
    """Genuine file exposure is verified against content signatures (.git/HEAD, database.sql, .env)."""
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
    module = DirectoryDiscoveryModule(repo)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    class MultiExposureClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            if "awasap_404_probe" in target_url:
                return SafeHTTPResponse(url=target_url, status_code=404, headers={}, text="404", elapsed_seconds=0.02, redirect_chain=[target_url], content_type="text/plain")
            if target_url.endswith("/.git/HEAD"):
                return SafeHTTPResponse(url=target_url, status_code=200, headers={"content-type": "text/plain"}, text="ref: refs/heads/main\n", elapsed_seconds=0.02, redirect_chain=[target_url], content_type="text/plain")
            if target_url.endswith("/database.sql"):
                return SafeHTTPResponse(url=target_url, status_code=200, headers={"content-type": "application/sql"}, text="CREATE TABLE users (id INT, password VARCHAR(255));\nINSERT INTO users VALUES (1, 'hash');", elapsed_seconds=0.02, redirect_chain=[target_url], content_type="application/sql")
            return SafeHTTPResponse(url=target_url, status_code=404, headers={}, text="404", elapsed_seconds=0.02, redirect_chain=[target_url], content_type="text/plain")

    client = MultiExposureClient()
    main_resp = await client.get("https://app.example.com")
    res = await module.run(scan, "https://app.example.com", main_resp, client, counts)

    assert res["discovered_count"] == 2
    paths = [d["path"] for d in res["discovered"]]
    assert "/.git/HEAD" in paths
    assert "/database.sql" in paths

    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 2


# ── Area 5: SRI Detection Accuracy ───────────────────────────────────────────


async def test_sri_accuracy_cdn_with_and_without_integrity(db, setup_project_and_target):
    """SRI Checker flags CDN script without integrity, but accepts valid SHA-384 integrity."""
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
    checker = A08SoftwareIntegrityChecker(repo)

    # 1. Negative test: Script has valid integrity
    secure_html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.min.js" integrity="sha384-abc123xyz==" crossorigin="anonymous"></script>'
    resp_secure = SafeHTTPResponse(
        url="https://app.example.com",
        status_code=200,
        headers={"content-type": "text/html"},
        text=secure_html,
        elapsed_seconds=0.04,
        redirect_chain=["https://app.example.com"],
        content_type="text/html",
    )
    counts_secure = {"low": 0}
    await checker.run_check(scan, resp_secure, counts_secure)
    assert counts_secure["low"] == 0

    # 2. Positive test: Script lacks integrity
    vulnerable_html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.min.js"></script>'
    resp_vulnerable = SafeHTTPResponse(
        url="https://app.example.com",
        status_code=200,
        headers={"content-type": "text/html"},
        text=vulnerable_html,
        elapsed_seconds=0.04,
        redirect_chain=["https://app.example.com"],
        content_type="text/html",
    )
    counts_vuln = {"low": 0}
    await checker.run_check(scan, resp_vulnerable, counts_vuln)
    assert counts_vuln["low"] == 1

    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-353"


# ── Area 6: Security Headers, Cookies, & CORS Deduplication ──────────────────


async def test_header_cookie_cors_detection_and_deduplication(db, setup_project_and_target):
    """Audit creates canonical findings for missing CSP, HSTS, insecure cookies, and CORS wildcard without duplicates."""
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
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Insecure headers: missing CSP, missing HSTS, missing X-Frame-Options, wildcard CORS, insecure cookies
    resp = SafeHTTPResponse(
        url="https://app.example.com/login",
        status_code=200,
        headers={
            "content-type": "text/html",
            "access-control-allow-origin": "*",
            "set-cookie": "session=xyz123; Path=/",
        },
        text="<html><body><form><input type='password' name='p'></form></body></html>",
        elapsed_seconds=0.05,
        redirect_chain=["https://app.example.com/login"],
        content_type="text/html",
    )

    # Run checkers
    a02 = A02CryptoFailuresChecker(repo)
    a05 = A05MisconfigurationChecker(repo)
    a07 = A07AuthFailuresChecker(repo)

    # First execution pass
    await a02.run_check(scan, resp, counts)
    await a05.run_check(scan, resp, counts)
    await a07.run_check(scan, resp, counts)

    initial_count = sum(counts.values())
    findings = await repo.list_for_scan(scan.id)
    cwe_set = {f.cwe_id for f in findings}

    assert "CWE-523" in cwe_set  # Missing HSTS
    assert "CWE-693" in cwe_set  # Missing CSP
    assert "CWE-942" in cwe_set  # Wildcard CORS
    assert "CWE-614" in cwe_set  # Insecure Cookie

    # Second execution pass (simulating duplicate scanner stage)
    await a02.run_check(scan, resp, counts)
    await a05.run_check(scan, resp, counts)
    await a07.run_check(scan, resp, counts)

    # Assert counts did NOT inflate and findings were not duplicated
    second_pass_count = sum(counts.values())
    assert second_pass_count == initial_count

    all_findings = await repo.list_for_scan(scan.id)
    assert len(all_findings) == len(findings)


# ── Area 7: Finding Metadata, Severity, CWE, and CVSS Mapping ────────────────


async def test_finding_metadata_cwe_cvss_consistency(db, setup_project_and_target):
    """Validate that created findings satisfy integrity constraints for evidence, CWE, and CVSS."""
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
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Trigger A01 secrets finding
    a01 = A01AccessControlChecker(repo)
    resp = SafeHTTPResponse(
        url="https://app.example.com/.env",
        status_code=200,
        headers={"content-type": "text/plain"},
        text="DB_PASSWORD=secret123\nSECRET_KEY=abcd",
        elapsed_seconds=0.03,
        redirect_chain=["https://app.example.com/.env"],
        content_type="text/plain",
    )
    await a01.run_check(scan, resp, counts)

    findings = await repo.list_for_scan(scan.id)
    assert len(findings) == 1
    f = findings[0]

    assert f.severity == "critical"
    assert f.cvss_score >= 9.0
    assert f.cwe_id == "CWE-538"
    assert f.proof_of_concept is not None and len(f.proof_of_concept) > 0
    assert f.remediation is not None and len(f.remediation) > 0
    assert f.affected_url == "https://app.example.com/.env"


# ── Area 8: Active Payload Runner Guardrails & Outcomes ──────────────────────


async def test_payload_runner_safety_and_timeout_guardrails(db, setup_project_and_target):
    """Payload runner blocks destructive payloads and handles probe timeouts as INCONCLUSIVE."""
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

    # 1. Potentially destructive payload blocked by policy
    destructive_payload = SecurityPayload(
        payload="; rm -rf / ;",
        description="Destructive command injection attempt",
        type="command_injection",
        severity="Critical",
        context="shell",
    )
    res_destr = await runner._execute_safe_probe(
        scan=scan,
        base_url="https://app.example.com/api?cmd=test",
        payload_record=destructive_payload,
        http_client=SafeHTTPClient(),
        counts=counts,
    )
    assert res_destr["confidence"] == "INCONCLUSIVE"
    assert "blocked by safety policy" in res_destr["reason"]

    # 2. Timeout handling without crashing
    class TimeoutClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            raise TimeoutError("Simulated probe read timeout")

    normal_payload = SecurityPayload(
        payload="' OR 1=1 --",
        description="SQL tautology test",
        type="tautology",
        severity="High",
        context="sql_query",
    )
    res_timeout = await runner._execute_safe_probe(
        scan=scan,
        base_url="https://app.example.com/items?id=1",
        payload_record=normal_payload,
        http_client=TimeoutClient(),
        counts=counts,
    )
    assert res_timeout["confidence"] == "INCONCLUSIVE"
    assert "timeout" in res_timeout["reason"].lower()

    # 3. Target without query parameters skips aggressive testing cleanly
    with patch("app.services.scanner.payload_test_runner.validate_target_url", return_value="https://app.example.com/about"):
        no_param_res = await runner.run(
            scan=scan,
            target_url="https://app.example.com/about",
            main_resp=None,
            http_client=SafeHTTPClient(),
            counts=counts,
        )
        assert no_param_res["total_probes"] == 0
        assert "Passive Assessment Only" in no_param_res["tested_categories"]
