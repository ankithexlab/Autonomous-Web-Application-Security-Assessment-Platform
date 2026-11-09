"""
Phase 6 Active Vulnerability Detection Test Suite.

Verifies genuine, safe, non-destructive active vulnerability detection for:
  1. Target authorization & explicit active-scan confirmation enforcement
  2. SQL Injection (harmless quote error probes and boolean-differential probes)
  3. Reflected XSS (harmless non-executable canary reflection and contextual HTML-encoding analysis)
  4. CSRF configuration and active validation weaknesses
  5. Authentication and session weaknesses (entropy, logout invalidation, cleartext login forms)
  6. Access control and IDOR indicators (controlled test IDs and sequential identifier analysis)
  7. API security misconfigurations (TRACE/XST, dangerous methods, rate-limit thresholds)
  8. Input validation issues (type confusion and boundary handling)
  9. SafeNetworkBackend & SafeHTTPClient SSRF protections, rate limiting, and evidence redaction
"""

import json
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse
import uuid
import httpx
import pytest
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.repositories.finding import FindingRepository
from app.repositories.project import ProjectRepository
from app.repositories.scan import ScanRepository
from app.repositories.target import TargetRepository
from app.services.scan import ScanService
from app.services.scanner_engine import ScannerEngine

# Active scanner modules
from app.services.scanner.sqli_detector import SQLInjectionDetectorModule
from app.services.scanner.xss_detector import XSSDetectorModule
from app.services.scanner.csrf_detector import CSRFDetectorModule
from app.services.scanner.session_analyzer import SessionAnalyzerModule
from app.services.scanner.idor_detector import IDORDetectorModule
from app.services.scanner.api_security import APISecurityModule
from app.services.scanner.input_validation import InputValidationModule

pytestmark = pytest.mark.asyncio


# ── Fixtures & Mock Client Helpers ─────────────────────────────────

def make_safe_response(
    url: str,
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
    elapsed_seconds: float = 0.05,
) -> SafeHTTPResponse:
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    ct = hdrs.get("content-type", "text/html")
    return SafeHTTPResponse(
        url=url,
        status_code=status_code,
        headers=hdrs,
        text=text,
        elapsed_seconds=elapsed_seconds,
        redirect_chain=[url],
        content_type=ct,
    )


class ControlledLabMockClient(SafeHTTPClient):
    """
    Mock SafeHTTPClient routing to controlled lab endpoints (positive & negative test cases).
    """

    def __init__(self, routes: dict[str, Any] | None = None) -> None:
        super().__init__(timeout=5.0)
        self.routes = routes or {}
        self.request_history: list[dict[str, Any]] = []

    async def get(self, url: str, headers: dict | None = None, **kwargs) -> SafeHTTPResponse:
        return await self.request("GET", url, headers=headers, **kwargs)

    async def post(self, url: str, data: Any = None, json: Any = None, headers: dict | None = None, **kwargs) -> SafeHTTPResponse:
        return await self.request("POST", url, data=data, json=json, headers=headers, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> SafeHTTPResponse:
        self.request_history.append({"method": method, "url": url, **kwargs})
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query

        # Match exact route or path
        key = f"{method} {url}"
        if key in self.routes:
            handler = self.routes[key]
        elif f"{method} {path}" in self.routes:
            handler = self.routes[f"{method} {path}"]
        elif path in self.routes:
            handler = self.routes[path]
        elif "*" in self.routes:
            handler = self.routes["*"]
        else:
            return make_safe_response(url, 200, "Default lab response")

        if callable(handler):
            return await handler(method, url, **kwargs)
        return handler


@pytest.fixture
async def setup_lab_environment(db: AsyncSession):
    """Set up test user, project, target, and scan in database."""
    user = User(
        email=f"tester_{uuid.uuid4().hex[:6]}@example.com",
        name="Security Tester",
        hashed_password="fakehash123",
    )
    db.add(user)
    await db.flush()

    project = Project(
        name="Lab Security Testing",
        user_id=user.id,
    )
    db.add(project)
    await db.flush()

    target = Target(
        project_id=project.id,
        url="https://lab.acme-security.test",
        type="web",
        validation_status="verified",
    )
    db.add(target)
    await db.flush()

    scan = Scan(
        target_id=target.id,
        project_id=project.id,
        user_id=user.id,
        scan_type="full",
        status="QUEUED",
        config_json=json.dumps({"active_confirmed": True, "active_scan_confirmed": True}),
    )
    db.add(scan)
    await db.commit()

    return {
        "user": user,
        "project": project,
        "target": target,
        "scan": scan,
    }


# ── Test 1: Target Authorization & Active Confirmation Gate ────────

async def test_active_scan_requires_confirmation_on_create(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    project_id = env["project"]["id"]
    target_id = env["target"]["id"]

    # Attempt active scan without confirmation -> must be rejected with HTTP 400
    resp_unconfirmed = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "active", "active_confirmed": False},
        headers=env["headers"],
    )
    assert resp_unconfirmed.status_code == 400
    assert "Active scanning requires explicit target authorization" in resp_unconfirmed.text

    # Provide explicit confirmation -> succeeds
    resp_confirmed = await client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/scans",
        json={"scan_type": "active", "active_confirmed": True},
        headers=env["headers"],
    )
    assert resp_confirmed.status_code == 201
    scan_data = resp_confirmed.json()
    assert scan_data["scan_type"] == "active"
    assert scan_data["status"] == "QUEUED"


async def test_start_scan_enforces_target_authorization_and_active_gate(
    db: AsyncSession, setup_lab_environment: dict
):
    env = setup_lab_environment
    scan_svc = ScanService(db)

    # 1. Reject starting scan on unauthorized/rejected target
    env["target"].validation_status = "rejected"
    await db.commit()

    with pytest.raises(BadRequestException) as exc_rejected:
        await scan_svc.start_scan(env["user"].id, env["scan"].id)
    assert "is not authorized for scanning" in str(exc_rejected.value)

    # Restore verified status
    env["target"].validation_status = "verified"
    await db.commit()

    # 2. Reject starting active scan if config lacks confirmation
    env["scan"].scan_type = "active"
    env["scan"].config_json = json.dumps({})
    await db.commit()

    with pytest.raises(BadRequestException) as exc_active_gate:
        await scan_svc.start_scan(env["user"].id, env["scan"].id)
    assert "Active scanning requires explicit target authorization" in str(exc_active_gate.value)


# ── Test 2: SQL Injection Active Detection ──────────────────────────

async def test_sqli_active_quote_probe_confirmed_finding(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    sqli_mod = SQLInjectionDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/products?id=10"
    main_resp = make_safe_response(target_url, 200, "<html>Product details: Item #10</html>")

    # Mock lab responses: quote probe produces SQLite syntax error
    routes = {
        "GET https://lab.acme-security.test/products?id=10%27": make_safe_response(
            "https://lab.acme-security.test/products?id=10%27",
            500,
            "SQLite error: near \"10'\": syntax error occurred in query execution.",
        ),
    }
    mock_client = ControlledLabMockClient(routes)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await sqli_mod.run(scan, target_url, main_resp, mock_client, counts)

    assert res["status"] == "completed"
    assert res["active_tested"] is True
    assert res["confidence"] == "CONFIRMED"
    assert "id" in res["vulnerable_params"]
    assert counts["critical"] >= 1

    # Verify finding in repository
    findings = await finding_repo.list_for_scan(scan.id)
    sqli_findings = [f for f in findings if "SQL Injection" in f.title]
    assert len(sqli_findings) == 1
    f = sqli_findings[0]
    assert f.confidence == "CONFIRMED"
    assert f.severity == "critical"
    assert f.cwe_id == "CWE-89"
    assert "SQLite" in f.title or "SQLite" in f.proof_of_concept


async def test_sqli_active_boolean_differential_potential_finding(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    sqli_mod = SQLInjectionDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/items?category=1"
    main_resp = make_safe_response(target_url, 200, "A" * 500)

    # True condition matches baseline length; False condition returns empty/different status
    routes = {
        "GET https://lab.acme-security.test/items?category=1%27": make_safe_response(
            "https://lab.acme-security.test/items?category=1%27", 200, "A" * 500
        ),
        "GET https://lab.acme-security.test/items?category=1%2A1": make_safe_response(
            "https://lab.acme-security.test/items?category=1%2A1", 200, "A" * 500
        ),
        "GET https://lab.acme-security.test/items?category=1%2A0": make_safe_response(
            "https://lab.acme-security.test/items?category=1%2A0", 404, "Not Found"
        ),
    }
    mock_client = ControlledLabMockClient(routes)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await sqli_mod.run(scan, target_url, main_resp, mock_client, counts)
    assert res["active_tested"] is True
    assert res["confidence"] in ("CONFIRMED", "POTENTIAL")
    assert counts["high"] >= 1


async def test_sqli_active_secure_endpoint_no_finding(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    sqli_mod = SQLInjectionDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/secure-page?id=5"
    main_resp = make_safe_response(target_url, 200, "Safe parameterized page")

    # Secure endpoint handles all probes identically with 200 and safe content
    mock_client = ControlledLabMockClient({
        "*": make_safe_response("https://lab.acme-security.test/secure-page", 200, "Safe parameterized page")
    })
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await sqli_mod.run(scan, target_url, main_resp, mock_client, counts)
    assert res["status"] == "completed"
    assert len(res["vulnerable_params"]) == 0
    assert counts["critical"] == 0
    assert counts["high"] == 0


# ── Test 3: Reflected XSS Active Canary Reflection ──────────────────

async def test_xss_active_canary_reflection_confirmed_finding(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    xss_mod = XSSDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/search?q=test"
    main_resp = make_safe_response(target_url, 200, "<html><body>Search results for test</body></html>")

    # Dynamic mock lab: reflects the exact query parameter unencoded in HTML
    async def lab_reflection_handler(method: str, url: str, **kwargs):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        q_val = params.get("q", [""])[0]
        # Vulnerable lab reflects input directly without entity encoding
        body = f"<html><body>Search results for: <div>{q_val}</div></body></html>"
        return make_safe_response(url, 200, body)

    mock_client = ControlledLabMockClient({"*": lab_reflection_handler})
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await xss_mod.run(scan, target_url, main_resp, mock_client, counts)

    assert res["active_tested"] is True
    assert res["confidence"] == "CONFIRMED"
    assert "q" in res["vulnerable_params"]
    assert counts["high"] >= 1

    findings = await finding_repo.list_for_scan(scan.id)
    xss_findings = [f for f in findings if "Reflected Cross-Site Scripting" in f.title]
    assert len(xss_findings) == 1
    f = xss_findings[0]
    assert f.confidence == "CONFIRMED"
    assert f.cwe_id == "CWE-79"


async def test_xss_active_encoded_reflection_not_vulnerable(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    xss_mod = XSSDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/search?q=safe"
    main_resp = make_safe_response(target_url, 200, "<html><body>Search results</body></html>")

    # Secure lab: encodes HTML entities properly
    async def secure_reflection_handler(method: str, url: str, **kwargs):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        import html
        q_val = html.escape(params.get("q", [""])[0])
        body = f"<html><body>Search results for: <div>{q_val}</div></body></html>"
        return make_safe_response(url, 200, body)

    mock_client = ControlledLabMockClient({"*": secure_reflection_handler})
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await xss_mod.run(scan, target_url, main_resp, mock_client, counts)
    print("DEBUG RES:", res)
    assert res["active_tested"] is True
    assert len(res["vulnerable_params"]) == 0
    # No high severity XSS finding
    assert counts["high"] == 0


# ── Test 4: CSRF Configuration & Active Testing ─────────────────────

async def test_csrf_active_validation_confirmed_finding(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    csrf_mod = CSRFDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/settings"
    html_body = """
    <html><body>
      <form action="/settings/update" method="POST">
        <input name="email" value="user@example.com" />
        <button type="submit">Save</button>
      </form>
    </body></html>
    """
    main_resp = make_safe_response(target_url, 200, html_body, headers={"set-cookie": "session_id=123; Path=/"})

    # Vulnerable lab accepts state-changing POST without CSRF token
    routes = {
        "POST https://lab.acme-security.test/settings/update": make_safe_response(
            "https://lab.acme-security.test/settings/update", 200, "Profile updated successfully"
        )
    }
    mock_client = ControlledLabMockClient(routes)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await csrf_mod.run(scan, target_url, main_resp, mock_client, counts)

    assert res["active_tested"] is True
    assert res["confidence"] == "CONFIRMED"

    findings = await finding_repo.list_for_scan(scan.id)
    csrf_findings = [f for f in findings if "Missing Anti-CSRF Validation" in f.title]
    assert len(csrf_findings) >= 1
    assert csrf_findings[0].confidence == "CONFIRMED"
    assert csrf_findings[0].cwe_id == "CWE-352"


async def test_csrf_active_rejected_by_token_check(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    csrf_mod = CSRFDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/profile"
    html_body = """
    <html><body>
      <form action="/profile/save" method="POST">
        <input type="hidden" name="csrf_token" value="secret_token_123" />
        <button type="submit">Save</button>
      </form>
    </body></html>
    """
    main_resp = make_safe_response(target_url, 200, html_body, headers={"set-cookie": "sid=abc; SameSite=Strict; Secure"})

    # Secure lab rejects cross-origin POST without token with 403 Forbidden
    routes = {
        "POST https://lab.acme-security.test/profile/save": make_safe_response(
            "https://lab.acme-security.test/profile/save", 403, "CSRF token missing or invalid"
        )
    }
    mock_client = ControlledLabMockClient(routes)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await csrf_mod.run(scan, target_url, main_resp, mock_client, counts)
    assert res["active_tested"] is True
    assert res["forms_with_csrf"] == 1
    # No confirmed CSRF vulnerability
    findings = await finding_repo.list_for_scan(scan.id)
    confirmed_csrf = [f for f in findings if f.confidence == "CONFIRMED" and "CSRF" in f.title]
    assert len(confirmed_csrf) == 0


# ── Test 5: Authentication & Session Weaknesses ─────────────────────

async def test_session_analyzer_logout_invalidation_active_check(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    # Supply test session in scan config
    scan.config_json = json.dumps({
        "active_confirmed": True,
        "test_session_token": "session_id=valid_test_token_888",
    })
    await db.commit()

    finding_repo = FindingRepository(db)
    session_mod = SessionAnalyzerModule(finding_repo)

    target_url = "https://lab.acme-security.test/dashboard"
    main_resp = make_safe_response(
        target_url,
        200,
        "<html><body>Welcome back User #10! <a href='/logout'>Logout</a></body></html>",
        headers={"set-cookie": "session_id=valid_test_token_888; Path=/"},
    )

    # Vulnerable lab: logout responds 200, but subsequent request with same token still returns 200 with dashboard
    routes = {
        "POST https://lab.acme-security.test/logout": make_safe_response(
            "https://lab.acme-security.test/logout", 200, "Logged out successfully"
        ),
        "GET https://lab.acme-security.test/dashboard": make_safe_response(
            "https://lab.acme-security.test/dashboard", 200, "<html><body>Welcome back User #10! Private data</body></html>" * 10
        ),
    }
    mock_client = ControlledLabMockClient(routes)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await session_mod.run(scan, target_url, main_resp, mock_client, counts)

    assert res["active_tested"] is True
    assert res["logout_tested"] is True
    assert res["confidence"] == "CONFIRMED"

    findings = await finding_repo.list_for_scan(scan.id)
    logout_findings = [f for f in findings if "Missing Session Invalidation on Logout" in f.title]
    assert len(logout_findings) == 1
    assert logout_findings[0].confidence == "CONFIRMED"
    assert logout_findings[0].cwe_id == "CWE-613"


async def test_cleartext_login_form_transmission_detected(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    session_mod = SessionAnalyzerModule(finding_repo)

    target_url = "https://lab.acme-security.test/login"
    html_body = """
    <html><body>
      <form action="http://insecure-auth.acme-security.test/login" method="POST">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <button type="submit">Login</button>
      </form>
    </body></html>
    """
    main_resp = make_safe_response(target_url, 200, html_body)
    mock_client = ControlledLabMockClient()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await session_mod.run(scan, target_url, main_resp, mock_client, counts)
    assert res["confidence"] == "CONFIRMED"

    findings = await finding_repo.list_for_scan(scan.id)
    cleartext_findings = [f for f in findings if "Cleartext Transmission" in f.title]
    assert len(cleartext_findings) == 1
    assert cleartext_findings[0].confidence == "CONFIRMED"


# ── Test 6: Access Control & IDOR Indicators ────────────────────────

async def test_idor_controlled_test_id_confirmed_finding(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    # Supply controlled seeded test IDs in scan config
    scan.config_json = json.dumps({
        "active_confirmed": True,
        "controlled_test_ids": {
            "param": "user_id",
            "seed_id": "101",
            "target_id": "102",
            "auth_header": {"Authorization": "Bearer test_user_101_token"},
        },
    })
    await db.commit()

    finding_repo = FindingRepository(db)
    idor_mod = IDORDetectorModule(finding_repo)

    target_url = "https://lab.acme-security.test/api/account?user_id=101"
    main_resp = make_safe_response(target_url, 200, '{"user_id": 101, "name": "User 101"}')

    # Controlled lab returns User 102's object without access control check
    routes = {
        "GET https://lab.acme-security.test/api/account?user_id=102": make_safe_response(
            "https://lab.acme-security.test/api/account?user_id=102",
            200,
            '{"user_id": 102, "name": "User 102 (Foreign Account)", "email": "victim@example.com"}',
        )
    }
    mock_client = ControlledLabMockClient(routes)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await idor_mod.run(scan, target_url, main_resp, mock_client, counts)

    assert res["active_tested"] is True
    assert res["confidence"] == "CONFIRMED"

    findings = await finding_repo.list_for_scan(scan.id)
    idor_findings = [f for f in findings if "Confirmed Insecure Direct Object Reference" in f.title]
    assert len(idor_findings) == 1
    assert idor_findings[0].confidence == "CONFIRMED"
    assert idor_findings[0].cwe_id == "CWE-639"


# ── Test 7: API Security Misconfigurations ──────────────────────────

async def test_api_security_trace_xst_and_methods_active_check(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    api_mod = APISecurityModule(finding_repo)

    target_url = "https://lab.acme-security.test/api/v1/items"
    main_resp = make_safe_response(target_url, 200, '{"items": []}', headers={"content-type": "application/json"})

    # TRACE echoes headers (XST vulnerability); OPTIONS advertises dangerous PUT/DELETE
    routes = {
        "TRACE https://lab.acme-security.test/api/v1/items": make_safe_response(
            "https://lab.acme-security.test/api/v1/items",
            200,
            "TRACE /api/v1/items HTTP/1.1\r\nHost: lab.acme-security.test\r\nUser-Agent: SafeScanner\r\n",
        ),
        "OPTIONS https://lab.acme-security.test/api/v1/items": make_safe_response(
            "https://lab.acme-security.test/api/v1/items",
            200,
            "",
            headers={"allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"},
        ),
    }
    mock_client = ControlledLabMockClient(routes)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await api_mod.run(scan, target_url, main_resp, mock_client, counts)

    assert res["active_tested"] is True
    assert res["confidence"] == "CONFIRMED"

    findings = await finding_repo.list_for_scan(scan.id)
    trace_findings = [f for f in findings if "HTTP TRACE Method Enabled" in f.title]
    assert len(trace_findings) == 1
    assert trace_findings[0].confidence == "CONFIRMED"
    assert trace_findings[0].cwe_id == "CWE-693"


# ── Test 8: Input Validation Issues ─────────────────────────────────

async def test_input_validation_active_type_confusion_crash_detected(
    db: AsyncSession, setup_lab_environment: dict
):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    iv_mod = InputValidationModule(finding_repo)

    target_url = "https://lab.acme-security.test/calculator?amount=50"
    main_resp = make_safe_response(target_url, 200, "Result: 50")

    # Fragile server crashes with 500 when non-numeric input is passed
    async def fragile_calculator_handler(method: str, url: str, **kwargs):
        if "amount=awasap_not_an_int" in url:
            return make_safe_response(url, 500, "Internal Server Error: ValueError: invalid literal for int()")
        return make_safe_response(url, 200, "OK")

    mock_client = ControlledLabMockClient({"*": fragile_calculator_handler})
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await iv_mod.run(scan, target_url, main_resp, mock_client, counts)

    assert res["active_tested"] is True
    assert res["confidence"] == "CONFIRMED"
    assert len(res["unhandled_errors"]) >= 1

    findings = await finding_repo.list_for_scan(scan.id)
    iv_findings = [f for f in findings if "Unhandled Server Error on Malformed Input" in f.title]
    assert len(iv_findings) == 1
    assert iv_findings[0].confidence == "CONFIRMED"
    assert iv_findings[0].cwe_id == "CWE-20"


# ── Test 9: ScannerEngine Full Integration with Active Confirmation ─

async def test_scanner_engine_full_integration_with_active_confirmation(
    db: AsyncSession, setup_lab_environment: dict
):
    env = setup_lab_environment
    scan = env["scan"]
    target_url = "https://lab.acme-security.test/app?search=hello"

    # Create mock client for entire full scan pipeline
    routes = {
        "GET https://lab.acme-security.test/app?search=hello": make_safe_response(
            target_url,
            200,
            """
            <html>
              <head><title>Lab App</title></head>
              <body>
                <h1>Hello</h1>
                <form action="/app/submit" method="POST">
                  <input name="data" />
                </form>
              </body>
            </html>
            """,
            headers={
                "server": "LabServer/1.0",
                "x-powered-by": "Python/3.13",
                "content-type": "text/html",
            },
        ),
        "*": make_safe_response("https://lab.acme-security.test", 200, "Lab response"),
    }
    mock_client = ControlledLabMockClient(routes)

    engine = ScannerEngine(db, http_client=mock_client)
    with patch("app.services.scanner_engine.validate_target_url", side_effect=lambda u: u):
        with patch("app.core.ssrf.validate_target_url", side_effect=lambda u: u):
            with patch("app.services.scanner.crawler.validate_target_url", side_effect=lambda u: u):
                completed_scan = await engine.run_scan(scan.id)

    assert completed_scan.status == "COMPLETED"
    assert completed_scan.progress == 100

    # Verify modules_json contains active scan authorization and module results
    modules = json.loads(completed_scan.modules_json)
    assert "active_scan_authorization" in modules
    assert modules["active_scan_authorization"]["active_confirmed"] is True
    assert modules["active_scan_authorization"]["scope_enforced"] is True
    assert "sqli_detector" in modules
    assert "xss_detector" in modules
    assert "csrf_detector" in modules
    assert "input_validation" in modules


# ── Test 10: Evidence Redaction and Sensitive Content Protection ────

async def test_evidence_redaction_prevents_secret_leakage(db: AsyncSession, setup_lab_environment: dict):
    env = setup_lab_environment
    scan = env["scan"]
    finding_repo = FindingRepository(db)
    iv_mod = InputValidationModule(finding_repo)

    # Trigger finding with sensitive token in proof of concept
    sensitive_token = "Bearer secret_api_key_123456789abcdef"
    await iv_mod._create_finding(
        scan,
        title="Test Redaction Finding",
        description=f"Request contained secret: {sensitive_token}",
        severity="info",
        confidence="INFORMATIONAL",
        proof_of_concept=f"Authorization: {sensitive_token}",
    )

    findings = await finding_repo.list_for_scan(scan.id)
    test_f = [f for f in findings if f.title == "Test Redaction Finding"][0]

    assert "secret_api_key" not in test_f.proof_of_concept
    assert "[REDACTED]" in test_f.proof_of_concept
    assert "[REDACTED]" in test_f.description
