"""
Phase 7 OWASP Engine & Findings Test Suite.

Verifies:
  1. All 10 OWASP Top 10 categories (A01 - A10) execute real inspection logic with canonical 2021 mappings.
  2. Accurate CWE IDs, CVSS v3.1 scores, severities, and confidence classifications.
  3. Evidence preservation, affected URLs, and sensitive secret redaction.
  4. Finding deduplication preserving distinct endpoint vulnerabilities on different URLs.
  5. Full findings lifecycle: open -> confirmed -> in_progress -> resolved -> reopened -> false_positive -> accepted_risk.
  6. User ownership, authorization, and IDOR protection on GET, PATCH, and DELETE endpoints.
  7. OWASP dashboard summary aggregation, category counts, and dynamic active risk score calculation.
"""

from typing import Any
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.http_client import SafeHTTPResponse
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.repositories.finding import FindingRepository
from app.services.owasp.owasp_engine import OWASPEngine
from app.services.owasp.checkers.a01_access_control import A01AccessControlChecker
from app.services.owasp.checkers.a02_crypto_failures import A02CryptoFailuresChecker
from app.services.owasp.checkers.a03_injection import A03InjectionChecker
from app.services.owasp.checkers.a04_insecure_design import A04InsecureDesignChecker
from app.services.owasp.checkers.a05_misconfiguration import A05MisconfigurationChecker
from app.services.owasp.checkers.a06_vulnerable_components import A06VulnerableComponentsChecker
from app.services.owasp.checkers.a07_auth_failures import A07AuthFailuresChecker
from app.services.owasp.checkers.a08_software_integrity import A08SoftwareIntegrityChecker
from app.services.owasp.checkers.a09_logging_failures import A09LoggingFailuresChecker
from app.services.owasp.checkers.a10_ssrf import A10SSRFChecker


def make_safe_response(
    url: str,
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> SafeHTTPResponse:
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    content_type = norm_headers.get("content-type", "text/html")
    return SafeHTTPResponse(
        url=url,
        status_code=status_code,
        headers=norm_headers,
        text=text,
        elapsed_seconds=0.04,
        redirect_chain=[url],
        content_type=content_type,
    )


@pytest.fixture
async def setup_owasp_env(db: AsyncSession):
    uid = uuid.uuid4().hex[:6]
    user = User(
        email=f"owasp_tester_{uid}@example.com",
        name=f"OWASP Tester {uid}",
        hashed_password="hashed_pw_secret_123",
        role="analyst",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    project = Project(
        name=f"OWASP Test Project {uid}",
        description="PBL Project for OWASP Testing",
        user_id=user.id,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    target = Target(
        project_id=project.id,
        url="https://owasp-lab.test",
        type="web",
        validation_status="authorized",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    scan = Scan(
        project_id=project.id,
        target_id=target.id,
        user_id=user.id,
        scan_type="active",
        status="QUEUED",
        progress=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    return {
        "user": user,
        "project": project,
        "target": target,
        "scan": scan,
    }


# ── Test 1: A01 Broken Access Control ──────────────────────────────

async def test_owasp_a01_broken_access_control(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A01AccessControlChecker(repo)

    resp = make_safe_response(
        url="https://owasp-lab.test/.env",
        status_code=200,
        text="DB_PASSWORD=supersecret_pass\nSECRET_KEY=secret_key_12345",
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A01:2021-Broken Access Control"
    assert f.cwe_id == "CWE-538"
    assert f.severity == "critical"
    assert f.cvss_score == 9.1
    assert counts["critical"] == 1


# ── Test 2: A02 Cryptographic Failures ─────────────────────────────

async def test_owasp_a02_cryptographic_failures(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A02CryptoFailuresChecker(repo)

    # 1. Plain HTTP target
    http_resp = make_safe_response(url="http://owasp-lab.test/login", status_code=200, text="Login page")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], http_resp, counts)

    # 2. HTTPS missing HSTS
    https_resp = make_safe_response(url="https://owasp-lab.test/app", status_code=200, headers={"server": "nginx"})
    await checker.run_check(env["scan"], https_resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 2
    cats = [f.owasp_category for f in findings]
    assert all(c == "A02:2021-Cryptographic Failures" for c in cats)
    cwes = {f.cwe_id for f in findings}
    assert "CWE-319" in cwes  # Cleartext HTTP
    assert "CWE-523" in cwes  # Missing HSTS


# ── Test 3: A03 Injection ──────────────────────────────────────────

async def test_owasp_a03_injection(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A03InjectionChecker(repo)

    resp = make_safe_response(
        url="https://owasp-lab.test/items?id=1",
        status_code=500,
        text="<html><body>Error: You have an error in your SQL syntax near '1'</body></html>",
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A03:2021-Injection"
    assert f.cwe_id == "CWE-89"
    assert f.severity == "high"
    assert f.cvss_score == 7.5


# ── Test 4: A04 Insecure Design ────────────────────────────────────

async def test_owasp_a04_insecure_design(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A04InsecureDesignChecker(repo)

    resp = make_safe_response(
        url="https://owasp-lab.test/api/v1/authenticate",
        status_code=200,
        headers={"content-type": "application/json"},
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A04:2021-Insecure Design"
    assert f.cwe_id == "CWE-799"
    assert f.severity == "low"
    assert f.cvss_score == 3.1


# ── Test 5: A05 Security Misconfiguration ──────────────────────────

async def test_owasp_a05_misconfiguration(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A05MisconfigurationChecker(repo)

    # Missing CSP, X-Frame-Options, X-Content-Type-Options
    resp = make_safe_response(
        url="https://owasp-lab.test/dashboard",
        status_code=200,
        headers={"access-control-allow-origin": "*"},
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) >= 3
    for f in findings:
        assert f.owasp_category == "A05:2021-Security Misconfiguration"
    cwes = {f.cwe_id for f in findings}
    assert "CWE-693" in cwes   # CSP or X-Content-Type-Options
    assert "CWE-1021" in cwes  # X-Frame-Options
    assert "CWE-942" in cwes   # Wildcard CORS


# ── Test 6: A06 Vulnerable and Outdated Components ─────────────────

async def test_owasp_a06_vulnerable_components(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A06VulnerableComponentsChecker(repo)

    resp = make_safe_response(
        url="https://owasp-lab.test/app",
        status_code=200,
        text='<html><head><script src="/static/js/jquery-1.11.2.min.js"></script></head></html>',
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A06:2021-Vulnerable and Outdated Components"
    assert f.cwe_id == "CWE-937"
    assert f.severity == "medium"
    assert f.cvss_score == 6.1


# ── Test 7: A07 Identification and Authentication Failures ─────────

async def test_owasp_a07_auth_failures(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A07AuthFailuresChecker(repo)

    # Insecure cookie without Secure, HttpOnly, SameSite
    resp = make_safe_response(
        url="https://owasp-lab.test/login",
        status_code=200,
        headers={"set-cookie": "session_id=12345678; Path=/"},
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A07:2021-Identification and Authentication Failures"
    assert f.cwe_id == "CWE-614"
    assert f.severity == "medium"


# ── Test 8: A08 Software and Data Integrity Failures ───────────────

async def test_owasp_a08_software_integrity(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A08SoftwareIntegrityChecker(repo)

    # CDN script missing integrity attribute
    resp = make_safe_response(
        url="https://owasp-lab.test/page",
        status_code=200,
        text='<html><body><script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.production.min.js"></script></body></html>',
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A08:2021-Software and Data Integrity Failures"
    assert f.cwe_id == "CWE-353"
    assert f.severity == "low"
    assert f.cvss_score == 3.7


# ── Test 9: A09 Security Logging and Monitoring Failures ───────────

async def test_owasp_a09_logging_failures(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A09LoggingFailuresChecker(repo)

    # 1. API endpoint missing request tracking header
    api_resp = make_safe_response(
        url="https://owasp-lab.test/api/v1/orders",
        status_code=200,
        headers={"content-type": "application/json"},
        text='{"orders": []}',
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], api_resp, counts)

    # 2. Server response leaking internal traceback
    err_resp = make_safe_response(
        url="https://owasp-lab.test/error",
        status_code=500,
        text="<html><body>Traceback (most recent call last):\n  File 'app.py', line 42 in get_user</body></html>",
    )
    await checker.run_check(env["scan"], err_resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 2
    for f in findings:
        assert f.owasp_category == "A09:2021-Security Logging and Monitoring Failures"
    cwes = {f.cwe_id for f in findings}
    assert "CWE-778" in cwes  # Missing tracking
    assert "CWE-209" in cwes  # Diagnostic traceback leak


# ── Test 10: A10 Server-Side Request Forgery (SSRF) ────────────────

async def test_owasp_a10_ssrf(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A10SSRFChecker(repo)

    resp = make_safe_response(
        url="https://owasp-lab.test/proxy?url=https://remote-service.internal/webhook",
        status_code=200,
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A10:2021-Server-Side Request Forgery (SSRF)"
    assert f.cwe_id == "CWE-918"
    assert f.severity == "low"
    assert f.cvss_score == 3.9


# ── Test 11: OWASP Engine Orchestration & Fault Isolation ──────────

async def test_owasp_engine_orchestration_and_fault_isolation(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    engine = OWASPEngine(repo)

    assert len(engine.checkers) == 10

    resp = make_safe_response(
        url="https://owasp-lab.test/api/v1/profile",
        status_code=200,
        headers={"content-type": "application/json"},
        text="<html><script src='/jquery-1.11.2.js'></script></html>",
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    res = await engine.execute_owasp_checks(env["scan"], resp, counts)

    assert res["total_checkers"] == 10
    assert res["executed"] == 10
    assert res["errors"] == 0
    assert "A01:2021" in res["categories"]
    assert "A09:2021" in res["categories"]
    assert "A10:2021" in res["categories"]


# ── Test 12: Deduplication Preserves Distinct Endpoints ────────────

async def test_finding_deduplication_preserves_distinct_urls(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    scan = env["scan"]

    # Endpoint 1
    f1 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="SQL Injection Detected",
        description="SQL injection via quote probe",
        severity="high",
        confidence="CONFIRMED",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        affected_url="https://owasp-lab.test/api/users?id=1",
    )
    assert f1 is not None

    # Endpoint 2: same title and CWE, but DIFFERENT URL -> MUST be preserved
    f2 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="SQL Injection Detected",
        description="SQL injection via boolean probe",
        severity="high",
        confidence="CONFIRMED",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        affected_url="https://owasp-lab.test/api/products?cat=2",
    )
    assert f2 is not None
    assert f1.id != f2.id

    # Duplicate on same endpoint -> MUST be deduplicated (return None)
    f3 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="SQL Injection Detected",
        description="Duplicate probe",
        severity="high",
        confidence="CONFIRMED",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        affected_url="https://owasp-lab.test/api/users?id=1",
    )
    assert f3 is None

    # Site-wide header -> Deduplicated across scan
    f_csp1 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Missing Content-Security-Policy Header",
        description="Missing CSP",
        severity="low",
        cwe_id="CWE-693",
        affected_url="https://owasp-lab.test/page1",
    )
    assert f_csp1 is not None

    f_csp2 = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Missing Content-Security-Policy Header",
        description="Missing CSP again",
        severity="low",
        cwe_id="CWE-693",
        affected_url="https://owasp-lab.test/page2",
    )
    assert f_csp2 is None  # Scan-wide header deduplicated cleanly


# ── Test 13: Finding Lifecycle Transitions ─────────────────────────

async def test_finding_lifecycle_status_transitions(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    scan = env["scan"]

    finding = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Test Lifecycle Finding",
        description="Testing status state machine",
        severity="medium",
        confidence="CONFIRMED",
    )
    assert finding is not None
    assert finding.status == "open"

    # Transition 1: Confirmed
    f_conf = await repo.update_status(finding, "confirmed")
    assert f_conf.status == "confirmed"

    # Transition 2: In Progress
    f_prog = await repo.update_status(finding, "in_progress")
    assert f_prog.status == "in_progress"

    # Transition 3: Resolved
    f_res = await repo.update_status(finding, "resolved")
    assert f_res.status == "resolved"

    # Transition 4: Reopened
    f_reopen = await repo.update_status(finding, "reopened")
    assert f_reopen.status == "reopened"

    # Transition 5: False Positive
    f_fp = await repo.update_status(finding, "false_positive")
    assert f_fp.status == "false_positive"

    # Transition 6: Accepted Risk
    f_ar = await repo.update_status(finding, "accepted_risk")
    assert f_ar.status == "accepted_risk"


# ── Test 14: User Ownership & IDOR Protection on API Endpoints ─────

async def test_finding_api_idor_protection(client: AsyncClient, db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    user_a = env["user"]
    scan_a = env["scan"]

    # Create user B
    user_b = User(
        email=f"user_b_{uuid.uuid4().hex[:6]}@example.com",
        name="User B",
        hashed_password="hashed_pw_secret_456",
        role="analyst",
    )
    db.add(user_b)
    await db.commit()
    await db.refresh(user_b)

    # Finding owned by User A
    finding_a = await repo.create(
        scan_id=scan_a.id,
        target_id=scan_a.target_id,
        project_id=scan_a.project_id,
        user_id=user_a.id,
        title="User A Secret Finding",
        description="Private vulnerability finding",
        severity="high",
    )
    assert finding_a is not None

    # Authenticate as User B
    from app.core.security import create_access_token
    token_b = create_access_token(user_b.id)
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 1. User B attempts to GET User A's finding -> 404 (IDOR safe)
    get_res = await client.get(f"/api/v1/findings/{finding_a.id}", headers=headers_b)
    assert get_res.status_code == 404

    # 2. User B attempts to PATCH User A's finding status -> 404 (IDOR safe)
    patch_res = await client.patch(
        f"/api/v1/findings/{finding_a.id}",
        json={"status": "resolved"},
        headers=headers_b,
    )
    assert patch_res.status_code == 404

    # 3. User B attempts to DELETE User A's finding -> 404 (IDOR safe)
    del_res = await client.delete(f"/api/v1/findings/{finding_a.id}", headers=headers_b)
    assert del_res.status_code == 404


# ── Test 15: Invalid Status Update Rejected by API ─────────────────

async def test_finding_api_invalid_status_rejected(client: AsyncClient, db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    user_a = env["user"]
    scan_a = env["scan"]

    finding_a = await repo.create(
        scan_id=scan_a.id,
        target_id=scan_a.target_id,
        project_id=scan_a.project_id,
        user_id=user_a.id,
        title="Test Status Reject Finding",
        description="Invalid status testing",
        severity="low",
    )
    assert finding_a is not None

    from app.core.security import create_access_token
    token_a = create_access_token(user_a.id)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Valid status "reopened" succeeds
    valid_res = await client.patch(
        f"/api/v1/findings/{finding_a.id}",
        json={"status": "reopened"},
        headers=headers_a,
    )
    assert valid_res.status_code == 200
    assert valid_res.json()["status"] == "reopened"

    # Invalid status "completely_vanished" fails with 400 Bad Request
    invalid_res = await client.patch(
        f"/api/v1/findings/{finding_a.id}",
        json={"status": "completely_vanished"},
        headers=headers_a,
    )
    assert invalid_res.status_code == 400


# ── Test 16: OWASP Summary & Active Risk Score Calculation ─────────

async def test_owasp_summary_reflects_persisted_findings_and_lifecycle(
    client: AsyncClient, db: AsyncSession, setup_owasp_env: dict
):
    env = setup_owasp_env
    repo = FindingRepository(db)
    user = env["user"]
    scan = env["scan"]

    # Seed 1 Critical Injection finding (A03)
    f_crit = await repo.create(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=user.id,
        title="Critical SQL Injection",
        description="Active SQLi finding",
        severity="critical",
        confidence="CONFIRMED",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        cvss_score=8.5,
    )

    from app.core.security import create_access_token
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    # Check 1: Active critical finding reduces overall risk score and triggers FAIL
    res1 = await client.get("/api/v1/owasp/summary", headers=headers)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["critical_count"] == 1
    assert data1["total_vulnerabilities"] == 1
    assert data1["overall_risk_score"] == 75.0  # 100 - 25

    a03_cat = [c for c in data1["category_breakdown"] if c["category_id"] == "A03:2021"][0]
    assert a03_cat["compliance_status"] == "FAIL"
    assert a03_cat["critical_count"] == 1

    # Transition finding to "resolved"
    await repo.update_status(f_crit, "resolved")

    # Check 2: Resolved finding restores overall score and returns PASS
    res2 = await client.get("/api/v1/owasp/summary", headers=headers)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["total_vulnerabilities"] == 1  # Persisted history intact
    assert data2["overall_risk_score"] == 100.0  # No active risk penalty!

    a03_cat_updated = [c for c in data2["category_breakdown"] if c["category_id"] == "A03:2021"][0]
    assert a03_cat_updated["compliance_status"] == "PASS"  # Compliance restored!

    # Transition finding to "accepted_risk"
    await repo.update_status(f_crit, "accepted_risk")

    # Check 3: Accepted risk also does not penalize active risk score
    res3 = await client.get("/api/v1/owasp/summary", headers=headers)
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["overall_risk_score"] == 100.0
    a03_cat_ar = [c for c in data3["category_breakdown"] if c["category_id"] == "A03:2021"][0]
    assert a03_cat_ar["compliance_status"] == "PASS"


# ── Test 17: A09 Tracking Header Finding is NOT Confirmed ──────────

async def test_owasp_a09_missing_tracking_header_is_not_confirmed(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A09LoggingFailuresChecker(repo)

    api_resp = make_safe_response(
        url="https://owasp-lab.test/api/v2/items",
        status_code=200,
        headers={"content-type": "application/json"},
        text='{"items": []}',
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], api_resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Missing Request Correlation and Transaction Tracing Header"
    assert f.confidence != "CONFIRMED"
    assert f.confidence == "INFORMATIONAL"
    assert f.severity == "info"


# ── Test 18: Deduplication Never Merges Across Users or Targets ─────

async def test_deduplication_never_merges_across_different_users_or_targets(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    user_a = env["user"]
    scan_a = env["scan"]
    target_a = env["target"]
    project_a = env["project"]

    # Target B under same project
    target_b = Target(
        project_id=project_a.id,
        url="https://second-target.test",
        type="web",
        validation_status="authorized",
    )
    db.add(target_b)
    await db.commit()
    await db.refresh(target_b)

    scan_b = Scan(
        project_id=project_a.id,
        target_id=target_b.id,
        user_id=user_a.id,
        scan_type="active",
        status="QUEUED",
        progress=0,
    )
    db.add(scan_b)
    await db.commit()
    await db.refresh(scan_b)

    # 1. Finding on Target A
    f_t1 = await repo.create(
        scan_id=scan_a.id,
        target_id=target_a.id,
        project_id=project_a.id,
        user_id=user_a.id,
        title="Missing Content-Security-Policy Header",
        description="Missing CSP on Target A",
        severity="low",
        cwe_id="CWE-693",
    )
    assert f_t1 is not None

    # 2. Identical finding on Target B -> Must NOT be deduplicated / merged
    f_t2 = await repo.create(
        scan_id=scan_b.id,
        target_id=target_b.id,
        project_id=project_a.id,
        user_id=user_a.id,
        title="Missing Content-Security-Policy Header",
        description="Missing CSP on Target B",
        severity="low",
        cwe_id="CWE-693",
    )
    assert f_t2 is not None
    assert f_t1.id != f_t2.id


# ── Test 19: Session Cookie Redaction in Evidence ──────────────────

async def test_cookie_redaction_prevents_session_leakage(db: AsyncSession, setup_owasp_env: dict):
    env = setup_owasp_env
    repo = FindingRepository(db)
    checker = A07AuthFailuresChecker(repo)

    sensitive_cookie = "secret_session_token_xyz987654321"
    resp = make_safe_response(
        url="https://owasp-lab.test/login",
        status_code=200,
        headers={"set-cookie": f"auth_token={sensitive_cookie}; Path=/"},
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    await checker.run_check(env["scan"], resp, counts)

    findings = await repo.list_for_scan(env["scan"].id)
    assert len(findings) == 1
    f = findings[0]
    assert sensitive_cookie not in f.proof_of_concept
    assert "<redacted>" in f.proof_of_concept

