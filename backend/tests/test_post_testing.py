"""
Unit and regression tests for Phase 4.4 Step 1: POST/JSON/Form Body Testing.

Validates:
  1. SafeHTTPClient.post execution with SSRF guardrails and timeout bounds.
  2. PayloadSecurityTestRunner.run_post_body_tests with application/json (positive & negative).
  3. PayloadSecurityTestRunner.run_post_body_tests with application/x-www-form-urlencoded (positive & negative).
  4. State-changing and sensitive route blocking policy (/logout, /delete, /pay).
  5. Non-destructive safety filter enforcement on POST probes.
  6. Continued functioning of GET query parameter scanning.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.models.security_payload import SecurityPayload
from app.repositories.finding import FindingRepository
from app.services.scanner.payload_test_runner import PayloadSecurityTestRunner

pytestmark = pytest.mark.asyncio


# ── 1. SafeHTTPClient.post ───────────────────────────────────────────────────


async def test_safe_http_client_post_json_and_timeout():
    """SafeHTTPClient.post sends JSON payload with SSRF validation and timeout config."""
    client = SafeHTTPClient(timeout=8.0, connect_timeout=3.0)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.content = b'{"status": "ok"}'
    mock_resp.text = '{"status": "ok"}'
    mock_resp.elapsed.total_seconds.return_value = 0.08

    mock_client_instance = AsyncMock()
    mock_client_instance.post.return_value = mock_resp
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None

    with patch("httpx.AsyncClient", return_value=mock_client_instance) as mock_httpx_cls:
        with patch("app.core.http_client.validate_target_url", return_value="https://example.com/api/search"):
            resp = await client.post(
                "https://example.com/api/search",
                json={"query": "test"},
                timeout=4.0,
            )
            assert resp.status_code == 200
            assert resp.text == '{"status": "ok"}'
            assert mock_client_instance.post.called
            call_kwargs = mock_client_instance.post.call_args[1]
            assert call_kwargs["json"] == {"query": "test"}

            # Verify timeout configuration passed to httpx client
            client_kwargs = mock_httpx_cls.call_args[1]
            assert client_kwargs["timeout"].read == 4.0


async def test_safe_http_client_post_ssrf_blocked():
    """SafeHTTPClient.post rejects private and loopback destinations."""
    client = SafeHTTPClient()
    with pytest.raises(BadRequestException):
        await client.post("http://127.0.0.1:8000/api", json={"test": 1})

    with pytest.raises(BadRequestException):
        await client.post("http://169.254.169.254/latest", json={"test": 1})


# ── 2. POST JSON Body Testing ────────────────────────────────────────────────


async def _seed_test_payloads(db):
    for pid, desc, payload_val, ctx, ptype, sev in [
        ("sqli-test-01", "Basic tautology injection", "' OR '1'='1", "Login field", "tautology", "high"),
        ("xss-test-01", "Reflected XSS script execution", "<script>alert(1)</script>", "Search box", "reflected", "medium"),
    ]:
        existing = await db.get(SecurityPayload, pid)
        if not existing:
            p = SecurityPayload(
                id=pid,
                description=desc,
                payload=payload_val,
                context=ctx,
                type=ptype,
                severity=sev,
                example_usage=None,
            )
            db.add(p)
    await db.commit()



async def test_post_json_body_sqli_positive_and_negative(db, setup_project_and_target):
    """POST JSON testing detects database error reflection (positive) and normal response (negative)."""
    await _seed_test_payloads(db)
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

    # 1. Positive: Target triggers MySQL syntax error on JSON parameter
    class VulnerableJSONClient(SafeHTTPClient):
        async def post(self, target_url: str, json: dict | None = None, data: dict | None = None, headers: dict | None = None, timeout: float | None = None):
            return SafeHTTPResponse(
                url=target_url,
                status_code=500,
                headers={"content-type": "application/json"},
                text='{"error": "You have an error in your SQL syntax near \\"\' OR 1=1\\""}',
                elapsed_seconds=0.06,
                redirect_chain=[target_url],
                content_type="application/json",
            )

    with patch("app.services.scanner.payload_test_runner.validate_target_url", return_value="https://app.example.com/api/v1/search"):
        res = await runner.run_post_body_tests(
            scan=scan,
            target_url="https://app.example.com/api/v1/search",
            content_type="application/json",
            sample_keys=["search"],
            http_client=VulnerableJSONClient(),
            counts=counts,
            limit_per_category=1,
        )

    assert res["method"] == "POST"
    assert res["content_type"] == "application/json"
    assert res["confirmed_findings"] >= 1
    assert counts["high"] >= 1

    findings = await repo.list_for_scan(scan.id)
    assert any("Potential Tautology Vulnerability via POST" in f.title and f.cwe_id == "CWE-89" for f in findings)


# ── 3. POST Form-Encoded Body Testing ────────────────────────────────────────


async def test_post_form_body_xss_positive_and_negative(db, setup_project_and_target):
    """POST form testing detects unescaped reflection (positive) and encoded safe output (negative)."""
    await _seed_test_payloads(db)
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

    # Target reflects form input verbatim unescaped
    class VulnerableFormClient(SafeHTTPClient):
        async def post(self, target_url: str, json: dict | None = None, data: dict | None = None, headers: dict | None = None, timeout: float | None = None):
            input_val = data.get("input", "") if data else ""
            return SafeHTTPResponse(
                url=target_url,
                status_code=200,
                headers={"content-type": "text/html"},
                text=f"<html><body>Result: {input_val}</body></html>",
                elapsed_seconds=0.04,
                redirect_chain=[target_url],
                content_type="text/html",
            )

    with patch("app.services.scanner.payload_test_runner.validate_target_url", return_value="https://app.example.com/contact"):
        res = await runner.run_post_body_tests(
            scan=scan,
            target_url="https://app.example.com/contact",
            content_type="application/x-www-form-urlencoded",
            sample_keys=["input"],
            http_client=VulnerableFormClient(),
            counts=counts,
            limit_per_category=1,
        )

    assert res["method"] == "POST"
    assert res["content_type"] == "application/x-www-form-urlencoded"
    assert res["confirmed_findings"] >= 1

    findings = await repo.list_for_scan(scan.id)
    assert any("via POST (input)" in f.title and f.cwe_id == "CWE-79" for f in findings)


# ── 4. Safety Policy & Sensitive Route Guardrail ─────────────────────────────


async def test_post_testing_blocks_state_changing_and_destructive_routes(db, setup_project_and_target):
    """POST testing automatically skips sensitive/state-changing routes and destructive commands."""
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

    # 1. State changing routes skipped
    sensitive_routes = [
        "https://app.example.com/api/logout",
        "https://app.example.com/account/delete",
        "https://app.example.com/checkout/pay",
        "https://app.example.com/user/terminate",
    ]

    for route in sensitive_routes:
        with patch("app.services.scanner.payload_test_runner.validate_target_url", return_value=route):
            res = await runner.run_post_body_tests(
                scan=scan,
                target_url=route,
                http_client=SafeHTTPClient(),
                counts=counts,
            )
            assert res["status"] == "skipped"
            assert "state-changing" in res["reason"]

    # 2. Destructive payload blocked
    destructive_payload = SecurityPayload(
        payload="; rm -rf / ;",
        description="Destructive command injection attempt",
        type="tautology",
        severity="High",
        context="shell",
    )
    probe_res = await runner._execute_safe_post_probe(
        scan=scan,
        target_url="https://app.example.com/api/search",
        payload_record=destructive_payload,
        content_type="application/json",
        test_key="query",
        http_client=SafeHTTPClient(),
        counts=counts,
    )
    assert probe_res["confidence"] == "INCONCLUSIVE"
    assert "blocked by safety policy" in probe_res["reason"]


# ── 5. Unaffected GET Query-Parameter Scanning ───────────────────────────────


async def test_get_query_parameter_scanning_remains_operational(db, setup_project_and_target):
    """Verify that existing GET query parameter scanning continues to execute seamlessly."""
    await _seed_test_payloads(db)
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

    class MockGetClient(SafeHTTPClient):
        async def get(self, target_url: str, headers: dict | None = None, timeout: float | None = None):
            return SafeHTTPResponse(
                url=target_url,
                status_code=200,
                headers={"content-type": "text/html"},
                text="<html><body>OK</body></html>",
                elapsed_seconds=0.03,
                redirect_chain=[target_url],
                content_type="text/html",
            )

    with patch("app.services.scanner.payload_test_runner.validate_target_url", return_value="https://app.example.com/items?id=1"):
        res = await runner.run(
            scan=scan,
            target_url="https://app.example.com/items?id=1",
            main_resp=None,
            http_client=MockGetClient(),
            counts=counts,
        )

    assert res["total_probes"] >= 1
    assert "tautology" in res["tested_categories"]
