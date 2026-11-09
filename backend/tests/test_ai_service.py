"""
AI Analysis & Assistant Unit Tests.

Coverage:
  1. Finding analysis endpoint (POST /api/v1/ai/findings/{id}/analyze)
  2. Chat assistant endpoint (POST /api/v1/ai/chat)
  3. AI provider status (GET /api/v1/ai/status)
  4. Evidence sanitization & secret redaction
  5. IDOR / Cross-user finding access protection (returns 404)
  6. AI analysis caching on finding record
"""

from unittest.mock import patch
import pytest
from httpx import AsyncClient

from app.core.http_client import SafeHTTPResponse
from app.repositories.scan import ScanRepository
from app.services.ai.service import sanitize_evidence_text
from app.services.scanner_engine import ScannerEngine

pytestmark = pytest.mark.asyncio


class MockAIHTTPClient:
    async def get(self, target_url: str, headers: dict[str, str] | None = None) -> SafeHTTPResponse:
        return SafeHTTPResponse(
            url=target_url,
            status_code=200,
            headers={
                "content-type": "text/html",
                "server": "nginx/1.18.0",
            },
            text="<html><body><h1>Test</h1></body></html>",
            elapsed_seconds=0.1,
            redirect_chain=[target_url],
            content_type="text/html",
        )


async def _create_test_scan(db, env: dict) -> str:
    scan_repo = ScanRepository(db)
    scan = await scan_repo.create(
        target_id=env["target"]["id"],
        project_id=env["project"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="headers",
        config_json='{"modules": ["security_headers"]}',
    )

    engine = ScannerEngine(db, http_client=MockAIHTTPClient())
    with patch("app.services.scanner_engine.validate_target_url", return_value="https://example.com"):
        await engine.run_scan(scan.id)

    return str(scan.id)


async def test_evidence_sanitization_and_redaction():
    text_with_token = "Authorization: Bearer secret_token_12345; Cookie: sessionid=abc"
    sanitized = sanitize_evidence_text(text_with_token)
    assert "secret_token_12345" not in sanitized
    assert "[REDACTED]" in sanitized


async def test_ai_status_endpoint(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    res = await client.get("/api/v1/ai/status", headers=env["headers"])
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["provider"] in ("mock", "openai", "gemini")


async def test_analyze_finding_endpoint(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan(db, env)

    # 1. Fetch finding ID
    findings_res = await client.get("/api/v1/findings", headers=env["headers"])
    assert findings_res.status_code == 200
    finding_id = findings_res.json()["items"][0]["id"]

    # 2. Analyze finding
    ai_res = await client.post(f"/api/v1/ai/findings/{finding_id}/analyze", headers=env["headers"])
    assert ai_res.status_code == 200, ai_res.text
    analysis = ai_res.json()

    assert "summary" in analysis
    assert "risk_explanation" in analysis
    assert "impact" in analysis
    assert "remediation_guidance" in analysis
    assert isinstance(analysis["remediation_guidance"], list)
    assert len(analysis["remediation_guidance"]) > 0


async def test_ai_chat_assistant_endpoint(client: AsyncClient, setup_project_and_target: dict):
    env = setup_project_and_target
    chat_res = await client.post(
        "/api/v1/ai/chat",
        json={"messages": [{"role": "user", "content": "How do I fix SQL Injection?"}]},
        headers=env["headers"],
    )
    assert chat_res.status_code == 200, chat_res.text
    response = chat_res.json()
    assert "reply" in response
    assert "SQL Injection" in response["reply"]


async def test_cross_user_finding_analysis_prevention(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan(db, env)

    findings_res = await client.get("/api/v1/findings", headers=env["headers"])
    finding_id = findings_res.json()["items"][0]["id"]

    # Register second user
    second_user_res = await client.post(
        "/api/v1/auth/register",
        json={"name": "Attacker AI", "email": "attacker_ai@example.com", "password": "Password123!"},
    )
    second_headers = {"Authorization": f"Bearer {second_user_res.json()['access_token']}"}

    # Attempt cross-user access -> 404 Not Found (IDOR protection)
    cross_res = await client.post(f"/api/v1/ai/findings/{finding_id}/analyze", headers=second_headers)
    assert cross_res.status_code == 404

    # Attempt cross-user remediation access -> 404 Not Found
    cross_rem_res = await client.post(f"/api/v1/ai/findings/{finding_id}/remediation", headers=second_headers)
    assert cross_rem_res.status_code == 404


async def test_generate_remediation_endpoint(client: AsyncClient, setup_project_and_target: dict, db):
    env = setup_project_and_target
    await _create_test_scan(db, env)

    findings_res = await client.get("/api/v1/findings", headers=env["headers"])
    finding_id = findings_res.json()["items"][0]["id"]

    rem_res = await client.post(f"/api/v1/ai/findings/{finding_id}/remediation", headers=env["headers"])
    assert rem_res.status_code == 200, rem_res.text
    remediation = rem_res.json()

    assert "remediation_summary" in remediation
    assert "root_cause" in remediation
    assert "recommended_fix" in remediation
    assert "implementation_steps" in remediation
    assert "verification_steps" in remediation
    assert isinstance(remediation["implementation_steps"], list)
    assert len(remediation["implementation_steps"]) > 0
