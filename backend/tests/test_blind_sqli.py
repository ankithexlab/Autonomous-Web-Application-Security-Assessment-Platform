"""
Unit and regression tests for Phase 4.4 Step 3: Blind SQLi Timing Analysis.

Validates:
  1. Confirmed Time-Based Blind SQLi via dual-stage replication and fast control check.
  2. Negative case: Fast response (<1.7s delta) correctly classified as NEGATIVE.
  3. High baseline latency (>1.5s) correctly filtered out as INCONCLUSIVE.
  4. Transient latency spike where Probe 1 delays but Probe 2 does not replicate.
  5. Global latency spike where control probe also lags, returning INCONCLUSIVE.
  6. Parameterless URLs and SSRF violations gracefully skipped.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.repositories.finding import FindingRepository
from app.services.scanner.payload_test_runner import PayloadSecurityTestRunner


def _make_mock_response(url: str, elapsed: float, status_code: int = 200) -> SafeHTTPResponse:
    return SafeHTTPResponse(
        url=url,
        status_code=status_code,
        headers={"content-type": "text/html; charset=utf-8"},
        text="<html><body>OK</body></html>",
        elapsed_seconds=elapsed,
        redirect_chain=[url],
        content_type="text/html",
    )


@pytest.mark.asyncio
async def test_blind_sqli_confirmed_dual_stage(db, setup_project_and_target):
    """Dual-stage timing confirmation creates High-severity finding when both probes delay and control is fast."""
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

    # 1. Baseline: 0.08s
    # 2. Probe 1 (pg_sleep): 2.12s
    # 3. Control (pg_sleep 0): 0.07s
    # 4. Probe 2 (SLEEP): 2.10s
    mock_client.get.side_effect = [
        _make_mock_response("https://example.com/api?id=1", 0.08),
        _make_mock_response("https://example.com/api?id=probe1", 2.12),
        _make_mock_response("https://example.com/api?id=ctrl", 0.07),
        _make_mock_response("https://example.com/api?id=probe2", 2.10),
    ]

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        res = await runner.run_blind_sqli_timing_tests(
            scan=scan,
            target_url="https://example.com/api?id=1",
            http_client=mock_client,
            counts=counts,
        )

    assert res["status"] == "completed"
    assert res["confidence"] == "CONFIRMED"
    assert res["confirmed"] is True
    assert res["finding_created"] is True
    assert counts["high"] >= 1

    findings = await repo.list_for_scan(scan.id)
    sqli_findings = [f for f in findings if "Time-Based Blind SQL" in f.title]
    assert len(sqli_findings) == 1
    f = sqli_findings[0]
    assert f.severity == "high"
    assert f.cwe_id == "CWE-89"
    assert f.owasp_category == "A03:2021-Injection"
    assert "pg_sleep" in f.proof_of_concept


@pytest.mark.asyncio
async def test_blind_sqli_negative_case(db, setup_project_and_target):
    """Probe returning without significant delay is classified as NEGATIVE with no findings created."""
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
    # Baseline: 0.05s, Probe 1: 0.06s (delta: 0.01s < 1.7s)
    mock_client.get.side_effect = [
        _make_mock_response("https://example.com/api?id=1", 0.05),
        _make_mock_response("https://example.com/api?id=probe1", 0.06),
    ]

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        res = await runner.run_blind_sqli_timing_tests(
            scan=scan,
            target_url="https://example.com/api?id=1",
            http_client=mock_client,
            counts=counts,
        )

    assert res["status"] == "completed"
    assert res["confidence"] == "NEGATIVE"
    assert res["confirmed"] is False
    assert counts["high"] == 0

    findings = await repo.list_for_scan(scan.id)
    assert not any("Time-Based Blind SQL" in f.title for f in findings)


@pytest.mark.asyncio
async def test_blind_sqli_high_baseline_jitter_filter(db, setup_project_and_target):
    """Baseline latency >1.5s aborts timing analysis early to avoid jitter false positives."""
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
    # Baseline is already 1.95s (sluggish server)
    mock_client.get.return_value = _make_mock_response("https://example.com/api?id=1", 1.95)

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        res = await runner.run_blind_sqli_timing_tests(
            scan=scan,
            target_url="https://example.com/api?id=1",
            http_client=mock_client,
            counts=counts,
        )

    assert res["status"] == "inconclusive"
    assert res["confidence"] == "INCONCLUSIVE"
    assert "exceeds 1.5s" in res["reason"]
    # Only 1 request (baseline) should have been sent
    assert mock_client.get.call_count == 1
    assert counts["high"] == 0


@pytest.mark.asyncio
async def test_blind_sqli_transient_unreplicated_jitter(db, setup_project_and_target):
    """Probe 1 delayed but Probe 2 does NOT replicate delay -> classified as SUSPECTED, not CONFIRMED."""
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
    mock_client.get.side_effect = [
        _make_mock_response("https://example.com/api?id=1", 0.06),       # Baseline
        _make_mock_response("https://example.com/api?id=probe1", 2.10),  # Probe 1 delayed
        _make_mock_response("https://example.com/api?id=ctrl", 0.05),    # Control normal
        _make_mock_response("https://example.com/api?id=probe2", 0.08),  # Probe 2 failed to reproduce!
    ]

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        res = await runner.run_blind_sqli_timing_tests(
            scan=scan,
            target_url="https://example.com/api?id=1",
            http_client=mock_client,
            counts=counts,
        )

    assert res["status"] == "completed"
    assert res["confidence"] == "SUSPECTED"
    assert res["confirmed"] is False
    # No confirmed finding created
    findings = await repo.list_for_scan(scan.id)
    assert not any("Time-Based Blind SQL" in f.title for f in findings)


@pytest.mark.asyncio
async def test_blind_sqli_global_server_lag_rejected(db, setup_project_and_target):
    """If control probe also experiences latency, probe is rejected as INCONCLUSIVE server lag."""
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
    mock_client.get.side_effect = [
        _make_mock_response("https://example.com/api?id=1", 0.08),       # Baseline
        _make_mock_response("https://example.com/api?id=probe1", 2.20),  # Probe 1 delayed
        _make_mock_response("https://example.com/api?id=ctrl", 2.15),    # Control probe also slow!
    ]

    with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
        res = await runner.run_blind_sqli_timing_tests(
            scan=scan,
            target_url="https://example.com/api?id=1",
            http_client=mock_client,
            counts=counts,
        )

    assert res["status"] == "completed"
    assert res["confidence"] == "INCONCLUSIVE"
    assert res["confirmed"] is False
    assert "Control probe also exhibited elevated latency" in res["reason"]
    # Never called probe 2 because control failed
    assert mock_client.get.call_count == 3


@pytest.mark.asyncio
async def test_blind_sqli_skips_parameterless_and_ssrf(db, setup_project_and_target):
    """URLs without parameters or violating SSRF are safely skipped."""
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
    mock_client = AsyncMock(spec=SafeHTTPClient)

    # 1. No query parameters
    res_noparams = await runner.run_blind_sqli_timing_tests(
        scan=scan,
        target_url="https://example.com/dashboard",
        http_client=mock_client,
    )
    assert res_noparams["status"] == "skipped"

    # 2. SSRF violation
    res_ssrf = await runner.run_blind_sqli_timing_tests(
        scan=scan,
        target_url="http://169.254.169.254/latest/meta-data?id=1",
        http_client=mock_client,
    )
    assert res_ssrf["status"] == "skipped"
    assert "SSRF" in res_ssrf["reason"]
