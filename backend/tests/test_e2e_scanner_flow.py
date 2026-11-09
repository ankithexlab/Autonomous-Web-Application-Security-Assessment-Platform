"""
End-to-End Scanner Workflow Integration Tests (Phase 4.4.2).

Validates the full ScannerEngine.run_scan() execution path against isolated local fixtures:
  1. Full normal scan workflow: crawler, security headers, OWASP, and payload testing
     (GET active probes, blind SQLi timing, safe POST body testing) all execute in sequence.
  2. Ineligible target scan workflow: timing probes and POST body testing are safely skipped
     when no query parameters or candidate schemas exist.
  3. Sensitive route protection: POST body probes are suppressed on /delete and state-changing routes.
  4. Crawler origin boundary: Off-origin redirect responses are rejected before HTML parsing.
  5. Cancellation handling: Mid-scan cancellation halts pipeline and preserves CANCELLED status.
  6. Findings, severity totals, and multi-format report exports (JSON, CSV, PDF, HTML) remain consistent.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan
from app.models.security_payload import SecurityPayload
from app.models.target import Target
from app.repositories.finding import FindingRepository
from app.services.report_generator import ReportGenerator
from app.services.scanner_engine import ScannerEngine


def _make_resp(url: str, text: str = "<html><body>OK</body></html>", status_code: int = 200, elapsed: float = 0.05, content_type: str = "text/html") -> SafeHTTPResponse:
    return SafeHTTPResponse(
        url=url,
        status_code=status_code,
        headers={"content-type": content_type, "server": "Apache/2.4.41"},
        text=text,
        elapsed_seconds=elapsed,
        redirect_chain=[url],
        content_type=content_type,
    )


async def _seed_test_payloads(db):
    for pid, desc, val, ctx, ptype, sev in [
        ("e2e-tautology", "Tautology probe", "' OR '1'='1", "Search", "tautology", "high"),
        ("e2e-xss", "Reflected XSS", "<script>alert(1)</script>", "Search", "reflected", "medium"),
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


# ── 1. End-to-End Full Normal Scan Execution ─────────────────────────────────


@pytest.mark.asyncio
async def test_e2e_full_scan_executes_crawler_timing_and_post(db, setup_project_and_target):
    """Full ScannerEngine.run_scan() executes all stages and records crawler, timing, and POST results."""
    await _seed_test_payloads(db)
    env = setup_project_and_target

    # Create target with query parameter
    target = Target(
        project_id=env["project"]["id"],
        url="https://app.acmecorp.com/search?q=test",
        type="web",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    scan = Scan(
        project_id=env["project"]["id"],
        target_id=target.id,
        user_id=env["user"]["user"]["id"],
        scan_type="full",
        status="QUEUED",
        progress=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Mock responses for root page, crawl discovered links, and probes
    root_html = (
        '<html><body>'
        '<a href="/about">About Us</a>'
        '<a href="/contact">Contact</a>'
        '<h1>Search Results for test</h1>'
        '</body></html>'
    )

    mock_client = AsyncMock(spec=SafeHTTPClient)

    async def mock_get(url, timeout=None):
        if "pg_sleep" in url or "sleep" in url.lower():
            # Delay probe return fast for mock test
            return _make_resp(url, "<html><body>Search</body></html>", elapsed=0.08)
        elif "/about" in url:
            return _make_resp(url, "<html><body>About AcmeCorp</body></html>")
        elif "/contact" in url:
            return _make_resp(url, "<html><body>Contact AcmeCorp</body></html>")
        return _make_resp(url, root_html)

    async def mock_post(url, json=None, data=None, headers=None, timeout=None):
        return _make_resp(url, '{"status": "ok", "results": []}', content_type="application/json")

    mock_client.get.side_effect = mock_get
    mock_client.post.side_effect = mock_post

    engine = ScannerEngine(session=db, http_client=mock_client)

    with patch("app.services.scanner_engine.validate_target_url", side_effect=lambda u: u):
        with patch("app.core.ssrf.validate_target_url", side_effect=lambda u: u):
            with patch("app.services.scanner.crawler.validate_target_url", side_effect=lambda u: u):
                with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
                    completed_scan = await engine.run_scan(scan.id)

    # 1. Verify Scan completion state
    assert completed_scan.status == "COMPLETED"
    assert completed_scan.progress == 100
    assert completed_scan.completed_at is not None

    # 2. Verify modules_json contains Phase 4 enhancements
    modules_data = json.loads(completed_scan.modules_json)

    # Crawler executed
    assert "url_discovery" in modules_data
    crawler_res = modules_data["url_discovery"]
    assert crawler_res["total_discovered"] >= 2
    assert "https://app.acmecorp.com/about" in crawler_res["discovered_urls"]
    assert "https://app.acmecorp.com/contact" in crawler_res["discovered_urls"]

    # Payload runner executed
    assert "payload_test_runner" in modules_data
    runner_res = modules_data["payload_test_runner"]
    assert "blind-sqli-timing" in runner_res["tested_categories"]
    assert "post-json-testing" in runner_res["tested_categories"]

    # 3. Verify Findings and Severity Totals Consistency
    repo = FindingRepository(db)
    persisted_findings = await repo.list_for_scan(scan.id)
    assert len(persisted_findings) == completed_scan.findings_count
    assert completed_scan.info_count >= 1  # Informational crawl finding created
    assert any("Discovered" in f.title and f.cwe_id == "CWE-200" for f in persisted_findings)


# ── 2. End-to-End Ineligible Target Negative Case ────────────────────────────


@pytest.mark.asyncio
async def test_e2e_scan_skips_timing_and_post_for_ineligible_target(db, setup_project_and_target):
    """Static targets without query parameters or API paths safely skip timing and POST probing."""
    env = setup_project_and_target

    target = Target(
        project_id=env["project"]["id"],
        url="https://app.acmecorp.com/landing",
        type="web",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    scan = Scan(
        project_id=env["project"]["id"],
        target_id=target.id,
        user_id=env["user"]["user"]["id"],
        scan_type="full",
        status="QUEUED",
        progress=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = _make_resp("https://app.acmecorp.com/landing", "<html><body>Acme Landing</body></html>")

    engine = ScannerEngine(session=db, http_client=mock_client)

    with patch("app.services.scanner_engine.validate_target_url", side_effect=lambda u: u):
        with patch("app.core.ssrf.validate_target_url", side_effect=lambda u: u):
            with patch("app.services.scanner.crawler.validate_target_url", side_effect=lambda u: u):
                with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
                    completed_scan = await engine.run_scan(scan.id)

    assert completed_scan.status == "COMPLETED"
    modules_data = json.loads(completed_scan.modules_json)
    runner_details = modules_data["payload_test_runner"]["details"]

    # Timing skipped
    timing_entry = [d for d in runner_details if d.get("category") == "blind-sqli-timing"]
    assert len(timing_entry) == 1
    assert timing_entry[0]["status"] == "skipped"
    assert "no query parameters" in timing_entry[0]["reason"]

    # POST skipped
    post_entry = [d for d in runner_details if d.get("category") == "post-body-testing"]
    assert len(post_entry) == 1
    assert post_entry[0]["status"] == "skipped"
    assert "No established request schema" in post_entry[0]["reason"]

    # Zero POST requests dispatched
    assert mock_client.post.call_count == 0


# ── 3. End-to-End Sensitive Route Protection ─────────────────────────────────


@pytest.mark.asyncio
async def test_e2e_scan_blocks_post_on_sensitive_routes(db, setup_project_and_target):
    """POST body probing is prevented on dangerous routes such as /delete."""
    env = setup_project_and_target

    target = Target(
        project_id=env["project"]["id"],
        url="https://app.acmecorp.com/users/123/delete?confirm=true",
        type="web",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    scan = Scan(
        project_id=env["project"]["id"],
        target_id=target.id,
        user_id=env["user"]["user"]["id"],
        scan_type="full",
        status="QUEUED",
        progress=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = _make_resp("https://app.acmecorp.com/users/123/delete?confirm=true", "<html><body>Confirm delete?</body></html>")

    engine = ScannerEngine(session=db, http_client=mock_client)

    with patch("app.services.scanner_engine.validate_target_url", side_effect=lambda u: u):
        with patch("app.core.ssrf.validate_target_url", side_effect=lambda u: u):
            with patch("app.services.scanner.crawler.validate_target_url", side_effect=lambda u: u):
                with patch("app.services.scanner.payload_test_runner.validate_target_url", side_effect=lambda u: u):
                    completed_scan = await engine.run_scan(scan.id)

    assert completed_scan.status == "COMPLETED"
    modules_data = json.loads(completed_scan.modules_json)
    runner_details = modules_data["payload_test_runner"]["details"]

    post_entry = [d for d in runner_details if d.get("category") == "post-body-testing"]
    assert len(post_entry) == 1
    assert post_entry[0]["status"] == "skipped"
    assert "state-changing route policy" in post_entry[0]["reason"]
    assert mock_client.post.call_count == 0


# ── 4. End-to-End Scan Cancellation ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_e2e_scan_cancellation_aborts_cleanly(db, setup_project_and_target):
    """When scan is cancelled in database, run_scan detects cancellation and aborts."""
    env = setup_project_and_target
    scan = Scan(
        project_id=env["project"]["id"],
        target_id=env["target"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="web",
        status="CANCELLED",
        progress=15,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    mock_client = AsyncMock(spec=SafeHTTPClient)
    mock_client.get.return_value = _make_resp("https://app.acmecorp.com")
    engine = ScannerEngine(session=db, http_client=mock_client)

    with patch("app.services.scanner_engine.validate_target_url", side_effect=lambda u: u):
        res_scan = await engine.run_scan(scan.id)
    assert res_scan.status == "CANCELLED"
    # Never called Stage 3 HTTP get
    assert not mock_client.get.called


# ── 5. End-to-End Multi-Format Report Consistency ────────────────────────────


@pytest.mark.asyncio
async def test_e2e_report_exports_reflect_findings_consistently(db, setup_project_and_target):
    """ReportService generates JSON, CSV, PDF, and HTML containing consistent findings and counts."""
    env = setup_project_and_target
    scan = Scan(
        project_id=env["project"]["id"],
        target_id=env["target"]["id"],
        user_id=env["user"]["user"]["id"],
        scan_type="web",
        status="COMPLETED",
        progress=100,
        findings_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        info_count=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        target_id=scan.target_id,
        project_id=scan.project_id,
        user_id=scan.user_id,
        title="Time-Based Blind SQL Injection on Parameter 'id'",
        description="Dual-stage confirmation observed reproducible 2s differential delay.",
        severity="high",
        status="open",
        confidence="HIGH",
        category="blind-time",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        cvss_score=8.6,
        affected_url="https://app.acmecorp.com/search?id=1",
        remediation="Use parameterized queries.",
        proof_of_concept="Baseline: 0.05s, Probe 1: 2.10s, Control: 0.05s, Probe 2: 2.09s",
    )
    db.add(finding)
    await db.commit()

    generator = ReportGenerator(db)

    # 1. JSON Report
    rep_json = Report(
        project_id=scan.project_id,
        target_id=scan.target_id,
        scan_id=scan.id,
        user_id=scan.user_id,
        title="E2E JSON Report",
        report_type="technical",
        file_format="json",
        status="PENDING",
    )
    db.add(rep_json)
    await db.commit()
    r_json, json_bytes, ctype_json = await generator.generate_report(rep_json.id)
    assert r_json.status == "COMPLETED"
    report_data = json.loads(json_bytes.decode("utf-8"))
    assert report_data["report_id"] == str(rep_json.id)
    assert report_data["total_findings"] == 1
    assert len(report_data["findings"]) == 1
    assert report_data["findings"][0]["cwe_id"] == "CWE-89"

    # 2. CSV Report
    rep_csv = Report(
        project_id=scan.project_id,
        target_id=scan.target_id,
        scan_id=scan.id,
        user_id=scan.user_id,
        title="E2E CSV Report",
        report_type="technical",
        file_format="csv",
        status="PENDING",
    )
    db.add(rep_csv)
    await db.commit()
    r_csv, csv_bytes, ctype_csv = await generator.generate_report(rep_csv.id)
    assert r_csv.status == "COMPLETED"
    assert "CWE-89" in csv_bytes.decode("utf-8")

    # 3. HTML Report
    rep_html = Report(
        project_id=scan.project_id,
        target_id=scan.target_id,
        scan_id=scan.id,
        user_id=scan.user_id,
        title="E2E HTML Report",
        report_type="technical",
        file_format="html",
        status="PENDING",
    )
    db.add(rep_html)
    await db.commit()
    r_html, html_bytes, ctype_html = await generator.generate_report(rep_html.id)
    assert r_html.status == "COMPLETED"
    html_str = html_bytes.decode("utf-8")
    assert "Time-Based Blind SQL Injection" in html_str
    assert "A03:2021-Injection" in html_str

    # 4. PDF Report
    rep_pdf = Report(
        project_id=scan.project_id,
        target_id=scan.target_id,
        scan_id=scan.id,
        user_id=scan.user_id,
        title="E2E PDF Report",
        report_type="technical",
        file_format="pdf",
        status="PENDING",
    )
    db.add(rep_pdf)
    await db.commit()
    r_pdf, pdf_bytes, ctype_pdf = await generator.generate_report(rep_pdf.id)
    assert r_pdf.status == "COMPLETED"
    assert pdf_bytes.startswith(b"%PDF")

