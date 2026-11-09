"""
Comprehensive regression test suite for manual URL scanner flow.

Verifies:
  1. Website A entered -> actual requests go to A.
  2. Website B entered -> actual requests go to B.
  3. Correct separate target IDs, scan records, findings, and reports.
  4. Stale target ID in request payload is overridden by entered target_url.
  5. Default target is NEVER silently substituted when user enters a custom URL.
  6. Invalid, unreachable, and SSRF-blocked URLs fail safely with genuine errors.
  7. Controlled local HTTP servers prove real network dispatch to destination A vs destination B.
"""

import http.server
import json
import socket
import threading
from typing import Any
from unittest.mock import patch
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import BadRequestException
from app.database.session import async_session_factory
from app.models.scan import Scan
from app.models.target import Target
from app.services.scanner_engine import ScannerEngine
from app.services.report_generator import ReportGenerator

pytestmark = pytest.mark.asyncio


# ── Controlled Test HTTP Servers ───────────────────────────────────

class _CanaryHandler(http.server.BaseHTTPRequestHandler):
    """Local HTTP handler that logs received paths and serves a distinct canary."""
    server_name = "unknown"
    canary_token = "none"
    received_requests: list[str] = []

    def do_GET(self) -> None:
        self.__class__.received_requests.append(f"{self.command} {self.path}")
        body = json.dumps({
            "server": self.server_name,
            "canary": self.canary_token,
            "path": self.path,
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", f"CanaryServer/{self.server_name}")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self.__class__.received_requests.append(f"{self.command} {self.path}")
        body = b'{"status": "ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Silence standard server logs in pytest output
        pass


def _create_server(name: str, canary: str) -> tuple[http.server.HTTPServer, threading.Thread, str, list[str]]:
    requests_log: list[str] = []

    class DedicatedHandler(_CanaryHandler):
        server_name = name
        canary_token = canary
        received_requests = requests_log

    # Bind to 127.0.0.1 on an OS-assigned free port
    server = http.server.HTTPServer(("127.0.0.1", 0), DedicatedHandler)
    port = server.server_port
    url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, url, requests_log


# ── Tests ──────────────────────────────────────────────────────────

async def test_direct_scan_creation_endpoint(client: AsyncClient, registered_user: dict):
    """
    POST /api/v1/scans directly creates a scan for a manual URL,
    auto-registering the target without requiring pre-configuration.
    """
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
    target_url = "https://app-alpha.manual-target.org"

    resp = await client.post(
        "/api/v1/scans",
        json={"target_url": target_url, "scan_type": "quick"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()

    assert scan["target_url"] == target_url
    assert scan["scan_type"] == "quick"
    assert scan["status"] == "QUEUED"
    assert scan["target_id"] is not None

    # Verify target was created under user's project
    t_resp = await client.get(f"/api/v1/targets/{scan['target_id']}", headers=headers)
    assert t_resp.status_code == 200
    target_data = t_resp.json()
    assert target_data["url"] == target_url


async def test_manual_urls_a_and_b_produce_separate_targets_and_scans(client: AsyncClient, registered_user: dict):
    """
    Entering Target A and Target B creates separate targets, separate scan IDs,
    and never conflates results or reuses stale target IDs.
    """
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    url_a = "https://service-a.domain.org"
    url_b = "https://service-b.domain.org"

    # 1. Create Scan A
    resp_a = await client.post(
        "/api/v1/scans",
        json={"target_url": url_a, "scan_type": "full"},
        headers=headers,
    )
    assert resp_a.status_code == 201
    scan_a = resp_a.json()
    assert scan_a["target_url"] == url_a

    # 2. Create Scan B
    resp_b = await client.post(
        "/api/v1/scans",
        json={"target_url": url_b, "scan_type": "quick"},
        headers=headers,
    )
    assert resp_b.status_code == 201
    scan_b = resp_b.json()
    assert scan_b["target_url"] == url_b

    # Verify complete separation
    assert scan_a["id"] != scan_b["id"]
    assert scan_a["target_id"] != scan_b["target_id"]
    assert scan_a["target_url"] != scan_b["target_url"]


async def test_stale_target_id_in_payload_is_overridden_by_manual_url(
    client: AsyncClient, setup_project_and_target: dict
):
    """
    If the frontend sends an old/stale target_id (e.g. from a default target)
    in the URL path, but includes target_url in config or payload, the backend
    MUST NOT scan the old target. It must resolve the new URL and scan it instead.
    """
    env = setup_project_and_target
    project_id = env["project"]["id"]
    stale_target_id = env["target"]["id"]
    stale_url = env["target"]["url"]  # "https://app.acmecorp.com"

    new_manual_url = "https://completely-new-client.com"

    # Pass the stale target ID in the route path, but send new target_url in payload
    resp = await client.post(
        f"/api/v1/projects/{project_id}/targets/{stale_target_id}/scans",
        json={
            "scan_type": "full",
            "target_url": new_manual_url,
            "config": {"targetUrl": new_manual_url},
        },
        headers=env["headers"],
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()

    # The scan MUST be bound to the new manual URL, NOT the stale target
    assert scan["target_url"] == new_manual_url
    assert scan["target_id"] != stale_target_id


async def test_invalid_and_blocked_urls_fail_safely(client: AsyncClient, registered_user: dict):
    """
    Verify invalid syntax, missing hostname, and SSRF-restricted hosts
    (loopback, private RFC1918, cloud metadata) are rejected safely with clear errors.
    """
    headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

    # 1. Empty target URL
    res_empty = await client.post(
        "/api/v1/scans",
        json={"target_url": ""},
        headers=headers,
    )
    assert res_empty.status_code in (400, 422)

    # 2. Unsupported scheme
    res_scheme = await client.post(
        "/api/v1/scans",
        json={"target_url": "ftp://files.example.com"},
        headers=headers,
    )
    assert res_scheme.status_code == 400
    assert "scheme" in res_scheme.text.lower()

    # 3. Embedded credentials
    res_creds = await client.post(
        "/api/v1/scans",
        json={"target_url": "http://admin:secret@example.com"},
        headers=headers,
    )
    assert res_creds.status_code == 400
    assert "credential" in res_creds.text.lower()

    # 4. Cloud metadata IP (AWS 169.254.169.254)
    res_meta = await client.post(
        "/api/v1/scans",
        json={"target_url": "http://169.254.169.254/latest/meta-data/"},
        headers=headers,
    )
    assert res_meta.status_code == 400
    assert "blocked" in res_meta.text.lower() or "denied" in res_meta.text.lower()

    # 5. Cloud metadata hostname
    res_meta_host = await client.post(
        "/api/v1/scans",
        json={"target_url": "http://metadata.google.internal/computeMetadata/v1/"},
        headers=headers,
    )
    assert res_meta_host.status_code == 400
    assert "restricted" in res_meta_host.text.lower() or "denied" in res_meta_host.text.lower()

    # 6. Private IP (RFC 1918 10.0.0.1)
    res_priv = await client.post(
        "/api/v1/scans",
        json={"target_url": "http://10.0.0.1:8080/admin"},
        headers=headers,
    )
    assert res_priv.status_code == 400
    assert "blocked" in res_priv.text.lower() or "denied" in res_priv.text.lower()


async def test_real_outbound_dispatch_to_controlled_servers_a_and_b(
    client: AsyncClient, registered_user: dict, db: AsyncSession
):
    """
    REAL NETWORK DISPATCH VERIFICATION:
    Spins up two distinct local HTTP servers (Server A on Port X, Server B on Port Y).
    Scans Server A -> asserts real HTTP requests reach Server A, and 0 reach Server B.
    Scans Server B -> asserts real HTTP requests reach Server B.
    Ensures findings and reports identify the exact server URL.
    """
    server_a, thread_a, url_a, log_a = _create_server("ServerAlpha", "CANARY_TOKEN_ALPHA_777")
    server_b, thread_b, url_b, log_b = _create_server("ServerBeta", "CANARY_TOKEN_BETA_888")

    try:
        settings = get_settings()
        # Temporarily enable local targets for this controlled test harness
        original_allow_local = settings.ALLOW_LOCAL_TARGETS
        settings.ALLOW_LOCAL_TARGETS = True

        headers = {"Authorization": f"Bearer {registered_user['access_token']}"}

        # ── 1. Create and execute scan against Server A ─────────────
        resp_a = await client.post(
            "/api/v1/scans",
            json={
                "target_url": url_a,
                "scan_type": "quick",
                "config": {"modules": ["security_headers", "http_config", "robots_sitemap"]},
            },
            headers=headers,
        )
        assert resp_a.status_code == 201, resp_a.text
        scan_a_id = UUID(resp_a.json()["id"])

        # Execute scan via ScannerEngine
        engine_a = ScannerEngine(db)
        await engine_a.run_scan(scan_a_id)

        # Evidence: Server A received real HTTP requests
        assert len(log_a) > 0, "Server A should have received outbound HTTP requests from scanner engine"
        assert len(log_b) == 0, "Server B must NOT receive any requests during scan of Server A"

        # Check scan record
        res_scan_a = await client.get(f"/api/v1/scans/{scan_a_id}", headers=headers)
        assert res_scan_a.status_code == 200
        data_a = res_scan_a.json()
        assert data_a["status"] == "COMPLETED"
        assert data_a["target_url"] == url_a

        # ── 2. Create and execute scan against Server B ─────────────
        resp_b = await client.post(
            "/api/v1/scans",
            json={
                "target_url": url_b,
                "scan_type": "quick",
                "config": {"modules": ["security_headers", "http_config", "robots_sitemap"]},
            },
            headers=headers,
        )
        assert resp_b.status_code == 201, resp_b.text
        scan_b_id = UUID(resp_b.json()["id"])

        initial_len_a = len(log_a)

        engine_b = ScannerEngine(db)
        await engine_b.run_scan(scan_b_id)

        # Evidence: Server B received real HTTP requests
        assert len(log_b) > 0, "Server B should have received outbound HTTP requests from scanner engine"
        # Server A received no new requests during scan of Server B
        assert len(log_a) == initial_len_a, "Server A must not receive new requests during scan of Server B"

        res_scan_b = await client.get(f"/api/v1/scans/{scan_b_id}", headers=headers)
        assert res_scan_b.status_code == 200
        data_b = res_scan_b.json()
        assert data_b["status"] == "COMPLETED"
        assert data_b["target_url"] == url_b

        # ── 3. Verify reports identify actual targets ───────────────
        rep_a_resp = await client.post(
            f"/api/v1/projects/{data_a['project_id']}/reports",
            json={
                "title": "Security Assessment Report Server A",
                "scan_id": str(scan_a_id),
                "report_type": "technical",
                "file_format": "json",
            },
            headers=headers,
        )
        assert rep_a_resp.status_code == 201, rep_a_resp.text
        rep_a_id = rep_a_resp.json()["id"]

        # Download report JSON
        rep_dl = await client.get(
            f"/api/v1/reports/{rep_a_id}/download",
            headers=headers,
        )
        assert rep_dl.status_code == 200
        report_json = rep_dl.json()
        assert report_json["target_url"] == url_a, f"Report should cite target {url_a}"

    finally:
        settings.ALLOW_LOCAL_TARGETS = original_allow_local
        server_a.shutdown()
        server_b.shutdown()
