"""
HTTP/HTTPS Configuration Analysis Module — Phase 5.

Passively analyzes HTTP/HTTPS transport security configuration:
  1. Detects cleartext HTTP service without HTTPS enforcement.
  2. Verifies whether an HTTP service properly redirects to HTTPS.
  3. Checks for passive mixed-content indicators in HTML responses (e.g. http:// script/img/link on HTTPS).
  4. Observes HSTS and Upgrade-Insecure-Requests support.

Security:
  - Fully passive: operates on collected responses or at most a single SSRF-validated GET request.
  - SSRF protections enforced via validate_target_url().
  - Never submits exploit payloads or alters server configuration.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import AppException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)

# Pattern to detect insecure passive/active mixed content in HTML
_MIXED_CONTENT_RE = re.compile(
    r"""(?:src|href)\s*=\s*["'](http://[a-zA-Z0-9_\-\.]+/[^"']*)["']""",
    re.IGNORECASE,
)


class HttpConfigModule(BaseScannerModule):
    """Passive HTTP/HTTPS transport configuration analyzer."""

    module_id = "http_config"
    module_name = "HTTP/HTTPS Configuration"
    category = "Network Security"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        if not main_resp:
            return {
                "status": "skipped",
                "reason": "No primary HTTP response available",
                "findings_count": 0,
            }

        parsed = urlparse(target_url)
        is_https_target = parsed.scheme.lower() == "https"
        final_url = main_resp.url
        is_https_final = final_url.startswith("https://")
        headers = {k.lower(): v for k, v in main_resp.headers.items()}
        body = main_resp.text or ""

        result: dict[str, Any] = {
            "status": "completed",
            "target_scheme": parsed.scheme.lower(),
            "final_scheme": "https" if is_https_final else "http",
            "enforces_https": is_https_final,
            "hsts_active": "strict-transport-security" in headers,
            "upgrade_insecure_requests": "upgrade-insecure-requests" in headers,
            "mixed_content_count": 0,
            "mixed_content_samples": [],
            "findings_count": 0,
        }

        # ── 1. Cleartext HTTP without HTTPS redirect ─────────────────
        if not is_https_target and not is_https_final:
            await self._create_finding(
                scan,
                title="Unencrypted HTTP Service — Cleartext Transport",
                description=(
                    f"The web application at {target_url} serves content over plain HTTP and does not "
                    "enforce redirection to HTTPS. Traffic including authentication credentials, cookies, "
                    "and sensitive application data is vulnerable to interception and modification by network adversaries."
                ),
                severity="high",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-319",
                cvss_score=7.5,
                affected_url=target_url,
                remediation=(
                    "Configure the web server to enforce HTTPS for all incoming connections with a 301 Permanent Redirect, "
                    "and enable HTTP Strict Transport Security (HSTS)."
                ),
                proof_of_concept=f"GET {target_url} resolved to unencrypted URL: {final_url}",
                counts=counts,
            )
            result["findings_count"] += 1

        # ── 2. Check HTTP -> HTTPS redirect if target was HTTPS ─────
        if is_https_target:
            http_candidate = f"http://{parsed.netloc}{parsed.path or '/'}"
            try:
                validate_target_url(http_candidate)
                http_resp = await http_client.get(http_candidate, timeout=5.0)
                redirects_to_https = http_resp.url.startswith("https://")
                result["http_redirects_to_https"] = redirects_to_https
                if not redirects_to_https:
                    await self._create_finding(
                        scan,
                        title="HTTP Endpoint Accessible Without HTTPS Redirection",
                        description=(
                            f"The HTTP port for this service ({http_candidate}) accepts connections without "
                            "redirecting clients to HTTPS. Users typing the domain without a scheme may "
                            "inadvertently transmit credentials or data in cleartext."
                        ),
                        severity="medium",
                        owasp_category="A02:2021-Cryptographic Failures",
                        cwe_id="CWE-319",
                        cvss_score=5.3,
                        affected_url=http_candidate,
                        remediation="Configure the web server to permanently redirect HTTP (port 80) to HTTPS (port 443).",
                        proof_of_concept=f"GET {http_candidate} returned HTTP {http_resp.status_code} at {http_resp.url} without HTTPS redirect",
                        counts=counts,
                    )
                    result["findings_count"] += 1
            except AppException:
                pass
            except Exception:
                pass

        # ── 3. Passive Mixed Content Detection on HTTPS pages ────────
        if is_https_final and body:
            matches = _MIXED_CONTENT_RE.findall(body)
            # Filter out same-origin localhost or doc links
            insecure_assets = [m for m in matches if not m.startswith("http://localhost")]
            if insecure_assets:
                unique_insecure = list(dict.fromkeys(insecure_assets))[:5]
                result["mixed_content_count"] = len(insecure_assets)
                result["mixed_content_samples"] = unique_insecure
                await self._create_finding(
                    scan,
                    title=f"Passive Mixed Content Detected ({len(insecure_assets)} insecure URLs)",
                    description=(
                        f"The HTTPS page at {final_url} references resources over plain HTTP: "
                        f"{', '.join(unique_insecure[:3])}. Modern browsers block active mixed content "
                        "and may warn users about passive mixed content (images, audio)."
                    ),
                    severity="medium",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-311",
                    cvss_score=5.0,
                    affected_url=final_url,
                    remediation="Update all resource URLs to use HTTPS schemes or relative paths.",
                    proof_of_concept=(
                        "Insecure HTTP resources referenced in response body:\n"
                        + "\n".join(f"  - {u}" for u in unique_insecure)
                    ),
                    counts=counts,
                )
                result["findings_count"] += 1

        return result
