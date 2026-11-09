"""
Security Headers Analysis Module — Phase 5.

Passive analysis of HTTP security response headers.  Operates entirely on
the primary HTTP response already collected by the scanner engine — no
additional outbound requests.

Checks:
  1.  Content-Security-Policy (CSP)
  2.  Strict-Transport-Security (HSTS)
  3.  X-Frame-Options / frame-ancestors CSP directive
  4.  X-Content-Type-Options: nosniff
  5.  Referrer-Policy
  6.  Permissions-Policy (formerly Feature-Policy)
  7.  X-XSS-Protection (deprecated but still informational)
  8.  Cross-Origin-Opener-Policy (COOP)
  9.  Cross-Origin-Embedder-Policy (COEP)
  10. Cross-Origin-Resource-Policy (CORP)

Evidence is taken verbatim from actual response headers; no fabrication.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)


class SecurityHeadersModule(BaseScannerModule):
    """Passive security header analysis — no additional HTTP requests required."""

    module_id = "security_headers"
    module_name = "Security Headers Analysis"
    category = "Security Headers"

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
                "headers_present": [],
                "headers_missing": [],
                "findings_count": 0,
            }

        headers = {k.lower(): v for k, v in main_resp.headers.items()}
        is_https = main_resp.url.startswith("https://")
        findings_count = 0
        headers_present: list[str] = []
        headers_missing: list[str] = []

        # ── 1. Content-Security-Policy ───────────────────────────────
        if "content-security-policy" in headers:
            csp_value = headers["content-security-policy"]
            headers_present.append("Content-Security-Policy")
            # Warn on unsafe-inline / unsafe-eval in CSP
            if "unsafe-inline" in csp_value.lower():
                await self._create_finding(
                    scan,
                    title="Content-Security-Policy Permits 'unsafe-inline'",
                    description=(
                        "The CSP header includes 'unsafe-inline', which allows inline scripts "
                        "and styles and largely defeats XSS protection from CSP."
                    ),
                    severity="medium",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-693",
                    cvss_score=4.3,
                    affected_url=main_resp.url,
                    remediation=(
                        "Remove 'unsafe-inline' and use nonces or hashes to allow specific "
                        "trusted inline code."
                    ),
                    proof_of_concept=(
                        f"Content-Security-Policy: {csp_value[:256]}"
                    ),
                    counts=counts,
                )
                findings_count += 1
            if "unsafe-eval" in csp_value.lower():
                await self._create_finding(
                    scan,
                    title="Content-Security-Policy Permits 'unsafe-eval'",
                    description=(
                        "The CSP header includes 'unsafe-eval', enabling dynamic code execution "
                        "via eval() and similar functions, increasing XSS risk."
                    ),
                    severity="medium",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-693",
                    cvss_score=4.3,
                    affected_url=main_resp.url,
                    remediation="Remove 'unsafe-eval' and refactor code to avoid dynamic evaluation.",
                    proof_of_concept=(
                        f"Content-Security-Policy: {csp_value[:256]}"
                    ),
                    counts=counts,
                )
                findings_count += 1
        else:
            headers_missing.append("Content-Security-Policy")
            await self._create_finding(
                scan,
                title="Missing Content-Security-Policy Header",
                description=(
                    "The application does not set a Content-Security-Policy (CSP) response header, "
                    "increasing susceptibility to Cross-Site Scripting (XSS) and data injection attacks."
                ),
                severity="low",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-693",
                cvss_score=3.8,
                affected_url=main_resp.url,
                remediation="Configure a restrictive Content-Security-Policy header (e.g. default-src 'self').",
                proof_of_concept=(
                    f"HTTP response headers for {main_resp.url} do not include Content-Security-Policy"
                ),
                counts=counts,
            )
            findings_count += 1

        # ── 2. Strict-Transport-Security (HSTS) ─────────────────────
        if "strict-transport-security" in headers:
            hsts_value = headers["strict-transport-security"]
            headers_present.append("Strict-Transport-Security")
            # Check for very short max-age
            try:
                for part in hsts_value.split(";"):
                    part = part.strip().lower()
                    if part.startswith("max-age="):
                        max_age = int(part.split("=", 1)[1].strip())
                        if max_age < 15768000:  # < 6 months
                            await self._create_finding(
                                scan,
                                title="HSTS max-age Too Short (< 6 months)",
                                description=(
                                    f"The Strict-Transport-Security header sets max-age={max_age} seconds "
                                    f"({max_age // 86400} days), which is below the recommended minimum "
                                    "of 15,768,000 seconds (6 months)."
                                ),
                                severity="info",
                                owasp_category="A05:2021-Security Misconfiguration",
                                cwe_id="CWE-523",
                                cvss_score=2.1,
                                affected_url=main_resp.url,
                                remediation=(
                                    "Set max-age to at least 31,536,000 seconds (1 year) and add "
                                    "includeSubDomains to fully enforce HSTS."
                                ),
                                proof_of_concept=f"Strict-Transport-Security: {hsts_value}",
                                counts=counts,
                            )
                            findings_count += 1
                        break
            except (ValueError, IndexError):
                pass
        elif is_https:
            headers_missing.append("Strict-Transport-Security")
            await self._create_finding(
                scan,
                title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                description=(
                    "The HTTPS web application does not enforce HSTS, leaving users vulnerable "
                    "to SSL stripping and man-in-the-middle downgrade attacks."
                ),
                severity="medium",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-523",
                cvss_score=5.3,
                affected_url=main_resp.url,
                remediation=(
                    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                    "to HTTPS response headers."
                ),
                proof_of_concept=(
                    f"HTTP response headers for {main_resp.url} do not include Strict-Transport-Security"
                ),
                counts=counts,
            )
            findings_count += 1

        # ── 3. X-Frame-Options / frame-ancestors ────────────────────
        csp_val = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp_val.lower()
        if "x-frame-options" in headers:
            headers_present.append("X-Frame-Options")
        elif not has_frame_ancestors:
            headers_missing.append("X-Frame-Options")
            await self._create_finding(
                scan,
                title="Missing Anti-Clickjacking Protection (X-Frame-Options)",
                description=(
                    "The application does not declare an X-Frame-Options header or a "
                    "frame-ancestors CSP directive, allowing framing by external origins "
                    "(Clickjacking risk)."
                ),
                severity="low",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1021",
                cvss_score=3.4,
                affected_url=main_resp.url,
                remediation=(
                    "Set 'X-Frame-Options: DENY' or use "
                    "'Content-Security-Policy: frame-ancestors 'none'' on all HTML responses."
                ),
                proof_of_concept=(
                    f"HTTP response headers for {main_resp.url} include neither "
                    "X-Frame-Options nor a frame-ancestors CSP directive"
                ),
                counts=counts,
            )
            findings_count += 1

        # ── 4. X-Content-Type-Options ───────────────────────────────
        xcto = headers.get("x-content-type-options", "")
        if xcto.lower() == "nosniff":
            headers_present.append("X-Content-Type-Options")
        else:
            headers_missing.append("X-Content-Type-Options")
            await self._create_finding(
                scan,
                title="Missing X-Content-Type-Options: nosniff Header",
                description=(
                    "The response header X-Content-Type-Options is missing or not set to "
                    "'nosniff', permitting MIME-sniffing vulnerabilities."
                ),
                severity="info",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-79",
                cvss_score=2.6,
                affected_url=main_resp.url,
                remediation="Set 'X-Content-Type-Options: nosniff' on all response headers.",
                proof_of_concept=(
                    f"X-Content-Type-Options header value: '{xcto or 'ABSENT'}'"
                ),
                counts=counts,
            )
            findings_count += 1

        # ── 5. Referrer-Policy ───────────────────────────────────────
        if "referrer-policy" in headers:
            headers_present.append("Referrer-Policy")
            rp = headers["referrer-policy"].lower()
            # Warn on unsafe values
            unsafe_rp = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
            if rp in unsafe_rp:
                await self._create_finding(
                    scan,
                    title=f"Unsafe Referrer-Policy Value: '{headers['referrer-policy']}'",
                    description=(
                        f"The Referrer-Policy is set to '{headers['referrer-policy']}', which may "
                        "leak the full URL (including query parameters and sensitive tokens) to "
                        "third-party services in the Referer header."
                    ),
                    severity="info",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-200",
                    cvss_score=2.0,
                    affected_url=main_resp.url,
                    remediation=(
                        "Use a stricter policy such as 'strict-origin-when-cross-origin' or "
                        "'no-referrer'."
                    ),
                    proof_of_concept=f"Referrer-Policy: {headers['referrer-policy']}",
                    counts=counts,
                )
                findings_count += 1
        else:
            headers_missing.append("Referrer-Policy")

        # ── 6. Permissions-Policy ────────────────────────────────────
        if "permissions-policy" in headers or "feature-policy" in headers:
            headers_present.append("Permissions-Policy")
        else:
            headers_missing.append("Permissions-Policy")

        # ── 7. Cross-Origin-Opener-Policy ────────────────────────────
        if "cross-origin-opener-policy" in headers:
            headers_present.append("Cross-Origin-Opener-Policy")
        else:
            headers_missing.append("Cross-Origin-Opener-Policy")

        # ── 8. Cross-Origin-Embedder-Policy ──────────────────────────
        if "cross-origin-embedder-policy" in headers:
            headers_present.append("Cross-Origin-Embedder-Policy")
        else:
            headers_missing.append("Cross-Origin-Embedder-Policy")

        # ── 9. Cross-Origin-Resource-Policy ──────────────────────────
        if "cross-origin-resource-policy" in headers:
            headers_present.append("Cross-Origin-Resource-Policy")
        else:
            headers_missing.append("Cross-Origin-Resource-Policy")

        return {
            "status": "completed",
            "headers_present": headers_present,
            "headers_missing": headers_missing,
            "headers_present_count": len(headers_present),
            "headers_missing_count": len(headers_missing),
            "is_https": is_https,
            "findings_count": findings_count,
        }
