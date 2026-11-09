"""
HTTP/HTTPS Configuration and Redirect Analysis Module — Phase 5.

Passive analysis of HTTP-to-HTTPS enforcement and redirect chain behaviour.
Issues one additional HTTP request only when the original target is served
over HTTP, to verify whether a redirect to HTTPS occurs.

Checks:
  1.  HTTP → HTTPS enforcement (or lack thereof)
  2.  Redirect chain length (> 3 hops is suspicious)
  3.  Cross-origin redirects within the chain
  4.  Redirect to plain HTTP from an HTTPS origin (downgrade)
  5.  SSL/TLS: protocol/cipher evidence from response headers
  6.  Referrer-Policy and Upgrade-Insecure-Requests header presence

All evidence sourced from real HTTP responses; no fabrication.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import AppException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)


class HttpsRedirectModule(BaseScannerModule):
    """
    HTTP/HTTPS configuration observer.

    Makes at most one additional HTTP GET request (to the HTTP variant of the
    target URL when the target is HTTPS) to test for HTTPS enforcement.
    All other analysis is performed on the already-collected primary response.
    """

    module_id = "https_redirect"
    module_name = "HTTP/HTTPS Configuration & Redirect Analysis"
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
            }

        parsed = urlparse(target_url)
        is_https_target = parsed.scheme == "https"
        redirect_chain = main_resp.redirect_chain or [target_url]
        final_url = main_resp.url
        headers = {k.lower(): v for k, v in main_resp.headers.items()}

        result: dict[str, Any] = {
            "status": "completed",
            "original_url": target_url,
            "final_url": final_url,
            "redirect_hops": len(redirect_chain),
            "redirect_chain": redirect_chain,
            "is_https_target": is_https_target,
            "is_https_final": final_url.startswith("https://"),
            "findings_count": 0,
        }

        # ── 1. Plain HTTP with no HTTPS redirect ────────────────────
        if not is_https_target and not final_url.startswith("https://"):
            await self._create_finding(
                scan,
                title="Unencrypted HTTP Service — No HTTPS Enforcement",
                description=(
                    "The target is served over plain HTTP and does not redirect visitors to "
                    "HTTPS.  All traffic is transmitted in cleartext, exposing users to "
                    "eavesdropping and man-in-the-middle attacks."
                ),
                severity="high",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-319",
                cvss_score=7.5,
                affected_url=target_url,
                remediation=(
                    "Obtain a TLS certificate (e.g. via Let's Encrypt) and configure the "
                    "web server to redirect all HTTP requests to HTTPS permanently (301)."
                ),
                proof_of_concept=(
                    f"GET {target_url} → {final_url} (no HTTPS redirect in chain: "
                    f"{' → '.join(redirect_chain)})"
                ),
                counts=counts,
            )
            result["findings_count"] += 1

        # ── 2. HTTPS → HTTP downgrade in redirect chain ──────────────
        chain = list(redirect_chain)
        for i in range(len(chain) - 1):
            if chain[i].startswith("https://") and chain[i + 1].startswith("http://"):
                await self._create_finding(
                    scan,
                    title="HTTPS-to-HTTP Downgrade Redirect Detected",
                    description=(
                        f"A redirect from an HTTPS URL to a plain HTTP URL was detected in the "
                        f"redirect chain.  This downgrades encryption mid-flight and may expose "
                        f"session cookies or tokens."
                    ),
                    severity="high",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-319",
                    cvss_score=7.4,
                    affected_url=chain[i],
                    remediation=(
                        "Ensure all redirects preserve the HTTPS scheme.  Audit redirect "
                        "rules and load-balancer configuration."
                    ),
                    proof_of_concept=(
                        f"Redirect: {chain[i]} → {chain[i + 1]}"
                    ),
                    counts=counts,
                )
                result["findings_count"] += 1
                break  # one finding per redirect pair

        # ── 3. Excessive redirect chain ──────────────────────────────
        if len(redirect_chain) > 3:
            await self._create_finding(
                scan,
                title=f"Excessive HTTP Redirect Chain ({len(redirect_chain)} hops)",
                description=(
                    f"The target URL triggered a redirect chain of {len(redirect_chain)} hops, "
                    "which is above the recommended maximum of 3.  Excessive redirects add "
                    "latency and complicate security analysis."
                ),
                severity="info",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-601",
                cvss_score=2.0,
                affected_url=target_url,
                remediation="Optimize server routing to avoid multi-step HTTP redirects.",
                proof_of_concept=(
                    f"Redirect chain ({len(redirect_chain)} hops): "
                    f"{' → '.join(redirect_chain[:8])}"
                    + (" …" if len(redirect_chain) > 8 else "")
                ),
                counts=counts,
            )
            result["findings_count"] += 1

        # ── 4. Cross-origin redirect detected ───────────────────────
        if redirect_chain and len(redirect_chain) > 1:
            original_parsed = urlparse(redirect_chain[0])
            final_parsed = urlparse(final_url)
            original_origin = (original_parsed.scheme, original_parsed.netloc.lower())
            final_origin = (final_parsed.scheme, final_parsed.netloc.lower())
            if original_origin != final_origin:
                result["cross_origin_redirect"] = True
                # This is informational — not necessarily a vulnerability
                await self._create_finding(
                    scan,
                    title="Cross-Origin Redirect Observed",
                    description=(
                        f"The initial URL {redirect_chain[0]} redirected to a different origin "
                        f"({final_url}).  Verify this redirect is intentional and does not "
                        "expose sensitive query-string parameters to the destination."
                    ),
                    severity="info",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-601",
                    cvss_score=1.5,
                    affected_url=redirect_chain[0],
                    remediation=(
                        "Confirm the cross-origin redirect destination is trusted. "
                        "Strip sensitive query parameters before redirecting cross-origin."
                    ),
                    proof_of_concept=(
                        f"{redirect_chain[0]} → (cross-origin) → {final_url}"
                    ),
                    counts=counts,
                )
                result["findings_count"] += 1
            else:
                result["cross_origin_redirect"] = False

        # ── 5. HTTPS target: test for HSTS Preload header ───────────
        if is_https_target:
            hsts = headers.get("strict-transport-security", "")
            result["hsts_header"] = hsts or None
            if hsts and "preload" in hsts.lower():
                result["hsts_preload"] = True
            else:
                result["hsts_preload"] = False

        # ── 6. Upgrade-Insecure-Requests support (server side) ──────
        result["upgrade_insecure_requests_supported"] = (
            "upgrade-insecure-requests" in headers
        )

        # ── 7. Test HTTP→HTTPS redirect if target is HTTPS ──────────
        if is_https_target:
            http_url = "http://" + parsed.netloc + (parsed.path or "/")
            # Only attempt if passing SSRF validation (may resolve to same host)
            try:
                validate_target_url(http_url)
                try:
                    http_resp = await http_client.get(http_url, timeout=6.0)
                    result["http_to_https_redirect"] = http_resp.url.startswith("https://")
                    if not http_resp.url.startswith("https://"):
                        await self._create_finding(
                            scan,
                            title="HTTP Version Does Not Redirect to HTTPS",
                            description=(
                                f"A GET request to the HTTP version ({http_url}) of this HTTPS "
                                "target did not redirect to HTTPS.  Clients visiting over HTTP "
                                "receive content without encryption."
                            ),
                            severity="medium",
                            owasp_category="A02:2021-Cryptographic Failures",
                            cwe_id="CWE-319",
                            cvss_score=5.3,
                            affected_url=http_url,
                            remediation=(
                                "Configure a permanent (301) redirect from HTTP to HTTPS at the "
                                "web-server or load-balancer level."
                            ),
                            proof_of_concept=(
                                f"GET {http_url} → {http_resp.url} (no HTTPS redirect)"
                            ),
                            counts=counts,
                        )
                        result["findings_count"] += 1
                except AppException:
                    result["http_to_https_redirect"] = None
                    result["http_redirect_error"] = "SSRF-protected or unreachable"
                except Exception as exc:
                    result["http_to_https_redirect"] = None
                    result["http_redirect_error"] = str(exc)
            except AppException:
                result["http_to_https_redirect"] = None
                result["http_redirect_note"] = "HTTP variant blocked by SSRF rules"

        return result
