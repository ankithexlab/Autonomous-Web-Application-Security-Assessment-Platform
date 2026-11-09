"""
Rate Limit Detector Scanner Module.

Checks for rate limiting protections on the target by analyzing response
headers and identifying authentication endpoints that may lack brute-force
protection.
"""

import re
from typing import Any
from urllib.parse import urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# Authentication endpoints to check
AUTH_PATHS = [
    "/login", "/signin", "/sign-in", "/auth/login",
    "/api/login", "/api/auth/login", "/api/v1/auth/login",
    "/api/auth/token", "/oauth/token", "/token",
]


class RateLimitDetectorModule(BaseScannerModule):
    module_id = "rate_limit"
    module_name = "Rate Limiting Detection"
    category = "Vulnerability Detection"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        if not main_resp:
            return {"checked": False}

        headers = main_resp.headers
        results: dict[str, Any] = {
            "checked": True,
            "main_page_rate_limiting": {},
            "auth_endpoints": [],
            "findings_list": [],
        }

        # ── 1. Check main response for rate limit headers ───────────
        rate_limit_headers = {
            "x-ratelimit-limit": headers.get("x-ratelimit-limit", ""),
            "x-ratelimit-remaining": headers.get("x-ratelimit-remaining", ""),
            "x-ratelimit-reset": headers.get("x-ratelimit-reset", ""),
            "x-rate-limit-limit": headers.get("x-rate-limit-limit", ""),
            "x-rate-limit-remaining": headers.get("x-rate-limit-remaining", ""),
            "retry-after": headers.get("retry-after", ""),
            "ratelimit-limit": headers.get("ratelimit-limit", ""),
            "ratelimit-remaining": headers.get("ratelimit-remaining", ""),
        }

        active_headers = {k: v for k, v in rate_limit_headers.items() if v}
        results["main_page_rate_limiting"] = {
            "detected": bool(active_headers),
            "headers": active_headers,
        }

        # ── 2. Check auth endpoints for rate limiting ───────────────
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for auth_path in AUTH_PATHS:
            auth_url = f"{origin}{auth_path}"
            try:
                resp = await http_client.get(auth_url)
                # Only check endpoints that exist (not 404)
                if resp.status_code not in (404, 400):
                    auth_rate_headers = {
                        k: resp.headers.get(k, "")
                        for k in ("x-ratelimit-limit", "x-ratelimit-remaining", "retry-after", "ratelimit-limit")
                    }
                    has_rate_limit = any(v for v in auth_rate_headers.values())

                    results["auth_endpoints"].append({
                        "path": auth_path,
                        "status": resp.status_code,
                        "rate_limited": has_rate_limit,
                    })

                    if not has_rate_limit and resp.status_code in (200, 401, 403, 405, 422):
                        await self._create_finding(
                            scan,
                            title=f"Authentication Endpoint Without Rate Limiting ({auth_path})",
                            description=f"The authentication endpoint '{auth_path}' (HTTP {resp.status_code}) does not return rate limiting headers. This makes it vulnerable to credential brute-force and stuffing attacks.",
                            severity="medium",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cwe_id="CWE-307",
                            cvss_score=5.9,
                            affected_url=auth_url,
                            remediation="Implement rate limiting on authentication endpoints (e.g., max 5 attempts per minute). Use account lockout, CAPTCHA, or progressive delays after failed attempts.",
                            proof_of_concept=f"GET {auth_url} returned HTTP {resp.status_code} without rate limiting headers",
                            counts=counts,
                        )
                        results["findings_list"].append(f"no_rate_limit_{auth_path}")
                        break  # One finding is enough
            except Exception:
                continue

        return results
