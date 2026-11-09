"""
API Security Scanner Module.

Supports:
  1. PASSIVE Detection: Checks common API security patterns — rate limiting headers,
     verbose error responses, API versioning, and large unpaginated datasets.
  2. ACTIVE Detection: When explicit target authorization and active scan confirmation
     are granted, probes HTTP method support (OPTIONS, TRACE for XST risk) and verifies
     active rate limiting thresholds under rapid requests.
"""

import asyncio
import json
import re
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule


class APISecurityModule(BaseScannerModule):
    module_id = "api_security"
    module_name = "API Security"
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
            return {"checked": False, "status": "skipped", "reason": "Target unreachable"}

        headers = main_resp.headers
        body = main_resp.text or ""
        results: dict[str, Any] = {
            "checked": True,
            "status": "completed",
            "rate_limiting": {},
            "error_verbosity": {},
            "api_docs_exposed": [],
            "findings_list": [],
            "active_tested": False,
            "http_methods": [],
            "confidence": "INFORMATIONAL",
        }

        # ── 1. Passive Rate Limiting Headers ────────────────────────
        rate_headers = {
            "x-ratelimit-limit": headers.get("x-ratelimit-limit", ""),
            "x-ratelimit-remaining": headers.get("x-ratelimit-remaining", ""),
            "x-ratelimit-reset": headers.get("x-ratelimit-reset", ""),
            "retry-after": headers.get("retry-after", ""),
            "x-rate-limit-limit": headers.get("x-rate-limit-limit", ""),
        }

        has_rate_limiting = any(v for v in rate_headers.values())
        results["rate_limiting"] = {
            "detected": has_rate_limiting,
            "headers": {k: v for k, v in rate_headers.items() if v},
        }

        if not has_rate_limiting:
            await self._create_finding(
                scan,
                title="No Rate Limiting Headers Detected",
                description=(
                    "The API response does not include rate limiting headers (X-RateLimit-Limit, "
                    "X-RateLimit-Remaining, Retry-After). Without rate limiting, the API is vulnerable to "
                    "brute-force attacks, credential stuffing, and denial-of-service."
                ),
                severity="medium",
                confidence="POTENTIAL",
                owasp_category="A04:2021-Insecure Design",
                cwe_id="CWE-770",
                cvss_score=5.3,
                affected_url=target_url,
                remediation="Implement rate limiting on all API endpoints. Return X-RateLimit-* headers to inform clients of their usage limits.",
                proof_of_concept="No rate limiting headers found in HTTP response",
                counts=counts,
            )
            results["findings_list"].append("no_rate_limiting")
            results["confidence"] = "POTENTIAL"

        # ── 2. Passive Verbose Error Responses ──────────────────────
        error_indicators = [
            (r"Traceback \(most recent call last\)", "Python traceback"),
            (r"at\s+[\w.]+\.java:\d+", "Java stack trace"),
            (r"at\s+[\w.]+\s+in\s+[\w/\\]+\.cs:line\s+\d+", "C# stack trace"),
            (r"Fatal error:.*in\s+/[\w/]+\.php\s+on\s+line\s+\d+", "PHP fatal error"),
            (r"Node\.js\s+v\d+\.\d+", "Node.js version disclosure"),
            (r"Internal Server Error.*debug", "Debug mode error"),
            (r'"stack"\s*:\s*"', "JSON stack trace"),
            (r'"debug"\s*:\s*true', "Debug mode enabled"),
        ]

        for pattern, name in error_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                results["error_verbosity"][name] = True
                await self._create_finding(
                    scan,
                    title=f"Verbose Error Response: {name}",
                    description=(
                        f"The API response contains verbose error information ({name}), potentially exposing "
                        "internal application structure, file paths, and technology stack to attackers."
                    ),
                    severity="medium",
                    confidence="CONFIRMED",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-209",
                    cvss_score=5.3,
                    affected_url=target_url,
                    remediation="Disable debug mode in production. Return generic error messages to clients and log detailed errors server-side only.",
                    proof_of_concept=f"Response body contains: {name}",
                    counts=counts,
                )
                results["findings_list"].append(f"verbose_error_{name}")
                results["confidence"] = "CONFIRMED"
                break  # One finding is enough

        # ── 3. Passive Missing API Versioning ───────────────────────
        content_type = headers.get("content-type", "")
        is_api = "json" in content_type or "xml" in content_type
        if is_api:
            has_versioning = bool(re.search(r"/api/v\d+/", main_resp.url))
            has_version_header = bool(headers.get("api-version", "") or headers.get("x-api-version", ""))

            if not has_versioning and not has_version_header:
                await self._create_finding(
                    scan,
                    title="API Missing Version Identifier",
                    description="The API endpoint does not use URL-based versioning (e.g., /api/v1/) or version headers. This can lead to breaking changes affecting clients.",
                    severity="info",
                    confidence="INFORMATIONAL",
                    owasp_category="A04:2021-Insecure Design",
                    cwe_id="CWE-693",
                    cvss_score=1.5,
                    affected_url=target_url,
                    remediation="Implement API versioning via URL path (/api/v1/) or Accept/Content-Type headers.",
                    proof_of_concept=f"API URL: {main_resp.url} - no version pattern found",
                    counts=counts,
                )
                results["findings_list"].append("no_api_versioning")

        # ── 4. Passive Missing pagination ───────────────────────────
        if is_api and body:
            try:
                data = json.loads(body)
                if isinstance(data, list) and len(data) > 50:
                    await self._create_finding(
                        scan,
                        title=f"API Returns Large Unpaginated Response ({len(data)} items)",
                        description=f"The API returned {len(data)} items without pagination metadata. Large responses can cause performance issues and may expose more data than intended.",
                        severity="info",
                        confidence="INFORMATIONAL",
                        owasp_category="A04:2021-Insecure Design",
                        cwe_id="CWE-770",
                        cvss_score=2.0,
                        affected_url=target_url,
                        remediation="Implement pagination with page/limit parameters and return total count metadata.",
                        proof_of_concept=f"API returned array of {len(data)} items without pagination",
                        counts=counts,
                    )
                    results["findings_list"].append("no_pagination")
            except Exception:
                pass

        # ── 5. Active: HTTP Method Probing & Active Rate Limiting ────
        if not self.is_active_confirmed(scan):
            return results

        results["active_tested"] = True

        # 5a. Probing HTTP OPTIONS / TRACE
        try:
            # Probe TRACE method (XST test)
            trace_resp = await http_client.request("TRACE", target_url)
            await asyncio.sleep(0.05)
            results["http_methods"].append(f"TRACE:{trace_resp.status_code}")

            if trace_resp.status_code == 200 and ("host:" in (trace_resp.text or "").lower() or "user-agent:" in (trace_resp.text or "").lower()):
                results["confidence"] = "CONFIRMED"
                await self._create_finding(
                    scan,
                    title="HTTP TRACE Method Enabled (Cross-Site Tracing Risk)",
                    description=(
                        f"The server responded with HTTP 200 to an HTTP TRACE request against '{target_url}', "
                        "reflecting back request headers. This enables Cross-Site Tracing (XST) attacks, which "
                        "can allow attackers to steal HttpOnly cookies and authorization tokens."
                    ),
                    severity="medium",
                    confidence="CONFIRMED",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-693",
                    cvss_score=5.3,
                    affected_url=target_url,
                    remediation="Disable the HTTP TRACE and TRACK methods in your web server or reverse proxy configuration.",
                    proof_of_concept=f"TRACE {target_url} returned status 200 with echoed headers: {self._redact_sensitive_content((trace_resp.text or '')[:120])}",
                    counts=counts,
                )
        except Exception as e:
            results["trace_probe_error"] = str(e)

        try:
            # Probe OPTIONS method
            options_resp = await http_client.request("OPTIONS", target_url)
            await asyncio.sleep(0.05)
            allow_header = options_resp.headers.get("allow", "") or options_resp.headers.get("access-control-allow-methods", "")
            results["http_methods"].append(f"OPTIONS:{options_resp.status_code} (Allow: {allow_header})")

            dangerous_methods = [m for m in ("PUT", "DELETE", "CONNECT") if m in allow_header.upper()]
            if dangerous_methods:
                if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                    results["confidence"] = "POTENTIAL"
                await self._create_finding(
                    scan,
                    title=f"Potentially Dangerous HTTP Methods Advertised ({', '.join(dangerous_methods)})",
                    description=(
                        f"The HTTP OPTIONS Allow header advertises dangerous methods ({', '.join(dangerous_methods)}). "
                        "If unauthenticated or improperly validated, these methods may allow unauthorized resource modification or deletion."
                    ),
                    severity="low",
                    confidence="POTENTIAL",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-693",
                    cvss_score=4.0,
                    affected_url=target_url,
                    remediation="Disable unsupported or sensitive HTTP methods if not required for public clients.",
                    proof_of_concept=f"OPTIONS {target_url} returned Allow: '{allow_header}'",
                    counts=counts,
                )
        except Exception as e:
            results["options_probe_error"] = str(e)

        # 5b. Bounded Active Rate Limiting Probe (5 rapid requests)
        rate_limited_observed = False
        all_succeeded = True
        try:
            for _ in range(5):
                r = await http_client.get(target_url)
                if r.status_code == 429:
                    rate_limited_observed = True
                    break
                if r.status_code >= 500:
                    all_succeeded = False
                await asyncio.sleep(0.02)

            if rate_limited_observed:
                results["rate_limiting"]["active_verified"] = True
            elif all_succeeded and not has_rate_limiting:
                # Confirmed no rate limiting active under rapid bursts
                results["rate_limiting"]["active_verified"] = False
        except Exception:
            pass

        return results
