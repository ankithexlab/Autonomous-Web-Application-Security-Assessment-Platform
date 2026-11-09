"""
CORS Analyzer Scanner Module.

Analyzes Cross-Origin Resource Sharing (CORS) configuration by inspecting
response headers for overly permissive or dangerous configurations.
"""

from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule


class CORSAnalyzerModule(BaseScannerModule):
    module_id = "cors_analyzer"
    module_name = "CORS Analysis"
    category = "Security Analysis"

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
            "allow_origin": headers.get("access-control-allow-origin", ""),
            "allow_credentials": headers.get("access-control-allow-credentials", ""),
            "allow_methods": headers.get("access-control-allow-methods", ""),
            "allow_headers": headers.get("access-control-allow-headers", ""),
            "expose_headers": headers.get("access-control-expose-headers", ""),
            "max_age": headers.get("access-control-max-age", ""),
            "findings": [],
        }

        allow_origin = results["allow_origin"]
        allow_creds = results["allow_credentials"].lower()

        # ── 1. Wildcard origin with credentials ─────────────────────
        if allow_origin == "*" and allow_creds == "true":
            await self._create_finding(
                scan,
                title="Critical CORS Misconfiguration: Wildcard Origin with Credentials",
                description="The server sets Access-Control-Allow-Origin to '*' alongside Access-Control-Allow-Credentials: true. This is a critical misconfiguration that allows any website to make authenticated cross-origin requests and steal sensitive data.",
                severity="critical",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-942",
                cvss_score=9.1,
                affected_url=target_url,
                remediation="Never combine wildcard origins with credentials. Validate and whitelist specific trusted origins.",
                proof_of_concept=f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                counts=counts,
            )
            results["findings"].append("wildcard_with_credentials")

        # ── 2. Wildcard origin without credentials ──────────────────
        elif allow_origin == "*":
            await self._create_finding(
                scan,
                title="Overly Permissive CORS Policy (Wildcard Origin)",
                description="Access-Control-Allow-Origin is set to wildcard '*', permitting any arbitrary origin to read responses. While less critical without credentials, this may leak sensitive API data.",
                severity="medium",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-942",
                cvss_score=5.3,
                affected_url=target_url,
                remediation="Specify trusted domain origins explicitly instead of using wildcard '*'.",
                proof_of_concept=f"Access-Control-Allow-Origin: *",
                counts=counts,
            )
            results["findings"].append("wildcard_origin")

        # ── 3. Null origin allowed ──────────────────────────────────
        if allow_origin.lower() == "null":
            await self._create_finding(
                scan,
                title="CORS Allows Null Origin",
                description="Access-Control-Allow-Origin is set to 'null'. Attackers can craft requests with a null origin (e.g., from sandboxed iframes or data URIs) to bypass CORS restrictions.",
                severity="high",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-942",
                cvss_score=7.5,
                affected_url=target_url,
                remediation="Never allow 'null' as a trusted origin. Use explicit domain whitelisting.",
                proof_of_concept=f"Access-Control-Allow-Origin: null",
                counts=counts,
            )
            results["findings"].append("null_origin")

        # ── 4. Dangerous methods allowed ────────────────────────────
        allow_methods = results["allow_methods"].upper()
        dangerous_methods = []
        for method in ("PUT", "DELETE", "PATCH"):
            if method in allow_methods:
                dangerous_methods.append(method)

        if dangerous_methods:
            await self._create_finding(
                scan,
                title=f"CORS Allows Dangerous HTTP Methods ({', '.join(dangerous_methods)})",
                description=f"The CORS policy allows destructive HTTP methods ({', '.join(dangerous_methods)}) for cross-origin requests, increasing the attack surface for CSRF and data modification attacks.",
                severity="low",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-942",
                cvss_score=3.7,
                affected_url=target_url,
                remediation="Restrict Access-Control-Allow-Methods to only necessary methods (GET, POST) for cross-origin requests.",
                proof_of_concept=f"Access-Control-Allow-Methods: {allow_methods}",
                counts=counts,
            )
            results["findings"].append("dangerous_methods")

        return results
