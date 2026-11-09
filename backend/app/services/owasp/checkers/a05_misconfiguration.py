"""
A05: Security Misconfiguration Checker.
"""

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A05MisconfigurationChecker(BaseOWASPChecker):
    category_id = "A05:2021"
    category_name = "Security Misconfiguration"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        headers = main_resp.headers

        # 1. Missing Content-Security-Policy Header
        if "content-security-policy" not in headers:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing Content-Security-Policy Header",
                description="The target does not declare a Content-Security-Policy (CSP) response header, increasing susceptibility to XSS and data injection attacks.",
                severity="low",
                status="open",
                confidence="HIGH",
                category="Security Headers",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-693",
                cvss_score=3.8,
                affected_url=main_resp.url,
                remediation="Configure a restrictive Content-Security-Policy header (e.g. default-src 'self').",
                proof_of_concept=f"Headers for {main_resp.url} missing Content-Security-Policy",
            )
            if f is not None:
                counts["low"] += 1

        # 2. Missing X-Frame-Options Header
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing Anti-Clickjacking Protection (X-Frame-Options)",
                description="The application does not declare X-Frame-Options, permitting Clickjacking attacks via iframe embedding.",
                severity="low",
                status="open",
                confidence="HIGH",
                category="Security Headers",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1021",
                cvss_score=3.4,
                affected_url=main_resp.url,
                remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                proof_of_concept=f"Headers for {main_resp.url} missing X-Frame-Options",
            )
            if f is not None:
                counts["low"] += 1

        # 3. Missing X-Content-Type-Options Header
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing X-Content-Type-Options Header",
                description="X-Content-Type-Options header is missing or not set to 'nosniff', allowing MIME-sniffing exploits.",
                severity="info",
                status="open",
                confidence="HIGH",
                category="Security Headers",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-693",
                cvss_score=2.6,
                affected_url=main_resp.url,
                remediation="Set 'X-Content-Type-Options: nosniff' on response headers.",
                proof_of_concept=f"X-Content-Type-Options header: '{headers.get('x-content-type-options', 'NONE')}'",
            )
            if f is not None:
                counts["info"] += 1

        # 4. Overly Permissive CORS Policy (Wildcard *)
        cors_origin = headers.get("access-control-allow-origin", "")
        if cors_origin == "*":
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Overly Permissive Cross-Origin Resource Sharing (CORS) Policy",
                description="Access-Control-Allow-Origin header is set to wildcard '*', permitting any arbitrary origin to read resource responses.",
                severity="medium",
                status="open",
                confidence="HIGH",
                category="CORS Security",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-942",
                cvss_score=5.3,
                affected_url=main_resp.url,
                remediation="Specify trusted domain origins explicitly instead of using wildcard '*'.",
                proof_of_concept=f"Access-Control-Allow-Origin header set to '*'",
            )
            if f is not None:
                counts["medium"] += 1
