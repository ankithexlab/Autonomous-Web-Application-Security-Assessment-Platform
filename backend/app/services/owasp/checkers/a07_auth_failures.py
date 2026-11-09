"""
A07: Identification and Authentication Failures Checker.
"""

import re
from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A07AuthFailuresChecker(BaseOWASPChecker):
    category_id = "A07:2021"
    category_name = "Identification and Authentication Failures"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        headers = main_resp.headers
        body = main_resp.text.lower()

        # 1. Inspect Set-Cookie flags
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            cookie_lower = set_cookie.lower()
            missing_flags = []
            if main_resp.url.startswith("https://") and "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                # Redact raw cookie values to avoid credential leakage in reports
                redacted_cookie = re.sub(r'=([^;]+)', '=<redacted>', set_cookie)
                f = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title="Insecure Session Cookie Attributes",
                    description=f"Session cookies set by the web server lack essential security attributes: {', '.join(missing_flags)}.",
                    severity="medium",
                    status="open",
                    confidence="HIGH",
                    category="Authentication",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    cwe_id="CWE-614",
                    cvss_score=4.8,
                    affected_url=main_resp.url,
                    remediation="Set Secure, HttpOnly, and SameSite=Lax (or Strict) attributes on all application cookies.",
                    proof_of_concept=f"Set-Cookie header: '{redacted_cookie}'",
                )
                if f is not None:
                    counts["medium"] += 1

        # 2. Login Form Served over Unencrypted HTTP
        if main_resp.url.startswith("http://") and ('type="password"' in body or 'name="password"' in body):
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Login Form Transmitted over Cleartext HTTP",
                description="An authentication login form containing password input fields is transmitted over unencrypted HTTP.",
                severity="high",
                status="open",
                confidence="HIGH",
                category="Authentication",
                owasp_category="A07:2021-Identification and Authentication Failures",
                cwe_id="CWE-319",
                cvss_score=7.4,
                affected_url=main_resp.url,
                remediation="Enforce HTTPS for all authentication and login pages.",
                proof_of_concept=f"GET {main_resp.url} served HTML password input over cleartext HTTP",
            )
            if f is not None:
                counts["high"] += 1
