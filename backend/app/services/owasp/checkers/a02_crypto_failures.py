"""
A02: Cryptographic Failures Checker.
"""

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A02CryptoFailuresChecker(BaseOWASPChecker):
    category_id = "A02:2021"
    category_name = "Cryptographic Failures"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        headers = main_resp.headers

        # 1. Cleartext HTTP Check
        if main_resp.url.startswith("http://"):
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Unencrypted HTTP Transmission",
                description="The target application communicates over plain unencrypted HTTP, permitting wiretapping and MitM interception.",
                severity="high",
                status="open",
                confidence="HIGH",
                category="Encryption",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-319",
                cvss_score=7.5,
                affected_url=main_resp.url,
                remediation="Enforce HTTPS across all application routes and configure HTTP-to-HTTPS redirects.",
                proof_of_concept=f"GET {main_resp.url} served over HTTP",
            )
            if f is not None:
                counts["high"] += 1

        # 2. Missing Strict-Transport-Security (HSTS) on HTTPS
        if main_resp.url.startswith("https://") and "strict-transport-security" not in headers:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing HTTP Strict-Transport-Security (HSTS)",
                description="The HTTPS web application does not specify an HSTS header, leaving users vulnerable to SSL stripping attacks.",
                severity="medium",
                status="open",
                confidence="HIGH",
                category="Encryption",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-523",
                cvss_score=5.3,
                affected_url=main_resp.url,
                remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                proof_of_concept=f"HTTPS response headers for {main_resp.url} missing Strict-Transport-Security",
            )
            if f is not None:
                counts["medium"] += 1
