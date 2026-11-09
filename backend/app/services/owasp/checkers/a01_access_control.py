"""
A01: Broken Access Control Checker.
"""

from urllib.parse import urlparse

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A01AccessControlChecker(BaseOWASPChecker):
    category_id = "A01:2021"
    category_name = "Broken Access Control"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        parsed = urlparse(main_resp.url)
        path = parsed.path.lower()

        # Check for exposed sensitive files or routes in URL path
        sensitive_paths = ["/.env", "/.git", "/wp-config.php", "/config.json", "/admin/config"]
        for sp in sensitive_paths:
            if sp in path or main_resp.text.find("DB_PASSWORD=") != -1 or main_resp.text.find("SECRET_KEY=") != -1:
                finding = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title="Exposed Environment or System Secrets File",
                    description=f"The application path '{sp}' or response content exposes environment configurations or secret credentials.",
                    severity="critical",
                    status="open",
                    confidence="HIGH",
                    category="Access Control",
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_id="CWE-538",
                    cvss_score=9.1,
                    affected_url=main_resp.url,
                    remediation="Block public access to .env, .git, and configuration files via web server directives.",
                    proof_of_concept=f"GET {main_resp.url} disclosed sensitive environment key patterns",
                )
                if finding is not None:
                    counts["critical"] += 1
                return
