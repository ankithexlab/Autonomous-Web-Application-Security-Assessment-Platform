"""
A06: Vulnerable and Outdated Components Checker.
"""

import re

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A06VulnerableComponentsChecker(BaseOWASPChecker):
    category_id = "A06:2021"
    category_name = "Vulnerable and Outdated Components"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        body = main_resp.text.lower()
        headers = main_resp.headers

        # Fingerprint known outdated frontend library signatures
        outdated_rules = [
            (r"jquery[/-](1\.[0-9]+\.[0-9]+|2\.[0-9]+\.[0-9]+)", "jQuery 1.x / 2.x", "CWE-937", "CVE-2015-9251 (XSS in jQuery)"),
            (r"bootstrap[/-](3\.[0-3]\.[0-9]+)", "Bootstrap 3.3.x", "CWE-937", "CVE-2018-14041 (XSS in Bootstrap)"),
        ]

        for pattern, lib_name, cwe, cve_info in outdated_rules:
            if re.search(pattern, body):
                f = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title=f"Outdated & Vulnerable Frontend Component Detected ({lib_name})",
                    description=f"The application includes an outdated version of {lib_name} known to contain public security vulnerabilities ({cve_info}).",
                    severity="medium",
                    status="open",
                    confidence="MEDIUM",
                    category="Vulnerable Components",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    cwe_id=cwe,
                    cvss_score=6.1,
                    affected_url=main_resp.url,
                    remediation=f"Upgrade {lib_name} to the latest stable release.",
                    proof_of_concept=f"HTML script tag matching signature '{pattern}'",
                )
                if f is not None:
                    counts["medium"] += 1
                return
