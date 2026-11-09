"""
A10: Server-Side Request Forgery (SSRF) Checker.
"""

from urllib.parse import parse_qs, urlparse

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A10SSRFChecker(BaseOWASPChecker):
    category_id = "A10:2021"
    category_name = "Server-Side Request Forgery (SSRF)"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        parsed = urlparse(main_resp.url)
        params = parse_qs(parsed.query)

        # Inspect query parameter names for SSRF acceptor patterns
        ssrf_param_names = ["url", "dest", "destination", "feed", "uri", "target", "path", "redirect_to", "fetch"]
        matched_params = [p for p in params.keys() if p.lower() in ssrf_param_names]

        if matched_params:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="URL Destination Parameter Detected (Potential SSRF Vector)",
                description=f"The application accepts URL destination query parameters ({', '.join(matched_params)}) which may be vulnerable to Server-Side Request Forgery (SSRF) if unvalidated.",
                severity="low",
                status="open",
                confidence="MEDIUM",
                category="SSRF",
                owasp_category="A10:2021-Server-Side Request Forgery (SSRF)",
                cwe_id="CWE-918",
                cvss_score=3.9,
                affected_url=main_resp.url,
                remediation="Enforce strict allowlists and IP resolution checks before fetching external resources requested via URL parameters.",
                proof_of_concept=f"GET {main_resp.url} contained URL parameter keys: {', '.join(matched_params)}",
            )
            if f is not None:
                counts["low"] += 1
