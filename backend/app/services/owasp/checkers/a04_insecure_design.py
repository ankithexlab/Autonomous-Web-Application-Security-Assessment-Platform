"""
A04: Insecure Design Checker.
"""

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A04InsecureDesignChecker(BaseOWASPChecker):
    category_id = "A04:2021"
    category_name = "Insecure Design"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        headers = main_resp.headers

        # Check for missing rate-limiting headers on API or login routes
        has_rate_limit = any(h in headers for h in ["x-ratelimit-limit", "retry-after", "ratelimit-limit"])
        if not has_rate_limit and ("/api/" in main_resp.url or "/login" in main_resp.url or "/auth" in main_resp.url):
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing Anti-Automation / Rate-Limiting Controls",
                description="Sensitive API or authentication endpoints lack rate-limiting response headers, exposing routes to automated abuse.",
                severity="low",
                status="open",
                confidence="LOW",
                category="Insecure Design",
                owasp_category="A04:2021-Insecure Design",
                cwe_id="CWE-799",
                cvss_score=3.1,
                affected_url=main_resp.url,
                remediation="Implement rate limiting and throttle headers (e.g., X-RateLimit-Limit, Retry-After) on sensitive application routes.",
                proof_of_concept=f"Headers for {main_resp.url} do not include rate limit policies",
            )
            if f is not None:
                counts["low"] += 1
