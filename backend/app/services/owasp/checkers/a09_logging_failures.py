"""
A09: Security Logging and Monitoring Failures Checker.

Validates that target applications employ proper transaction correlation and do not
leak internal exception stack traces in lieu of centralized secure logging.
"""

from urllib.parse import urlparse

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A09LoggingFailuresChecker(BaseOWASPChecker):
    category_id = "A09:2021"
    category_name = "Security Logging and Monitoring Failures"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        headers = main_resp.headers
        body_lower = (main_resp.text or "").lower()
        parsed = urlparse(main_resp.url)
        path_lower = parsed.path.lower()
        content_type = headers.get("content-type", "").lower()

        # 1. Missing Request Traceability / Correlation Header on API endpoints
        is_api_route = any(p in path_lower for p in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")) or "application/json" in content_type
        if is_api_route:
            correlation_headers = (
                "x-request-id",
                "x-correlation-id",
                "x-trace-id",
                "request-id",
                "traceparent",
                "x-amzn-trace-id",
            )
            has_tracking = any(h in headers for h in correlation_headers)
            if not has_tracking:
                f = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title="Missing Request Correlation and Transaction Tracing Header",
                    description=(
                        "The application API endpoint does not return a request correlation or tracking identifier header "
                        "(e.g., X-Request-ID, X-Correlation-ID). Missing transaction correlation hinders incident response, "
                        "distributed tracing, and centralized security audit logging."
                    ),
                    severity="info",
                    status="open",
                    confidence="INFORMATIONAL",
                    category="Logging & Monitoring",
                    owasp_category="A09:2021-Security Logging and Monitoring Failures",
                    cwe_id="CWE-778",
                    cvss_score=2.1,
                    affected_url=main_resp.url,
                    remediation=(
                        "Configure your web server, API gateway, or reverse proxy to generate and return a unique "
                        "'X-Request-ID' or 'X-Correlation-ID' header on all HTTP transactions for centralized audit correlation."
                    ),
                    proof_of_concept=f"GET {main_resp.url} response headers lacked transaction correlation identifiers",
                )
                if f is not None:
                    counts["info"] += 1

        # 2. Detailed Diagnostic Stack Trace / Server Exception Leakage
        stack_trace_markers = [
            ("traceback (most recent call last)", "Python Traceback"),
            ("django.core.handlers", "Django Debug Exception"),
            ("org.springframework.web", "Spring Framework Stack Trace"),
            ("at object.<anonymous>", "Node.js Stack Trace"),
            ("at module._compile", "Node.js Module Compilation Error"),
            ("werkzeug.debug", "Werkzeug Interactive Debugger"),
            ("fatal error: uncaught exception", "PHP Fatal Exception"),
            ("system.web.httpunhandledexception", "ASP.NET Unhandled Exception"),
        ]

        for marker, marker_name in stack_trace_markers:
            if marker in body_lower:
                f = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title=f"Unhandled Diagnostic Stack Trace Exposure ({marker_name})",
                    description=(
                        f"The application returned an unhandled {marker_name} containing detailed internal system diagnostic "
                        "information in the HTTP response body. This indicates missing custom error pages and inadequate production "
                        "exception handling/logging."
                    ),
                    severity="medium",
                    status="open",
                    confidence="CONFIRMED",
                    category="Logging & Monitoring",
                    owasp_category="A09:2021-Security Logging and Monitoring Failures",
                    cwe_id="CWE-209",
                    cvss_score=5.3,
                    affected_url=main_resp.url,
                    remediation=(
                        "Implement custom error-handling middleware that logs detailed exceptions to an internal, secure logging "
                        "system while presenting generic error pages without stack traces to clients."
                    ),
                    proof_of_concept=f"Response body for {main_resp.url} leaked diagnostic stack trace marker '{marker}'",
                )
                if f is not None:
                    counts["medium"] += 1
                break
