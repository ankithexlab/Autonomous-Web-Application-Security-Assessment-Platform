"""
A03: Injection Checker.
"""

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A03InjectionChecker(BaseOWASPChecker):
    category_id = "A03:2021"
    category_name = "Injection"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        body = main_resp.text.lower()

        # Passive inspection for exposed database syntax error strings in response body
        sql_error_patterns = [
            ("you have an error in your sql syntax", "MySQL"),
            ("unclosed quotation mark after the character string", "MSSQL"),
            ("pg_query(): query failed", "PostgreSQL"),
            ("sqlite3::sqlexception", "SQLite"),
            ("ora-01756: quoted string not properly terminated", "Oracle"),
        ]

        for pattern, db_name in sql_error_patterns:
            if pattern in body:
                f = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title=f"Exposed {db_name} Error Message (SQL Injection Indicator)",
                    description=f"The application returned an unhandled {db_name} database syntax error message in the HTTP response body.",
                    severity="high",
                    status="open",
                    confidence="MEDIUM",
                    category="Injection",
                    owasp_category="A03:2021-Injection",
                    cwe_id="CWE-89",
                    cvss_score=7.5,
                    affected_url=main_resp.url,
                    remediation="Use parameterized queries and suppress raw database error tracebacks in production.",
                    proof_of_concept=f"Response body for {main_resp.url} contained DB error string: '{pattern}'",
                )
                if f is not None:
                    counts["high"] += 1
                return
