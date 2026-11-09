"""
OWASP Engine Orchestrator.

Registers and runs all OWASP Top 10 category checkers (A01 - A10) against HTTP response metadata.
Enforces per-checker fault isolation so failure in a single category checker cannot abort others.
"""

import logging
from typing import Any

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.repositories.finding import FindingRepository
from app.services.owasp.base_checker import BaseOWASPChecker
from app.services.owasp.checkers.a01_access_control import A01AccessControlChecker
from app.services.owasp.checkers.a02_crypto_failures import A02CryptoFailuresChecker
from app.services.owasp.checkers.a03_injection import A03InjectionChecker
from app.services.owasp.checkers.a04_insecure_design import A04InsecureDesignChecker
from app.services.owasp.checkers.a05_misconfiguration import A05MisconfigurationChecker
from app.services.owasp.checkers.a06_vulnerable_components import A06VulnerableComponentsChecker
from app.services.owasp.checkers.a07_auth_failures import A07AuthFailuresChecker
from app.services.owasp.checkers.a08_software_integrity import A08SoftwareIntegrityChecker
from app.services.owasp.checkers.a09_logging_failures import A09LoggingFailuresChecker
from app.services.owasp.checkers.a10_ssrf import A10SSRFChecker

logger = logging.getLogger("awsap.owasp.engine")


class OWASPEngine:
    """Orchestrator for OWASP Top 10 security assessment checkers."""

    def __init__(self, finding_repo: FindingRepository) -> None:
        self._finding_repo = finding_repo
        self.checkers: list[BaseOWASPChecker] = [
            A01AccessControlChecker(finding_repo),
            A02CryptoFailuresChecker(finding_repo),
            A03InjectionChecker(finding_repo),
            A04InsecureDesignChecker(finding_repo),
            A05MisconfigurationChecker(finding_repo),
            A06VulnerableComponentsChecker(finding_repo),
            A07AuthFailuresChecker(finding_repo),
            A08SoftwareIntegrityChecker(finding_repo),
            A09LoggingFailuresChecker(finding_repo),
            A10SSRFChecker(finding_repo),
        ]

    async def execute_owasp_checks(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        """
        Run all registered category checkers sequentially with per-checker fault isolation.
        Returns a dictionary summary of executed categories and statuses.
        """
        results: dict[str, Any] = {
            "total_checkers": len(self.checkers),
            "executed": 0,
            "errors": 0,
            "categories": {},
        }

        for checker in self.checkers:
            cat_id = getattr(checker, "category_id", "A00")
            cat_name = getattr(checker, "category_name", "Unknown")
            try:
                await checker.run_check(scan, main_resp, counts)
                results["executed"] += 1
                results["categories"][cat_id] = {
                    "name": cat_name,
                    "status": "completed",
                }
            except Exception as e:
                logger.error(f"OWASP checker {cat_id} ({cat_name}) failed: {e}", exc_info=True)
                results["errors"] += 1
                results["categories"][cat_id] = {
                    "name": cat_name,
                    "status": "error",
                    "error": str(e),
                }

        return results
