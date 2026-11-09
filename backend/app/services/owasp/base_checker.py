"""
Base OWASP Checker Class.

Abstract base class for all category-specific OWASP checkers (A01 - A10).
"""

from abc import ABC, abstractmethod
from typing import Any

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.repositories.finding import FindingRepository


class BaseOWASPChecker(ABC):
    """Abstract base class for OWASP category-specific checkers."""

    category_id: str
    category_name: str

    def __init__(self, finding_repo: FindingRepository) -> None:
        self._finding_repo = finding_repo

    @abstractmethod
    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        """
        Execute passive security checks against HTTP response metadata and log findings.
        """
        pass
