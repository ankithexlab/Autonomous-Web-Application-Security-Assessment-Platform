"""
Base Scanner Module.

Abstract base class for all scanner modules (Info Gathering, Security Analysis,
Additional Vulnerability Detection).  Mirrors the BaseOWASPChecker pattern but
accepts the target URL and HTTP client directly so modules can make their own
requests (e.g. DNS queries, WHOIS, directory probing).
"""

import json
import re
from abc import ABC, abstractmethod
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.repositories.finding import FindingRepository


class BaseScannerModule(ABC):
    """Abstract base class for scanner modules."""

    module_id: str = ""
    module_name: str = ""
    category: str = ""

    def __init__(self, finding_repo: FindingRepository) -> None:
        self._finding_repo = finding_repo

    @staticmethod
    def is_active_confirmed(scan: Scan) -> bool:
        """
        Check whether explicit active scan confirmation has been granted for this scan.
        Active vulnerability probes are strictly prohibited without explicit user confirmation.
        """
        if not scan or not scan.config_json:
            return False
        try:
            cfg = json.loads(scan.config_json)
            if isinstance(cfg, dict):
                return bool(cfg.get("active_confirmed") or cfg.get("active_scan_confirmed"))
        except Exception:
            pass
        return False

    @staticmethod
    def _redact_sensitive_content(text: str) -> str:
        """
        Redact sensitive tokens, passwords, and authorization keys from findings evidence.
        """
        if not text:
            return ""
        # Redact Bearer tokens: "Bearer <token>"
        redacted = re.sub(
            r"(?i)\bbearer\s+([a-zA-Z0-9_\-\.]{6,})",
            r"Bearer [REDACTED]",
            text,
        )
        # Redact key-value secrets: api_key=..., password: ..., token: ...
        redacted = re.sub(
            r"(?i)\b(api[_-]?key|secret|password|passwd|token|auth)\b\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{4,})['\"]?",
            r"\1: [REDACTED]",
            redacted,
        )
        # Redact JWT tokens
        redacted = re.sub(
            r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
            "[REDACTED_JWT]",
            redacted,
        )
        return redacted

    @abstractmethod
    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        """
        Execute the scanner module and return structured results.

        Args:
            scan: The current Scan ORM object.
            target_url: The validated target URL.
            main_resp: The primary HTTP response (may be None if unreachable).
            http_client: Safe HTTP client for making additional requests.
            counts: Severity counts dict to increment.

        Returns:
            A dict of structured results for this module.
        """
        ...

    async def _create_finding(
        self,
        scan: Scan,
        *,
        title: str,
        description: str,
        severity: str = "info",
        status: str = "open",
        confidence: str = "HIGH",
        category: str | None = None,
        owasp_category: str | None = None,
        cwe_id: str | None = None,
        cvss_score: float | None = None,
        affected_url: str | None = None,
        remediation: str | None = None,
        proof_of_concept: str | None = None,
        counts: dict[str, int] | None = None,
    ) -> None:
        """Helper to create a finding and bump the severity counter."""
        safe_poc = self._redact_sensitive_content(proof_of_concept or "") if proof_of_concept else None
        safe_desc = self._redact_sensitive_content(description)

        finding = await self._finding_repo.create(
            scan_id=scan.id,
            target_id=scan.target_id,
            project_id=scan.project_id,
            user_id=scan.user_id,
            title=title,
            description=safe_desc,
            severity=severity,
            status=status,
            confidence=confidence,
            category=category or self.category,
            owasp_category=owasp_category,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            affected_url=affected_url,
            remediation=remediation,
            proof_of_concept=safe_poc,
        )
        if finding is not None and counts is not None:
            counts[severity] = counts.get(severity, 0) + 1
