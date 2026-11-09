"""
A08: Software and Data Integrity Failures Checker.
"""

import re

from app.core.http_client import SafeHTTPResponse
from app.models.scan import Scan
from app.services.owasp.base_checker import BaseOWASPChecker


class A08SoftwareIntegrityChecker(BaseOWASPChecker):
    category_id = "A08:2021"
    category_name = "Software and Data Integrity Failures"

    async def run_check(
        self,
        scan: Scan,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
    ) -> None:
        body = main_resp.text

        # Find external CDN script tags missing Subresource Integrity (integrity="sha...") attributes
        script_pattern = re.compile(r'<script\b([^>]*)>', re.IGNORECASE)
        for tag_match in script_pattern.finditer(body):
            attrs = tag_match.group(1)
            src_match = re.search(r'src=["\'](https?://([^"\'/\s]+)[^"\']*)["\']', attrs, re.IGNORECASE)
            if not src_match:
                continue

            cdn_host = src_match.group(2).lower()
            if any(cdn in cdn_host for cdn in ("cdn", "unpkg", "cdnjs", "jsdelivr")):
                # Check for valid SRI hash attribute in tag attributes
                has_sri = bool(re.search(r'\bintegrity=["\']sha(?:256|384|512)-[A-Za-z0-9+/=]+["\']', attrs, re.IGNORECASE))
                if not has_sri:
                    finding = await self._finding_repo.create(
                        scan_id=scan.id,
                        target_id=scan.target_id,
                        project_id=scan.project_id,
                        user_id=scan.user_id,
                        title="Missing Subresource Integrity (SRI) Attribute on External Script",
                        description=f"External JavaScript library loaded from CDN '{cdn_host}' lacks a Subresource Integrity (SRI) cryptographic hash attribute.",
                        severity="low",
                        status="open",
                        confidence="MEDIUM",
                        category="Software Integrity",
                        owasp_category="A08:2021-Software and Data Integrity Failures",
                        cwe_id="CWE-353",
                        cvss_score=3.7,
                        affected_url=main_resp.url,
                        remediation="Add integrity='sha384-...' and crossorigin='anonymous' attributes to third-party CDN script tags.",
                        proof_of_concept=f"HTML script tag: <script{attrs[:120]}>",
                    )
                    if finding is not None:
                        counts["low"] += 1
                    return
