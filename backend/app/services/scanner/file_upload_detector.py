"""
File Upload Detector Scanner Module.

PASSIVE detection — scans HTML for file upload forms and checks for
client-side-only validation, missing type restrictions, and upload surfaces.
"""

import re
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule


class FileUploadDetectorModule(BaseScannerModule):
    module_id = "file_upload"
    module_name = "File Upload Detection"
    category = "Vulnerability Detection"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        if not main_resp:
            return {"checked": False}

        body = main_resp.text or ""
        results: dict[str, Any] = {
            "checked": True,
            "upload_forms_found": 0,
            "upload_details": [],
        }

        # ── Find file upload inputs ─────────────────────────────────
        upload_inputs = re.findall(
            r'<input[^>]+type\s*=\s*["\']?file["\']?[^>]*>',
            body,
            re.IGNORECASE,
        )

        results["upload_forms_found"] = len(upload_inputs)

        for input_tag in upload_inputs:
            detail: dict[str, Any] = {
                "has_accept": False,
                "accept_value": "",
                "has_name": False,
                "name_value": "",
            }

            # Check accept attribute
            accept_match = re.search(r'accept\s*=\s*["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
            if accept_match:
                detail["has_accept"] = True
                detail["accept_value"] = accept_match.group(1)

            # Check name attribute
            name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', input_tag, re.IGNORECASE)
            if name_match:
                detail["has_name"] = True
                detail["name_value"] = name_match.group(1)

            results["upload_details"].append(detail)

        # ── Report findings ─────────────────────────────────────────
        if upload_inputs:
            no_accept = [d for d in results["upload_details"] if not d["has_accept"]]

            if no_accept:
                await self._create_finding(
                    scan,
                    title=f"File Upload Without Type Restriction ({len(no_accept)} inputs)",
                    description=f"Found {len(no_accept)} file upload input(s) without an 'accept' attribute to restrict file types. Without server-side validation, attackers may upload malicious files (shells, scripts, malware).",
                    severity="medium",
                    owasp_category="A04:2021-Insecure Design",
                    cwe_id="CWE-434",
                    cvss_score=6.5,
                    affected_url=target_url,
                    remediation="Add 'accept' attributes for client-side filtering AND implement server-side file type validation, content scanning, and storage isolation.",
                    proof_of_concept=f"Found {len(no_accept)} <input type='file'> without accept attribute",
                    counts=counts,
                )
            else:
                await self._create_finding(
                    scan,
                    title=f"File Upload Surface Detected ({len(upload_inputs)} inputs)",
                    description=f"Found {len(upload_inputs)} file upload form(s). File uploads are a common attack vector — ensure server-side validation is properly implemented.",
                    severity="info",
                    owasp_category="A04:2021-Insecure Design",
                    cwe_id="CWE-434",
                    cvss_score=2.0,
                    affected_url=target_url,
                    remediation="Ensure server-side file type validation, size limits, filename sanitization, and antivirus scanning for uploaded files.",
                    proof_of_concept=f"Found {len(upload_inputs)} <input type='file'> elements",
                    counts=counts,
                )

        # ── Check for multipart form encoding ──────────────────────
        multipart_forms = re.findall(
            r'<form[^>]+enctype\s*=\s*["\']multipart/form-data["\']',
            body,
            re.IGNORECASE,
        )
        results["multipart_forms"] = len(multipart_forms)

        return results
