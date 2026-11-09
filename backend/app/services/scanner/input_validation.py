"""
Input Validation Scanner Module.

Supports:
  1. PASSIVE Detection: Inspects target URL and parameters for missing validation constraints
     and permissive parameter schemas.
  2. ACTIVE Detection: When explicit target authorization and active scan confirmation
     are granted, executes safe boundary tests (type confusion, length boundaries, and null bytes)
     to verify whether inputs are validated gracefully (HTTP 400/422) or crash the application
     with unhandled HTTP 500 Internal Server Errors.
"""

import asyncio
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule


class InputValidationModule(BaseScannerModule):
    module_id = "input_validation"
    module_name = "Input Validation Testing"
    category = "Vulnerability Testing"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        if not main_resp:
            return {"checked": False, "status": "skipped", "reason": "Target unreachable"}

        results: dict[str, Any] = {
            "checked": True,
            "status": "completed",
            "active_tested": False,
            "probes_sent": 0,
            "tested_parameters": [],
            "unhandled_errors": [],
            "confidence": "INFORMATIONAL",
        }

        # ── 1. Passive Parameter Inspection ─────────────────────────
        parsed = urlparse(main_resp.url)
        params = parse_qs(parsed.query)
        if not params:
            parsed_orig = urlparse(target_url)
            params = parse_qs(parsed_orig.query)
            if params:
                parsed = parsed_orig

        if not params:
            results["note"] = "No query parameters found for input validation testing."
            return results

        results["parameters_found"] = list(params.keys())

        # ── 2. Active Safe Input Boundary Probing ───────────────────
        if not self.is_active_confirmed(scan):
            return results

        results["active_tested"] = True
        testable_params = list(params.keys())[:3]

        for param in testable_params:
            results["tested_parameters"].append(param)
            orig_vals = params[param]
            orig_val = orig_vals[0] if orig_vals else ""

            # Define safe boundary test cases:
            # Probe A: Type confusion (string for integer or vice-versa)
            type_probe_val = "awasap_not_an_int" if orig_val.isdigit() else "12345678"
            # Probe B: Length boundary (bounded 500-char string)
            length_probe_val = "A" * 500
            # Probe C: Harmless special character boundary
            special_probe_val = "%00~!@#$%"

            boundary_probes = [
                ("type_confusion", type_probe_val),
                ("length_boundary", length_probe_val),
                ("special_chars", special_probe_val),
            ]

            for probe_type, probe_val in boundary_probes:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param] = [probe_val]
                probe_query = urlencode(mutated, doseq=True)
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))

                try:
                    results["probes_sent"] += 1
                    probe_resp = await http_client.get(probe_url)
                    await asyncio.sleep(0.05)  # Rate control

                    # Check for unhandled server crashes (HTTP 500)
                    if probe_resp.status_code == 500:
                        results["unhandled_errors"].append({
                            "param": param,
                            "probe_type": probe_type,
                            "status_code": 500,
                        })
                        results["confidence"] = "CONFIRMED"

                        await self._create_finding(
                            scan,
                            title=f"Unhandled Server Error on Malformed Input (Parameter '{param}')",
                            description=(
                                f"Active input boundary testing ({probe_type}) on parameter '{param}' triggered "
                                "an unhandled HTTP 500 Internal Server Error. The application fails to validate "
                                "input schema and crashes instead of returning a 400 Bad Request or 422 Unprocessable response."
                            ),
                            severity="medium",
                            confidence="CONFIRMED",
                            owasp_category="A04:2021-Insecure Design",
                            cwe_id="CWE-20",
                            cvss_score=5.3,
                            affected_url=probe_url,
                            remediation=(
                                "Implement strict server-side schema validation and type checking. "
                                "Catch malformed input exceptions and return clean HTTP 400 Bad Request error responses."
                            ),
                            proof_of_concept=(
                                f"Probe URL: {probe_url}\n"
                                f"Probe Type: {probe_type}\n"
                                f"Payload: {self._redact_sensitive_content(probe_val[:60])}\n"
                                f"Server Response: HTTP 500 Internal Server Error"
                            ),
                            counts=counts,
                        )
                        break  # One finding per parameter is sufficient

                except Exception as e:
                    results["active_error"] = str(e)
                    if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                        results["confidence"] = "INCONCLUSIVE"

        return results
