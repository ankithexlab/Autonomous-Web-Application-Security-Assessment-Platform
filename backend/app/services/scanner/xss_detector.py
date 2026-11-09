"""
XSS Detector Scanner Module.

Supports:
  1. PASSIVE Detection: Scans HTTP response bodies for DOM-based XSS sinks,
     missing output encoding indicators, and excessive inline event handlers.
  2. ACTIVE Detection: When explicit target authorization and active scan confirmation
     are granted, injects harmless unique canary tokens (e.g. awasap_xss_<id>) to test
     contextual reflection and output encoding without executing malicious scripts.
"""

import asyncio
import html
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import uuid

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# DOM XSS sinks — JavaScript functions that can execute arbitrary code
DOM_XSS_SINKS = [
    (r"\.innerHTML\s*=", "innerHTML assignment"),
    (r"\.outerHTML\s*=", "outerHTML assignment"),
    (r"document\.write\s*\(", "document.write()"),
    (r"document\.writeln\s*\(", "document.writeln()"),
    (r"eval\s*\(", "eval()"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout with string"),
    (r"setInterval\s*\(\s*['\"]", "setInterval with string"),
    (r"new\s+Function\s*\(", "new Function()"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
    (r"window\.location\s*=", "window.location assignment"),
    (r"document\.location\s*=", "document.location assignment"),
    (r"location\.href\s*=", "location.href assignment"),
]

# DOM XSS sources — user-controllable inputs
DOM_XSS_SOURCES = [
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"document\.referrer", "document.referrer"),
    (r"document\.URL", "document.URL"),
    (r"window\.name", "window.name"),
    (r"document\.cookie", "document.cookie (as source)"),
    (r"postMessage", "postMessage handler"),
]


class XSSDetectorModule(BaseScannerModule):
    module_id = "xss_detector"
    module_name = "XSS Detection"
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
            return {"checked": False, "status": "skipped", "reason": "Target unreachable"}

        body = main_resp.text or ""
        headers = main_resp.headers
        results: dict[str, Any] = {
            "checked": True,
            "status": "completed",
            "dom_sinks_found": [],
            "dom_sources_found": [],
            "findings_list": [],
            "active_tested": False,
            "canary_probes_sent": 0,
            "reflected_params": [],
            "vulnerable_params": [],
            "confidence": "INFORMATIONAL",
        }

        # ── 1. DOM-based XSS Sink Analysis ──────────────────────────
        for pattern, sink_name in DOM_XSS_SINKS:
            matches = re.findall(pattern, body)
            if matches:
                results["dom_sinks_found"].append({
                    "sink": sink_name,
                    "count": len(matches),
                })

        # ── 2. DOM-based XSS Source Analysis ────────────────────────
        for pattern, source_name in DOM_XSS_SOURCES:
            matches = re.findall(pattern, body)
            if matches:
                results["dom_sources_found"].append({
                    "source": source_name,
                    "count": len(matches),
                })

        # Report if both sinks AND sources are present (high risk)
        if results["dom_sinks_found"] and results["dom_sources_found"]:
            sinks = ", ".join(s["sink"] for s in results["dom_sinks_found"][:3])
            sources = ", ".join(s["source"] for s in results["dom_sources_found"][:3])
            await self._create_finding(
                scan,
                title="Potential DOM-Based XSS Vulnerability",
                description=f"The page contains both DOM XSS sinks ({sinks}) and user-controllable sources ({sources}), creating a potential DOM-based Cross-Site Scripting vulnerability.",
                severity="high",
                confidence="POTENTIAL",
                owasp_category="A03:2021-Injection",
                cwe_id="CWE-79",
                cvss_score=7.1,
                affected_url=target_url,
                remediation="Sanitize all user input before passing to DOM manipulation functions. Use textContent instead of innerHTML. Implement a strict Content-Security-Policy.",
                proof_of_concept=f"Sinks: {sinks} | Sources: {sources}",
                counts=counts,
            )
            results["findings_list"].append("dom_xss_risk")
            results["confidence"] = "POTENTIAL"

        elif results["dom_sinks_found"]:
            sinks = ", ".join(s["sink"] for s in results["dom_sinks_found"][:3])
            await self._create_finding(
                scan,
                title="DOM XSS Sinks Detected in JavaScript",
                description=f"The page uses dangerous DOM manipulation functions ({sinks}) that can lead to XSS if user input reaches them.",
                severity="low",
                confidence="INFORMATIONAL",
                owasp_category="A03:2021-Injection",
                cwe_id="CWE-79",
                cvss_score=3.5,
                affected_url=target_url,
                remediation="Replace innerHTML with textContent or use DOMPurify to sanitize HTML content.",
                proof_of_concept=f"DOM sinks found: {sinks}",
                counts=counts,
            )
            results["findings_list"].append("dom_sinks")

        # ── 3. Missing X-XSS-Protection (legacy awareness check) ────
        xss_protection = headers.get("x-xss-protection", "")
        if not xss_protection:
            await self._create_finding(
                scan,
                title="Missing X-XSS-Protection Header",
                description="The X-XSS-Protection header is not set. While deprecated in modern browsers, its absence may indicate a lack of defense-in-depth approach.",
                severity="info",
                confidence="INFORMATIONAL",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-79",
                cvss_score=1.5,
                affected_url=target_url,
                remediation="While X-XSS-Protection is deprecated, implement a strong Content-Security-Policy as the modern replacement.",
                proof_of_concept="X-XSS-Protection header not present in response",
                counts=counts,
            )
            results["findings_list"].append("missing_xss_protection")

        # ── 4. Inline event handlers in HTML ────────────────────────
        inline_handlers = re.findall(
            r'\bon(?:click|load|error|mouseover|focus|submit|change|input|keyup|keydown)\s*=\s*["\']',
            body, re.IGNORECASE,
        )
        if len(inline_handlers) > 5:
            await self._create_finding(
                scan,
                title=f"Excessive Inline Event Handlers ({len(inline_handlers)} found)",
                description=f"The page contains {len(inline_handlers)} inline JavaScript event handlers (onclick, onload, etc.), which increase XSS attack surface and indicate CSP bypass risks.",
                severity="info",
                confidence="INFORMATIONAL",
                owasp_category="A03:2021-Injection",
                cwe_id="CWE-79",
                cvss_score=2.5,
                affected_url=target_url,
                remediation="Move inline event handlers to external JavaScript files and enforce CSP with 'unsafe-inline' disabled.",
                proof_of_concept=f"Found {len(inline_handlers)} inline event handlers in HTML",
                counts=counts,
            )
            results["findings_list"].append("inline_handlers")

        # ── 5. Active: Safe Harmless Canary Reflection Probing ───────
        if not self.is_active_confirmed(scan):
            return results

        results["active_tested"] = True
        parsed = urlparse(main_resp.url)
        params = parse_qs(parsed.query)
        if not params:
            parsed_orig = urlparse(target_url)
            params = parse_qs(parsed_orig.query)
            if params:
                parsed = parsed_orig

        if not params:
            results["active_note"] = "No query parameters found for active XSS canary probing."
            return results

        testable_params = list(params.keys())[:3]
        for param in testable_params:
            canary_id = uuid.uuid4().hex[:8]
            canary = f"awasap_xss_{canary_id}"

            # Step A: Test basic reflection of benign canary
            probe_params = {k: list(v) for k, v in params.items()}
            probe_params[param] = [canary]
            canary_query = urlencode(probe_params, doseq=True)
            canary_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, canary_query, parsed.fragment))

            try:
                results["canary_probes_sent"] += 1
                canary_resp = await http_client.get(canary_url)
                await asyncio.sleep(0.05)

                canary_body = canary_resp.text or ""
                if canary not in canary_body:
                    continue  # Parameter is not reflected

                results["reflected_params"].append(param)

                # Step B: Test delimiter output encoding with safe non-executable canary probe
                delimiter_probe = f'{canary}">xss_probe<'
                probe_params[param] = [delimiter_probe]
                delim_query = urlencode(probe_params, doseq=True)
                delim_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, delim_query, parsed.fragment))

                results["canary_probes_sent"] += 1
                delim_resp = await http_client.get(delim_url)
                await asyncio.sleep(0.05)

                delim_body = delim_resp.text or ""

                # Check if unencoded delimiters are present in the response
                unencoded_delim = f'{canary}">xss_probe<'
                encoded_delim = f'{canary}&quot;&gt;xss_probe&lt;'

                if unencoded_delim in delim_body:
                    # Confirmed: parameter reflects angle brackets and quotes without HTML encoding
                    results["vulnerable_params"].append(param)
                    results["confidence"] = "CONFIRMED"

                    # Find reflection context snippet
                    idx = delim_body.find(unencoded_delim)
                    snippet = delim_body[max(0, idx - 40):min(len(delim_body), idx + len(unencoded_delim) + 40)]

                    await self._create_finding(
                        scan,
                        title=f"Reflected Cross-Site Scripting (XSS) on Parameter '{param}'",
                        description=(
                            f"Active testing revealed that input supplied to parameter '{param}' is reflected directly "
                            "in the HTML response without HTML entity encoding of quotes (\") and angle brackets (< >). "
                            "An attacker can exploit this to inject arbitrary script."
                        ),
                        severity="high",
                        confidence="CONFIRMED",
                        owasp_category="A03:2021-Injection",
                        cwe_id="CWE-79",
                        cvss_score=7.5,
                        affected_url=delim_url,
                        remediation=(
                            "Apply context-aware output encoding (such as HTML entity encoding) to all user-controlled data "
                            "before inserting it into the DOM. Implement a restrictive Content-Security-Policy."
                        ),
                        proof_of_concept=(
                            f"Probe URL: {delim_url}\n"
                            f"Canary Token: {canary}\n"
                            f"Unencoded Reflection Context: {self._redact_sensitive_content(snippet)}"
                        ),
                        counts=counts,
                    )
                elif canary in delim_body:
                    # Canary is reflected, but delimiters were properly encoded
                    results["findings_list"].append(f"param_{param}_encoded_reflection")

            except Exception as e:
                results["active_error"] = str(e)
                if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                    results["confidence"] = "INCONCLUSIVE"

        return results
