"""
CSRF Detector Scanner Module.

Supports:
  1. PASSIVE Detection: Scans HTML forms for missing CSRF tokens and inspects
     SameSite cookie attributes and Referrer-Policy headers.
  2. ACTIVE Detection: When explicit target authorization and active scan confirmation
     are granted, executes safe, bounded test POST requests without Anti-CSRF tokens
     (or with invalid dummy tokens) to verify whether the server enforces token validation
     or rejects unauthorized cross-origin requests.
"""

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# Common CSRF token input names
CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "csrftoken", "_csrf", "csrf-token",
    "_token", "authenticity_token", "xsrf", "xsrf_token", "_xsrf",
    "__requestverificationtoken", "antiforgerytoken",
    "anti-forgery-token", "verification_token",
]


class CSRFDetectorModule(BaseScannerModule):
    module_id = "csrf_detector"
    module_name = "CSRF Detection"
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
            "forms_found": 0,
            "forms_without_csrf": 0,
            "forms_with_csrf": 0,
            "samesite_protection": False,
            "findings_list": [],
            "active_tested": False,
            "tested_endpoints": [],
            "confidence": "INFORMATIONAL",
        }

        # ── 1. Find all HTML forms ──────────────────────────────────
        forms = re.findall(
            r'<form\b[^>]*>(.*?)</form>',
            body,
            re.IGNORECASE | re.DOTALL,
        )
        results["forms_found"] = len(forms)

        state_changing_forms: list[tuple[str, str]] = []
        for form_match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
            attrs = form_match.group(1)
            form_content = form_match.group(2)
            method_match = re.search(r'method\s*=\s*["\']?(post|put|patch|delete)["\']?', attrs, re.IGNORECASE)
            action_match = re.search(r'action\s*=\s*["\']?([^"\'\s>]+)["\']?', attrs, re.IGNORECASE)
            action_url = action_match.group(1) if action_match else ""

            if method_match:
                state_changing_forms.append((action_url, form_content))

        for action_url, form_html in state_changing_forms:
            has_csrf = False
            for token_name in CSRF_TOKEN_NAMES:
                # Check hidden inputs
                if re.search(
                    rf'<input[^>]+name\s*=\s*["\']?{re.escape(token_name)}["\']?',
                    form_html,
                    re.IGNORECASE,
                ):
                    has_csrf = True
                    break
                # Check meta tags with CSRF tokens (common in Rails, Laravel)
                if re.search(
                    rf'<meta[^>]+name\s*=\s*["\']?{re.escape(token_name)}["\']?',
                    body,
                    re.IGNORECASE,
                ):
                    has_csrf = True
                    break

            if has_csrf:
                results["forms_with_csrf"] += 1
            else:
                results["forms_without_csrf"] += 1

        # ── 2. Report unprotected forms (Passive) ───────────────────
        if results["forms_without_csrf"] > 0:
            await self._create_finding(
                scan,
                title=f"Forms Without CSRF Protection ({results['forms_without_csrf']} found)",
                description=(
                    f"Found {results['forms_without_csrf']} state-changing HTML form(s) (POST/PUT/PATCH/DELETE) "
                    "without CSRF token protection. An attacker could trick authenticated users into submitting malicious requests."
                ),
                severity="medium",
                confidence="POTENTIAL",
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-352",
                cvss_score=6.5,
                affected_url=target_url,
                remediation="Add unique CSRF tokens to all state-changing forms. Use SameSite=Strict or Lax cookies as additional protection.",
                proof_of_concept=f"{results['forms_without_csrf']} of {len(state_changing_forms)} POST/PUT/PATCH forms lack CSRF tokens",
                counts=counts,
            )
            results["findings_list"].append("missing_csrf_tokens")
            results["confidence"] = "POTENTIAL"

        # ── 3. Check SameSite cookie attribute ──────────────────────
        set_cookie = headers.get("set-cookie", "").lower()
        if set_cookie:
            if "samesite=strict" in set_cookie or "samesite=lax" in set_cookie:
                results["samesite_protection"] = True
            elif "samesite=none" in set_cookie:
                await self._create_finding(
                    scan,
                    title="SameSite Cookie Attribute Set to None",
                    description="Session cookies use SameSite=None, which provides no CSRF protection. Cookies will be sent with cross-origin requests.",
                    severity="low",
                    confidence="INFORMATIONAL",
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_id="CWE-352",
                    cvss_score=3.5,
                    affected_url=target_url,
                    remediation="Set SameSite=Lax or SameSite=Strict on session cookies unless cross-origin usage is explicitly required.",
                    proof_of_concept="Set-Cookie header contains SameSite=None",
                    counts=counts,
                )
                results["findings_list"].append("samesite_none")

        # ── 4. Missing Referrer-Policy ──────────────────────────────
        referrer_policy = headers.get("referrer-policy", "")
        if not referrer_policy:
            await self._create_finding(
                scan,
                title="Missing Referrer-Policy Header",
                description="The Referrer-Policy header is not set. Without it, the browser may send the full URL (including query parameters) to third-party sites, potentially leaking CSRF tokens or sensitive data.",
                severity="info",
                confidence="INFORMATIONAL",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                cvss_score=2.0,
                affected_url=target_url,
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                proof_of_concept="Referrer-Policy header not present in response",
                counts=counts,
            )
            results["findings_list"].append("missing_referrer_policy")

        # ── 5. Active: Probe state-changing endpoints without Anti-CSRF token ─
        if not self.is_active_confirmed(scan):
            return results

        results["active_tested"] = True
        base_parsed = urlparse(main_resp.url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        # Test up to 2 candidate action endpoints
        candidate_actions: list[str] = []
        for action_url, _ in state_changing_forms:
            full_action = urljoin(main_resp.url, action_url)
            action_parsed = urlparse(full_action)
            # Same-origin enforcement
            if action_parsed.netloc.lower() == base_parsed.netloc.lower():
                candidate_actions.append(full_action)

        if not candidate_actions and any(s in base_parsed.path.lower() for s in ("/api/", "/account", "/profile")):
            candidate_actions.append(main_resp.url)

        for endpoint in candidate_actions[:2]:
            results["tested_endpoints"].append(endpoint)
            try:
                # Active probe: Send POST with dummy body, no CSRF token, and cross-origin header
                post_headers = {
                    "Origin": "https://unauthorized-attacker.example.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                dummy_payload = "awasap_csrf_test=1&action=test"

                # Send via safe client
                resp = await http_client.post(endpoint, data=dummy_payload, headers=post_headers)
                await asyncio.sleep(0.05)

                # Analyze server response
                if resp.status_code in (400, 401, 403, 422):
                    # CSRF or Origin check rejected the request
                    results["findings_list"].append(f"csrf_protected_{endpoint}")
                elif resp.status_code in (200, 201, 302, 303) and not results["samesite_protection"]:
                    # State-changing endpoint accepted cross-origin POST with no CSRF token
                    results["confidence"] = "CONFIRMED"
                    await self._create_finding(
                        scan,
                        title="State-Changing POST Endpoint Missing Anti-CSRF Validation",
                        description=(
                            f"Active testing confirmed that the endpoint '{endpoint}' accepted a state-changing POST "
                            "request without an Anti-CSRF token and without a valid SameSite cookie configuration (HTTP status "
                            f"{resp.status_code}). Cross-origin requests can induce state changes on behalf of authenticated victims."
                        ),
                        severity="high",
                        confidence="CONFIRMED",
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-352",
                        cvss_score=7.5,
                        affected_url=endpoint,
                        remediation=(
                            "Implement strict Anti-CSRF tokens (synchronizer token pattern or Double Submit Cookie) "
                            "and enforce SameSite=Lax or SameSite=Strict cookies. Verify Origin/Referer headers on state-changing requests."
                        ),
                        proof_of_concept=(
                            f"POST {endpoint}\n"
                            f"Origin: https://unauthorized-attacker.example.com\n"
                            f"Response Code: {resp.status_code}\n"
                            f"Anti-CSRF Token: Not Required"
                        ),
                        counts=counts,
                    )
            except Exception as e:
                results["active_error"] = str(e)
                if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                    results["confidence"] = "INCONCLUSIVE"

        return results
