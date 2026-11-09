"""
Open Redirect Detector Scanner Module.

PASSIVE detection — identifies common redirect parameters in URLs and
HTML content that may be exploitable for open redirect attacks.
"""

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# Common redirect parameter names
REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "redirectUrl", "redirectUri",
    "url", "next", "return", "return_url", "returnUrl", "return_to", "returnTo",
    "goto", "dest", "destination", "target", "rurl", "redir",
    "continue", "forward", "forward_url", "callback", "callback_url",
    "out", "checkout_url", "login_url", "logout_url", "ref",
]


class OpenRedirectDetectorModule(BaseScannerModule):
    module_id = "open_redirect"
    module_name = "Open Redirect Detection"
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
        url = main_resp.url
        results: dict[str, Any] = {
            "checked": True,
            "redirect_params_found": [],
            "redirect_links_found": [],
            "redirect_chain_issues": [],
        }

        # ── 1. Check current URL for redirect parameters ────────────
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in REDIRECT_PARAMS:
            if param_name in params:
                for val in params[param_name]:
                    # Check if the value looks like an external URL
                    if val.startswith(("http://", "https://", "//", "\\\\")) or "://" in val:
                        results["redirect_params_found"].append({
                            "param": param_name,
                            "value": val[:200],
                            "external": True,
                        })
                    else:
                        results["redirect_params_found"].append({
                            "param": param_name,
                            "value": val[:200],
                            "external": False,
                        })

        # ── 2. Check HTML links for redirect patterns ───────────────
        links = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE)
        for link in links[:300]:
            link_parsed = urlparse(link)
            link_params = parse_qs(link_parsed.query)
            for param_name in REDIRECT_PARAMS:
                if param_name in link_params:
                    results["redirect_links_found"].append({
                        "link": link[:200],
                        "param": param_name,
                    })
                    break

        # ── 3. Check JavaScript for redirect patterns ───────────────
        js_redirects = re.findall(
            r'(?:window\.location|document\.location|location\.href)\s*=\s*[^;]+',
            body,
        )

        # ── 4. Check redirect chain ────────────────────────────────
        if main_resp.redirect_chain and len(main_resp.redirect_chain) > 1:
            for i, redirect_url in enumerate(main_resp.redirect_chain[1:], 1):
                original_host = urlparse(main_resp.redirect_chain[0]).hostname
                redirect_host = urlparse(redirect_url).hostname
                if original_host and redirect_host and original_host != redirect_host:
                    results["redirect_chain_issues"].append({
                        "from": main_resp.redirect_chain[i - 1],
                        "to": redirect_url,
                        "cross_domain": True,
                    })

        # ── Report findings ─────────────────────────────────────────
        external_params = [p for p in results["redirect_params_found"] if p.get("external")]
        if external_params:
            param_details = ", ".join(f"?{p['param']}={p['value'][:50]}" for p in external_params[:3])
            await self._create_finding(
                scan,
                title="Potential Open Redirect Vulnerability",
                description=f"The URL contains redirect parameters with external URLs ({param_details}). An attacker could modify these to redirect users to malicious sites for phishing.",
                severity="medium",
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-601",
                cvss_score=5.4,
                affected_url=url,
                remediation="Validate redirect targets against a whitelist of allowed domains. Use relative paths instead of full URLs for internal redirects.",
                proof_of_concept=f"Redirect params with external URLs: {param_details}",
                counts=counts,
            )

        if len(results["redirect_links_found"]) > 5:
            await self._create_finding(
                scan,
                title=f"Multiple Redirect Parameters in Links ({len(results['redirect_links_found'])} found)",
                description=f"The page contains {len(results['redirect_links_found'])} links with redirect parameters, increasing the surface for open redirect attacks.",
                severity="info",
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-601",
                cvss_score=2.5,
                affected_url=target_url,
                remediation="Validate and whitelist all redirect destinations server-side.",
                proof_of_concept=f"Sample: {results['redirect_links_found'][0]['link'][:100]}",
                counts=counts,
            )

        return results
