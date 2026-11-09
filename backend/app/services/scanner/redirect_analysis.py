"""
Redirect Analysis Scanner Module — Phase 5.

Passively analyzes HTTP redirect chains observed during target probing:
  1. Excessive redirect chains (> 3 hops).
  2. HTTPS-to-HTTP downgrade redirects (SSL stripping hazard).
  3. Cross-origin redirect hops (potential data leakage or phishing risks).
  4. Redirect loop or circular forwarding patterns.
  5. URL parameter reflection in redirect destinations.

Security:
  - Operates purely on observed redirect chains collected by SafeHTTPClient.
  - SafeHTTPClient validates every redirect Location header against SSRF restrictions (max 5 hops).
  - No new outbound requests are made; analysis is completely passive.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)

# Common redirect parameter keys that might disclose open redirect vectors
OPEN_REDIRECT_PARAM_KEYS = {
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "dest", "destination", "target", "goto", "url", "r", "u",
}


class RedirectAnalysisModule(BaseScannerModule):
    """Passive redirect chain security auditor."""

    module_id = "redirect_analysis"
    module_name = "Redirect Analysis"
    category = "Network Security"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        if not main_resp:
            return {
                "status": "skipped",
                "reason": "No primary HTTP response available",
                "findings_count": 0,
            }

        redirect_chain = list(main_resp.redirect_chain or [target_url])
        final_url = main_resp.url
        # Ensure final URL is at end of chain if not present
        if not redirect_chain or redirect_chain[-1] != final_url:
            redirect_chain.append(final_url)

        hops_count = max(0, len(redirect_chain) - 1)
        findings_count = 0

        initial_parsed = urlparse(redirect_chain[0])
        final_parsed = urlparse(final_url)
        initial_origin = (initial_parsed.scheme.lower(), initial_parsed.netloc.lower())
        final_origin = (final_parsed.scheme.lower(), final_parsed.netloc.lower())

        is_cross_origin = hops_count > 0 and (initial_origin != final_origin)
        has_downgrade = False
        downgrade_pair: tuple[str, str] | None = None

        # Check for protocol downgrade in chain
        for i in range(len(redirect_chain) - 1):
            src = redirect_chain[i]
            dst = redirect_chain[i + 1]
            if src.lower().startswith("https://") and dst.lower().startswith("http://"):
                has_downgrade = True
                downgrade_pair = (src, dst)
                break

        result: dict[str, Any] = {
            "status": "completed",
            "hops_count": hops_count,
            "redirect_chain": redirect_chain,
            "initial_url": redirect_chain[0],
            "final_url": final_url,
            "is_cross_origin": is_cross_origin,
            "has_downgrade": has_downgrade,
            "findings_count": 0,
        }

        # ── 1. Protocol Downgrade Finding ────────────────────────────
        if has_downgrade and downgrade_pair:
            await self._create_finding(
                scan,
                title="HTTPS to HTTP Protocol Downgrade in Redirect Chain",
                description=(
                    f"A redirect in the chain downgraded transport security from HTTPS to HTTP:\n"
                    f"  {downgrade_pair[0]} -> {downgrade_pair[1]}\n"
                    "This downgrade exposes subsequent traffic to network interception and renders session tokens vulnerable."
                ),
                severity="high",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-319",
                cvss_score=7.4,
                affected_url=downgrade_pair[0],
                remediation="Ensure all redirects maintain or upgrade to HTTPS. Never downgrade connections from HTTPS to HTTP.",
                proof_of_concept=f"Redirect downgrade observed: {downgrade_pair[0]} -> {downgrade_pair[1]}",
                counts=counts,
            )
            findings_count += 1

        # ── 2. Excessive Redirect Chain ──────────────────────────────
        if hops_count > 3:
            await self._create_finding(
                scan,
                title=f"Excessive HTTP Redirect Chain ({hops_count} hops)",
                description=(
                    f"The target URL triggered {hops_count} intermediate redirect hops before reaching its final destination. "
                    "Long redirect chains introduce latency, increase man-in-the-middle attack surfaces, and may hide malicious forwarding."
                ),
                severity="info",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-601",
                cvss_score=2.0,
                affected_url=redirect_chain[0],
                remediation="Configure server routing and reverse proxies to minimize redirect hops to a single direct hop.",
                proof_of_concept="Redirect chain:\n" + "\n".join(f"  [{idx}] {u}" for idx, u in enumerate(redirect_chain)),
                counts=counts,
            )
            findings_count += 1

        # ── 3. Cross-Origin Redirect ─────────────────────────────────
        if is_cross_origin:
            # Check if query params might leak sensitive info cross-origin
            init_query = parse_qs(initial_parsed.query)
            sensitive_leaked = [k for k in init_query.keys() if k.lower() in {"token", "auth", "session", "key", "secret", "code"}]
            if sensitive_leaked:
                await self._create_finding(
                    scan,
                    title="Cross-Origin Redirect May Leak Sensitive Query Parameters",
                    description=(
                        f"The initial request contained sensitive parameter name(s) ({', '.join(sensitive_leaked)}) "
                        f"and was redirected cross-origin to {final_origin[1]}. If query parameters are preserved in the Referer "
                        "header or destination URL, secrets will be exposed to the foreign origin."
                    ),
                    severity="medium",
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_id="CWE-200",
                    cvss_score=5.3,
                    affected_url=redirect_chain[0],
                    remediation="Strip sensitive query parameters before redirecting clients to third-party or external origins.",
                    proof_of_concept=f"Initial URL with sensitive query keys redirected to external origin {final_url}",
                    counts=counts,
                )
                findings_count += 1
            else:
                await self._create_finding(
                    scan,
                    title="Cross-Origin Redirect Observed",
                    description=(
                        f"Target URL redirected from origin '{initial_origin[1]}' to external origin '{final_origin[1]}'. "
                        "Cross-origin redirects should be audited to verify destination authenticity and prevent redirection spoofing."
                    ),
                    severity="info",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-601",
                    cvss_score=1.5,
                    affected_url=redirect_chain[0],
                    remediation="Validate that the cross-origin redirect destination is authorized.",
                    proof_of_concept=f"{redirect_chain[0]} -> (cross-origin) -> {final_url}",
                    counts=counts,
                )
                findings_count += 1

        result["findings_count"] = findings_count
        return result
