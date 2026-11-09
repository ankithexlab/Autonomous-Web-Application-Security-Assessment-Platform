"""
Endpoint and Parameter Discovery Module — Phase 5.

Passive discovery of HTTP endpoints and URL parameters by analysing
real HTTP responses already collected by the crawler and the primary
request.  No additional outbound HTTP requests are issued here — all
analysis is performed on the in-memory data passed from the engine.

What this module does:
  1.  Extracts unique URL paths from discovered crawler URLs.
  2.  Collects query-string parameter names (never values) across all
      discovered URLs.
  3.  Detects potentially sensitive parameter names (e.g. token, id,
      redirect_url, password, key, secret).
  4.  Flags endpoints that contain numeric ID patterns that may be
      susceptible to IDOR if not properly authenticated.
  5.  Detects file-extension patterns indicating server technology or
      legacy endpoints (.php, .asp, .aspx, .jsp, .cgi).
  6.  Summarises the endpoint attack surface without storing or leaking
      parameter values.

Evidence is derived only from URLs discovered by the crawler; no
assumptions or fabricated data are added.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)

# Parameter names that commonly carry sensitive data
SENSITIVE_PARAM_NAMES: frozenset[str] = frozenset({
    "token", "access_token", "api_key", "apikey", "key", "secret",
    "password", "passwd", "pass", "pwd",
    "redirect", "redirect_url", "redirect_uri", "next", "return_url",
    "returnurl", "return", "goto", "url", "target", "destination",
    "file", "path", "dir", "filename", "filepath",
    "user", "username", "userid", "user_id", "account",
    "admin", "debug", "test", "cmd", "exec", "command",
    "id", "pid", "uid", "oid", "object_id",
    "ref", "referrer", "callback", "jsonp",
    "auth", "session", "sid", "jwt",
    "email", "phone", "ssn",
})

# Legacy / technology-revealing extensions
LEGACY_EXTENSIONS: dict[str, str] = {
    ".php": "PHP",
    ".asp": "Classic ASP",
    ".aspx": "ASP.NET",
    ".jsp": "Java Server Pages",
    ".cgi": "CGI Script",
    ".cfm": "ColdFusion",
    ".pl": "Perl",
    ".py": "Python CGI",
    ".rb": "Ruby CGI",
}

# Numeric ID pattern in path segments
_NUMERIC_ID_RE = re.compile(r"/(\d{1,10})(?:/|$|\?)")


class EndpointParamDiscoveryModule(BaseScannerModule):
    """
    Passive endpoint and parameter surface mapper.

    Requires crawler data injected via the scan's modules_json — if the
    crawler has not run, this module still analyses the primary response URL.
    """

    module_id = "endpoint_discovery"
    module_name = "Endpoint & Parameter Discovery"
    category = "Information Gathering"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        import json

        # Collect URLs: start with the primary target URL
        urls_to_analyse: list[str] = [target_url]

        # Pull in crawler-discovered URLs from modules_json if available
        if scan.modules_json:
            try:
                modules_data = json.loads(scan.modules_json)
                crawler_data = modules_data.get("url_discovery", {})
                if isinstance(crawler_data, dict):
                    discovered = crawler_data.get("discovered_urls", [])
                    if isinstance(discovered, list):
                        urls_to_analyse.extend(str(u) for u in discovered if u)
            except Exception:
                pass

        # Deduplicate
        seen: set[str] = set()
        unique_urls: list[str] = []
        for u in urls_to_analyse:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        # ── Analysis ─────────────────────────────────────────────────
        all_paths: set[str] = set()
        all_param_names: set[str] = set()
        sensitive_params_found: list[dict[str, str]] = []
        numeric_id_urls: list[str] = []
        legacy_tech_urls: list[dict[str, str]] = []

        for url in unique_urls:
            try:
                parsed = urlparse(url)
                path = parsed.path or "/"
                all_paths.add(path)

                # Query parameters (names only — never values)
                if parsed.query:
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    for pname in params.keys():
                        all_param_names.add(pname)
                        if pname.lower() in SENSITIVE_PARAM_NAMES:
                            sensitive_params_found.append({
                                "parameter": pname,
                                "url": self._redact_query_values(url),
                            })

                # Numeric IDs in path
                if _NUMERIC_ID_RE.search(path):
                    numeric_id_urls.append(url)

                # Legacy extension detection
                path_lower = path.lower()
                for ext, tech in LEGACY_EXTENSIONS.items():
                    if path_lower.endswith(ext):
                        legacy_tech_urls.append({"url": url, "extension": ext, "technology": tech})
                        break

            except Exception as exc:
                logger.debug("Endpoint analysis parse error for %s: %s", url, exc)
                continue

        # ── Findings ─────────────────────────────────────────────────
        findings_count = 0

        # Finding: sensitive parameter names observed
        if sensitive_params_found:
            # Deduplicate by parameter name
            seen_params: set[str] = set()
            deduped: list[dict] = []
            for item in sensitive_params_found:
                if item["parameter"].lower() not in seen_params:
                    seen_params.add(item["parameter"].lower())
                    deduped.append(item)

            param_names_str = ", ".join(d["parameter"] for d in deduped[:10])
            example_url = deduped[0]["url"]
            await self._create_finding(
                scan,
                title=f"Sensitive Parameter Names Observed in URL: {param_names_str[:80]}",
                description=(
                    f"The following URL query parameter names, which typically carry sensitive "
                    f"data or control application flow, were observed in discovered URLs: "
                    f"{param_names_str}.  Ensure these parameters are protected with "
                    f"authentication, authorisation, and input validation.  Parameter values "
                    f"are not stored in this finding."
                ),
                severity="info",
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-200",
                cvss_score=2.5,
                affected_url=example_url,
                remediation=(
                    "Validate and authorise access to all sensitive parameters.  Avoid passing "
                    "secrets, session tokens, or redirect targets in URL query strings."
                ),
                proof_of_concept=(
                    f"Sensitive parameter names discovered: {param_names_str}\n"
                    f"Example URL: {example_url}"
                ),
                counts=counts,
            )
            findings_count += 1

        # Finding: numeric IDs in URL paths (potential IDOR surface)
        if numeric_id_urls:
            example = numeric_id_urls[0]
            await self._create_finding(
                scan,
                title="Numeric ID Parameters in URL Paths — Potential IDOR Surface",
                description=(
                    f"URL paths containing numeric identifiers (e.g. /items/42/) were discovered "
                    f"across {len(numeric_id_urls)} URL(s).  If access control is not enforced "
                    f"server-side, these identifiers may be enumerable, enabling Insecure Direct "
                    f"Object Reference (IDOR) attacks."
                ),
                severity="info",
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-284",
                cvss_score=3.1,
                affected_url=example,
                remediation=(
                    "Implement server-side authorisation on every endpoint that accepts an "
                    "object identifier.  Consider using non-sequential opaque identifiers "
                    "(UUIDs) instead of integer IDs."
                ),
                proof_of_concept=(
                    f"Example URLs with numeric path segments:\n"
                    + "\n".join(f"  {u}" for u in numeric_id_urls[:5])
                ),
                counts=counts,
            )
            findings_count += 1

        # Finding: legacy technology extensions
        if legacy_tech_urls:
            techs = {item["technology"] for item in legacy_tech_urls}
            techs_str = ", ".join(sorted(techs))
            example = legacy_tech_urls[0]["url"]
            await self._create_finding(
                scan,
                title=f"Legacy Server-Side Technology Endpoints Detected ({techs_str})",
                description=(
                    f"URL paths with legacy server-side technology extensions were discovered: "
                    f"{techs_str}.  These may indicate outdated software stacks with known "
                    f"vulnerabilities or unmaintained components."
                ),
                severity="info",
                owasp_category="A06:2021-Vulnerable and Outdated Components",
                cwe_id="CWE-1104",
                cvss_score=2.1,
                affected_url=example,
                remediation=(
                    "Audit all legacy endpoints and ensure they run on a supported, patched "
                    "version of the technology.  Remove unmaintained endpoints."
                ),
                proof_of_concept=(
                    "Legacy endpoints detected:\n"
                    + "\n".join(
                        f"  {item['url']} ({item['technology']})"
                        for item in legacy_tech_urls[:5]
                    )
                ),
                counts=counts,
            )
            findings_count += 1

        return {
            "status": "completed",
            "urls_analysed": len(unique_urls),
            "unique_paths": len(all_paths),
            "unique_param_names": sorted(all_param_names),
            "param_count": len(all_param_names),
            "sensitive_params": [d["parameter"] for d in sensitive_params_found],
            "numeric_id_url_count": len(numeric_id_urls),
            "legacy_extension_count": len(legacy_tech_urls),
            "findings_count": findings_count,
        }

    @staticmethod
    def _redact_query_values(url: str) -> str:
        """Return URL with all query parameter values replaced by <redacted>."""
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return url
            params = parse_qs(parsed.query, keep_blank_values=True)
            redacted_parts = [f"{k}=<redacted>" for k in params.keys()]
            redacted_query = "&".join(redacted_parts)
            return parsed._replace(query=redacted_query).geturl()
        except Exception:
            return url
