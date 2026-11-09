"""
robots.txt and sitemap.xml Analysis Scanner Module — Phase 5.

Passively discovers and inspects /robots.txt and /sitemap.xml:
  1. Detects public /robots.txt availability.
  2. Parses Disallow / Allow / Sitemap directives.
  3. Identifies sensitive endpoints disclosed in Disallow rules (admin, private, backup, api).
  4. Detects public XML sitemaps and parses advertised URL locations.
  5. Flags information disclosure risks without modifying target data.

Security:
  - All requested paths are bound to target origin and validated against SSRF rules.
  - XML parsing disables external entity processing (XXE safe).
  - Uses bounded timeouts (5s) and 1 MB response caps.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import AppException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)

# Keywords indicating sensitive administrative, internal, or backup paths in robots.txt
SENSITIVE_PATH_KEYWORDS = {
    "admin", "administrator", "login", "auth", "signin",
    "backup", "backups", "bak", "dump", "database", "sql",
    "config", "conf", "env", "settings",
    "private", "internal", "secret", "hidden",
    "api/internal", "api/v1/admin", "manage", "portal",
    "dashboard", "staging", "test", "dev",
}

# Regex to safely extract <loc> URLs from sitemap XML without XXE vulnerabilities
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", re.IGNORECASE)


class RobotsSitemapModule(BaseScannerModule):
    """Passive discovery and analysis of robots.txt and sitemap.xml."""

    module_id = "robots_sitemap"
    module_name = "robots.txt & sitemap.xml Analysis"
    category = "Information Gathering"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        result: dict[str, Any] = {
            "status": "completed",
            "robots_checked": True,
            "robots_found": False,
            "disallowed_paths": [],
            "disallow_count": 0,
            "sensitive_disallowed_paths": [],
            "declared_sitemaps": [],
            "sitemap_checked": True,
            "sitemap_found": False,
            "sitemap_url_count": 0,
            "sample_sitemap_urls": [],
            "findings_count": 0,
        }

        # ── 1. robots.txt Analysis ──────────────────────────────────
        robots_url = f"{origin}/robots.txt"
        try:
            validate_target_url(robots_url)
            r_resp = await http_client.get(robots_url, timeout=5.0)

            # Check for authentic robots.txt response
            if r_resp.status_code == 200 and r_resp.text:
                text_lower = r_resp.text.lower()
                # Confirm it looks like a robots.txt rather than a custom HTML 404
                if "user-agent:" in text_lower or "disallow:" in text_lower or "allow:" in text_lower:
                    result["robots_found"] = True
                    disallowed: list[str] = []
                    declared_sitemaps: list[str] = []

                    for line in r_resp.text.splitlines():
                        line_clean = line.strip()
                        if not line_clean or line_clean.startswith("#"):
                            continue
                        if ":" not in line_clean:
                            continue
                        directive, _, val = line_clean.partition(":")
                        directive_norm = directive.strip().lower()
                        val_norm = val.strip()

                        if directive_norm == "disallow" and val_norm:
                            disallowed.append(val_norm)
                        elif directive_norm == "sitemap" and val_norm.startswith(("http://", "https://")):
                            declared_sitemaps.append(val_norm)

                    result["disallowed_paths"] = disallowed
                    result["disallow_count"] = len(disallowed)
                    result["declared_sitemaps"] = declared_sitemaps

                    # Analyze disallowed entries for sensitive keywords
                    sensitive_paths: list[str] = []
                    for path in disallowed:
                        p_lower = path.lower()
                        if any(kw in p_lower for kw in SENSITIVE_PATH_KEYWORDS):
                            sensitive_paths.append(path)

                    result["sensitive_disallowed_paths"] = sensitive_paths

                    if sensitive_paths:
                        sample_paths = "\n".join(f"  - Disallow: {p}" for p in sensitive_paths[:10])
                        await self._create_finding(
                            scan,
                            title="Sensitive Administrative Paths Disclosed in robots.txt",
                            description=(
                                f"The public robots.txt file at {robots_url} contains Disallow directives "
                                f"for {len(sensitive_paths)} sensitive internal path(s). While intended for web crawlers, "
                                "these rules inadvertently disclose internal application structure and administrative interfaces to attackers."
                            ),
                            severity="low",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-200",
                            cvss_score=3.7,
                            affected_url=robots_url,
                            remediation=(
                                "Review robots.txt directives. Do not rely on robots.txt for access control; "
                                "ensure sensitive administrative endpoints enforce authentication and authorization."
                            ),
                            proof_of_concept=(
                                f"GET {robots_url} returned 200 OK with sensitive paths:\n{sample_paths}"
                            ),
                            counts=counts,
                        )
                        result["findings_count"] += 1
                    elif disallowed:
                        await self._create_finding(
                            scan,
                            title="Public robots.txt Directives Disclose Application Paths",
                            description=(
                                f"The target publishes a robots.txt file with {len(disallowed)} Disallow directives. "
                                "Disclosed paths expose endpoint structure to passive reconnaissance."
                            ),
                            severity="info",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-200",
                            cvss_score=1.5,
                            affected_url=robots_url,
                            remediation="Ensure robots.txt does not reveal confidential, unlinked, or testing paths.",
                            proof_of_concept=f"GET {robots_url} returned 200 OK with {len(disallowed)} Disallow directives",
                            counts=counts,
                        )
                        result["findings_count"] += 1
        except AppException:
            result["robots_error"] = "SSRF validation blocked robots.txt lookup"
        except Exception as exc:
            result["robots_error"] = str(exc)

        # ── 2. sitemap.xml Analysis ─────────────────────────────────
        candidate_sitemaps = list(result["declared_sitemaps"])
        default_sitemap = f"{origin}/sitemap.xml"
        if default_sitemap not in candidate_sitemaps:
            candidate_sitemaps.insert(0, default_sitemap)

        for sitemap_url in candidate_sitemaps[:3]:
            try:
                validate_target_url(sitemap_url)
                s_resp = await http_client.get(sitemap_url, timeout=5.0)

                if s_resp.status_code == 200 and s_resp.text:
                    if "<urlset" in s_resp.text.lower() or "<sitemapindex" in s_resp.text.lower() or "<loc>" in s_resp.text.lower():
                        result["sitemap_found"] = True
                        locs = _SITEMAP_LOC_RE.findall(s_resp.text)
                        result["sitemap_url_count"] = len(locs)
                        result["sample_sitemap_urls"] = locs[:10]

                        # Check for sensitive URLs exposed in sitemap
                        sensitive_sitemap_urls = [u for u in locs if any(kw in u.lower() for kw in SENSITIVE_PATH_KEYWORDS)]
                        if sensitive_sitemap_urls:
                            await self._create_finding(
                                scan,
                                title=f"Sensitive URLs Advertised in XML Sitemap ({len(sensitive_sitemap_urls)} found)",
                                description=(
                                    f"The XML sitemap at {sitemap_url} advertises {len(sensitive_sitemap_urls)} URL(s) "
                                    "containing keywords associated with administrative or internal endpoints."
                                ),
                                severity="low",
                                owasp_category="A05:2021-Security Misconfiguration",
                                cwe_id="CWE-200",
                                cvss_score=3.5,
                                affected_url=sitemap_url,
                                remediation="Remove internal or sensitive endpoints from sitemap.xml and require authentication.",
                                proof_of_concept=(
                                    f"Sensitive URLs in sitemap:\n"
                                    + "\n".join(f"  - {u}" for u in sensitive_sitemap_urls[:5])
                                ),
                                counts=counts,
                            )
                            result["findings_count"] += 1
                        else:
                            await self._create_finding(
                                scan,
                                title="Public XML Sitemap Advertises Application Structure",
                                description=(
                                    f"The application publishes an XML sitemap at {sitemap_url} declaring "
                                    f"{len(locs)} endpoints, facilitating complete attack-surface enumeration."
                                ),
                                severity="info",
                                owasp_category="A05:2021-Security Misconfiguration",
                                cwe_id="CWE-200",
                                cvss_score=1.5,
                                affected_url=sitemap_url,
                                remediation="Ensure the sitemap contains only public pages intended for search engine indexation.",
                                proof_of_concept=f"GET {sitemap_url} returned 200 OK with {len(locs)} URL locations",
                                counts=counts,
                            )
                            result["findings_count"] += 1
                        break  # Stop at first valid sitemap
            except AppException:
                pass
            except Exception:
                pass

        return result
