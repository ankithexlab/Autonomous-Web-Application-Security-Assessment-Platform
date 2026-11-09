"""
Cookie Security Attributes Module — Phase 5.

Passive analysis of Set-Cookie headers from the primary HTTP response.
Inspects each cookie individually for missing Secure, HttpOnly, and
SameSite attributes. No additional HTTP requests are made.

Evidence is taken verbatim from the actual Set-Cookie response header
values; no fabrication occurs.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)

# Regex to split multiple Set-Cookie values reliably.
# Multiple cookies may appear as comma-separated entries in a single header
# when the HTTP library collapses them, or they may appear as separate
# header entries.  We handle both.
_COOKIE_SPLIT_RE = re.compile(r",\s*(?=[A-Za-z0-9_\-\.]+\s*=)")


def _parse_cookie_flags(raw: str) -> dict[str, bool | str]:
    """Extract boolean flags and attributes from a single Set-Cookie string."""
    lower = raw.lower()
    result: dict[str, bool | str] = {
        "has_secure": False,
        "has_httponly": False,
        "has_samesite": False,
        "samesite_value": "",
        "has_path": False,
        "has_expires_or_maxage": False,
        "is_session_cookie": True,
    }
    parts = [p.strip() for p in raw.split(";")]
    for part in parts:
        part_lower = part.lower()
        if part_lower == "secure":
            result["has_secure"] = True
        elif part_lower == "httponly":
            result["has_httponly"] = True
        elif part_lower.startswith("samesite="):
            result["has_samesite"] = True
            result["samesite_value"] = part.split("=", 1)[1].strip()
        elif part_lower.startswith("path="):
            result["has_path"] = True
        elif part_lower.startswith("expires=") or part_lower.startswith("max-age="):
            result["has_expires_or_maxage"] = True
            result["is_session_cookie"] = False
    return result


def _extract_cookie_name(raw: str) -> str:
    """Extract the cookie name from a Set-Cookie header value."""
    first_part = raw.split(";")[0]
    if "=" in first_part:
        return first_part.split("=", 1)[0].strip()
    return first_part.strip()


class CookieSecurityModule(BaseScannerModule):
    """Passive per-cookie security attribute inspector."""

    module_id = "cookie_security"
    module_name = "Cookie Security Attributes"
    category = "Cookie Security"

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
                "cookies_analyzed": 0,
                "cookies_with_issues": 0,
            }

        is_https = main_resp.url.startswith("https://")
        # Collect all Set-Cookie values (may be single or list collapsed)
        raw_cookies: list[str] = []
        set_cookie_raw = main_resp.headers.get("set-cookie", "")
        if set_cookie_raw:
            # Split on comma boundaries between separate cookies (not within expires dates)
            raw_cookies = _COOKIE_SPLIT_RE.split(set_cookie_raw)

        if not raw_cookies or not set_cookie_raw.strip():
            return {
                "status": "completed",
                "cookies_analyzed": 0,
                "cookies_with_issues": 0,
                "note": "No Set-Cookie headers present in response",
            }

        cookies_analyzed = 0
        cookies_with_issues = 0
        cookie_summary: list[dict] = []

        for raw in raw_cookies:
            raw = raw.strip()
            if not raw:
                continue

            name = _extract_cookie_name(raw)
            # Redact cookie value from evidence — keep only name and directives
            # Build a safe evidence string with name=<redacted> + all directives
            parts = raw.split(";")
            evidence_parts = ["<redacted>"] + [p.strip() for p in parts[1:]]
            evidence = f"{name}={'; '.join(evidence_parts)}"

            flags = _parse_cookie_flags(raw)
            cookies_analyzed += 1
            missing_flags: list[str] = []

            if is_https and not flags["has_secure"]:
                missing_flags.append("Secure")
            if not flags["has_httponly"]:
                missing_flags.append("HttpOnly")
            if not flags["has_samesite"]:
                missing_flags.append("SameSite")

            # Flag SameSite=None without Secure
            if (
                flags["has_samesite"]
                and str(flags.get("samesite_value", "")).lower() == "none"
                and not flags["has_secure"]
            ):
                await self._create_finding(
                    scan,
                    title=f"Cookie '{name}' — SameSite=None Without Secure Flag",
                    description=(
                        f"Cookie '{name}' is set with SameSite=None but lacks the Secure "
                        "attribute.  Modern browsers will reject this cookie, and when served "
                        "over HTTP it allows cross-site request forgery."
                    ),
                    severity="medium",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-614",
                    cvss_score=4.3,
                    affected_url=main_resp.url,
                    remediation=(
                        f"Add the Secure flag when using SameSite=None on cookie '{name}'."
                    ),
                    proof_of_concept=f"Set-Cookie: {evidence}",
                    counts=counts,
                )
                cookies_with_issues += 1

            if missing_flags:
                cookies_with_issues += 1
                await self._create_finding(
                    scan,
                    title="Insecure Cookie Attributes Detected",
                    description=(
                        f"The cookie '{name}' is missing the following security attributes: "
                        f"{', '.join(missing_flags)}. Missing HttpOnly increases risk of "
                        "JavaScript-based theft. Missing Secure allows transmission over "
                        "HTTP. Missing SameSite enables CSRF attacks."
                    ),
                    severity="medium",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-614",
                    cvss_score=4.8,
                    affected_url=main_resp.url,
                    remediation=(
                        f"Set the {', '.join(missing_flags)} attribute(s) on cookie '{name}'."
                    ),
                    proof_of_concept=f"Set-Cookie: {evidence}",
                    counts=counts,
                )

            cookie_summary.append({
                "name": name,
                "has_secure": flags["has_secure"],
                "has_httponly": flags["has_httponly"],
                "has_samesite": flags["has_samesite"],
                "samesite_value": flags.get("samesite_value", ""),
                "is_session_cookie": flags["is_session_cookie"],
                "issues": missing_flags,
            })

        return {
            "status": "completed",
            "cookies_analyzed": cookies_analyzed,
            "cookies_with_issues": cookies_with_issues,
            "cookies": cookie_summary,
        }
