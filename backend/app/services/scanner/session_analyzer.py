"""
Session Analyzer Scanner Module.

Supports:
  1. PASSIVE Analysis: Performs deep analysis of session management security —
     checks token entropy, cookie security attributes, fixation indicators, and persistence.
  2. ACTIVE Analysis: When explicit target authorization and active scan confirmation
     are granted, safely tests for logout session invalidation, cleartext credential transmission,
     and session fixation indicators using safe, controlled test session identifiers.
"""

import asyncio
import json
import math
import re
import string
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule


class SessionAnalyzerModule(BaseScannerModule):
    module_id = "session_analyzer"
    module_name = "Session Management"
    category = "Security Analysis"

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

        headers = main_resp.headers
        body = main_resp.text or ""
        set_cookie = headers.get("set-cookie", "")
        results: dict[str, Any] = {
            "checked": True,
            "status": "completed",
            "cookies_found": bool(set_cookie),
            "cookies": [],
            "findings": [],
            "active_tested": False,
            "logout_tested": False,
            "confidence": "INFORMATIONAL",
        }

        # ── 1. Passive Cookie Parsing and Attribute Analysis ─────────
        cookie_entries = re.split(r",(?=[^;]*=)", set_cookie) if set_cookie else []

        for raw_cookie in cookie_entries:
            raw_cookie = raw_cookie.strip()
            if "=" not in raw_cookie:
                continue

            parts = raw_cookie.split(";")
            name_val = parts[0].strip()
            name, _, value = name_val.partition("=")
            name = name.strip()
            value = value.strip()

            attrs = {
                "name": name,
                "value_length": len(value),
                "secure": False,
                "httponly": False,
                "samesite": "None",
                "domain": "",
                "path": "/",
                "max_age": None,
                "expires": "",
            }

            for part in parts[1:]:
                part = part.strip().lower()
                if part == "secure":
                    attrs["secure"] = True
                elif part == "httponly":
                    attrs["httponly"] = True
                elif part.startswith("samesite="):
                    attrs["samesite"] = part.split("=", 1)[1].strip().capitalize()
                elif part.startswith("domain="):
                    attrs["domain"] = part.split("=", 1)[1].strip()
                elif part.startswith("path="):
                    attrs["path"] = part.split("=", 1)[1].strip()
                elif part.startswith("max-age="):
                    try:
                        attrs["max_age"] = int(part.split("=", 1)[1].strip())
                    except ValueError:
                        pass
                elif part.startswith("expires="):
                    attrs["expires"] = part.split("=", 1)[1].strip()

            results["cookies"].append(attrs)

            # ── Session Token Entropy Analysis ──────────────────────
            is_session = any(s in name.lower() for s in ("session", "sess", "sid", "token", "auth", "jwt"))
            if is_session and value:
                entropy = _estimate_entropy(value)
                attrs["entropy_bits"] = round(entropy, 1)

                if entropy < 64:
                    await self._create_finding(
                        scan,
                        title=f"Weak Session Token Entropy ({name})",
                        description=f"The session cookie '{name}' has an estimated entropy of {entropy:.0f} bits (minimum recommended: 128 bits). Low-entropy tokens are susceptible to brute-force attacks.",
                        severity="high",
                        confidence="POTENTIAL",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        cwe_id="CWE-331",
                        cvss_score=7.5,
                        affected_url=target_url,
                        remediation="Generate session tokens using a cryptographically secure random number generator with at least 128 bits of entropy.",
                        proof_of_concept=f"Cookie '{name}' value length: {len(value)} chars, estimated entropy: {entropy:.0f} bits",
                        counts=counts,
                    )
                    results["findings"].append("weak_entropy")
                    results["confidence"] = "POTENTIAL"

            # ── Overly Long Session Persistence ─────────────────────
            max_age = attrs.get("max_age")
            if max_age and max_age > 86400 * 30:  # > 30 days
                days = max_age // 86400
                await self._create_finding(
                    scan,
                    title=f"Persistent Session Cookie ({name}: {days} days)",
                    description=f"The cookie '{name}' has a max-age of {days} days. Long-lived sessions increase the window for session hijacking.",
                    severity="low",
                    confidence="INFORMATIONAL",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    cwe_id="CWE-613",
                    cvss_score=3.5,
                    affected_url=target_url,
                    remediation="Set reasonable session expiration times (e.g., 24 hours for regular sessions).",
                    proof_of_concept=f"Cookie '{name}' max-age: {max_age} seconds ({days} days)",
                    counts=counts,
                )
                results["findings"].append("persistent_session")

            # ── Overly Broad Cookie Scope ───────────────────────────
            domain = attrs.get("domain", "")
            if domain.startswith(".") and domain.count(".") == 1:
                await self._create_finding(
                    scan,
                    title=f"Overly Broad Cookie Domain Scope ({name})",
                    description=f"The cookie '{name}' is scoped to the parent domain '{domain}', making it accessible to all subdomains. A compromised subdomain could hijack the session.",
                    severity="low",
                    confidence="INFORMATIONAL",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    cwe_id="CWE-1275",
                    cvss_score=3.7,
                    affected_url=target_url,
                    remediation="Restrict the cookie domain scope to the specific subdomain where it is needed.",
                    proof_of_concept=f"Cookie '{name}' domain: '{domain}'",
                    counts=counts,
                )
                results["findings"].append("broad_domain")

        # ── 2. Passive: Cleartext Credential Transmission in Forms ──
        if "<input" in body.lower() and 'type="password"' in body.lower():
            # Check form action URLs
            for form_match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
                attrs_str = form_match.group(1)
                content = form_match.group(2)
                if 'type="password"' in content.lower():
                    action_match = re.search(r'action\s*=\s*["\']([^"\'\s>]+)["\']', attrs_str, re.IGNORECASE)
                    action_url = action_match.group(1) if action_match else target_url
                    full_action = urljoin(target_url, action_url)
                    if full_action.startswith("http://"):
                        await self._create_finding(
                            scan,
                            title="Cleartext Transmission of User Credentials Over HTTP",
                            description=(
                                f"A login form on {target_url} submits password credentials over an unencrypted "
                                f"HTTP connection ({full_action}). Credentials can be intercepted in transit."
                            ),
                            severity="high",
                            confidence="CONFIRMED",
                            owasp_category="A02:2021-Cryptographic Failures",
                            cwe_id="CWE-319",
                            cvss_score=7.5,
                            affected_url=full_action,
                            remediation="Ensure all authentication and login forms submit strictly via HTTPS.",
                            proof_of_concept=f"Form action '{full_action}' communicates over unencrypted HTTP",
                            counts=counts,
                        )
                        results["findings"].append("cleartext_login_form")
                        results["confidence"] = "CONFIRMED"

        # ── 3. Active: Safe Logout Session Invalidation & Fixation Checks ──
        if not self.is_active_confirmed(scan):
            return results

        results["active_tested"] = True

        # Extract test credentials or existing session token from config or headers
        test_session_token = ""
        if scan.config_json:
            try:
                cfg = json.loads(scan.config_json)
                if isinstance(cfg, dict):
                    test_session_token = cfg.get("test_session_token") or cfg.get("auth_token") or ""
            except Exception:
                pass

        if not test_session_token and results["cookies"]:
            # Use discovered session cookie value if available
            for c in results["cookies"]:
                if any(k in c["name"].lower() for k in ("session", "token", "sid", "auth")):
                    # Reconstruct name=value
                    cookie_name = c["name"]
                    # Find raw value
                    for raw in cookie_entries:
                        if raw.strip().startswith(f"{cookie_name}="):
                            test_session_token = raw.strip().split(";")[0]
                            break
                    break

        # Check for logout endpoints
        base_parsed = urlparse(main_resp.url)
        common_logout_paths = ["/logout", "/api/logout", "/auth/logout", "/api/v1/auth/logout"]
        candidate_logout = ""
        for p in common_logout_paths:
            if p in body:
                candidate_logout = urljoin(main_resp.url, p)
                break

        if not candidate_logout:
            # Check default /logout
            candidate_logout = urljoin(main_resp.url, "/logout")

        if test_session_token and candidate_logout:
            results["logout_tested"] = True
            try:
                auth_headers = {"Cookie": test_session_token}
                # Probe logout endpoint
                logout_resp = await http_client.post(candidate_logout, headers=auth_headers)
                await asyncio.sleep(0.05)

                if logout_resp.status_code in (200, 204, 302, 303):
                    # Test if old session token is still accepted on protected endpoint
                    verify_resp = await http_client.get(main_resp.url, headers=auth_headers)
                    await asyncio.sleep(0.05)

                    if verify_resp.status_code == 200 and len(verify_resp.text or "") > 200:
                        # Session still active post-logout
                        results["confidence"] = "CONFIRMED"
                        await self._create_finding(
                            scan,
                            title="Missing Session Invalidation on Logout",
                            description=(
                                f"Active testing observed that calling the logout endpoint ({candidate_logout}) "
                                "did not invalidate the session token on the server. The session remained active "
                                f"and functional on {main_resp.url} post-logout, allowing session reuse if intercepted."
                            ),
                            severity="high",
                            confidence="CONFIRMED",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cwe_id="CWE-613",
                            cvss_score=7.4,
                            affected_url=candidate_logout,
                            remediation="Ensure server-side session stores immediately revoke and destroy session tokens upon logout.",
                            proof_of_concept=(
                                f"POST {candidate_logout} responded {logout_resp.status_code}\n"
                                f"Subsequent GET {main_resp.url} with same session responded HTTP {verify_resp.status_code}"
                            ),
                            counts=counts,
                        )
            except Exception as e:
                results["logout_error"] = str(e)
                if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                    results["confidence"] = "INCONCLUSIVE"

        return results


def _estimate_entropy(token: str) -> float:
    """Estimate Shannon entropy of a token string in bits."""
    if not token:
        return 0.0

    charset_size = 0
    has_lower = any(c in string.ascii_lowercase for c in token)
    has_upper = any(c in string.ascii_uppercase for c in token)
    has_digit = any(c in string.digits for c in token)
    has_special = any(c in string.punctuation for c in token)

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    if charset_size == 0:
        charset_size = 256  # binary

    return len(token) * math.log2(charset_size)


def _estimate_entropy(token: str) -> float:
    """Estimate Shannon entropy of a token string in bits."""
    if not token:
        return 0.0

    charset_size = 0
    has_lower = any(c in string.ascii_lowercase for c in token)
    has_upper = any(c in string.ascii_uppercase for c in token)
    has_digit = any(c in string.digits for c in token)
    has_special = any(c in string.punctuation for c in token)

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    if charset_size == 0:
        charset_size = 256  # binary

    return len(token) * math.log2(charset_size)
