"""
JWT Analyzer Scanner Module.

Analyzes JSON Web Tokens found in response headers, cookies, or body content.
Decodes header/payload (base64, no verification) and checks for weak algorithms,
missing claims, and sensitive data exposure.
"""

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# JWT regex: 3 base64url segments separated by dots
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"
)

# Sensitive fields that should never appear in JWT payload
SENSITIVE_FIELDS = [
    "password", "passwd", "pass", "secret", "credit_card", "creditCard",
    "ssn", "social_security", "bank_account", "api_key", "apiKey",
    "private_key", "privateKey", "access_token", "accessToken",
]


class JWTAnalyzerModule(BaseScannerModule):
    module_id = "jwt_analyzer"
    module_name = "JWT Analysis"
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

        headers = main_resp.headers
        body = main_resp.text or ""
        results: dict[str, Any] = {
            "checked": True,
            "jwts_found": [],
            "findings_list": [],
        }

        # ── Collect JWTs from various sources ───────────────────────
        jwt_tokens: list[str] = []

        # From Authorization header
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            if JWT_PATTERN.match(token):
                jwt_tokens.append(token)

        # From Set-Cookie
        set_cookie = headers.get("set-cookie", "")
        for match in JWT_PATTERN.finditer(set_cookie):
            jwt_tokens.append(match.group(0))

        # From response body
        for match in JWT_PATTERN.finditer(body):
            jwt_tokens.append(match.group(0))

        # Deduplicate
        jwt_tokens = list(set(jwt_tokens))[:5]  # Max 5 tokens

        for token in jwt_tokens:
            jwt_info = _decode_jwt(token)
            if not jwt_info:
                continue

            results["jwts_found"].append(jwt_info)

            header_data = jwt_info.get("header", {})
            payload_data = jwt_info.get("payload", {})
            alg = header_data.get("alg", "").upper()

            # ── Check 1: "none" algorithm ───────────────────────────
            if alg in ("NONE", ""):
                await self._create_finding(
                    scan,
                    title="JWT Using 'none' Algorithm (Critical)",
                    description="A JWT token was found using the 'none' algorithm, meaning it has no cryptographic signature. An attacker can forge arbitrary tokens.",
                    severity="critical",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-327",
                    cvss_score=9.8,
                    affected_url=target_url,
                    remediation="Enforce strong algorithms (RS256, ES256) and reject tokens with 'none' algorithm server-side.",
                    proof_of_concept=f"JWT header: {json.dumps(header_data)}",
                    counts=counts,
                )
                results["findings_list"].append("none_algorithm")

            # ── Check 2: Weak algorithm (HS256 for public APIs) ─────
            elif alg == "HS256":
                await self._create_finding(
                    scan,
                    title="JWT Using Symmetric Algorithm (HS256)",
                    description="The JWT uses HS256 (HMAC-SHA256), a symmetric algorithm. If the secret key is weak or shared, tokens can be forged. Asymmetric algorithms (RS256, ES256) are recommended.",
                    severity="low",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-327",
                    cvss_score=3.7,
                    affected_url=target_url,
                    remediation="Consider using asymmetric algorithms (RS256, ES256) and ensure the HMAC secret is at least 256 bits of random data.",
                    proof_of_concept=f"JWT algorithm: {alg}",
                    counts=counts,
                )
                results["findings_list"].append("weak_algorithm")

            # ── Check 3: Missing expiration ─────────────────────────
            if "exp" not in payload_data:
                await self._create_finding(
                    scan,
                    title="JWT Missing Expiration Claim (exp)",
                    description="The JWT payload does not contain an 'exp' (expiration) claim. Tokens without expiration never expire, allowing indefinite session hijacking.",
                    severity="medium",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    cwe_id="CWE-613",
                    cvss_score=5.5,
                    affected_url=target_url,
                    remediation="Always include an 'exp' claim in JWT payloads with a reasonable expiration time.",
                    proof_of_concept=f"JWT payload keys: {list(payload_data.keys())}",
                    counts=counts,
                )
                results["findings_list"].append("missing_expiration")

            # ── Check 4: Sensitive data in payload ──────────────────
            exposed_fields = [f for f in SENSITIVE_FIELDS if f in payload_data]
            if exposed_fields:
                await self._create_finding(
                    scan,
                    title=f"Sensitive Data in JWT Payload ({', '.join(exposed_fields)})",
                    description=f"The JWT payload contains sensitive fields ({', '.join(exposed_fields)}). JWT payloads are only base64-encoded, not encrypted — anyone can read them.",
                    severity="high",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-312",
                    cvss_score=7.5,
                    affected_url=target_url,
                    remediation="Never store sensitive data in JWT payloads. Use JWE (JSON Web Encryption) if payload confidentiality is required.",
                    proof_of_concept=f"Exposed fields in JWT: {', '.join(exposed_fields)}",
                    counts=counts,
                )
                results["findings_list"].append("sensitive_data")

        return results


def _decode_jwt(token: str) -> dict[str, Any] | None:
    """Decode a JWT token (header + payload) without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)

        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        return {
            "header": header,
            "payload": payload,
            "token_preview": token[:50] + "...",
        }
    except Exception:
        return None
