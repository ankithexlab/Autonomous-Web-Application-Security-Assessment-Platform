"""
SSL/TLS Observations Scanner Module — Phase 5.

Performs passive and safe observation of SSL/TLS configurations on HTTPS targets:
  1. TLS protocol version (TLSv1.2, TLSv1.3, or deprecated TLSv1.0/1.1).
  2. Active cipher suite name and encryption bit strength.
  3. Certificate validity dates (notBefore, notAfter) and days until expiration.
  4. Certificate subject Common Name (CN) and Subject Alternative Names (SANs).
  5. Certificate issuer Organization / Common Name.
  6. Detection of expired, self-signed, untrusted, or soon-expiring certificates.
  7. Cleartext HTTP detection for non-HTTPS target URLs.

Security:
  - All targets are validated with validate_target_url() before any network connection.
  - Connections are strictly bounded by a 5-second socket timeout.
  - Never submits exploits or alters remote configuration.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import AppException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)

# Deprecated TLS protocols that should be flagged
DEPRECATED_PROTOCOLS = {"tlsv1", "tlsv1.0", "tlsv1.1", "sslv2", "sslv3"}

# Weak cipher substrings
WEAK_CIPHER_SUBSTRINGS = {"RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "anon"}


class SslTlsModule(BaseScannerModule):
    """Passive SSL/TLS observation and certificate validation module."""

    module_id = "ssl_tls"
    module_name = "SSL/TLS Observations"
    category = "Cryptography"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        parsed = urlparse(target_url)
        is_https = parsed.scheme.lower() == "https"
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if not is_https:
            return {
                "status": "completed",
                "is_https": False,
                "target_url": target_url,
                "note": "Target uses unencrypted HTTP; no SSL/TLS layer present.",
                "tls_version": None,
                "cipher": None,
                "findings_count": 0,
            }

        if not hostname:
            return {
                "status": "error",
                "error": "Target URL missing valid hostname for SSL/TLS inspection.",
            }

        # SSRF validation before establishing raw socket connection
        try:
            validate_target_url(target_url)
        except AppException as e:
            return {
                "status": "error",
                "error": f"SSRF guard blocked SSL/TLS inspection: {e}",
            }

        result: dict[str, Any] = {
            "status": "completed",
            "is_https": True,
            "hostname": hostname,
            "port": port,
            "tls_version": None,
            "cipher": None,
            "cipher_bits": None,
            "cert_subject": None,
            "cert_issuer": None,
            "cert_expires": None,
            "days_until_expiry": None,
            "sans": [],
            "findings_count": 0,
        }

        # Perform SSL/TLS handshake in background thread to avoid event loop blocking
        try:
            tls_info = await asyncio.wait_for(
                asyncio.to_thread(self._inspect_ssl, hostname, port),
                timeout=5.0,
            )
            result.update(tls_info)
        except asyncio.TimeoutError:
            result["status"] = "error"
            result["error"] = f"SSL/TLS handshake timed out after 5.0s for {hostname}:{port}"
            return result
        except ssl.SSLCertVerificationError as cert_err:
            result["cert_verification_error"] = str(cert_err)
            await self._create_finding(
                scan,
                title="SSL/TLS Certificate Verification Failed (Untrusted or Self-Signed)",
                description=(
                    f"The SSL/TLS certificate presented by {hostname}:{port} could not be "
                    f"verified by standard trust stores ({cert_err.verify_message or cert_err}). "
                    "This may indicate a self-signed certificate, missing intermediate CA, or expired certificate."
                ),
                severity="high",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-295",
                cvss_score=7.4,
                affected_url=target_url,
                remediation=(
                    "Install a valid SSL/TLS certificate issued by a trusted Certificate Authority (CA) "
                    "such as Let's Encrypt and verify that intermediate certificates are properly bundled."
                ),
                proof_of_concept=f"SSLCertVerificationError: {cert_err}",
                counts=counts,
            )
            result["findings_count"] += 1
            # Try to get unverified cert details for evidence
            try:
                unverified_info = await asyncio.to_thread(self._inspect_ssl_unverified, hostname, port)
                result.update(unverified_info)
            except Exception:
                pass
            return result
        except Exception as exc:
            result["status"] = "error"
            result["error"] = f"SSL/TLS inspection failed: {exc}"
            return result

        # ── Analyze Collected TLS Properties ──────────────────────────

        # 1. Deprecated protocol check
        proto = result.get("tls_version") or ""
        if proto.lower() in DEPRECATED_PROTOCOLS:
            await self._create_finding(
                scan,
                title=f"Deprecated TLS Protocol in Use: {proto}",
                description=(
                    f"The server negotiated {proto}, which is deprecated by RFC 8996 due to "
                    "known cryptographic weaknesses (e.g., POODLE, BEAST). Modern standards mandate TLS 1.2 or TLS 1.3."
                ),
                severity="high",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-326",
                cvss_score=7.5,
                affected_url=target_url,
                remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in web server configuration; require TLS 1.2 or TLS 1.3.",
                proof_of_concept=f"Negotiated TLS Protocol: {proto}",
                counts=counts,
            )
            result["findings_count"] += 1

        # 2. Certificate expiration check
        days_left = result.get("days_until_expiry")
        if days_left is not None:
            if days_left < 0:
                await self._create_finding(
                    scan,
                    title="SSL/TLS Certificate Has Expired",
                    description=(
                        f"The certificate for {hostname} expired {abs(days_left)} day(s) ago "
                        f"(notAfter: {result.get('cert_expires')}). Browsers will block connections with security warnings."
                    ),
                    severity="critical",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-298",
                    cvss_score=9.1,
                    affected_url=target_url,
                    remediation="Renew and deploy an active SSL/TLS certificate immediately.",
                    proof_of_concept=f"Certificate expiration date: {result.get('cert_expires')} ({days_left} days remaining)",
                    counts=counts,
                )
                result["findings_count"] += 1
            elif days_left < 30:
                await self._create_finding(
                    scan,
                    title=f"SSL/TLS Certificate Expiring Soon ({days_left} days remaining)",
                    description=(
                        f"The certificate for {hostname} will expire in {days_left} day(s) "
                        f"on {result.get('cert_expires')}. If not renewed promptly, service disruption will occur."
                    ),
                    severity="low",
                    owasp_category="A02:2021-Cryptographic Failures",
                    cwe_id="CWE-298",
                    cvss_score=3.7,
                    affected_url=target_url,
                    remediation="Renew the SSL/TLS certificate prior to expiration.",
                    proof_of_concept=f"Certificate expires on {result.get('cert_expires')} ({days_left} days remaining)",
                    counts=counts,
                )
                result["findings_count"] += 1

        # 3. Weak cipher check
        cipher_name = (result.get("cipher") or "").upper()
        cipher_bits = result.get("cipher_bits")
        is_weak = any(w in cipher_name for w in WEAK_CIPHER_SUBSTRINGS) or (cipher_bits and cipher_bits < 128)
        if is_weak:
            await self._create_finding(
                scan,
                title=f"Weak SSL/TLS Cipher Suite Negotiated: {cipher_name}",
                description=(
                    f"The server negotiated cipher suite '{cipher_name}' ({cipher_bits} bits), "
                    "which employs deprecated algorithms vulnerable to cryptanalysis."
                ),
                severity="medium",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-327",
                cvss_score=5.9,
                affected_url=target_url,
                remediation="Configure web servers to prioritize strong AEAD cipher suites (e.g. ECDHE-ECDSA-AES256-GCM-SHA384).",
                proof_of_concept=f"Negotiated Cipher: {cipher_name} ({cipher_bits} bits)",
                counts=counts,
            )
            result["findings_count"] += 1

        return result

    @staticmethod
    def _inspect_ssl(hostname: str, port: int) -> dict[str, Any]:
        """Perform verified SSL handshake and extract certificate metadata."""
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                cipher, _, bits = ssock.cipher() or (None, None, None)
                cert = ssock.getpeercert() or {}

                subject_parts = [f"{k}={v}" for item in cert.get("subject", ()) for k, v in item]
                issuer_parts = [f"{k}={v}" for item in cert.get("issuer", ()) for k, v in item]
                sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

                expires_str = cert.get("notAfter")
                days_left = None
                if expires_str:
                    try:
                        # Format example: 'May 15 12:00:00 2026 GMT'
                        exp_dt = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (exp_dt - datetime.now(timezone.utc)).days
                    except Exception:
                        pass

                return {
                    "tls_version": version,
                    "cipher": cipher,
                    "cipher_bits": bits,
                    "cert_subject": ", ".join(subject_parts),
                    "cert_issuer": ", ".join(issuer_parts),
                    "cert_expires": expires_str,
                    "days_until_expiry": days_left,
                    "sans": sans[:10],
                }

    @staticmethod
    def _inspect_ssl_unverified(hostname: str, port: int) -> dict[str, Any]:
        """Extract TLS version and cipher even if cert verification fails."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                cipher, _, bits = ssock.cipher() or (None, None, None)
                return {
                    "tls_version": version,
                    "cipher": cipher,
                    "cipher_bits": bits,
                }
