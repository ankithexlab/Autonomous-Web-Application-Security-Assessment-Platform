"""
WHOIS Lookup Scanner Module.

Queries domain WHOIS data and flags security-relevant findings such as
upcoming domain expiration and missing WHOIS privacy protection.
"""

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule


class WHOISLookupModule(BaseScannerModule):
    module_id = "whois_lookup"
    module_name = "WHOIS Lookup"
    category = "Information Gathering"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        import asyncio

        hostname = urlparse(target_url).hostname or ""
        results: dict[str, Any] = {"hostname": hostname, "data": {}}

        try:
            import whois

            w = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, hostname),
                timeout=5.0,
            )

            results["data"] = {
                "domain_name": _normalize(w.domain_name),
                "registrar": w.registrar or "Unknown",
                "creation_date": _format_date(w.creation_date),
                "expiration_date": _format_date(w.expiration_date),
                "updated_date": _format_date(w.updated_date),
                "name_servers": _normalize_list(w.name_servers),
                "registrant_name": getattr(w, "name", None) or "REDACTED",
                "registrant_org": getattr(w, "org", None) or "REDACTED",
                "registrant_country": getattr(w, "country", None) or "Unknown",
                "emails": _normalize_list(getattr(w, "emails", None)),
                "dnssec": getattr(w, "dnssec", "unknown"),
            }

            # ── Security Findings ─────────────────────────────────────

            # Check domain expiry
            exp_date = w.expiration_date
            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            if exp_date:
                if isinstance(exp_date, datetime):
                    if exp_date.tzinfo is None:
                        exp_date = exp_date.replace(tzinfo=timezone.utc)
                    days_left = (exp_date - datetime.now(timezone.utc)).days
                    results["data"]["days_until_expiry"] = days_left

                    if days_left < 30:
                        await self._create_finding(
                            scan,
                            title="Domain Expiration Imminent",
                            description=f"The domain '{hostname}' expires in {days_left} days ({exp_date.strftime('%Y-%m-%d')}). If not renewed, an attacker could register it.",
                            severity="high" if days_left < 7 else "medium",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-672",
                            cvss_score=7.5 if days_left < 7 else 5.0,
                            affected_url=target_url,
                            remediation="Renew the domain registration immediately and enable auto-renewal.",
                            proof_of_concept=f"WHOIS expiration_date: {exp_date.isoformat()}, days remaining: {days_left}",
                            counts=counts,
                        )

            # Check WHOIS privacy
            registrant = str(results["data"].get("registrant_name", "")).lower()
            if registrant and registrant not in ("redacted", "redacted for privacy", "data protected", ""):
                await self._create_finding(
                    scan,
                    title="Domain WHOIS Privacy Not Enabled",
                    description=f"The domain '{hostname}' publicly exposes registrant information in WHOIS records, potentially leaking personal data.",
                    severity="info",
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_id="CWE-200",
                    cvss_score=2.0,
                    affected_url=target_url,
                    remediation="Enable WHOIS privacy protection through your domain registrar.",
                    proof_of_concept=f"WHOIS registrant name: '{results['data']['registrant_name']}'",
                    counts=counts,
                )

        except Exception as e:
            results["error"] = str(e)

        return results


def _normalize(value: Any) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value else ""


def _normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if value:
        return [str(value)]
    return []


def _format_date(value: Any) -> str:
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value) if value else "Unknown"
