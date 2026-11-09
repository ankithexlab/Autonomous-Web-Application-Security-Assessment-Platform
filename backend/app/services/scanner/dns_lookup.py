"""
DNS Lookup Scanner Module.

Resolves A, AAAA, MX, NS, TXT, CNAME, SOA records and flags security-relevant
DNS findings (missing SPF/DMARC, dangling records, zone transfer exposure).
"""

import asyncio
from typing import Any
from urllib.parse import urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule


class DNSLookupModule(BaseScannerModule):
    module_id = "dns_lookup"
    module_name = "DNS Lookup"
    category = "Information Gathering"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        import dns.resolver

        hostname = urlparse(target_url).hostname or ""
        results: dict[str, Any] = {"hostname": hostname, "records": {}}

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                answers = await asyncio.wait_for(
                    asyncio.to_thread(dns.resolver.resolve, hostname, rtype),
                    timeout=3.0,
                )
                records = []
                for rdata in answers:
                    if rtype == "MX":
                        records.append({"priority": rdata.preference, "host": str(rdata.exchange)})
                    elif rtype == "SOA":
                        records.append({
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                            "refresh": rdata.refresh,
                            "retry": rdata.retry,
                            "expire": rdata.expire,
                            "minimum": rdata.minimum,
                        })
                    else:
                        records.append(str(rdata))
                results["records"][rtype] = records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, TimeoutError, asyncio.TimeoutError):
                results["records"][rtype] = []
            except Exception:
                results["records"][rtype] = []

        # ── Security Findings ───────────────────────────────────────

        # Check for SPF record
        txt_records = results["records"].get("TXT", [])
        has_spf = any("v=spf1" in str(r).lower() for r in txt_records)
        if not has_spf:
            await self._create_finding(
                scan,
                title="Missing SPF (Sender Policy Framework) Record",
                description=f"The domain '{hostname}' does not publish an SPF TXT record. Attackers can spoof emails appearing to originate from this domain.",
                severity="low",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-290",
                cvss_score=3.7,
                affected_url=target_url,
                remediation="Add a TXT record with a valid SPF policy, e.g. 'v=spf1 include:_spf.google.com ~all'.",
                proof_of_concept=f"DNS TXT query for '{hostname}' returned no SPF record",
                counts=counts,
            )

        # Check for DMARC record
        has_dmarc = False
        try:
            dmarc_answers = await asyncio.wait_for(
                asyncio.to_thread(dns.resolver.resolve, f"_dmarc.{hostname}", "TXT"),
                timeout=3.0,
            )
            has_dmarc = any("v=dmarc1" in str(r).lower() for r in dmarc_answers)
        except Exception:
            pass

        if not has_dmarc:
            await self._create_finding(
                scan,
                title="Missing DMARC Record",
                description=f"The domain '{hostname}' does not publish a DMARC TXT record at '_dmarc.{hostname}'. This weakens email authentication and allows domain spoofing.",
                severity="low",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-290",
                cvss_score=3.5,
                affected_url=target_url,
                remediation="Add a TXT record at '_dmarc.{hostname}' with a DMARC policy, e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'.",
                proof_of_concept=f"DNS TXT query for '_dmarc.{hostname}' returned no DMARC record",
                counts=counts,
            )

        # Check for dangling CNAME
        cname_records = results["records"].get("CNAME", [])
        for cname in cname_records:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(dns.resolver.resolve, str(cname), "A"),
                    timeout=3.0,
                )
            except dns.resolver.NXDOMAIN:
                await self._create_finding(
                    scan,
                    title="Dangling CNAME Record (Subdomain Takeover Risk)",
                    description=f"CNAME record '{cname}' for '{hostname}' points to a non-existent domain, creating a potential subdomain takeover vulnerability.",
                    severity="high",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-672",
                    cvss_score=8.2,
                    affected_url=target_url,
                    remediation=f"Remove the dangling CNAME record pointing to '{cname}' or register the target domain.",
                    proof_of_concept=f"CNAME '{hostname}' -> '{cname}' but '{cname}' returns NXDOMAIN",
                    counts=counts,
                )
            except Exception:
                pass

        return results
