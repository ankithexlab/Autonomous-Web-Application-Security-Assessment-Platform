"""
IP Detection Scanner Module.

Resolves the target hostname to IP addresses, performs reverse DNS lookups,
and identifies CDN/hosting providers from known IP ranges.
"""

import asyncio
import socket
from typing import Any
from urllib.parse import urlparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# Known CDN / Cloud provider header fingerprints
CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-cdn": "Generic CDN",
    "x-cache": "CDN Cache",
    "x-akamai-transformed": "Akamai",
    "x-fastly-request-id": "Fastly",
    "x-vercel-id": "Vercel",
    "x-netlify-request-id": "Netlify",
    "fly-request-id": "Fly.io",
    "x-azure-ref": "Azure CDN",
}

# Known server header patterns mapping to hosting providers
SERVER_PATTERNS = {
    "cloudflare": "Cloudflare",
    "amazons3": "AWS S3",
    "awselb": "AWS ELB",
    "gws": "Google Web Server",
    "nginx": "Nginx",
    "apache": "Apache",
    "microsoft-iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "openresty": "OpenResty (Nginx-based)",
    "gunicorn": "Gunicorn (Python)",
    "uvicorn": "Uvicorn (Python ASGI)",
    "cowboy": "Cowboy (Erlang)",
}


class IPDetectionModule(BaseScannerModule):
    module_id = "ip_detection"
    module_name = "IP Detection"
    category = "Information Gathering"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        hostname = urlparse(target_url).hostname or ""
        results: dict[str, Any] = {
            "hostname": hostname,
            "ipv4": [],
            "ipv6": [],
            "reverse_dns": [],
            "cdn_detected": None,
            "hosting_provider": None,
        }

        # ── Resolve IP addresses ────────────────────────────────────
        try:
            addr_infos = await asyncio.wait_for(
                asyncio.to_thread(socket.getaddrinfo, hostname, None),
                timeout=3.0,
            )
            seen_ips: set[str] = set()
            for family, _, _, _, sockaddr in addr_infos:
                ip = sockaddr[0]
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                if family == socket.AF_INET:
                    results["ipv4"].append(ip)
                elif family == socket.AF_INET6:
                    results["ipv6"].append(ip)
        except (socket.gaierror, TimeoutError, asyncio.TimeoutError):
            results["error"] = f"Could not resolve hostname '{hostname}'"
            return results
        except Exception as e:
            results["error"] = f"Error resolving hostname '{hostname}': {e}"
            return results

        # ── Reverse DNS ─────────────────────────────────────────────
        for ip in results["ipv4"][:3]:
            try:
                rdns = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyaddr, ip),
                    timeout=2.0,
                )
                results["reverse_dns"].append({"ip": ip, "hostname": rdns[0]})
            except (socket.herror, socket.gaierror, TimeoutError, asyncio.TimeoutError, Exception):
                results["reverse_dns"].append({"ip": ip, "hostname": "N/A"})

        # ── CDN Detection from response headers ─────────────────────
        if main_resp:
            headers = main_resp.headers
            for header_key, cdn_name in CDN_HEADERS.items():
                if header_key in headers:
                    results["cdn_detected"] = cdn_name
                    break

            # Server header analysis
            server = headers.get("server", "").lower()
            for pattern, provider in SERVER_PATTERNS.items():
                if pattern in server:
                    results["hosting_provider"] = provider
                    break

        return results
