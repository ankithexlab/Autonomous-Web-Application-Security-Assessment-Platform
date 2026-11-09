"""
Directory Discovery Scanner Module.

Probes a curated list of commonly-exposed sensitive paths and reports
findings for any that return HTTP 200 or 403 (indicating existence).
All requests go through SafeHTTPClient — fully SSRF-safe.
"""

import re
from typing import Any
from urllib.parse import urlparse
import uuid

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# ── Sensitive paths to probe ────────────────────────────────────────
SENSITIVE_PATHS: list[dict[str, Any]] = [
    # Version control
    {"path": "/.git/HEAD", "name": "Git Repository", "severity": "high", "cwe": "CWE-538"},
    {"path": "/.svn/entries", "name": "SVN Repository", "severity": "high", "cwe": "CWE-538"},
    {"path": "/.hg/dirstate", "name": "Mercurial Repository", "severity": "high", "cwe": "CWE-538"},
    # Environment / config
    {"path": "/.env", "name": "Environment File", "severity": "critical", "cwe": "CWE-200"},
    {"path": "/.htaccess", "name": "Apache Config", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/web.config", "name": "IIS Config", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/.DS_Store", "name": "macOS DS_Store", "severity": "low", "cwe": "CWE-538"},
    # Admin panels
    {"path": "/admin/", "name": "Admin Panel", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/administrator/", "name": "Admin Panel", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/wp-admin/", "name": "WordPress Admin", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/wp-login.php", "name": "WordPress Login", "severity": "info", "cwe": "CWE-200"},
    {"path": "/phpmyadmin/", "name": "phpMyAdmin", "severity": "high", "cwe": "CWE-200"},
    # Debug / info
    {"path": "/phpinfo.php", "name": "PHP Info Page", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/server-status", "name": "Apache Server Status", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/server-info", "name": "Apache Server Info", "severity": "medium", "cwe": "CWE-200"},
    {"path": "/elmah.axd", "name": "ELMAH Error Log", "severity": "high", "cwe": "CWE-200"},
    {"path": "/trace.axd", "name": "ASP.NET Trace", "severity": "high", "cwe": "CWE-200"},
    # API documentation
    {"path": "/swagger.json", "name": "Swagger API Docs", "severity": "info", "cwe": "CWE-200"},
    {"path": "/api/docs", "name": "API Documentation", "severity": "info", "cwe": "CWE-200"},
    {"path": "/openapi.json", "name": "OpenAPI Spec", "severity": "info", "cwe": "CWE-200"},
    {"path": "/graphql", "name": "GraphQL Endpoint", "severity": "info", "cwe": "CWE-200"},
    # Backups
    {"path": "/backup/", "name": "Backup Directory", "severity": "high", "cwe": "CWE-530"},
    {"path": "/backups/", "name": "Backup Directory", "severity": "high", "cwe": "CWE-530"},
    {"path": "/db.sql", "name": "Database Dump", "severity": "critical", "cwe": "CWE-530"},
    {"path": "/database.sql", "name": "Database Dump", "severity": "critical", "cwe": "CWE-530"},
    # CI/CD
    {"path": "/.github/workflows/", "name": "GitHub Actions", "severity": "low", "cwe": "CWE-200"},
    {"path": "/.gitlab-ci.yml", "name": "GitLab CI Config", "severity": "low", "cwe": "CWE-200"},
    {"path": "/Dockerfile", "name": "Dockerfile", "severity": "low", "cwe": "CWE-200"},
    {"path": "/docker-compose.yml", "name": "Docker Compose", "severity": "low", "cwe": "CWE-200"},
    # Other
    {"path": "/crossdomain.xml", "name": "Flash Crossdomain Policy", "severity": "low", "cwe": "CWE-942"},
    {"path": "/clientaccesspolicy.xml", "name": "Silverlight Policy", "severity": "low", "cwe": "CWE-942"},
]


class DirectoryDiscoveryModule(BaseScannerModule):
    module_id = "directory_discovery"
    module_name = "Directory Discovery"
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
        discovered: list[dict[str, Any]] = []

        # 1. Baseline soft-404 check with randomized non-existent path
        random_path = f"/awasap_404_probe_{uuid.uuid4().hex[:12]}"
        has_soft_404 = False
        baseline_body = ""
        try:
            baseline_resp = await http_client.get(f"{origin}{random_path}")
            if baseline_resp and baseline_resp.status_code == 200:
                has_soft_404 = True
                baseline_body = baseline_resp.text or ""
        except Exception:
            pass

        for entry in SENSITIVE_PATHS:
            probe_url = f"{origin}{entry['path']}"
            try:
                resp = await http_client.get(probe_url)
                if resp.status_code in (200, 403):
                    if not _is_valid_exposure(entry, resp, has_soft_404, baseline_body):
                        continue

                    discovered.append({
                        "path": entry["path"],
                        "name": entry["name"],
                        "status_code": resp.status_code,
                        "severity": entry["severity"],
                    })

                    severity = entry["severity"]
                    # Downgrade to info if we only get 403 (exists but forbidden)
                    if resp.status_code == 403:
                        severity = "info"

                    await self._create_finding(
                        scan,
                        title=f"Exposed {entry['name']} ({entry['path']})",
                        description=f"The path '{entry['path']}' is accessible (HTTP {resp.status_code}), potentially exposing {entry['name'].lower()} to attackers.",
                        severity=severity,
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id=entry["cwe"],
                        cvss_score=_severity_to_cvss(severity),
                        affected_url=probe_url,
                        remediation=f"Restrict access to '{entry['path']}' via web server configuration, firewall rules, or by removing it from the public web root.",
                        proof_of_concept=f"GET {probe_url} returned HTTP {resp.status_code}",
                        counts=counts,
                    )
            except Exception:
                # Connection errors, timeouts — skip silently
                continue

        return {
            "paths_checked": len(SENSITIVE_PATHS),
            "discovered": discovered,
            "discovered_count": len(discovered),
        }


def _is_valid_exposure(
    entry: dict[str, Any],
    resp: SafeHTTPResponse,
    has_soft_404: bool,
    baseline_body: str,
) -> bool:
    """
    Validates whether an HTTP 200/403 response represents genuine file exposure
    rather than a soft-404, SPA catch-all, or generic HTML response.
    """
    if resp.status_code == 403:
        return True

    if resp.status_code != 200:
        return False

    body = resp.text or ""
    headers = resp.headers
    content_type = headers.get("content-type", "").lower()
    path = entry["path"]

    # Filter out soft-404 / SPA catch-all pages
    if has_soft_404:
        if abs(len(body) - len(baseline_body)) < 80 or body == baseline_body:
            return False
        if ("<html" in body.lower() or "<!doctype" in body.lower()) and not path.endswith(("/", ".html", ".php")):
            return False

    # Path-specific content validation
    if path == "/.env":
        if "text/html" in content_type or "<html" in body.lower():
            return False
        return bool(re.search(r'^\s*[A-Z0-9_]{2,}\s*=', body, re.MULTILINE))

    if path == "/.git/HEAD":
        if "<html" in body.lower():
            return False
        return bool(re.search(r'^(ref:\s*refs/|[0-9a-f]{40})', body.strip()))

    if path == "/.svn/entries":
        if "<html" in body.lower():
            return False
        return bool(re.search(r'^(10|12|\d+\s+dir|\$svn:)', body.strip(), re.IGNORECASE))

    if path == "/.hg/dirstate":
        return "<html" not in body.lower()

    if path in ("/db.sql", "/database.sql"):
        if "<html" in body.lower():
            return False
        return bool(re.search(r'\b(CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|LOCK\s+TABLES)\b', body, re.IGNORECASE))

    if path in ("/swagger.json", "/openapi.json"):
        if "<html" in body.lower():
            return False
        return bool(re.search(r'["\'](swagger|openapi)["\']\s*:\s*["\']', body))

    if path in ("/.htaccess", "/web.config"):
        if "<html" in body.lower():
            return False
        if path == "/.htaccess":
            return bool(re.search(r'\b(RewriteEngine|Order\s+(allow|deny)|Deny\s+from|Options\s+[+-]|DirectoryIndex)\b', body, re.IGNORECASE))
        return bool(re.search(r'<configuration\b|<system\.webServer\b', body, re.IGNORECASE))

    if path == "/phpinfo.php":
        return bool(re.search(r'PHP Version|phpinfo\(\)', body, re.IGNORECASE))

    if path == "/server-status":
        return bool(re.search(r'Apache Server Status|Server Version:', body, re.IGNORECASE))

    if path == "/server-info":
        return bool(re.search(r'Apache Server Information|Server Settings', body, re.IGNORECASE))

    if path == "/elmah.axd":
        return bool(re.search(r'Error Log for|ELMAH', body, re.IGNORECASE))

    if path == "/trace.axd":
        return bool(re.search(r'Application Trace', body, re.IGNORECASE))

    if path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
        return bool(re.search(r'<cross-domain-policy\b|<access-policy\b', body, re.IGNORECASE))

    if path.endswith(".yml") or path.endswith(".yaml"):
        if "<html" in body.lower():
            return False
        return bool(re.search(r'^\s*[\w.-]+:\s*', body, re.MULTILINE))

    if path in ("/Dockerfile", "/.DS_Store"):
        if "<html" in body.lower():
            return False
        if path == "/Dockerfile":
            return bool(re.search(r'^\s*(FROM|RUN|CMD|ENTRYPOINT|ENV)\s+', body, re.MULTILINE | re.IGNORECASE))
        return True

    # For directory listings
    if path.endswith("/"):
        if has_soft_404 and "<html" in body.lower() and abs(len(body) - len(baseline_body)) < 150:
            return False
        return True

    return True


def _severity_to_cvss(severity: str) -> float:
    return {
        "critical": 9.1,
        "high": 7.5,
        "medium": 5.3,
        "low": 3.0,
        "info": 1.5,
    }.get(severity, 3.0)
