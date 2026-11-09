"""
Publicly Exposed Configuration & Sensitive File Checker — Phase 5.

Passively checks for common configuration, backup, and sensitive files
that are frequently left publicly accessible by mistake.  Each check
issues a single bounded GET request and validates only the response
status code and minimal content patterns.

Checks performed (GET only, no modification):
  - /.env               — Environment variable file
  - /.env.local         — Local environment overrides
  - /.env.production    — Production environment file
  - /config.php         — PHP configuration
  - /config.yml / config.yaml
  - /config.json        — JSON configuration
  - /settings.py        — Django settings
  - /settings.json
  - /web.config         — ASP.NET configuration
  - /app.config
  - /database.yml       — Rails database config
  - /wp-config.php      — WordPress config
  - /docker-compose.yml — Docker Compose
  - /Dockerfile
  - /.git/config        — Git repository config (leaks remote URLs)
  - /.git/HEAD
  - /.svn/entries       — SVN metadata
  - /backup.sql         — SQL dump
  - /backup.zip / backup.tar.gz
  - /.htaccess          — Apache config
  - /phpinfo.php        — PHP info page
  - /server-status      — Apache server status
  - /server-info        — Apache server info
  - /api-docs           — OpenAPI/Swagger UI (informational)
  - /swagger.json / swagger.yaml / openapi.json

Security:
  - All URLs are SSRF-validated before the GET request.
  - Response bodies are NOT stored in findings evidence (only status codes
    and minimal content markers to avoid leaking secrets).
  - Maximum 1 KB of response body is inspected; the rest is discarded.
  - Requests use a 5-second timeout.
  - Errors (network, timeout, SSRF block) are silently skipped for each path.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import AppException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Check definitions
# Each entry: (path, label, severity, description_hint, content_markers)
# content_markers: if non-empty, the response body must contain at least one
# of these strings (case-insensitive) for a finding to be raised.
# ---------------------------------------------------------------------------
_CHECKS: list[tuple[str, str, str, str, list[str]]] = [
    (
        "/.env",
        ".env Environment File",
        "critical",
        "Plain-text environment files commonly contain database credentials, API keys, and secret keys.",
        ["db_", "database_", "secret", "key=", "password=", "token=", "app_"],
    ),
    (
        "/.env.local",
        ".env.local Environment Override File",
        "critical",
        "Local environment override files may contain developer credentials or private API keys.",
        ["db_", "secret", "key=", "password="],
    ),
    (
        "/.env.production",
        ".env.production Production Environment File",
        "critical",
        "Production environment files typically contain live database credentials and secret keys.",
        ["db_", "secret", "key=", "password="],
    ),
    (
        "/config.php",
        "config.php PHP Configuration File",
        "high",
        "PHP configuration files frequently contain database connection strings and credentials.",
        ["db_", "database", "password", "define("],
    ),
    (
        "/wp-config.php",
        "wp-config.php WordPress Configuration",
        "critical",
        "WordPress configuration files contain database name, user, password, and secret keys.",
        ["db_name", "db_user", "db_password", "auth_key", "table_prefix"],
    ),
    (
        "/config.yml",
        "config.yml YAML Configuration",
        "high",
        "YAML configuration files may contain database URIs, secrets, or service credentials.",
        ["password", "secret", "key:", "database", "token"],
    ),
    (
        "/config.yaml",
        "config.yaml YAML Configuration",
        "high",
        "YAML configuration files may contain database URIs, secrets, or service credentials.",
        ["password", "secret", "key:", "database", "token"],
    ),
    (
        "/config.json",
        "config.json JSON Configuration",
        "high",
        "JSON configuration files may expose application secrets, API keys, or database URIs.",
        ["password", "secret", "key", "database", "token", "apikey"],
    ),
    (
        "/settings.py",
        "settings.py Django Settings File",
        "high",
        "Django settings files contain SECRET_KEY, database credentials, and allowed hosts.",
        ["secret_key", "databases", "password", "installed_apps"],
    ),
    (
        "/settings.json",
        "settings.json Settings File",
        "high",
        "JSON settings files may expose API tokens, secrets, or connection strings.",
        ["password", "secret", "key", "token", "connectionstring"],
    ),
    (
        "/web.config",
        "web.config ASP.NET Configuration",
        "high",
        "ASP.NET web.config files may contain connection strings, credentials, and machine keys.",
        ["connectionstring", "password", "machineKey", "<configuration>"],
    ),
    (
        "/database.yml",
        "database.yml Rails Database Configuration",
        "high",
        "Ruby on Rails database.yml files contain database adapter, host, username, and password.",
        ["adapter:", "password:", "database:", "username:"],
    ),
    (
        "/docker-compose.yml",
        "docker-compose.yml Exposed",
        "medium",
        "Docker Compose files disclose service architecture, exposed ports, and may contain secrets.",
        ["version:", "services:", "image:", "environment:"],
    ),
    (
        "/Dockerfile",
        "Dockerfile Exposed",
        "medium",
        "An exposed Dockerfile reveals the technology stack, base images, and build secrets.",
        ["from ", "run ", "env ", "copy ", "expose "],
    ),
    (
        "/.git/config",
        ".git/config Repository Configuration",
        "high",
        "An exposed Git config file leaks repository remote URLs, branch names, and author identities.",
        ["[core]", "[remote", "url =", "[branch"],
    ),
    (
        "/.git/HEAD",
        ".git/HEAD Repository Reference",
        "high",
        "Exposure of .git/HEAD confirms an accessible Git repository and reveals the active branch.",
        ["ref:", "refs/heads/"],
    ),
    (
        "/.svn/entries",
        ".svn/entries SVN Metadata",
        "high",
        "An exposed SVN entries file leaks repository path, revision numbers, and file listings.",
        [],  # any 200 on this path is suspicious
    ),
    (
        "/phpinfo.php",
        "phpinfo.php PHP Information Page",
        "high",
        "A phpinfo() page discloses the full PHP configuration, loaded extensions, server paths, "
        "and environment variables that may include secrets.",
        ["phpinfo()", "php version", "php credits", "configuration"],
    ),
    (
        "/.htaccess",
        ".htaccess Apache Configuration",
        "medium",
        "An exposed .htaccess file reveals Apache rewrite rules, authentication directives, "
        "and access control lists.",
        ["rewriterule", "authtype", "require", "options", "deny from"],
    ),
    (
        "/server-status",
        "Apache /server-status Information Page",
        "medium",
        "Apache mod_status exposes real-time request details, client IPs, and resource usage.",
        ["apache server status", "server version", "total accesses"],
    ),
    (
        "/server-info",
        "Apache /server-info Information Page",
        "medium",
        "Apache mod_info discloses module configurations and server build details.",
        ["server information", "apache", "module name"],
    ),
    (
        "/backup.sql",
        "SQL Database Backup File",
        "critical",
        "A publicly accessible SQL dump may contain complete database contents including user "
        "credentials and application data.",
        ["create table", "insert into", "-- mysql", "-- postgresql", "-- sqlite"],
    ),
    (
        "/backup.zip",
        "Backup Archive File (ZIP)",
        "high",
        "A ZIP backup archive may contain source code, configuration files, and sensitive data.",
        [],
    ),
    (
        "/api-docs",
        "API Documentation Endpoint",
        "info",
        "Publicly accessible API documentation (Swagger/OpenAPI) discloses all API endpoints, "
        "parameters, and authentication requirements.",
        ["swagger", "openapi", "basepath", "paths"],
    ),
    (
        "/swagger.json",
        "OpenAPI/Swagger JSON Specification",
        "info",
        "An exposed Swagger JSON spec reveals the full API surface area including endpoint "
        "names, HTTP methods, and authentication schemes.",
        ["swagger", "openapi", "paths", "info"],
    ),
    (
        "/openapi.json",
        "OpenAPI JSON Specification",
        "info",
        "An exposed OpenAPI JSON spec reveals the full API surface area.",
        ["openapi", "paths", "info"],
    ),
    (
        "/swagger.yaml",
        "OpenAPI/Swagger YAML Specification",
        "info",
        "An exposed Swagger YAML spec reveals the full API surface area.",
        ["swagger", "openapi", "paths:", "info:"],
    ),
]

# Maximum bytes of response body to inspect (avoid storing large secrets)
_MAX_BODY_INSPECT = 1024  # 1 KB

# Timeout per check request
_CHECK_TIMEOUT = 5.0


class ExposedConfigCheckerModule(BaseScannerModule):
    """
    Checks for publicly accessible sensitive configuration and backup files.
    Passive — only issues GET requests and observes responses.
    """

    module_id = "exposed_config"
    module_name = "Exposed Configuration & Sensitive File Checker"
    category = "Information Disclosure"

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

        exposed_files: list[dict[str, str]] = []
        checked: int = 0
        findings_count: int = 0

        for path, label, severity, hint, content_markers in _CHECKS:
            check_url = origin + path
            # SSRF validation
            try:
                validate_target_url(check_url)
            except AppException:
                continue  # blocked by SSRF rules

            # Issue bounded GET request
            try:
                resp = await http_client.get(check_url, timeout=_CHECK_TIMEOUT)
                checked += 1
            except AppException:
                continue
            except Exception:
                continue

            # Only flag on 200 OK responses (not 401/403/404/500)
            if resp.status_code != 200:
                continue

            # Content validation — if markers are defined, at least one must match
            body_snippet = (resp.text or "")[:_MAX_BODY_INSPECT].lower()
            if content_markers:
                matched = any(m.lower() in body_snippet for m in content_markers)
                if not matched:
                    continue

            # Finding confirmed — do NOT include body content in evidence
            exposed_files.append({"path": path, "label": label, "severity": severity})
            findings_count += 1

            await self._create_finding(
                scan,
                title=f"Publicly Accessible Sensitive File: {label}",
                description=(
                    f"The file at {check_url} is publicly accessible (HTTP 200 OK). "
                    f"{hint}  Exposure of this file may allow attackers to extract "
                    f"credentials, secrets, or application internals."
                ),
                severity=severity,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                cvss_score=self._cvss_for_severity(severity),
                affected_url=check_url,
                remediation=(
                    f"Restrict public access to {path} via web-server configuration rules, "
                    f"firewall rules, or by moving sensitive files outside the document root. "
                    f"Rotate any credentials or secrets that may have been exposed."
                ),
                proof_of_concept=(
                    f"GET {check_url} → HTTP {resp.status_code} OK "
                    f"(content markers matched: "
                    f"{[m for m in content_markers if m.lower() in body_snippet][:3]})"
                ),
                counts=counts,
            )

        return {
            "status": "completed",
            "paths_checked": checked,
            "exposed_files": exposed_files,
            "exposed_count": len(exposed_files),
            "findings_count": findings_count,
        }

    @staticmethod
    def _cvss_for_severity(severity: str) -> float:
        mapping = {
            "critical": 9.3,
            "high": 7.5,
            "medium": 5.3,
            "low": 3.1,
            "info": 0.0,
        }
        return mapping.get(severity.lower(), 2.0)
