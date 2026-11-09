"""
Command Injection Detector Scanner Module.

PASSIVE detection only — scans HTTP response bodies for signs of command
execution output, shell error messages, and exposed CGI-BIN paths.
Does NOT execute any commands.
"""

import re
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# Shell / OS error patterns that indicate command injection
COMMAND_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"/bin/sh:", "name": "Shell path exposed", "severity": "critical"},
    {"pattern": r"/bin/bash:", "name": "Bash path exposed", "severity": "critical"},
    {"pattern": r"command not found", "name": "Command not found error", "severity": "high"},
    {"pattern": r"syntax error near unexpected token", "name": "Shell syntax error", "severity": "critical"},
    {"pattern": r"sh: \d+:", "name": "Shell error output", "severity": "critical"},
    {"pattern": r"Cannot execute binary file", "name": "Binary execution error", "severity": "critical"},
    {"pattern": r"Permission denied.*exec", "name": "Exec permission error", "severity": "high"},
    {"pattern": r"root:.*:0:0:", "name": "/etc/passwd content", "severity": "critical"},
    {"pattern": r"uid=\d+\(.*?\)\s+gid=\d+", "name": "id command output", "severity": "critical"},
    {"pattern": r"total \d+\s+drwx", "name": "ls -l directory listing", "severity": "high"},
    {"pattern": r"Windows IP Configuration", "name": "ipconfig output", "severity": "high"},
    {"pattern": r"Directory of [A-Z]:\\", "name": "Windows dir command output", "severity": "high"},
    {"pattern": r"Volume Serial Number", "name": "Windows volume info", "severity": "high"},
]

# CGI-BIN and script paths
CGI_PATTERNS = [
    r"/cgi-bin/",
    r"/cgi/",
    r"\.cgi\b",
    r"\.sh\b",
    r"\.pl\b",
    r"\.py\?",
]


class CommandInjectionDetectorModule(BaseScannerModule):
    module_id = "cmd_injection"
    module_name = "Command Injection Detection"
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

        body = main_resp.text or ""
        results: dict[str, Any] = {
            "checked": True,
            "command_output_found": [],
            "cgi_paths_found": [],
        }

        # ── 1. Scan for command output in response body ─────────────
        for entry in COMMAND_PATTERNS:
            matches = re.findall(entry["pattern"], body, re.IGNORECASE)
            if matches:
                results["command_output_found"].append({
                    "name": entry["name"],
                    "count": len(matches),
                    "severity": entry["severity"],
                })

                await self._create_finding(
                    scan,
                    title=f"Command Execution Output Detected: {entry['name']}",
                    description=f"The HTTP response contains output patterns consistent with operating system command execution ({entry['name']}). This strongly indicates a command injection vulnerability.",
                    severity=entry["severity"],
                    owasp_category="A03:2021-Injection",
                    cwe_id="CWE-78",
                    cvss_score=9.8 if entry["severity"] == "critical" else 7.5,
                    affected_url=main_resp.url,
                    remediation="Never pass user input to shell commands. Use language-native APIs instead of shell execution. If unavoidable, use strict input validation and argument escaping.",
                    proof_of_concept=f"Pattern '{entry['pattern']}' found {len(matches)} time(s) in response body",
                    counts=counts,
                )
                break  # One finding per page

        # ── 2. Check for CGI-BIN / script paths ────────────────────
        all_links = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE)
        for link in all_links[:200]:
            for pattern in CGI_PATTERNS:
                if re.search(pattern, link, re.IGNORECASE):
                    results["cgi_paths_found"].append(link[:200])
                    break

        if results["cgi_paths_found"]:
            unique_paths = list(set(results["cgi_paths_found"]))[:5]
            await self._create_finding(
                scan,
                title=f"CGI/Script Paths Detected ({len(unique_paths)} found)",
                description=f"The application references CGI or server-side script paths ({', '.join(unique_paths[:3])}), which are commonly vulnerable to command injection attacks.",
                severity="info",
                owasp_category="A03:2021-Injection",
                cwe_id="CWE-78",
                cvss_score=2.5,
                affected_url=target_url,
                remediation="Audit all CGI scripts for command injection. Consider migrating to modern web frameworks.",
                proof_of_concept=f"CGI paths: {', '.join(unique_paths[:3])}",
                counts=counts,
            )

        return results
