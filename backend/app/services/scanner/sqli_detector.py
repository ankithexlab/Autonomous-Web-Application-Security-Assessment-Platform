"""
SQL Injection Detector Scanner Module.

Supports:
  1. PASSIVE Detection: Scans HTTP response bodies and URLs for SQL error messages
     and suspicious parameter patterns.
  2. ACTIVE Detection: When explicit target authorization and active scan confirmation
     are granted, executes safe, non-destructive harmless error probes and boolean-differential
     probes against testable parameters.
"""

import asyncio
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# SQL error patterns by database engine
SQL_ERROR_PATTERNS: list[dict[str, str]] = [
    # MySQL
    {"pattern": r"You have an error in your SQL syntax", "db": "MySQL", "severity": "critical"},
    {"pattern": r"mysql_fetch_array\(\)", "db": "MySQL", "severity": "critical"},
    {"pattern": r"mysql_num_rows\(\)", "db": "MySQL", "severity": "critical"},
    {"pattern": r"Warning.*mysql_", "db": "MySQL", "severity": "critical"},
    {"pattern": r"MySqlException", "db": "MySQL", "severity": "critical"},
    # PostgreSQL
    {"pattern": r"ERROR:\s+syntax error at or near", "db": "PostgreSQL", "severity": "critical"},
    {"pattern": r"pg_query\(\)", "db": "PostgreSQL", "severity": "critical"},
    {"pattern": r"pg_exec\(\)", "db": "PostgreSQL", "severity": "critical"},
    {"pattern": r"PostgreSQL.*ERROR", "db": "PostgreSQL", "severity": "critical"},
    # MSSQL
    {"pattern": r"Unclosed quotation mark after the character string", "db": "MSSQL", "severity": "critical"},
    {"pattern": r"Microsoft OLE DB Provider for SQL Server", "db": "MSSQL", "severity": "critical"},
    {"pattern": r"Microsoft SQL Native Client", "db": "MSSQL", "severity": "critical"},
    {"pattern": r"\[Microsoft\]\[ODBC SQL Server Driver\]", "db": "MSSQL", "severity": "critical"},
    # SQLite
    {"pattern": r"SQLITE_ERROR", "db": "SQLite", "severity": "critical"},
    {"pattern": r"near \".*\": syntax error", "db": "SQLite", "severity": "critical"},
    {"pattern": r"unrecognized token:", "db": "SQLite", "severity": "critical"},
    # Oracle
    {"pattern": r"ORA-\d{5}", "db": "Oracle", "severity": "critical"},
    {"pattern": r"quoted string not properly terminated", "db": "Oracle", "severity": "critical"},
    # Generic
    {"pattern": r"SQL syntax.*error", "db": "Unknown", "severity": "high"},
    {"pattern": r"sql error.*message", "db": "Unknown", "severity": "high"},
    {"pattern": r"unterminated quoted string", "db": "Unknown", "severity": "high"},
]

# URL patterns that suggest SQL injection susceptibility
SUSPICIOUS_PARAM_PATTERNS = [
    r"[?&]\w+=(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b",
    r"[?&]\w+=\d+['\"\\]",
    r"[?&](id|uid|pid|sid|item|page|cat|order|sort)=\d+$",
]


class SQLInjectionDetectorModule(BaseScannerModule):
    module_id = "sqli_detector"
    module_name = "SQL Injection Detection"
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
            return {"checked": False, "status": "skipped", "reason": "Target unreachable"}

        body = main_resp.text or ""
        results: dict[str, Any] = {
            "checked": True,
            "status": "completed",
            "error_messages_found": [],
            "suspicious_params": [],
            "active_tested": False,
            "probes_sent": 0,
            "vulnerable_params": [],
            "confidence": "INFORMATIONAL",
        }

        # ── 1. Passive: Scan primary response body for SQL error messages ─
        passive_confirmed = False
        for entry in SQL_ERROR_PATTERNS:
            matches = re.findall(entry["pattern"], body, re.IGNORECASE)
            if matches:
                results["error_messages_found"].append({
                    "database": entry["db"],
                    "pattern": entry["pattern"],
                    "count": len(matches),
                })

                await self._create_finding(
                    scan,
                    title=f"SQL Error Message Disclosed ({entry['db']})",
                    description=(
                        f"The HTTP response body contains {entry['db']} database error messages, "
                        "indicating a potential SQL injection vulnerability. Error messages also leak database engine information."
                    ),
                    severity=entry["severity"],
                    confidence="CONFIRMED",
                    owasp_category="A03:2021-Injection",
                    cwe_id="CWE-89",
                    cvss_score=9.8 if entry["severity"] == "critical" else 7.5,
                    affected_url=main_resp.url,
                    remediation="Implement parameterized queries (prepared statements) for all database interactions. Suppress verbose SQL error messages in production.",
                    proof_of_concept=f"Pattern '{entry['pattern']}' found {len(matches)} time(s) in response body",
                    counts=counts,
                )
                passive_confirmed = True
                results["confidence"] = "CONFIRMED"
                break  # One finding per page is enough

        # ── 2. Passive: Check URL for suspicious parameters ───────────
        for pattern in SUSPICIOUS_PARAM_PATTERNS:
            match = re.search(pattern, main_resp.url, re.IGNORECASE)
            if match:
                results["suspicious_params"].append(match.group(0))

        if results["suspicious_params"] and not results["error_messages_found"]:
            await self._create_finding(
                scan,
                title="Potentially Injectable URL Parameters Detected",
                description=f"The URL contains parameters that commonly serve as SQL injection entry points: {', '.join(results['suspicious_params'])}",
                severity="info",
                confidence="INFORMATIONAL",
                owasp_category="A03:2021-Injection",
                cwe_id="CWE-89",
                cvss_score=2.0,
                affected_url=main_resp.url,
                remediation="Ensure all URL parameters are validated and used in parameterized queries.",
                proof_of_concept=f"Suspicious parameters: {', '.join(results['suspicious_params'])}",
                counts=counts,
            )

        # ── 3. Active: Safe Non-Destructive Active Testing ────────────
        if not self.is_active_confirmed(scan):
            return results

        results["active_tested"] = True
        parsed = urlparse(main_resp.url)
        params = parse_qs(parsed.query)
        if not params:
            # Check target_url if different
            parsed_orig = urlparse(target_url)
            params = parse_qs(parsed_orig.query)
            if params:
                parsed = parsed_orig

        if not params:
            results["active_note"] = "No query parameters found for active SQLi probing."
            return results

        # Bound parameter testing to max 3 parameters for safety
        testable_params = list(params.keys())[:3]
        for param in testable_params:
            orig_vals = params[param]
            orig_val = orig_vals[0] if orig_vals else "1"

            # ── 3a. Quote Error Probe (Harmless Syntax Trigger) ───────
            mutated_params = {k: list(v) for k, v in params.items()}
            mutated_params[param] = [f"{orig_val}'"]
            probe_query = urlencode(mutated_params, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))

            try:
                results["probes_sent"] += 1
                probe_resp = await http_client.get(probe_url)
                await asyncio.sleep(0.05)  # Safe rate control

                error_detected = False
                for entry in SQL_ERROR_PATTERNS:
                    probe_body = probe_resp.text or ""
                    if re.search(entry["pattern"], probe_body, re.IGNORECASE):
                        error_detected = True
                        results["vulnerable_params"].append(param)
                        results["confidence"] = "CONFIRMED"

                        # Extract matching snippet for proof of concept
                        match = re.search(entry["pattern"], probe_body, re.IGNORECASE)
                        snippet = match.group(0) if match else entry["pattern"]

                        await self._create_finding(
                            scan,
                            title=f"SQL Injection Vulnerability Detected via Error Probe ({entry['db']})",
                            description=(
                                f"Active security testing with a harmless single-quote probe on parameter '{param}' "
                                f"triggered a {entry['db']} database syntax error. This confirms unparameterized SQL query execution."
                            ),
                            severity="critical",
                            confidence="CONFIRMED",
                            owasp_category="A03:2021-Injection",
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                            affected_url=probe_url,
                            remediation=(
                                "Use parameterized queries (prepared statements) or an Object-Relational Mapper (ORM). "
                                "Never concatenate untrusted user input directly into SQL commands."
                            ),
                            proof_of_concept=(
                                f"Probe URL: {probe_url}\n"
                                f"Database Engine: {entry['db']}\n"
                                f"Error Evidence: {snippet}"
                            ),
                            counts=counts,
                        )
                        break

                if error_detected:
                    continue  # Found confirmed SQLi on this param, proceed to next

                # ── 3b. Harmless Boolean-Differential Probe ────────────
                # Compare True condition vs False condition (e.g. 1*1 vs 1*0 or '1'='1' vs '1'='2')
                if orig_val.isdigit():
                    t_val = f"{orig_val}*1"
                    f_val = f"{orig_val}*0"
                else:
                    t_val = f"{orig_val}' AND '1'='1"
                    f_val = f"{orig_val}' AND '1'='2"

                mutated_t = {k: list(v) for k, v in params.items()}
                mutated_t[param] = [t_val]
                t_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mutated_t, doseq=True), parsed.fragment))

                mutated_f = {k: list(v) for k, v in params.items()}
                mutated_f[param] = [f_val]
                f_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mutated_f, doseq=True), parsed.fragment))

                results["probes_sent"] += 2
                t_resp = await http_client.get(t_url)
                await asyncio.sleep(0.05)
                f_resp = await http_client.get(f_url)
                await asyncio.sleep(0.05)

                baseline_len = len(main_resp.text or "")
                t_len = len(t_resp.text or "")
                f_len = len(f_resp.text or "")

                # Boolean condition check: True response similar to baseline, False response distinct
                if (
                    t_resp.status_code == main_resp.status_code
                    and abs(t_len - baseline_len) < max(50, int(0.1 * baseline_len))
                    and (f_resp.status_code != t_resp.status_code or abs(f_len - t_len) > max(100, int(0.3 * baseline_len)))
                ):
                    results["vulnerable_params"].append(param)
                    if results["confidence"] != "CONFIRMED":
                        results["confidence"] = "POTENTIAL"

                    await self._create_finding(
                        scan,
                        title=f"Potential Boolean-Based SQL Injection on Parameter '{param}'",
                        description=(
                            f"Active testing on parameter '{param}' showed a significant differential response "
                            "between True and False boolean conditions, suggesting that user input alters SQL execution logic."
                        ),
                        severity="high",
                        confidence="POTENTIAL",
                        owasp_category="A03:2021-Injection",
                        cwe_id="CWE-89",
                        cvss_score=8.1,
                        affected_url=t_url,
                        remediation="Ensure the parameter is cast to its expected type and bound to SQL statements using parameters.",
                        proof_of_concept=(
                            f"True condition response ({t_url}): HTTP {t_resp.status_code}, length {t_len} bytes\n"
                            f"False condition response ({f_url}): HTTP {f_resp.status_code}, length {f_len} bytes"
                        ),
                        counts=counts,
                    )

            except Exception as e:
                # Honestly record inconclusive probe without crashing
                results["active_error"] = str(e)
                if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                    results["confidence"] = "INCONCLUSIVE"

        return results
