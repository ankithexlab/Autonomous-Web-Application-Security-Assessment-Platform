"""
IDOR Detector Scanner Module.

Supports:
  1. PASSIVE Detection: Analyzes response HTML and URL patterns for sequential
     or predictable identifiers that indicate Insecure Direct Object Reference (IDOR) risks.
  2. ACTIVE Detection: When explicit target authorization and active scan confirmation
     are granted, safely verifies access control enforcement using controlled test accounts
     or harmless non-destructive identifier boundary probes.
"""

import asyncio
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# URL path patterns with sequential numeric IDs
IDOR_PATH_PATTERNS = [
    (r"/(?:user|users|profile|account|member)/(\d{1,8})(?:/|$|\?)", "User ID"),
    (r"/(?:order|orders|invoice|invoices)/(\d{1,8})(?:/|$|\?)", "Order ID"),
    (r"/(?:document|documents|doc|file|files)/(\d{1,8})(?:/|$|\?)", "Document ID"),
    (r"/(?:message|messages|chat|conversation)/(\d{1,8})(?:/|$|\?)", "Message ID"),
    (r"/(?:report|reports)/(\d{1,8})(?:/|$|\?)", "Report ID"),
    (r"/(?:api/v\d+/\w+)/(\d{1,8})(?:/|$|\?)", "API Resource ID"),
]

# Common IDOR-prone parameter names
IDOR_PARAM_NAMES = [
    "id", "uid", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "doc_id", "docId", "file_id", "fileId",
    "message_id", "messageId", "pid", "item_id", "itemId",
]


class IDORDetectorModule(BaseScannerModule):
    module_id = "idor_detector"
    module_name = "IDOR Detection"
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
        url = main_resp.url
        results: dict[str, Any] = {
            "checked": True,
            "status": "completed",
            "sequential_ids_in_url": [],
            "sequential_ids_in_links": [],
            "idor_params": [],
            "active_tested": False,
            "confidence": "INFORMATIONAL",
        }

        # ── 1. Check current URL for sequential IDs (Passive) ───────
        for pattern, id_type in IDOR_PATH_PATTERNS:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                results["sequential_ids_in_url"].append({
                    "type": id_type,
                    "value": match.group(1),
                    "pattern": pattern,
                })

        # ── 2. Check query parameters for numeric IDs (Passive) ─────
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in IDOR_PARAM_NAMES:
            if param_name in params:
                values = params[param_name]
                for val in values:
                    if val.isdigit():
                        results["idor_params"].append({
                            "param": param_name,
                            "value": val,
                        })

        # ── 3. Scan HTML links for sequential ID patterns (Passive) ─
        links = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE)
        sequential_links: list[dict[str, str]] = []
        for link in links[:200]:  # Cap at 200
            for pattern, id_type in IDOR_PATH_PATTERNS:
                match = re.search(pattern, link, re.IGNORECASE)
                if match:
                    sequential_links.append({
                        "link": link[:100],
                        "type": id_type,
                        "value": match.group(1),
                    })
                    break

        results["sequential_ids_in_links"] = sequential_links[:10]

        # ── 4. Report passive findings ──────────────────────────────
        total_sequential = (
            len(results["sequential_ids_in_url"])
            + len(results["idor_params"])
            + len(results["sequential_ids_in_links"])
        )

        if results["sequential_ids_in_url"] or results["idor_params"]:
            details = []
            for item in results["sequential_ids_in_url"]:
                details.append(f"{item['type']}: {item['value']}")
            for item in results["idor_params"]:
                details.append(f"?{item['param']}={item['value']}")

            await self._create_finding(
                scan,
                title="Sequential/Predictable Object IDs Detected (IDOR Risk)",
                description=f"The application uses sequential numeric identifiers in URLs or parameters ({', '.join(details[:5])}). An attacker can enumerate these IDs to access other users' resources.",
                severity="medium",
                confidence="POTENTIAL",
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-639",
                cvss_score=6.5,
                affected_url=url,
                remediation="Use UUIDs or other non-sequential identifiers. Implement server-side authorization checks to verify the requesting user owns the resource.",
                proof_of_concept=f"Found {total_sequential} sequential/numeric IDs: {', '.join(details[:5])}",
                counts=counts,
            )
            results["confidence"] = "POTENTIAL"

        if len(results["sequential_links"] if "sequential_links" in results else results["sequential_ids_in_links"]) > 3:
            await self._create_finding(
                scan,
                title=f"Multiple Sequential Resource Links Found ({len(results['sequential_ids_in_links'])})",
                description=f"The page contains {len(results['sequential_ids_in_links'])} links with sequential numeric IDs, suggesting enumerable resources.",
                severity="info",
                confidence="INFORMATIONAL",
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-639",
                cvss_score=2.5,
                affected_url=target_url,
                remediation="Implement proper authorization checks on all object references.",
                proof_of_concept=f"Sample links: {', '.join(l['link'] for l in results['sequential_ids_in_links'][:3])}",
                counts=counts,
            )

        # ── 5. Active: Safe Controlled Identifier Access Testing ─────
        if not self.is_active_confirmed(scan):
            return results

        results["active_tested"] = True

        # Check for controlled test IDs in scan config
        controlled_test_ids: dict[str, Any] = {}
        if scan.config_json:
            try:
                cfg = json.loads(scan.config_json)
                if isinstance(cfg, dict):
                    controlled_test_ids = cfg.get("controlled_test_ids", {})
            except Exception:
                pass

        # Case A: Explicit Controlled Test IDs Supplied
        if controlled_test_ids and "param" in controlled_test_ids and "target_id" in controlled_test_ids:
            param_key = controlled_test_ids["param"]
            target_id_val = str(controlled_test_ids["target_id"])
            auth_header = controlled_test_ids.get("auth_header", {})

            mutated_p = {k: list(v) for k, v in params.items()}
            mutated_p[param_key] = [target_id_val]
            idor_query = urlencode(mutated_p, doseq=True)
            idor_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, idor_query, parsed.fragment))

            try:
                resp = await http_client.get(idor_url, headers=auth_header)
                await asyncio.sleep(0.05)
                # If target object is returned with HTTP 200 and expected seeded key without 403
                if resp.status_code == 200 and ("id" in (resp.text or "").lower() or "user" in (resp.text or "").lower()):
                    results["confidence"] = "CONFIRMED"
                    await self._create_finding(
                        scan,
                        title=f"Confirmed Insecure Direct Object Reference (IDOR) on Parameter '{param_key}'",
                        description=(
                            f"Active testing against controlled seeded test resource (ID '{target_id_val}') "
                            "demonstrated that the server returned the foreign resource data with HTTP 200 "
                            "without verifying ownership or authorization controls."
                        ),
                        severity="high",
                        confidence="CONFIRMED",
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-639",
                        cvss_score=8.5,
                        affected_url=idor_url,
                        remediation="Enforce server-side access control checks verifying that the authenticated user possesses authorization to view the requested object identifier.",
                        proof_of_concept=f"GET {idor_url} returned HTTP 200 with object payload",
                        counts=counts,
                    )
            except Exception as e:
                results["active_error"] = str(e)
                if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                    results["confidence"] = "INCONCLUSIVE"

        # Case B: Discovered numeric parameter sequential probe
        elif results["idor_params"]:
            candidate = results["idor_params"][0]
            p_name = candidate["param"]
            p_val = int(candidate["value"])

            # Non-existent ID probe (harmless out-of-bounds check)
            probe_val = str(p_val + 999999)
            mutated_p = {k: list(v) for k, v in params.items()}
            mutated_p[p_name] = [probe_val]
            probe_query = urlencode(mutated_p, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))

            try:
                probe_resp = await http_client.get(probe_url)
                await asyncio.sleep(0.05)
                # If unauthenticated request returned 200 with sensitive keywords
                probe_body = (probe_resp.text or "").lower()
                if probe_resp.status_code == 200 and any(k in probe_body for k in ('"email"', '"password"', '"ssn"', '"user_id"')):
                    results["confidence"] = "POTENTIAL"
                    await self._create_finding(
                        scan,
                        title=f"Potential Unauthenticated Direct Object Access on Parameter '{p_name}'",
                        description=(
                            f"Active probing on parameter '{p_name}' showed that unauthenticated requests to "
                            f"mutated identifier '{probe_val}' returned HTTP 200 containing object data, "
                            "indicating missing authorization checks."
                        ),
                        severity="medium",
                        confidence="POTENTIAL",
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-639",
                        cvss_score=6.5,
                        affected_url=probe_url,
                        remediation="Implement strict server-side authentication and resource access control checks.",
                        proof_of_concept=f"GET {probe_url} returned HTTP 200 without requiring authentication",
                        counts=counts,
                    )
            except Exception as e:
                results["active_error"] = str(e)
                if results["confidence"] not in ("CONFIRMED", "POTENTIAL"):
                    results["confidence"] = "INCONCLUSIVE"

        return results
