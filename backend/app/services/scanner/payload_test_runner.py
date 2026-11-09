"""
Payload Security Test Runner Module.

Connects the PostgreSQL Security Payloads Dataset to the AWASP testing engine.
Provides safe, controlled, rate-limited test probes against explicitly authorized targets.

Guardrails enforced:
  1. Explicit Target Authorization: Only runs against configured project targets.
  2. SSRF Protection: All destination URLs are filtered through validate_target_url()
     blocking private RFC1918, localhost, and cloud metadata (169.254.169.254) addresses.
  3. No Local Execution: Shell commands, reverse shells, and scripts are NEVER executed
     on the local server. They are treated solely as test data payloads.
  4. Non-Destructive Safe Probes: Replaces or bounds dangerous destructive clauses
     (e.g., DROP, RM) with benign test probes.
  5. Confidence Distinctions: Differentiates CONFIRMED, SUSPECTED, and INCONCLUSIVE findings.
  6. Rate Limiting & Timeouts: Strict per-request timeouts (5.0s) and controlled concurrency.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.models.security_payload import SecurityPayload
from app.repositories.finding import FindingRepository
from app.repositories.security_payload import SecurityPayloadRepository
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger("awasap.payload_runner")


class PayloadSecurityTestRunner(BaseScannerModule):
    """
    Executes controlled security tests using the curated security_payloads library.
    """

    module_id = "payload_test_runner"
    module_name = "Payload Dataset Test Runner"
    category = "Vulnerability Testing"

    def __init__(self, finding_repo: FindingRepository, session: AsyncSession) -> None:
        super().__init__(finding_repo)
        self._session = session
        self._payload_repo = SecurityPayloadRepository(session)

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        """
        Run safe payload probes against the target URL.
        """
        # Validate SSRF guardrails before sending requests
        try:
            validated_url = validate_target_url(target_url)
        except Exception as e:
            logger.warning("Target URL failed SSRF validation in payload runner: %s", e)
            return {"status": "skipped", "reason": "SSRF guardrail blocked destination"}

        parsed = urlparse(validated_url)
        query_params = parse_qs(parsed.query)

        results: dict[str, Any] = {
            "tested_categories": [],
            "total_probes": 0,
            "confirmed_findings": 0,
            "suspected_findings": 0,
            "inconclusive_tests": 0,
            "details": [],
        }

        # ── 1. GET Query-Parameter Active Probes ─────────────────────
        if query_params:
            test_categories = ["tautology", "reflected", "SSRF"]
            for cat in test_categories:
                payloads = await self._payload_repo.get_payloads_by_type(cat, limit=3)
                if not payloads:
                    continue

                results["tested_categories"].append(cat)
                for p in payloads:
                    probe_res = await self._execute_safe_probe(
                        scan=scan,
                        base_url=validated_url,
                        payload_record=p,
                        http_client=http_client,
                        counts=counts,
                    )
                    results["total_probes"] += 1
                    if probe_res["confidence"] == "CONFIRMED":
                        results["confirmed_findings"] += 1
                    elif probe_res["confidence"] == "SUSPECTED":
                        results["suspected_findings"] += 1
                    else:
                        results["inconclusive_tests"] += 1

                    results["details"].append(probe_res)
                    await asyncio.sleep(0.05)
        else:
            logger.info("Target has no query parameters; skipping aggressive GET parameter fuzzing.")
            results["tested_categories"].append("Passive Assessment Only")

        # ── 2. Blind SQLi Differential Timing Analysis ───────────────
        # Only invoked when the target has suitable query parameters and safety conditions are met
        if query_params:
            timing_res = await self.run_blind_sqli_timing_tests(
                scan=scan,
                target_url=validated_url,
                http_client=http_client,
                counts=counts,
            )
            if timing_res.get("status") == "completed":
                results["tested_categories"].append("blind-sqli-timing")
                results["total_probes"] += 1
                if timing_res.get("confirmed"):
                    results["confirmed_findings"] += 1
                elif timing_res.get("confidence") == "SUSPECTED":
                    results["suspected_findings"] += 1
                elif timing_res.get("confidence") == "INCONCLUSIVE":
                    results["inconclusive_tests"] += 1
                results["details"].append(timing_res)
            elif timing_res.get("status") == "inconclusive":
                results["inconclusive_tests"] += 1
                results["details"].append(timing_res)
        else:
            results["details"].append({
                "category": "blind-sqli-timing",
                "status": "skipped",
                "reason": "Target has no query parameters for timing analysis.",
            })

        # ── 3. Safe POST Body Testing ────────────────────────────────
        # Establish whether target has a safe endpoint schema or candidate keys
        candidate_keys: list[str] = []
        if query_params:
            candidate_keys = list(query_params.keys())[:2]
        elif any(seg in parsed.path.lower() for seg in ("/api/", "/search", "/query", "/v1/")):
            candidate_keys = ["query", "search"]

        # Content-type detection
        post_content_type = "application/json"
        if main_resp and "application/x-www-form-urlencoded" in main_resp.headers.get("content-type", "").lower():
            post_content_type = "application/x-www-form-urlencoded"

        lower_url = validated_url.lower()
        blocked_routes = ["logout", "signout", "delete", "destroy", "pay", "checkout", "billing", "upload", "reset-password", "terminate"]
        is_blocked_route = any(b in lower_url for b in blocked_routes)

        if not candidate_keys:
            # If a safe target endpoint or request schema cannot be established, skip the probe and record a clear reason
            results["details"].append({
                "category": "post-body-testing",
                "status": "skipped",
                "reason": "No established request schema or candidate parameter keys for safe POST testing.",
            })
        elif is_blocked_route:
            results["details"].append({
                "category": "post-body-testing",
                "status": "skipped",
                "reason": "Target path matches potentially sensitive/state-changing route policy.",
            })
        else:
            post_res = await self.run_post_body_tests(
                scan=scan,
                target_url=validated_url,
                content_type=post_content_type,
                sample_keys=candidate_keys,
                http_client=http_client,
                counts=counts,
                limit_per_category=1,
            )
            if post_res.get("status") == "completed":
                results["tested_categories"].append(f"post-{post_content_type.split('/')[-1]}-testing")
                results["total_probes"] += post_res.get("total_probes", 0)
                results["confirmed_findings"] += post_res.get("confirmed_findings", 0)
                results["suspected_findings"] += post_res.get("suspected_findings", 0)
                results["inconclusive_tests"] += post_res.get("inconclusive_tests", 0)
                results["details"].append(post_res)
            elif post_res.get("status") == "skipped":
                results["details"].append({
                    "category": "post-body-testing",
                    "status": "skipped",
                    "reason": post_res.get("reason", "Skipped by safety filter"),
                })

        return results

    async def _execute_safe_probe(
        self,
        scan: Scan,
        base_url: str,
        payload_record: SecurityPayload,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        """
        Executes a single, non-destructive probe and analyzes the response for evidence.
        """
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        # Non-destructive safety filter: reject any probe that contains destructive OS commands
        dangerous_tokens = ["rm -rf", "drop database", "shutdown", "format ", "mkfs"]
        lower_payload = payload_record.payload.lower()
        if any(token in lower_payload for token in dangerous_tokens):
            return {
                "payload_id": payload_record.id,
                "confidence": "INCONCLUSIVE",
                "reason": "Payload blocked by safety policy (potentially destructive)",
            }

        # Inject into the first test parameter
        first_param = next(iter(params.keys()))
        test_params = dict(params)
        test_params[first_param] = [payload_record.payload]

        new_query = urlencode(test_params, doseq=True)
        probe_url = urlunparse(parsed._replace(query=new_query))

        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            # Enforce 5s timeout on outbound test request
            resp = await http_client.get(probe_url, timeout=5.0)
            if not resp or not resp.text:
                return {
                    "payload_id": payload_record.id,
                    "target_url": probe_url,
                    "confidence": "INCONCLUSIVE",
                    "reason": "No response or empty body",
                    "timestamp": timestamp,
                }

            # Evidence evaluation
            confidence = "INCONCLUSIVE"
            evidence = ""

            # Check for SQL error reflection
            if payload_record.type in ("tautology", "union", "error-based"):
                if any(err in resp.text.lower() for err in ["sql syntax", "mysql_fetch", "syntax error at or near", "ora-"]):
                    confidence = "CONFIRMED"
                    evidence = f"Database error triggered by payload '{payload_record.id}'"
                elif resp.status_code == 500:
                    confidence = "SUSPECTED"
                    evidence = f"HTTP 500 Internal Server Error returned on parameter '{first_param}'"

            # Check for reflected XSS
            elif payload_record.type in ("reflected", "stored"):
                if payload_record.payload in resp.text:
                    confidence = "CONFIRMED"
                    evidence = f"Payload '{payload_record.id}' was reflected unescaped in response body"

            # Record finding if confirmed or suspected
            if confidence in ("CONFIRMED", "SUSPECTED"):
                sev = payload_record.severity.lower()
                if sev not in counts:
                    sev = "medium"

                await self._create_finding(
                    scan,
                    title=f"Potential {payload_record.type.capitalize()} Vulnerability via Test Case {payload_record.id}",
                    description=(
                        f"Target showed anomalous response during test case {payload_record.id} ({payload_record.description}). "
                        f"Evidence: {evidence}"
                    ),
                    severity=sev,
                    category=payload_record.type,
                    owasp_category="A03:2021-Injection" if "sql" in payload_record.type.lower() or "inj" in payload_record.type.lower() else "A01:2021-Broken Access Control",
                    cwe_id="CWE-89" if "sql" in payload_record.type.lower() else "CWE-79",
                    cvss_score=8.5 if confidence == "CONFIRMED" else 6.0,
                    affected_url=probe_url,
                    remediation=f"Sanitize inputs and use parameterized queries / output encoding. Context: {payload_record.context}",
                    proof_of_concept=f"Payload ID: {payload_record.id}\nPayload: {payload_record.payload}\nEvidence: {evidence}",
                    counts=counts,
                )

            return {
                "payload_id": payload_record.id,
                "target_url": probe_url,
                "status_code": resp.status_code,
                "confidence": confidence,
                "evidence": evidence,
                "timestamp": timestamp,
            }

        except Exception as exc:
            return {
                "payload_id": payload_record.id,
                "target_url": probe_url,
                "confidence": "INCONCLUSIVE",
                "reason": str(exc),
                "timestamp": timestamp,
            }

    async def run_post_body_tests(
        self,
        scan: Scan,
        target_url: str,
        content_type: str = "application/json",
        sample_keys: list[str] | None = None,
        http_client: SafeHTTPClient | None = None,
        counts: dict[str, int] | None = None,
        limit_per_category: int = 2,
    ) -> dict[str, Any]:
        """
        Safely bounded, opt-in testing for POST endpoints using JSON or form-encoded bodies.
        Uses controlled sampling (max 2 payloads per category) and non-destructive filters.
        Never executes arbitrary authenticated commands or modifies application state.
        """
        client = http_client or SafeHTTPClient()
        severity_counts = counts if counts is not None else {}

        # Validate SSRF guardrail before proceeding
        try:
            validated_url = validate_target_url(target_url)
        except Exception as e:
            logger.warning("Target URL failed SSRF validation in POST runner: %s", e)
            return {"status": "skipped", "reason": "SSRF guardrail blocked destination"}

        # Validate content type is explicitly supported
        if content_type not in ("application/json", "application/x-www-form-urlencoded"):
            return {
                "status": "skipped",
                "reason": f"Unsupported content type for safe testing: {content_type}. Only application/json and application/x-www-form-urlencoded are permitted.",
            }

        # Avoid state-changing / destructive URL routes
        lower_url = validated_url.lower()
        blocked_routes = ["logout", "signout", "delete", "destroy", "pay", "checkout", "billing", "upload", "reset-password", "terminate"]
        if any(b in lower_url for b in blocked_routes):
            return {
                "status": "skipped",
                "reason": "Target path matches potentially sensitive/state-changing route policy.",
            }

        keys_to_test = sample_keys or ["query", "input", "search"]
        test_key = keys_to_test[0]

        results: dict[str, Any] = {
            "status": "completed",
            "method": "POST",
            "content_type": content_type,
            "target_url": validated_url,
            "tested_key": test_key,
            "total_probes": 0,
            "confirmed_findings": 0,
            "suspected_findings": 0,
            "inconclusive_tests": 0,
            "details": [],
        }

        # Sample up to limit_per_category test cases from tautology and reflected
        for cat in ["tautology", "reflected"]:
            payloads = await self._payload_repo.get_payloads_by_type(cat, limit=limit_per_category)
            if not payloads:
                continue

            for p in payloads:
                probe_res = await self._execute_safe_post_probe(
                    scan=scan,
                    target_url=validated_url,
                    payload_record=p,
                    content_type=content_type,
                    test_key=test_key,
                    http_client=client,
                    counts=severity_counts,
                )
                results["total_probes"] += 1
                if probe_res["confidence"] == "CONFIRMED":
                    results["confirmed_findings"] += 1
                elif probe_res["confidence"] == "SUSPECTED":
                    results["suspected_findings"] += 1
                else:
                    results["inconclusive_tests"] += 1

                results["details"].append(probe_res)
                await asyncio.sleep(0.05)

        return results

    async def _execute_safe_post_probe(
        self,
        scan: Scan,
        target_url: str,
        payload_record: SecurityPayload,
        content_type: str,
        test_key: str,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        """
        Executes a single non-destructive POST probe with JSON or form payload.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # Non-destructive safety filter
        dangerous_tokens = ["rm -rf", "drop database", "shutdown", "format ", "mkfs"]
        lower_payload = payload_record.payload.lower()
        if any(token in lower_payload for token in dangerous_tokens):
            return {
                "payload_id": payload_record.id,
                "confidence": "INCONCLUSIVE",
                "reason": "Payload blocked by safety policy (potentially destructive)",
                "timestamp": timestamp,
            }

        headers = {"Content-Type": content_type}
        json_body = None
        data_body = None

        if content_type == "application/json":
            json_body = {test_key: payload_record.payload}
        else:
            data_body = {test_key: payload_record.payload}

        try:
            resp = await http_client.post(
                target_url=target_url,
                json=json_body,
                data=data_body,
                headers=headers,
                timeout=5.0,
            )

            if not resp or not resp.text:
                return {
                    "payload_id": payload_record.id,
                    "target_url": target_url,
                    "confidence": "INCONCLUSIVE",
                    "reason": "No response or empty body",
                    "timestamp": timestamp,
                }

            confidence = "INCONCLUSIVE"
            evidence = ""

            # Check for SQL error reflection
            if payload_record.type in ("tautology", "union", "error-based"):
                if any(err in resp.text.lower() for err in ["sql syntax", "mysql_fetch", "syntax error at or near", "ora-"]):
                    confidence = "CONFIRMED"
                    evidence = f"Database error triggered via POST body parameter '{test_key}' with payload '{payload_record.id}'"
                elif resp.status_code == 500:
                    confidence = "SUSPECTED"
                    evidence = f"HTTP 500 returned on POST body parameter '{test_key}'"

            # Check for reflected XSS in response
            elif payload_record.type in ("reflected", "stored"):
                if payload_record.payload in resp.text:
                    confidence = "CONFIRMED"
                    evidence = f"Payload '{payload_record.id}' reflected unescaped from POST body parameter '{test_key}'"

            # Record finding if confirmed or suspected
            if confidence in ("CONFIRMED", "SUSPECTED"):
                sev = payload_record.severity.lower()
                if sev not in counts:
                    sev = "medium"

                category_type = payload_record.type
                is_sql = (
                    category_type.lower() in ("tautology", "union", "error-based", "time-based", "blind", "sqli")
                    or "sql" in category_type.lower()
                    or "inj" in category_type.lower()
                )
                cwe = "CWE-89" if is_sql else "CWE-79"
                owasp = "A03:2021-Injection"


                await self._create_finding(
                    scan,
                    title=f"Potential {category_type.capitalize()} Vulnerability via POST ({test_key})",
                    description=(
                        f"Target showed anomalous response during POST {content_type} test case {payload_record.id}. "
                        f"Evidence: {evidence}"
                    ),
                    severity=sev,
                    category=category_type,
                    owasp_category=owasp,
                    cwe_id=cwe,
                    cvss_score=8.5 if confidence == "CONFIRMED" else 6.0,
                    affected_url=target_url,
                    remediation="Sanitize and validate POST body parameters. Use parameterized queries and output encoding.",
                    proof_of_concept=f"POST {target_url}\nContent-Type: {content_type}\nBody: {{{test_key}: {payload_record.payload}}}\nEvidence: {evidence}",
                    counts=counts,
                )

            return {
                "payload_id": payload_record.id,
                "target_url": target_url,
                "status_code": resp.status_code,
                "confidence": confidence,
                "evidence": evidence,
                "timestamp": timestamp,
            }

        except Exception as exc:
            return {
                "payload_id": payload_record.id,
                "target_url": target_url,
                "confidence": "INCONCLUSIVE",
                "reason": str(exc),
                "timestamp": timestamp,
            }

    async def run_blind_sqli_timing_tests(
        self,
        scan: Scan,
        target_url: str,
        http_client: SafeHTTPClient,
        counts: dict[str, int] | None = None,
        test_param: str | None = None,
        delay_seconds: float = 2.0,
    ) -> dict[str, Any]:
        """
        Executes bounded, safe differential timing analysis for Blind SQL Injection.

        Safety & Accuracy Guardrails:
          1. Bounded Baseline Measurement: Calculates target response latency T_base.
          2. Baseline Volatility Filter: Aborts if T_base > 1.5s to prevent false positives from latency jitter.
          3. Non-Destructive Sleep Payloads: Uses bounded 2-second sleep primitives (pg_sleep, SLEEP).
          4. Strict Timeout Bounds: Outbound requests capped at delay + 2.5s (max 4.5s).
          5. Dual-Stage Confirmation: Never confirms on a single delayed response:
             - Step A: Verify primary probe exhibits delta >= 1.7s.
             - Step B: Run non-delay control probe to verify target server is not experiencing global lag.
             - Step C: Run confirmation probe 2 to ensure reproducibility.
        """
        severity_counts = counts if counts is not None else {}
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            validated_url = validate_target_url(target_url)
        except Exception as e:
            return {
                "status": "skipped",
                "reason": f"Target URL failed SSRF validation: {e}",
                "timestamp": timestamp,
            }

        parsed = urlparse(validated_url)
        params = parse_qs(parsed.query)

        if not params:
            return {
                "status": "skipped",
                "reason": "Target has no query parameters for timing analysis.",
                "timestamp": timestamp,
            }

        # Select parameter to test
        target_param = test_param if (test_param and test_param in params) else next(iter(params.keys()))

        # ── 1. Measure Baseline Latency ─────────────────────────────
        try:
            base_resp = await http_client.get(validated_url, timeout=4.0)
            t_base = base_resp.elapsed_seconds if base_resp else 0.0
        except Exception as exc:
            return {
                "status": "inconclusive",
                "param": target_param,
                "reason": f"Failed to establish baseline response time: {exc}",
                "timestamp": timestamp,
            }

        # Baseline Volatility Filter: If server is already sluggish (>1.5s), timing analysis is unreliable
        if t_base > 1.5:
            return {
                "status": "inconclusive",
                "param": target_param,
                "baseline_seconds": round(t_base, 3),
                "confidence": "INCONCLUSIVE",
                "reason": f"Target baseline latency ({t_base:.2f}s) exceeds 1.5s jitter threshold; timing analysis aborted to avoid false positives.",
                "timestamp": timestamp,
            }

        # ── 2. Stage 1: Primary Delay Probe ─────────────────────────
        # Non-destructive 2s sleep payload (PostgreSQL / MySQL)
        primary_payload = f"1' AND (SELECT 1 FROM pg_sleep({int(delay_seconds)}))--"
        test_params = dict(params)
        test_params[target_param] = [primary_payload]
        probe1_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

        probe_timeout = delay_seconds + 2.5  # e.g., 4.5s
        try:
            resp1 = await http_client.get(probe1_url, timeout=probe_timeout)
            t_probe1 = resp1.elapsed_seconds if resp1 else 0.0
        except Exception:
            t_probe1 = probe_timeout

        delta1 = t_probe1 - t_base

        # If primary probe did not introduce significant delay, target is negative
        if delta1 < 1.7:
            return {
                "status": "completed",
                "param": target_param,
                "confidence": "NEGATIVE",
                "baseline_seconds": round(t_base, 3),
                "probe1_seconds": round(t_probe1, 3),
                "delta_seconds": round(delta1, 3),
                "confirmed": False,
                "reason": f"Observed delay ({delta1:.2f}s) below statistical threshold (1.7s).",
                "timestamp": timestamp,
            }

        # ── 3. Stage 2: Control Check & Replication Probe ────────────
        # Step 3a: Non-delay control probe (pg_sleep(0) or benign input)
        control_payload = "1' AND (SELECT 1 FROM pg_sleep(0))--"
        control_params = dict(params)
        control_params[target_param] = [control_payload]
        control_url = urlunparse(parsed._replace(query=urlencode(control_params, doseq=True)))

        try:
            resp_ctrl = await http_client.get(control_url, timeout=3.0)
            t_ctrl = resp_ctrl.elapsed_seconds if resp_ctrl else 0.0
        except Exception:
            t_ctrl = 3.0

        # If control probe also lags, server is experiencing global latency spike, not SQL sleep
        if t_ctrl > 1.5 or (t_ctrl - t_base) > 1.0:
            return {
                "status": "completed",
                "param": target_param,
                "confidence": "INCONCLUSIVE",
                "baseline_seconds": round(t_base, 3),
                "probe1_seconds": round(t_probe1, 3),
                "control_seconds": round(t_ctrl, 3),
                "confirmed": False,
                "reason": "Control probe also exhibited elevated latency; server experienced non-SQL latency spike.",
                "timestamp": timestamp,
            }

        # Step 3b: Confirmation probe 2 (MySQL sleep(2) / secondary delay)
        secondary_payload = f"1' AND (SELECT 1 FROM (SELECT SLEEP({int(delay_seconds)}))a)--"
        conf_params = dict(params)
        conf_params[target_param] = [secondary_payload]
        probe2_url = urlunparse(parsed._replace(query=urlencode(conf_params, doseq=True)))

        try:
            resp2 = await http_client.get(probe2_url, timeout=probe_timeout)
            t_probe2 = resp2.elapsed_seconds if resp2 else 0.0
        except Exception:
            t_probe2 = probe_timeout

        delta2 = t_probe2 - t_base

        if delta2 < 1.7:
            return {
                "status": "completed",
                "param": target_param,
                "confidence": "SUSPECTED",
                "baseline_seconds": round(t_base, 3),
                "probe1_seconds": round(t_probe1, 3),
                "probe2_seconds": round(t_probe2, 3),
                "confirmed": False,
                "reason": "Primary delay observed but failed to reproduce on confirmation probe; potential network jitter.",
                "timestamp": timestamp,
            }

        # ── 4. Stage 3: Confirmed Dual-Stage Finding ─────────────────
        proof = (
            f"Differential Timing Analysis on parameter '{target_param}':\n"
            f"- Baseline Latency: {t_base:.3f}s\n"
            f"- Probe 1 ({primary_payload}): {t_probe1:.3f}s (delta: +{delta1:.3f}s)\n"
            f"- Control Probe ({control_payload}): {t_ctrl:.3f}s\n"
            f"- Probe 2 ({secondary_payload}): {t_probe2:.3f}s (delta: +{delta2:.3f}s)\n"
            f"Evidence: Both delay probes consistently induced >= 1.7s differential latency while control returned normally."
        )

        await self._create_finding(
            scan,
            title=f"Time-Based Blind SQL Injection on Parameter '{target_param}'",
            description=(
                f"The parameter '{target_param}' was verified vulnerable to time-based blind SQL injection. "
                f"Injected delay payloads consistently altered server response times by >= {delay_seconds}s "
                f"across multiple distinct probe stages."
            ),
            severity="high",
            category="blind-time",
            owasp_category="A03:2021-Injection",
            cwe_id="CWE-89",
            cvss_score=8.6,
            affected_url=validated_url,
            remediation="Use parameterized queries / prepared statements for all SQL database interactions. Never concatenate user input into queries.",
            proof_of_concept=proof,
            counts=severity_counts,
        )

        return {
            "status": "completed",
            "param": target_param,
            "confidence": "CONFIRMED",
            "baseline_seconds": round(t_base, 3),
            "probe1_seconds": round(t_probe1, 3),
            "probe2_seconds": round(t_probe2, 3),
            "control_seconds": round(t_ctrl, 3),
            "confirmed": True,
            "finding_created": True,
            "timestamp": timestamp,
        }

