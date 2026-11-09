"""
AWASAP Project & Security Data Context Retriever.

Gathers:
1. Verified AWASAP repository knowledge (architecture, scanner engine, files, routes, scoring formula).
2. Live authenticated user security data (projects, targets, scans, findings, score breakdown).
3. Payload library statistics.
4. Targeted source code snippets for code-aware questions.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.security_payload import SecurityPayload
from app.models.target import Target
from app.services.ai.sanitizer import (
    sanitize_evidence_text,
    sanitize_sensitive_secrets,
    sanitize_user_input,
)


AWASAP_ARCHITECTURE_SUMMARY = """
=== AWASAP ARCHITECTURE & MODULES ===
- Project Name: AWASAP (Autonomous Web Application Security Assessment Platform)
- Purpose: Automated, safe, passive web application security assessment, vulnerability detection, and AI-assisted remediation.
- Frontend Stack: React 19, TypeScript, Vite, Tailwind CSS v4, Radix UI, TanStack React Query, Lucide icons, Framer Motion, Recharts, Sonner.
- Backend Stack: FastAPI (Python 3.11+), SQLAlchemy 2.0 (AsyncIO), Pydantic v2, Alembic, SQLite / PostgreSQL (asyncpg), HTTPX.
- AI Engine: Google Gemini (gemini-2.0-flash / gemini-1.5-flash) with structured remediation analysis and interactive Sentinel AI assistant.

=== CORE SOURCE CODE LOCATIONS ===
1. Scanner Engine:
   - Primary Controller: `backend/app/services/scanner_engine.py` (ScannerEngine class)
   - HTTP Client with SSRF Guardrails: `backend/app/core/http_client.py` and `backend/app/core/ssrf.py`
   - Modules (`backend/app/services/scanner/`):
     * Information Gathering: dns_lookup.py, whois_lookup.py, ip_detection.py, tech_detection.py, directory_discovery.py
     * Security Analysis: cors_analyzer.py, session_analyzer.py
     * Vulnerability Detection: sqli_detector.py, xss_detector.py, csrf_detector.py, idor_detector.py, open_redirect_detector.py, command_injection_detector.py, jwt_analyzer.py, api_security.py, file_upload_detector.py, rate_limit_detector.py, payload_test_runner.py
     * OWASP Checks: `backend/app/services/owasp/owasp_engine.py` (OWASP Top 10 A01 to A10)

2. Scanner Execution Pipeline (10 Sequential Stages):
   - Stage 1 (5%): URL & SSRF Validation (validates scheme, resolves IP, blocks loopback/private/metadata 169.254.169.254)
   - Stage 2 (15%): Information Gathering (DNS, WHOIS, IP geo/ASN, technology detection, directory discovery)
   - Stage 3 (30%): Primary HTTP Response Collection (SafeHTTPClient GET, status, headers, latency)
   - Stage 4 (45%): Security Headers & Cookie Audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; Secure, HttpOnly, SameSite)
   - Stage 5 (55%): HTTPS & Redirect Analysis (HTTP to HTTPS redirection, redirect chain hop count)
   - Stage 6 (65%): Server Information Disclosure (Server & X-Powered-By headers; robots.txt & sitemap.xml)
   - Stage 7 (75%): OWASP Top 10 Checks (A01: Broken Access Control through A10: SSRF)
   - Stage 8 (85%): Security Analysis Modules (CORS origins/credentials, session cookies)
   - Stage 9 (95%): Vulnerability Detection (SQLi, XSS, CSRF, IDOR, Open Redirect, Command Injection, JWT, API, File Upload, Rate Limiting, Payloads)
   - Stage 10 (100%): Summary Compilation & Result Persistence

3. Dashboard & Security Posture Score Calculation:
   - Location: `backend/app/services/dashboard.py` (DashboardService class, lines 83-85)
   - Formula:
     * Base Score = 100.0
     * deduction = (critical_count * 25) + (high_count * 15) + (medium_count * 8) + (low_count * 3)
     * overall_security_score = max(0.0, float(100 - deduction))
     * Note: Informational (info) findings cause 0 point deduction.
     * When there are 0 findings (or only info findings), the score is exactly 100/100.

4. Database Models (`backend/app/models/`):
   - User (`user.py`): id, email, hashed_password, role, is_active
   - Project (`project.py`): id, name, description, user_id
   - Target (`target.py`): id, url, name, project_id
   - Scan (`scan.py`): id, target_id, project_id, user_id, status, progress, findings_count, critical_count, high_count, medium_count, low_count, info_count, started_at, completed_at
   - Finding (`finding.py`): id, scan_id, target_id, project_id, user_id, title, description, severity, status, confidence, category, owasp_category, cwe_id, cvss_score, affected_url, remediation, proof_of_concept, ai_explanation_json, ai_remediation_json
   - Report (`report.py`): id, project_id, user_id, title, report_type, file_format, overall_score
   - SecurityPayload (`security_payload.py`): id, description, payload, context, type, severity, example_usage

5. API Routes:
   - Auth: `/api/v1/auth` (login, register, forgot-password, reset-password, me)
   - Projects: `/api/v1/projects`
   - Targets: `/api/v1/targets`
   - Scans: `/api/v1/scans` (create, list, get, cancel, start, findings)
   - Findings: `/api/v1/findings` (list, get, update status)
   - Reports: `/api/v1/reports` (generate, list, download)
   - Dashboard: `/api/v1/dashboard/summary`
   - Payloads: `/api/v1/payloads`
   - AI Assistant: `/api/v1/ai/chat`, `/api/v1/ai/status`, `/api/v1/ai/findings/{id}/analyze`, `/api/v1/ai/findings/{id}/remediation`
"""


class ContextRetriever:
    """Retrieves relevant project facts, code references, and live authorized database records."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_user_security_context(self, user_id: str | UUID | None) -> str:
        """Fetch live project, target, scan, and finding records strictly for the authenticated user."""
        if not user_id:
            return "No authenticated user session. Cannot retrieve user-specific database records."

        uid = UUID(str(user_id)) if isinstance(user_id, str) else user_id

        # 1. Projects
        proj_res = await self._session.execute(
            select(Project.name).where(Project.user_id == uid).limit(10)
        )
        project_names = [row[0] for row in proj_res.all()]

        # 2. Targets
        tgt_res = await self._session.execute(
            select(Target.url)
            .join(Project, Target.project_id == Project.id)
            .where(Project.user_id == uid)
            .limit(10)
        )
        target_urls = [row[0] for row in tgt_res.all()]

        # 3. Scans
        scan_res = await self._session.execute(
            select(Scan.status, Scan.scan_type, Scan.findings_count, Scan.created_at, Scan.id)
            .where(Scan.user_id == uid)
            .order_by(Scan.created_at.desc())
            .limit(5)
        )
        scans_info = []
        for row in scan_res.all():
            scans_info.append(
                f"- Scan {row[4]}: Type={row[1]}, Status={row[0]}, Findings={row[2]}, Created={row[3]}"
            )

        # 4. Findings & Severity counts (all vs active)
        sev_res = await self._session.execute(
            select(func.lower(Finding.severity), func.count(Finding.id))
            .where(Finding.user_id == uid)
            .group_by(func.lower(Finding.severity))
        )
        sev_map = {sev: count for sev, count in sev_res.all()}
        crit = sev_map.get("critical", 0)
        high = sev_map.get("high", 0)
        med = sev_map.get("medium", 0)
        low = sev_map.get("low", 0)
        info = sev_map.get("info", 0)
        total_findings = sum(sev_map.values())

        # Exact posture score (active risk deduction excluding resolved/fixed/false_positive/accepted_risk)
        inactive_statuses = ("resolved", "fixed", "false_positive", "accepted_risk")
        active_sev_res = await self._session.execute(
            select(func.lower(Finding.severity), func.count(Finding.id))
            .where(
                Finding.user_id == uid,
                func.coalesce(func.lower(Finding.status), "open").notin_(inactive_statuses),
            )
            .group_by(func.lower(Finding.severity))
        )
        active_sev_map = {sev: count for sev, count in active_sev_res.all()}
        act_crit = active_sev_map.get("critical", 0)
        act_high = active_sev_map.get("high", 0)
        act_med = active_sev_map.get("medium", 0)
        act_low = active_sev_map.get("low", 0)

        deduction = act_crit * 25 + act_high * 15 + act_med * 8 + act_low * 3
        score = max(0.0, float(100 - deduction))

        # Recent findings
        findings_res = await self._session.execute(
            select(Finding.title, Finding.severity, Finding.category, Finding.affected_url)
            .where(Finding.user_id == uid)
            .order_by(Finding.created_at.desc())
            .limit(8)
        )
        recent_findings = [
            f"- [{row[1].upper()}] {sanitize_user_input(row[0])} (Category: {row[2]}, Target: {row[3] or 'N/A'})"
            for row in findings_res.all()
        ]

        # 5. Generated Reports
        rep_res = await self._session.execute(
            select(Report.title, Report.report_type, Report.file_format, Report.overall_score, Report.created_at)
            .where(Report.user_id == uid)
            .order_by(Report.created_at.desc())
            .limit(5)
        )
        reports_info = [
            f"- '{row[0]}' (Type: {row[1]}, Format: {row[2]}, Score: {row[3]}, Created: {row[4]})"
            for row in rep_res.all()
        ]

        # Payload library stats
        payload_cnt_res = await self._session.execute(select(func.count(SecurityPayload.id)))
        payload_count = payload_cnt_res.scalar_one() or 0

        # Construct live context block
        lines = [
            "=== LIVE AUTHENTICATED USER DATABASE RECORDS ===",
            f"- Total Projects: {len(project_names)} ({', '.join(project_names) if project_names else 'None'})",
            f"- Configured Targets: {len(target_urls)} ({', '.join(target_urls) if target_urls else 'None'})",
            f"- Total Scans Performed: {len(scans_info)}",
        ]
        if scans_info:
            lines.append("  Recent Scans:")
            lines.extend(["  " + s for s in scans_info])
        else:
            lines.append("  (No scans recorded yet for this user)")

        lines.extend([
            f"- Total Generated Security Reports: {len(reports_info)}",
        ])
        if reports_info:
            lines.append("  Recent Reports:")
            lines.extend(["  " + r for r in reports_info])
        else:
            lines.append("  (No security reports generated yet for this user)")

        lines.extend([
            f"- Total Findings: {total_findings}",
            f"  * Critical: {crit}",
            f"  * High: {high}",
            f"  * Medium: {med}",
            f"  * Low: {low}",
            f"  * Informational: {info}",
            f"- Current Calculated Dashboard Security Posture Score: {score}/100",
            f"  * Score Deduction Formula: (Critical: {crit}*25) + (High: {high}*15) + (Medium: {med}*8) + (Low: {low}*3) = {deduction} points deducted from 100.",
        ])

        if recent_findings:
            lines.append("  Recent Findings:")
            lines.extend(["  " + f for f in recent_findings])
        else:
            lines.append("  (No vulnerability findings recorded yet for this user)")

        lines.append(f"- Global Security Payload Library: {payload_count} loaded test signatures")

        return "\n".join(lines)

    async def get_finding_context(self, finding_id: UUID | str, user_id: UUID | str) -> str | None:
        """Retrieve full details of a specific finding owned by user for targeted chat sessions."""
        try:
            fid = UUID(str(finding_id))
            uid = UUID(str(user_id))
        except Exception:
            return None
        res = await self._session.execute(
            select(Finding).where(Finding.id == fid, Finding.user_id == uid)
        )
        f = res.scalar_one_or_none()
        if not f:
            return None
        sanitized_desc = sanitize_evidence_text(f.description) or "N/A"
        sanitized_poc = sanitize_evidence_text(f.proof_of_concept) or "N/A"
        return (
            "=== ACTIVE FOCUSED VULNERABILITY FINDING IN SESSION ===\n"
            f"- ID: {f.id}\n"
            f"- Title: {sanitize_user_input(f.title)}\n"
            f"- Severity: {f.severity.upper()}\n"
            f"- Status: {f.status}\n"
            f"- Confidence: {f.confidence}\n"
            f"- Category: {f.category}\n"
            f"- OWASP Category: {f.owasp_category or 'N/A'}\n"
            f"- CWE: {f.cwe_id or 'N/A'}\n"
            f"- CVSS v3.1 Score: {f.cvss_score if f.cvss_score is not None else 'N/A'}\n"
            f"- Affected URL: {f.affected_url or 'N/A'}\n"
            f"- Description: {sanitized_desc}\n"
            f"- Evidence Proof of Concept: {sanitized_poc}\n"
            f"- Standard Remediation: {f.remediation or 'N/A'}"
        )

    async def get_scan_context(self, scan_id: UUID | str, user_id: UUID | str) -> str | None:
        """Retrieve full details of a specific scan owned by user for targeted chat sessions."""
        try:
            sid = UUID(str(scan_id))
            uid = UUID(str(user_id))
        except Exception:
            return None
        res = await self._session.execute(
            select(Scan, Target.url)
            .outerjoin(Target, Scan.target_id == Target.id)
            .where(Scan.id == sid, Scan.user_id == uid)
        )
        row = res.first()
        if not row:
            return None
        s, target_url = row
        return (
            "=== ACTIVE FOCUSED SECURITY SCAN IN SESSION ===\n"
            f"- Scan ID: {s.id}\n"
            f"- Target URL: {target_url or 'N/A'}\n"
            f"- Scan Type: {s.scan_type}\n"
            f"- Status: {s.status}\n"
            f"- Progress: {s.progress}%\n"
            f"- Findings Count: {s.findings_count} (Critical: {s.critical_count}, High: {s.high_count}, Medium: {s.medium_count}, Low: {s.low_count}, Info: {s.info_count})\n"
            f"- Execution Timestamps: Started={s.started_at}, Completed={s.completed_at}"
        )

    async def get_report_context(self, report_id: UUID | str, user_id: UUID | str) -> str | None:
        """Retrieve full details of a specific report owned by user for targeted chat sessions."""
        try:
            rid = UUID(str(report_id))
            uid = UUID(str(user_id))
        except Exception:
            return None
        res = await self._session.execute(
            select(Report).where(Report.id == rid, Report.user_id == uid)
        )
        r = res.scalar_one_or_none()
        if not r:
            return None
        return (
            "=== ACTIVE FOCUSED REPORT IN SESSION ===\n"
            f"- Report ID: {r.id}\n"
            f"- Title: {r.title}\n"
            f"- Report Type: {r.report_type}\n"
            f"- File Format: {r.file_format}\n"
            f"- Overall Score: {r.overall_score}/100\n"
            f"- Generated At: {r.created_at}"
        )

    def get_project_knowledge(self) -> str:
        """Return canonical AWASAP architecture and code documentation."""
        return AWASAP_ARCHITECTURE_SUMMARY

    def get_relevant_code_snippet(self, query: str) -> str:
        """Return targeted code snippets if the query specifically asks about implementation details."""
        query_lower = query.lower()
        snippets = []

        if "scanner" in query_lower or "engine" in query_lower:
            snippets.append(
                "--- Scanner Engine Implementation (backend/app/services/scanner_engine.py) ---\n"
                "class ScannerEngine:\n"
                "    async def run_scan(self, scan_id: UUID) -> Scan:\n"
                "        # Stage 1: URL & SSRF Validation (app/core/ssrf.py)\n"
                "        validated_url = validate_target_url(target_url)\n"
                "        # Stage 2: Information Gathering (DNS, WHOIS, IP, Tech, Directory)\n"
                "        # Stage 3: SafeHTTPClient GET response collection with byte limits\n"
                "        # Stage 4: Security Headers & Cookie Audit\n"
                "        # Stage 5: HTTPS & Redirect Analysis\n"
                "        # Stage 6: Server Info Disclosure & robots.txt / sitemap.xml\n"
                "        # Stage 7: OWASPEngine checks (A01 - A10)\n"
                "        # Stage 8: Security Analysis (CORS, Sessions)\n"
                "        # Stage 9: Vulnerability Detection (SQLi, XSS, CSRF, IDOR, Cmd Injection, etc.)\n"
                "        # Stage 10: Summary Compilation (counts, status=COMPLETED)\n"
            )

        if "score" in query_lower or "posture" in query_lower or "100" in query_lower or "deduction" in query_lower:
            snippets.append(
                "--- Security Score Calculation (backend/app/services/dashboard.py) ---\n"
                "# Lines 83-84:\n"
                "deduction = critical_cnt * 25 + high_cnt * 15 + medium_cnt * 8 + low_cnt * 3\n"
                "score = max(0.0, float(100 - deduction))\n"
                "# Explanation: Starts at 100. Each severity level has a fixed weight deduction.\n"
                "# If there are 0 findings or only info findings, deduction is 0, giving 100/100."
            )

        return "\n\n".join(snippets)
