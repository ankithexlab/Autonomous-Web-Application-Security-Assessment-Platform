"""
Report Generator Service.

Asynchronously generates structured security report documents (PDF, HTML, JSON, CSV)
based on project, target, scan, and vulnerability finding records.
"""

import csv
from datetime import datetime, timezone
import html
import io
import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.exceptions import BadRequestException
from app.models.report import Report
from app.repositories.finding import FindingRepository
from app.repositories.project import ProjectRepository
from app.repositories.report import ReportRepository
from app.repositories.scan import ScanRepository
from app.repositories.target import TargetRepository
from app.services.ai.sanitizer import sanitize_sensitive_secrets


logger = logging.getLogger("awsap.reports")


class ReportGenerator:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._report_repo = ReportRepository(session)
        self._project_repo = ProjectRepository(session)
        self._target_repo = TargetRepository(session)
        self._scan_repo = ScanRepository(session)
        self._finding_repo = FindingRepository(session)

    async def generate_report(self, report_id: UUID, format_override: str | None = None) -> tuple[Report, bytes, str]:
        """
        Execute report generation and return (Report, content_bytes, content_type).
        Optionally override the stored format on demand (pdf, html, json, csv).
        """
        report = await self._report_repo.get_by_id(report_id)
        if not report:
            raise BadRequestException(f"Report {report_id} not found.")

        project = await self._project_repo.get_by_id(report.project_id)
        project_name = project.name if project else "Project"
        active_format = (format_override or report.file_format or "json").lower().strip()
        logger.info(
            "Report generation started: report_id=%s type=%s format=%s project=%s",
            report.id,
            report.report_type,
            active_format,
            project_name,
        )

        target_url = None
        if report.scan_id:
            scan = await self._scan_repo.get_by_id(report.scan_id)
            if scan and scan.target:
                target_url = scan.target.url
        if not target_url and report.target_id:
            target = await self._target_repo.get_by_id(report.target_id)
            if target:
                target_url = target.url

        if report.scan_id:
            findings = await self._finding_repo.list_for_scan(report.scan_id)
        elif report.target_id:
            findings = await self._finding_repo.list_for_target(report.target_id)
        elif report.project_id:
            findings = await self._finding_repo.list_for_project(report.project_id)
        else:
            findings = await self._finding_repo.list_for_user(report.user_id)

        counts = {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "info": sum(1 for f in findings if f.severity == "info"),
        }

        inactive_statuses = ("resolved", "fixed", "false_positive", "accepted_risk")
        active_counts = {
            "critical": sum(
                1 for f in findings
                if f.severity == "critical"
                and (f.status or "open").lower() not in inactive_statuses
            ),
            "high": sum(
                1 for f in findings
                if f.severity == "high"
                and (f.status or "open").lower() not in inactive_statuses
            ),
            "medium": sum(
                1 for f in findings
                if f.severity == "medium"
                and (f.status or "open").lower() not in inactive_statuses
            ),
            "low": sum(
                1 for f in findings
                if f.severity == "low"
                and (f.status or "open").lower() not in inactive_statuses
            ),
            "info": sum(
                1 for f in findings
                if f.severity == "info"
                and (f.status or "open").lower() not in inactive_statuses
            ),
        }

        risk_deduction = (
            active_counts["critical"] * 25
            + active_counts["high"] * 15
            + active_counts["medium"] * 8
            + active_counts["low"] * 3
        )
        overall_score = max(0.0, float(100 - risk_deduction))
        summary_json = json.dumps(counts)

        content_bytes: bytes
        content_type: str

        if active_format == "json":
            content_bytes, content_type = self._generate_json(report, project_name, findings, counts, overall_score, target_url)
        elif active_format == "csv":
            content_bytes, content_type = self._generate_csv(findings)
        elif active_format == "pdf":
            content_bytes, content_type = self._generate_pdf(report, project_name, target_url, findings, counts, overall_score)
        elif active_format == "html":
            content_bytes, content_type = self._generate_html(report, project_name, findings, counts, overall_score, target_url)
        else:
            content_bytes, content_type = self._generate_json(report, project_name, findings, counts, overall_score, target_url)

        updated_report = await self._report_repo.update_completion(
            report,
            status="COMPLETED",
            overall_score=overall_score,
            findings_summary_json=summary_json,
        )
        logger.info(
            "Report generation completed: report_id=%s bytes=%d findings_count=%d score=%.1f format=%s",
            report.id,
            len(content_bytes),
            len(findings),
            overall_score,
            active_format,
        )

        return updated_report, content_bytes, content_type

    def _generate_json(
        self,
        report: Report,
        project_name: str,
        findings: list,
        counts: dict,
        score: float,
        target_url: str | None = None,
    ) -> tuple[bytes, str]:
        payload = {
            "report_id": str(report.id),
            "title": report.title,
            "report_type": report.report_type,
            "project_name": project_name,
            "target_url": target_url,
            "overall_security_score": score,
            "severity_counts": counts,
            "total_findings": len(findings),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": [
                {
                    "id": str(f.id),
                    "title": sanitize_sensitive_secrets(f.title),
                    "severity": f.severity,
                    "status": f.status,
                    "confidence": f.confidence,
                    "category": f.category,
                    "owasp_category": f.owasp_category,
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "affected_url": sanitize_sensitive_secrets(f.affected_url),
                    "remediation": sanitize_sensitive_secrets(f.remediation),
                    "proof_of_concept": sanitize_sensitive_secrets(f.proof_of_concept),
                }
                for f in findings
            ],
        }
        return json.dumps(payload, indent=2).encode("utf-8"), "application/json"

    def _sanitize_csv_cell(self, val: Any) -> Any:
        """Sanitize cell value against CSV / formula injection (DDE execution in Excel/Calc)."""
        if val is None:
            return ""
        val_str = str(val)
        if val_str.startswith(("=", "+", "-", "@", "\t", "\r", "%", "|")):
            return f"'{val_str}"
        return val_str

    def _generate_csv(self, findings: list) -> tuple[bytes, str]:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Title", "Severity", "Confidence", "Status",
            "Category", "OWASP Category", "CWE ID", "CVSS Score", "Affected URL",
            "Remediation", "Proof of Concept"
        ])
        for f in findings:
            writer.writerow([
                self._sanitize_csv_cell(str(f.id)),
                self._sanitize_csv_cell(sanitize_sensitive_secrets(f.title)),
                self._sanitize_csv_cell(f.severity),
                self._sanitize_csv_cell(f.confidence),
                self._sanitize_csv_cell(f.status),
                self._sanitize_csv_cell(f.category),
                self._sanitize_csv_cell(f.owasp_category or ""),
                self._sanitize_csv_cell(f.cwe_id or ""),
                self._sanitize_csv_cell(f.cvss_score or 0.0),
                self._sanitize_csv_cell(sanitize_sensitive_secrets(f.affected_url or "")),
                self._sanitize_csv_cell(sanitize_sensitive_secrets(f.remediation or "")),
                self._sanitize_csv_cell(sanitize_sensitive_secrets(f.proof_of_concept or "")),
            ])
        return output.getvalue().encode("utf-8"), "text/csv"

    def _generate_html(
        self,
        report: Report,
        project_name: str,
        findings: list,
        counts: dict,
        score: float,
        target_url: str | None = None,
    ) -> tuple[bytes, str]:
        safe_report_title = html.escape(report.title or "Security Assessment Report")
        safe_project_name = html.escape(project_name or "Project")
        safe_report_type = html.escape((report.report_type or "Executive").upper())
        safe_target = html.escape(target_url or "Full Project Scope")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Risk Grade & Status
        if score >= 90:
            grade, grade_color, status_text = "A", "#10b981", "LOW RISK - RESILIENT SECURITY POSTURE"
        elif score >= 80:
            grade, grade_color, status_text = "B", "#0284c7", "MODERATE RISK - GENERALLY SECURE"
        elif score >= 70:
            grade, grade_color, status_text = "C", "#f59e0b", "ELEVATED RISK - DEFENSIVE IMPROVEMENTS REQUIRED"
        elif score >= 60:
            grade, grade_color, status_text = "D", "#f97316", "HIGH RISK - MULTIPLE VULNERABILITIES IDENTIFIED"
        else:
            grade, grade_color, status_text = "F", "#ef4444", "CRITICAL RISK - IMMEDIATE REMEDIATION MANDATORY"

        sev_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#f59e0b",
            "low": "#3b82f6",
            "info": "#64748b",
        }

        # Summary Table Rows
        summary_rows = []
        for idx, f in enumerate(findings, start=1):
            sev = (f.severity or "medium").lower()
            c = sev_colors.get(sev, "#64748b")
            title = html.escape(sanitize_sensitive_secrets(f.title) or "Untitled")
            owasp = html.escape(f.owasp_category or f.category or "N/A")
            url = html.escape(sanitize_sensitive_secrets(f.affected_url) or "N/A")
            cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
            summary_rows.append(f"""
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #334155;"><strong>#{idx}. {title}</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid #334155;"><span style="color: {c}; font-weight: bold; text-transform: uppercase;">{html.escape(sev)}</span></td>
                    <td style="padding: 10px; border-bottom: 1px solid #334155;">{owasp}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #334155;">{cvss}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #334155; word-break: break-all;"><code>{url}</code></td>
                </tr>
            """)

        # Detailed Finding Cards
        detail_blocks = []
        for idx, f in enumerate(findings, start=1):
            sev = (f.severity or "medium").lower()
            c = sev_colors.get(sev, "#64748b")
            title = html.escape(sanitize_sensitive_secrets(f.title) or "Untitled")
            owasp = html.escape(f.owasp_category or f.category or "N/A")
            cwe = html.escape(f.cwe_id or "N/A")
            cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
            status = html.escape(f.status or "open")
            url = html.escape(sanitize_sensitive_secrets(f.affected_url) or "N/A")
            desc = html.escape(sanitize_sensitive_secrets(f.description) or "No description provided.").replace("\n", "<br/>")
            remediation = html.escape(sanitize_sensitive_secrets(f.remediation) or "Review defensive configuration and implement input validation.").replace("\n", "<br/>")
            poc = sanitize_sensitive_secrets(f.proof_of_concept)
            poc_html = f"<pre style='background: #020617; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 11px; color: #38bdf8;'>{html.escape(poc)}</pre>" if poc else "<p style='color: #64748b; font-style: italic; margin: 4px 0;'>No proof-of-concept payload attached.</p>"

            detail_blocks.append(f"""
                <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 18px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 12px;">
                        <h3 style="margin: 0; font-size: 14px; color: #f8fafc;">#{idx}. {title}</h3>
                        <span style="background: {c}20; color: {c}; border: 1px solid {c}40; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase;">{html.escape(sev)}</span>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; font-size: 12px; margin-bottom: 12px; color: #94a3b8;">
                        <div><strong>OWASP:</strong> {owasp}</div>
                        <div><strong>CWE:</strong> {cwe}</div>
                        <div><strong>CVSS Score:</strong> {cvss}</div>
                        <div><strong>Status:</strong> <span style="text-transform: capitalize;">{status}</span></div>
                    </div>
                    <div style="font-size: 12px; margin-bottom: 10px;">
                        <strong style="color: #cbd5e1;">Affected URL:</strong> <code style="color: #38bdf8; word-break: break-all;">{url}</code>
                    </div>
                    <div style="font-size: 12px; margin-bottom: 12px; line-height: 1.5; color: #cbd5e1;">
                        <strong style="color: #94a3b8;">Description:</strong><br/>{desc}
                    </div>
                    <div style="font-size: 12px; margin-bottom: 12px;">
                        <strong style="color: #94a3b8;">Proof of Concept / Safe Evidence:</strong>
                        {poc_html}
                    </div>
                    <div style="font-size: 12px; background: #0c4a6e20; border-left: 3px solid #0284c7; padding: 10px 12px; border-radius: 4px; color: #e0f2fe; line-height: 1.5;">
                        <strong style="color: #38bdf8;">Remediation Guidance:</strong><br/>{remediation}
                    </div>
                </div>
            """)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>{safe_report_title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 28px; line-height: 1.5; }}
        h1 {{ color: #38bdf8; margin-top: 0; font-size: 22px; }}
        h2 {{ color: #e2e8f0; font-size: 16px; margin-top: 28px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
        .header-box {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0284c7; padding-bottom: 12px; margin-bottom: 20px; }}
        .brand {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #38bdf8; font-weight: bold; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size: 13px; }}
        .score-banner {{ display: flex; align-items: center; justify-content: space-between; background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .score-box {{ text-align: center; border-right: 1px solid #334155; padding-right: 24px; margin-right: 24px; }}
        .score-val {{ font-size: 38px; font-weight: 800; color: {grade_color}; }}
        .counts-grid {{ display: flex; gap: 12px; flex-wrap: wrap; }}
        .count-card {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 10px 16px; text-align: center; min-width: 80px; }}
        .count-num {{ font-size: 20px; font-weight: bold; }}
        .count-label {{ font-size: 10px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
        th {{ background-color: #1e293b; color: #94a3b8; text-align: left; padding: 10px; border-bottom: 2px solid #334155; }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        @media print {{
            body {{ background-color: #ffffff; color: #000000; padding: 12px; }}
            .header-box, .meta-grid, .score-banner, .count-card {{ background-color: #ffffff !important; border-color: #cccccc !important; color: #000000 !important; }}
            h1, h2, h3, strong {{ color: #000000 !important; }}
        }}
    </style>
</head>
<body>
    <div class="header-box">
        <div>
            <div class="brand">AWASAP - Autonomous Web Security Platform</div>
            <h1>{safe_report_title}</h1>
        </div>
        <div style="text-align: right; font-size: 11px; color: #94a3b8;">
            Generated: {now_str}<br/>
            Scope: {safe_target}
        </div>
    </div>

    <div class="meta-grid">
        <div><strong>Project:</strong> {safe_project_name}</div>
        <div><strong>Report Type:</strong> {safe_report_type}</div>
        <div><strong>Total Findings:</strong> {len(findings)}</div>
        <div><strong>Security Posture Grade:</strong> <strong style="color: {grade_color};">{grade} ({score:.1f}/100)</strong></div>
    </div>

    <div class="score-banner">
        <div class="score-box">
            <div class="score-val">{score:.1f}</div>
            <div style="font-size: 11px; color: {grade_color}; font-weight: bold;">{status_text}</div>
        </div>
        <div class="counts-grid">
            <div class="count-card"><div class="count-num" style="color: #ef4444;">{counts['critical']}</div><div class="count-label">Critical</div></div>
            <div class="count-card"><div class="count-num" style="color: #f97316;">{counts['high']}</div><div class="count-label">High</div></div>
            <div class="count-card"><div class="count-num" style="color: #f59e0b;">{counts['medium']}</div><div class="count-label">Medium</div></div>
            <div class="count-card"><div class="count-num" style="color: #3b82f6;">{counts['low']}</div><div class="count-label">Low</div></div>
            <div class="count-card"><div class="count-num" style="color: #64748b;">{counts['info']}</div><div class="count-label">Info</div></div>
        </div>
    </div>

    <h2>Vulnerability Findings Summary</h2>
    <table>
        <thead>
            <tr>
                <th>Vulnerability Title</th>
                <th>Severity</th>
                <th>OWASP / Category</th>
                <th>CVSS</th>
                <th>Affected Endpoint</th>
            </tr>
        </thead>
        <tbody>
            {"".join(summary_rows) if summary_rows else "<tr><td colspan='5' style='padding: 16px; text-align: center; color: #94a3b8;'>No vulnerability findings identified during this assessment.</td></tr>"}
        </tbody>
    </table>

    <h2>Detailed Findings & Remediation Guidance</h2>
    {"".join(detail_blocks) if detail_blocks else "<p style='color: #94a3b8; font-style: italic;'>No vulnerabilities require remediation.</p>"}
</body>
</html>"""
        return html_doc.encode("utf-8"), "text/html"

    def _generate_pdf(
        self,
        report: Report,
        project_name: str,
        target_url: str | None,
        findings: list,
        counts: dict,
        score: float,
    ) -> tuple[bytes, str]:
        """
        Generate authentic binary PDF assessment document using ReportLab.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=48,
            bottomMargin=48,
        )

        base_styles = getSampleStyleSheet()
        brand_style = ParagraphStyle(
            "RepBrand",
            parent=base_styles["Normal"],
            fontSize=8.5,
            leading=11,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0284c7"),
        )
        title_style = ParagraphStyle(
            "RepTitle",
            parent=base_styles["Heading1"],
            fontSize=17,
            leading=21,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        )
        heading_style = ParagraphStyle(
            "RepHeading",
            parent=base_styles["Heading2"],
            fontSize=11,
            leading=14,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True,
        )
        normal_style = ParagraphStyle(
            "RepNormal",
            parent=base_styles["Normal"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#334155"),
        )
        header_cell_style = ParagraphStyle(
            "RepHCell",
            parent=base_styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )
        cell_style = ParagraphStyle(
            "RepCell",
            parent=base_styles["Normal"],
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#1e293b"),
        )
        body_style = ParagraphStyle(
            "RepBody",
            parent=base_styles["Normal"],
            fontSize=8,
            leading=10.5,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "RepCode",
            parent=base_styles["Normal"],
            fontSize=7.5,
            leading=9.5,
            fontName="Courier",
            textColor=colors.HexColor("#0f172a"),
        )

        story = []

        # ── 1. Branding Header ──────────────────────────────────────
        story.append(Paragraph("AWASAP - AUTONOMOUS WEB APPLICATION SECURITY ASSESSMENT PLATFORM", brand_style))
        story.append(Spacer(1, 2))
        safe_title = html.escape(report.title or "Security Assessment Report")
        story.append(Paragraph(safe_title, title_style))
        story.append(Spacer(1, 6))

        # ── 2. Scope & Assessment Metadata ─────────────────────────
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        meta_data = [
            [
                Paragraph(f"<b>Project:</b> {html.escape(project_name)}", normal_style),
                Paragraph(f"<b>Target Scope:</b> {html.escape(target_url or 'Full Project Scope')}", normal_style),
            ],
            [
                Paragraph(f"<b>Report Type:</b> {html.escape((report.report_type or 'Executive').upper())}", normal_style),
                Paragraph(f"<b>Generated:</b> {now_utc}", normal_style),
            ],
            [
                Paragraph(f"<b>Report ID:</b> {html.escape(str(report.id))}", normal_style),
                Paragraph(f"<b>Scan ID:</b> {html.escape(str(report.scan_id) if report.scan_id else 'N/A')}", normal_style),
            ],
        ]
        meta_table = Table(meta_data, colWidths=[270, 270])
        meta_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # ── 3. Security Posture Score & Distribution ────────────────
        if score >= 80:
            status_text = "LOW RISK - RESILIENT SECURITY POSTURE"
            score_color = "#059669"
            score_bg = "#ecfdf5"
            score_box_border = "#a7f3d0"
        elif score >= 50:
            status_text = "MODERATE RISK - SECURITY IMPROVEMENTS RECOMMENDED"
            score_color = "#d97706"
            score_bg = "#fffbeb"
            score_box_border = "#fde68a"
        else:
            status_text = "HIGH RISK - IMMEDIATE REMEDIATION REQUIRED"
            score_color = "#dc2626"
            score_bg = "#fef2f2"
            score_box_border = "#fecaca"

        score_content = (
            f"<b>Security Posture Score:</b><br/>"
            f"<font size=13 color='{score_color}'><b>{score:.1f} / 100</b></font><br/>"
            f"<font size=7.5 color='{score_color}'><b>{status_text}</b></font>"
        )

        counts_summary = (
            f"<b>Vulnerability Breakdown:</b><br/>"
            f"<font color='#dc2626'><b>Critical:</b> {counts['critical']}</font> &nbsp;|&nbsp; "
            f"<font color='#ea580c'><b>High:</b> {counts['high']}</font> &nbsp;|&nbsp; "
            f"<font color='#d97706'><b>Medium:</b> {counts['medium']}</font> &nbsp;|&nbsp; "
            f"<font color='#2563eb'><b>Low:</b> {counts['low']}</font> &nbsp;|&nbsp; "
            f"<font color='#64748b'><b>Info:</b> {counts['info']}</font><br/>"
            f"<b>Total Identified Issues:</b> {len(findings)}"
        )

        score_table_data = [
            [
                Paragraph(score_content, normal_style),
                Paragraph(counts_summary, normal_style),
            ]
        ]
        score_table = Table(score_table_data, colWidths=[200, 340])
        score_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(score_bg)),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (0, 0), 1, colors.HexColor(score_box_border)),
                ("BOX", (1, 0), (1, 0), 1, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(score_table)
        story.append(Spacer(1, 12))

        # ── 4. Findings Summary Table ──────────────────────────────
        story.append(Paragraph("Vulnerability Findings Summary", heading_style))

        sev_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#2563eb",
            "info": "#64748b",
        }

        table_rows = [
            [
                Paragraph("Vulnerability Title", header_cell_style),
                Paragraph("Severity", header_cell_style),
                Paragraph("OWASP / Category", header_cell_style),
                Paragraph("CVSS", header_cell_style),
                Paragraph("Affected Endpoint", header_cell_style),
            ]
        ]

        if findings:
            for f in findings:
                sev_key = (f.severity or "medium").lower()
                c = sev_colors.get(sev_key, "#64748b")
                sev_p = Paragraph(f"<font color='{c}'><b>{html.escape(f.severity.upper())}</b></font>", cell_style)
                table_rows.append([
                    Paragraph(html.escape(f.title or "Untitled Finding"), cell_style),
                    sev_p,
                    Paragraph(html.escape(f.owasp_category or f.category or "N/A"), cell_style),
                    Paragraph(f"{f.cvss_score:.1f}" if f.cvss_score else "N/A", cell_style),
                    Paragraph(html.escape(f.affected_url or "N/A"), cell_style),
                ])
        else:
            table_rows.append([
                Paragraph("<i>No vulnerability findings identified during this assessment.</i>", cell_style),
                Paragraph("-", cell_style),
                Paragraph("-", cell_style),
                Paragraph("-", cell_style),
                Paragraph("-", cell_style),
            ])

        # Widths: 160 + 55 + 135 + 45 + 145 = 540 pt
        findings_table = Table(table_rows, colWidths=[160, 55, 135, 45, 145])
        findings_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(findings_table)

        # ── 5. Detailed Findings Section (for technical/full/findings) ───
        if findings:
            story.append(Spacer(1, 14))
            story.append(Paragraph("Detailed Findings & Remediation Guidance", heading_style))

            for idx, f in enumerate(findings, start=1):
                sev_key = (f.severity or "medium").lower()
                c = sev_colors.get(sev_key, "#64748b")
                finding_items = []

                # Finding Title + Badge
                title_html = (
                    f"<b>#{idx}. {html.escape(f.title or 'Untitled')}</b> &nbsp; "
                    f"<font color='{c}'>[{html.escape(f.severity.upper())}]</font>"
                )
                finding_items.append(Paragraph(title_html, ParagraphStyle(
                    "FHead",
                    parent=normal_style,
                    fontSize=9.5,
                    leading=12,
                    fontName="Helvetica-Bold",
                    textColor=colors.HexColor("#0f172a"),
                )))
                finding_items.append(Spacer(1, 4))

                # Finding Meta Grid
                detail_meta = [
                    [
                        Paragraph(f"<b>Category:</b> {html.escape(f.category or 'N/A')}", cell_style),
                        Paragraph(f"<b>OWASP:</b> {html.escape(f.owasp_category or 'N/A')}", cell_style),
                    ],
                    [
                        Paragraph(f"<b>CWE ID:</b> {html.escape(f.cwe_id or 'N/A')}", cell_style),
                        Paragraph(f"<b>CVSS:</b> {f.cvss_score if f.cvss_score else 'N/A'}", cell_style),
                    ],
                    [
                        Paragraph(f"<b>Status:</b> {html.escape(f.status or 'open')}", cell_style),
                        Paragraph(f"<b>Confidence:</b> {html.escape(f.confidence or 'HIGH')}", cell_style),
                    ],
                    [
                        Paragraph(f"<b>Affected URL:</b> {html.escape(f.affected_url or 'N/A')}", cell_style),
                        Paragraph("", cell_style),
                    ],
                ]
                meta_grid = Table(detail_meta, colWidths=[260, 260])
                meta_grid.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ])
                )
                finding_items.append(meta_grid)
                finding_items.append(Spacer(1, 4))

                # Description
                if f.description:
                    desc_text = html.escape(sanitize_sensitive_secrets(f.description) or "").replace("\n", "<br/>")
                    finding_items.append(Paragraph(f"<b>Description:</b> {desc_text}", body_style))
                    finding_items.append(Spacer(1, 3))

                # Remediation
                if f.remediation:
                    rem_text = html.escape(sanitize_sensitive_secrets(f.remediation) or "").replace("\n", "<br/>")
                    finding_items.append(Paragraph(
                        f"<b>Remediation:</b> <font color='#0369a1'>{rem_text}</font>",
                        body_style,
                    ))
                    finding_items.append(Spacer(1, 3))

                # Proof of Concept
                if getattr(f, "proof_of_concept", None):
                    poc_text = html.escape(sanitize_sensitive_secrets(f.proof_of_concept) or "").replace("\n", "<br/>")
                    finding_items.append(Paragraph(
                        f"<b>Proof of Concept:</b><br/>{poc_text}",
                        code_style,
                    ))
                    finding_items.append(Spacer(1, 3))

                finding_items.append(Spacer(1, 6))
                finding_items.append(HRFlowable(
                    width="100%",
                    thickness=0.5,
                    color=colors.HexColor("#e2e8f0"),
                    spaceBefore=2,
                    spaceAfter=8,
                ))

                story.append(KeepTogether(finding_items))

        # ── 6. Build PDF Document ──────────────────────────────────
        doc.build(story, canvasmaker=NumberedCanvas)
        return buffer.getvalue(), "application/pdf"


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total pages and running header/footers.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, num_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        width, height = self._pagesize

        # Running header (pages 2+)
        if self._pageNumber > 1:
            self.drawString(36, height - 30, "AWASAP Security Assessment Report")
            self.drawRightString(width - 36, height - 30, "CONFIDENTIAL")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, height - 34, width - 36, height - 34)

        # Running footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 36, width - 36, 36)
        self.drawString(36, 24, "AWASAP - Autonomous Web Application Security Assessment Platform")
        self.drawRightString(width - 36, 24, f"Page {self._pageNumber} of {num_pages}")
        self.restoreState()

