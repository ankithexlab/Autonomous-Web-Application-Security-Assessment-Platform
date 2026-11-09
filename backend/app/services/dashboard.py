"""
Dashboard Metrics Aggregator Service.

Aggregates real database metrics (projects, targets, scans, findings, reports)
strictly for the authenticated user, avoiding N+1 queries.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.dashboard import DashboardSummaryResponse

OWASP_META = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery (SSRF)"),
]


class DashboardService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_user_summary(self, user_id: str | UUID) -> DashboardSummaryResponse:
        uid = UUID(str(user_id)) if isinstance(user_id, str) else user_id

        # 1. Efficient count aggregations with strict user_id scoping
        proj_cnt = (
            await self._session.execute(
                select(func.count(Project.id)).where(Project.user_id == uid)
            )
        ).scalar_one() or 0

        tgt_cnt = (
            await self._session.execute(
                select(func.count(Target.id))
                .join(Project, Target.project_id == Project.id)
                .where(Project.user_id == uid)
            )
        ).scalar_one() or 0

        # Scan status grouped aggregation
        scan_status_res = await self._session.execute(
            select(func.lower(Scan.status), func.count(Scan.id))
            .where(Scan.user_id == uid)
            .group_by(func.lower(Scan.status))
        )
        scan_status_map = {status: count for status, count in scan_status_res.all()}
        running_scans = scan_status_map.get("running", 0) + scan_status_map.get("queued", 0)
        completed_scans = scan_status_map.get("completed", 0)
        failed_scans = scan_status_map.get("failed", 0) + scan_status_map.get("error", 0)
        scan_cnt = sum(scan_status_map.values())

        # Finding severity grouped aggregation (all discovered findings)
        sev_res = await self._session.execute(
            select(func.lower(Finding.severity), func.count(Finding.id))
            .where(Finding.user_id == uid)
            .group_by(func.lower(Finding.severity))
        )
        sev_map = {sev: count for sev, count in sev_res.all()}
        critical_cnt = sev_map.get("critical", 0)
        high_cnt = sev_map.get("high", 0)
        medium_cnt = sev_map.get("medium", 0)
        low_cnt = sev_map.get("low", 0)
        info_cnt = sev_map.get("info", 0)
        total_findings = sum(sev_map.values())

        # Active findings severity grouped aggregation for risk deduction
        # (excluding resolved, fixed, false_positive, accepted_risk)
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

        # 2. Overall Security Posture Score (active risk deduction)
        deduction = act_crit * 25 + act_high * 15 + act_med * 8 + act_low * 3
        score = max(0.0, float(100 - deduction))

        # 3. Recent Scans with target and project details (joined, avoiding N+1)
        recent_scans_stmt = (
            select(Scan, Target.url.label("target_url"), Project.name.label("project_name"))
            .outerjoin(Target, Scan.target_id == Target.id)
            .outerjoin(Project, Scan.project_id == Project.id)
            .where(Scan.user_id == uid)
            .order_by(Scan.created_at.desc())
            .limit(5)
        )
        recent_scans_res = await self._session.execute(recent_scans_stmt)
        recent_scans_data = []
        for row in recent_scans_res.all():
            scan_obj: Scan = row[0]
            t_url = row[1] or ""
            p_name = row[2] or "Project"
            recent_scans_data.append({
                "id": str(scan_obj.id),
                "target_name": t_url or p_name,
                "target_url": t_url,
                "project_id": str(scan_obj.project_id),
                "project_name": p_name,
                "scan_type": scan_obj.scan_type,
                "status": scan_obj.status,
                "created_at": scan_obj.created_at.isoformat() if scan_obj.created_at else None,
                "completed_at": scan_obj.completed_at.isoformat() if scan_obj.completed_at else None,
                "findings_count": scan_obj.findings_count,
                "critical_count": scan_obj.critical_count,
                "high_count": scan_obj.high_count,
                "medium_count": scan_obj.medium_count,
                "low_count": scan_obj.low_count,
            })

        # 4. Recent Findings with target details (joined, avoiding N+1)
        recent_findings_stmt = (
            select(Finding, Target.url.label("target_url"))
            .outerjoin(Target, Finding.target_id == Target.id)
            .where(Finding.user_id == uid)
            .order_by(Finding.created_at.desc())
            .limit(5)
        )
        recent_findings_res = await self._session.execute(recent_findings_stmt)
        recent_findings_data = []
        for row in recent_findings_res.all():
            f_obj: Finding = row[0]
            t_url = row[1] or f_obj.affected_url or "Target"
            recent_findings_data.append({
                "id": str(f_obj.id),
                "title": f_obj.title,
                "severity": f_obj.severity,
                "confidence": f_obj.confidence,
                "category": f_obj.category,
                "owasp_category": f_obj.owasp_category,
                "target": t_url,
                "created_at": f_obj.created_at.isoformat() if f_obj.created_at else None,
                "cvss_score": f_obj.cvss_score or 0.0,
            })

        # 5. Recent Reports with project details (joined, avoiding N+1)
        recent_reports_stmt = (
            select(Report, Project.name.label("project_name"))
            .outerjoin(Project, Report.project_id == Project.id)
            .where(Report.user_id == uid)
            .order_by(Report.created_at.desc())
            .limit(5)
        )
        recent_reports_res = await self._session.execute(recent_reports_stmt)
        recent_reports_data = []
        for row in recent_reports_res.all():
            r_obj: Report = row[0]
            p_name = row[1] or "Project"
            recent_reports_data.append({
                "id": str(r_obj.id),
                "title": r_obj.title,
                "report_type": r_obj.report_type,
                "file_format": r_obj.file_format,
                "status": r_obj.status,
                "project_name": p_name,
                "created_at": r_obj.created_at.isoformat() if r_obj.created_at else None,
                "overall_score": r_obj.overall_score,
            })

        # 6. OWASP Distribution covering A01 - A10
        owasp_counts: dict[str, int] = {code: 0 for code, _ in OWASP_META}
        db_owasp_res = await self._session.execute(
            select(Finding.owasp_category, func.count(Finding.id))
            .where(Finding.user_id == uid, Finding.owasp_category.isnot(None))
            .group_by(Finding.owasp_category)
        )
        for cat_str, count in db_owasp_res.all():
            if not cat_str:
                continue
            for code, _ in OWASP_META:
                if code in cat_str:
                    owasp_counts[code] += count
                    break

        owasp_distribution = [
            {
                "category": code,
                "name": name,
                "count": owasp_counts[code],
            }
            for code, name in OWASP_META
        ]

        # 7. Synthesized Activity Stream strictly for authenticated user
        activities = []
        for item in recent_scans_data:
            s_status = (item.get("status") or "").lower()
            act_type = (
                "scan_completed" if s_status == "completed"
                else "scan_failed" if s_status in ("failed", "error")
                else "scan_cancelled" if s_status == "cancelled"
                else "scan_started"
            )
            activities.append({
                "id": f"act-scan-{item['id']}",
                "type": act_type,
                "title": f"{item['scan_type'].title()} Scan {item['status'].title()}",
                "description": f"Target: {item['target_name']}",
                "timestamp": item["created_at"],
                "scan_type": item["scan_type"],
                "scan_status": item["status"],
            })
        for f in recent_findings_data:
            activities.append({
                "id": f"act-find-{f['id']}",
                "type": "finding_discovered",
                "title": f["title"],
                "description": f"Target: {f['target']} ({f['category']})",
                "timestamp": f["created_at"],
                "severity": f["severity"],
            })
        for r in recent_reports_data:
            activities.append({
                "id": f"act-rep-{r['id']}",
                "type": "report_generated",
                "title": r["title"],
                "description": f"Generated {r['report_type'].upper()} report for {r['project_name']}",
                "timestamp": r["created_at"],
            })

        # Sort activities by timestamp descending
        activities.sort(key=lambda a: a.get("timestamp") or "", reverse=True)

        # 8. Real Scan Activity & Threat Trend over the last 7 calendar days
        now = datetime.now(timezone.utc)
        today = now.date()
        days_7 = [today - timedelta(days=i) for i in range(6, -1, -1)]
        start_7d = datetime.combine(days_7[0], datetime.min.time(), tzinfo=timezone.utc)

        scans_7d_stmt = (
            select(Scan.created_at, func.lower(Scan.status))
            .where(Scan.user_id == uid, Scan.created_at >= start_7d)
        )
        scans_7d_res = await self._session.execute(scans_7d_stmt)
        scans_by_date: dict[str, dict[str, int]] = {
            d.isoformat(): {"completed": 0, "failed": 0, "total": 0} for d in days_7
        }
        for s_created_at, s_status in scans_7d_res.all():
            if not s_created_at:
                continue
            d_str = s_created_at.date().isoformat()
            if d_str in scans_by_date:
                scans_by_date[d_str]["total"] += 1
                if s_status == "completed":
                    scans_by_date[d_str]["completed"] += 1
                elif s_status in ("failed", "error"):
                    scans_by_date[d_str]["failed"] += 1

        scan_activity = [
            {
                "day": d.strftime("%a"),
                "completed": scans_by_date[d.isoformat()]["completed"],
                "failed": scans_by_date[d.isoformat()]["failed"],
            }
            for d in days_7
        ]

        findings_7d_stmt = (
            select(Finding.created_at, func.lower(Finding.severity))
            .where(Finding.user_id == uid, Finding.created_at >= start_7d)
        )
        findings_7d_res = await self._session.execute(findings_7d_stmt)
        findings_by_date: dict[str, dict[str, int]] = {
            d.isoformat(): {"critical_high": 0, "total": 0} for d in days_7
        }
        for f_created_at, f_sev in findings_7d_res.all():
            if not f_created_at:
                continue
            d_str = f_created_at.date().isoformat()
            if d_str in findings_by_date:
                findings_by_date[d_str]["total"] += 1
                if f_sev in ("critical", "high"):
                    findings_by_date[d_str]["critical_high"] += 1

        threat_trend = [
            {
                "period": d.strftime("%a"),
                "velocity": scans_by_date[d.isoformat()]["total"] * 10,
                "exploitsPrevented": findings_by_date[d.isoformat()]["total"],
                "activeThreats": findings_by_date[d.isoformat()]["critical_high"],
            }
            for d in days_7
        ]

        # 9. Real Vulnerability Trend over the last 6 calendar months
        months: list[tuple[int, int]] = []
        cur_year = now.year
        cur_month = now.month
        for i in range(5, -1, -1):
            m = cur_month - i
            y = cur_year
            while m <= 0:
                m += 12
                y -= 1
            months.append((y, m))

        start_month_dt = datetime(months[0][0], months[0][1], 1, tzinfo=timezone.utc)
        findings_trend_stmt = (
            select(Finding.created_at, func.lower(Finding.severity))
            .where(Finding.user_id == uid, Finding.created_at >= start_month_dt)
        )
        findings_trend_res = await self._session.execute(findings_trend_stmt)
        trend_buckets: dict[tuple[int, int], dict[str, int]] = {
            (y, m): {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for y, m in months
        }
        for f_created_at, f_sev in findings_trend_res.all():
            if not f_created_at:
                continue
            key = (f_created_at.year, f_created_at.month)
            if key in trend_buckets and f_sev in trend_buckets[key]:
                trend_buckets[key][f_sev] += 1

        vulnerability_trend = [
            {
                "date": datetime(y, m, 1).strftime("%b"),
                "critical": trend_buckets[(y, m)]["critical"],
                "high": trend_buckets[(y, m)]["high"],
                "medium": trend_buckets[(y, m)]["medium"],
                "low": trend_buckets[(y, m)]["low"],
            }
            for y, m in months
        ]

        # 10. Risk Factors calculated from live security metrics
        risk_factors = [
            {
                "label": "Exploitability Index",
                "value": min(100, critical_cnt * 25 + high_cnt * 10),
                "status": "danger" if critical_cnt > 0 else "warning" if high_cnt > 0 else "good",
            },
            {
                "label": "Attack Surface Exposure",
                "value": min(100, tgt_cnt * 20),
                "status": "danger" if tgt_cnt > 5 else "warning" if tgt_cnt > 2 else "good",
            },
            {
                "label": "Remediation Velocity",
                "value": 100 if total_findings == 0 else max(10, 100 - (critical_cnt * 20 + high_cnt * 10)),
                "status": "good" if total_findings == 0 else "warning" if critical_cnt == 0 else "danger",
            },
            {
                "label": "Asset Criticality Weight",
                "value": min(100, (critical_cnt + high_cnt) * 15),
                "status": "danger" if (critical_cnt + high_cnt) > 3 else "warning" if (critical_cnt + high_cnt) > 0 else "good",
            },
        ]

        return DashboardSummaryResponse(
            total_projects=proj_cnt,
            total_targets=tgt_cnt,
            total_scans=scan_cnt,
            running_scans=running_scans,
            completed_scans=completed_scans,
            failed_scans=failed_scans,
            total_findings=total_findings,
            critical_findings=critical_cnt,
            high_findings=high_cnt,
            medium_findings=medium_cnt,
            low_findings=low_cnt,
            info_findings=info_cnt,
            overall_security_score=score,
            recent_scans=recent_scans_data,
            recent_findings=recent_findings_data,
            recent_reports=recent_reports_data,
            owasp_distribution=owasp_distribution,
            recent_activities=activities[:15],
            scan_activity=scan_activity,
            vulnerability_trend=vulnerability_trend,
            threat_trend=threat_trend,
            risk_factors=risk_factors,
        )

