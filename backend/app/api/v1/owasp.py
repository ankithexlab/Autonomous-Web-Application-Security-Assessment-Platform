"""
OWASP Top 10 Summary API Router.

Routes:
  GET /api/v1/owasp/summary — Aggregated OWASP posture metrics and category findings breakdown
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.repositories.finding import FindingRepository
from app.schemas.owasp import OWASPCategorySummary, OWASPStatsResponse

router = APIRouter(prefix="/owasp", tags=["OWASP"])


OWASP_CATEGORIES_META = [
    ("A01:2021", "Broken Access Control", "Access Control", 1),
    ("A02:2021", "Cryptographic Failures", "Crypto Failures", 2),
    ("A03:2021", "Injection", "Injection", 3),
    ("A04:2021", "Insecure Design", "Insecure Design", 4),
    ("A05:2021", "Security Misconfiguration", "Misconfiguration", 5),
    ("A06:2021", "Vulnerable and Outdated Components", "Vulnerable Components", 6),
    ("A07:2021", "Identification and Authentication Failures", "Auth Failures", 7),
    ("A08:2021", "Software and Data Integrity Failures", "Software Integrity", 8),
    ("A09:2021", "Security Logging and Monitoring Failures", "Logging Failures", 9),
    ("A10:2021", "Server-Side Request Forgery (SSRF)", "SSRF", 10),
]


@router.get(
    "/summary",
    response_model=OWASPStatsResponse,
    summary="Get aggregated OWASP Top 10 security posture summary",
)
async def get_owasp_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OWASPStatsResponse:
    finding_repo = FindingRepository(db)
    user_findings = await finding_repo.list_for_user(current_user.id)

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    active_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    category_map: dict[str, dict[str, int]] = {
        cat_id: {
            "findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "active_findings": 0,
            "active_critical": 0,
            "active_high": 0,
            "active_medium": 0,
            "active_low": 0,
        }
        for cat_id, _, _, _ in OWASP_CATEGORIES_META
    }

    for f in user_findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1

        is_active = (f.status or "open").lower() not in ("resolved", "fixed", "false_positive", "accepted_risk")
        if is_active and sev in active_counts:
            active_counts[sev] += 1

        owasp_cat = f.owasp_category or ""
        for cat_id, name, _, _ in OWASP_CATEGORIES_META:
            code_prefix = cat_id.split(":")[0]
            if cat_id in owasp_cat or code_prefix in owasp_cat or name.lower() in owasp_cat.lower():
                category_map[cat_id]["findings"] += 1
                if sev in category_map[cat_id]:
                    category_map[cat_id][sev] += 1
                if is_active:
                    category_map[cat_id]["active_findings"] += 1
                    active_key = f"active_{sev}"
                    if active_key in category_map[cat_id]:
                        category_map[cat_id][active_key] += 1
                break

    total_findings = len(user_findings)
    risk_deduction = (
        active_counts["critical"] * 25
        + active_counts["high"] * 15
        + active_counts["medium"] * 8
        + active_counts["low"] * 3
    )
    overall_score = max(0.0, float(100 - risk_deduction))

    breakdown = []
    for cat_id, name, short_name, rank in OWASP_CATEGORIES_META:
        cm = category_map[cat_id]
        if cm["active_critical"] > 0 or cm["active_high"] > 0:
            status = "FAIL"
        elif cm["active_medium"] > 0 or cm["active_low"] > 0:
            status = "WARNING"
        else:
            status = "PASS"

        breakdown.append(
            OWASPCategorySummary(
                category_id=cat_id,
                category_name=name,
                short_name=short_name,
                rank=rank,
                findings_count=cm["findings"],
                critical_count=cm["critical"],
                high_count=cm["high"],
                medium_count=cm["medium"],
                low_count=cm["low"],
                info_count=cm["info"],
                compliance_status=status,
            )
        )

    # 1. Real Risk Trend over the last 6 calendar months
    now = datetime.now(timezone.utc)
    cur_year = now.year
    cur_month = now.month
    months: list[tuple[int, int]] = []
    for i in range(5, -1, -1):
        m = cur_month - i
        y = cur_year
        while m <= 0:
            m += 12
            y -= 1
        months.append((y, m))

    trend_buckets = {(y, m): {"critical": 0, "high": 0} for y, m in months}
    for f in user_findings:
        if not f.created_at:
            continue
        # Inactive findings (resolved, fixed, false-positive, accepted-risk) do not contribute to risk deduction
        if (f.status or "open").lower() in ("resolved", "fixed", "false_positive", "accepted_risk"):
            continue
        key = (f.created_at.year, f.created_at.month)
        if key in trend_buckets:
            s = f.severity.lower()
            if s == "critical":
                trend_buckets[key]["critical"] += 1
            elif s == "high":
                trend_buckets[key]["high"] += 1

    risk_trend = [
        {
            "date": datetime(y, m, 1).strftime("%b"),
            "riskScore": max(0.0, float(100 - (trend_buckets[(y, m)]["critical"] * 25 + trend_buckets[(y, m)]["high"] * 15))),
            "criticalFindings": trend_buckets[(y, m)]["critical"],
            "highFindings": trend_buckets[(y, m)]["high"],
        }
        for y, m in months
    ]

    # 2. Most Affected Assets
    asset_map: dict[str, dict[str, int]] = {}
    for f in user_findings:
        asset_name = f.affected_url or "Target Asset"
        if asset_name not in asset_map:
            asset_map[asset_name] = {"findings": 0, "critical": 0, "high": 0}
        asset_map[asset_name]["findings"] += 1
        s = f.severity.lower()
        if s == "critical":
            asset_map[asset_name]["critical"] += 1
        elif s == "high":
            asset_map[asset_name]["high"] += 1

    most_affected_assets = [
        {
            "asset": asset_name,
            "findingsCount": d["findings"],
            "criticalCount": d["critical"],
            "riskScore": min(100, d["critical"] * 25 + d["high"] * 15 + d["findings"] * 2),
        }
        for asset_name, d in sorted(asset_map.items(), key=lambda x: x[1]["findings"], reverse=True)[:5]
    ]

    # 3. Top Findings
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sorted_findings = sorted(
        user_findings,
        key=lambda f: (
            1 if (f.status or "open").lower() not in ("resolved", "fixed", "false_positive") else 0,
            sev_order.get(f.severity.lower(), 0),
            f.cvss_score or 0.0,
            f.created_at or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    top_findings = []
    for f in sorted_findings[:5]:
        cat_id = "A01:2021"
        if f.owasp_category:
            for cid, _, _, _ in OWASP_CATEGORIES_META:
                if cid in f.owasp_category:
                    cat_id = cid
                    break
        top_findings.append({
            "id": str(f.id),
            "categoryId": cat_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.lower(),
            "cvssScore": float(f.cvss_score or 0.0),
            "affectedAsset": f.affected_url or "Target",
            "discoveredAt": f.created_at.strftime("%b %d, %Y") if f.created_at else "Recently",
            "status": f.status or "open",
            "remediation": f.remediation or "Review and remediate vulnerability according to OWASP guidelines.",
        })

    # 4. Scan Timeline
    scan_stmt = (
        select(Scan, Target.url.label("target_url"))
        .outerjoin(Target, Scan.target_id == Target.id)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(6)
    )
    scan_res = await db.execute(scan_stmt)
    scan_timeline = []
    for row in scan_res.all():
        s_obj: Scan = row[0]
        t_url = row[1] or "Target"
        scan_timeline.append({
            "id": f"scan-{s_obj.id}",
            "time": s_obj.created_at.strftime("%b %d, %H:%M") if s_obj.created_at else "Recently",
            "event": f"{s_obj.scan_type.title()} scan {s_obj.status.lower()}",
            "category": "All",
            "severity": "info" if s_obj.status.lower() == "completed" else "high" if s_obj.status.lower() in ("failed", "error") else "low",
            "target": t_url,
        })

    return OWASPStatsResponse(
        total_vulnerabilities=total_findings,
        categories_covered=10,
        overall_risk_score=overall_score,
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        info_count=counts["info"],
        category_breakdown=breakdown,
        risk_trend=risk_trend,
        most_affected_assets=most_affected_assets,
        top_findings=top_findings,
        scan_timeline=scan_timeline,
    )
