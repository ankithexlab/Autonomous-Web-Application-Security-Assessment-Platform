"""
Finding repository.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding


def _to_uuid(val: str | UUID) -> UUID:
    return UUID(val) if isinstance(val, str) else val


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        scan_id: str | UUID,
        target_id: str | UUID,
        project_id: str | UUID,
        user_id: str | UUID,
        title: str,
        description: str,
        severity: str = "medium",
        status: str = "open",
        confidence: str = "HIGH",
        category: str = "Web Security",
        owasp_category: str | None = None,
        cwe_id: str | None = None,
        cvss_score: float | None = None,
        affected_url: str | None = None,
        remediation: str | None = None,
        proof_of_concept: str | None = None,
    ) -> Finding | None:
        u_scan_id = _to_uuid(scan_id)
        u_target_id = _to_uuid(target_id)
        u_user_id = _to_uuid(user_id)

        # ── Deduplication for security headers, cookies, and identical titles ──
        # Scoped strictly to the specific scan, target, and user — never merges across users or targets
        existing_res = await self._session.execute(
            select(Finding).where(
                Finding.scan_id == u_scan_id,
                Finding.target_id == u_target_id,
                Finding.user_id == u_user_id,
            )
        )
        existing_findings = list(existing_res.scalars().all())

        title_lower = title.strip().lower()
        cwe_upper = (cwe_id or "").strip().upper()

        is_site_wide = (
            "content-security-policy" in title_lower
            or cwe_upper in ("CWE-693", "CWE-523", "CWE-1021", "CWE-614", "CWE-319", "CWE-942")
            or "strict-transport-security" in title_lower
            or "hsts" in title_lower
            or "x-frame-options" in title_lower
            or "x-content-type-options" in title_lower
            or "clickjacking" in title_lower
            or "cookie attributes" in title_lower
            or "session cookie" in title_lower
            or "unencrypted http" in title_lower
            or "cleartext http" in title_lower
            or "wildcard" in title_lower
        )

        for ef in existing_findings:
            ef_title_lower = ef.title.strip().lower()
            ef_cwe_upper = (ef.cwe_id or "").strip().upper()

            # 1. Exact title match on the same scan:
            if ef_title_lower == title_lower:
                # If site-wide header/config, deduplicate scan-wide regardless of URL
                if is_site_wide:
                    return None
                # If distinct endpoint URLs on injection/vulnerability findings, preserve both
                if affected_url and ef.affected_url:
                    if affected_url.strip().lower() != ef.affected_url.strip().lower():
                        continue
                return None  # Same endpoint or target-wide: deduplicate

            # 2. CSP deduplication (CWE-693 or Content-Security-Policy)
            if ("content-security-policy" in title_lower or cwe_upper == "CWE-693") and (
                "content-security-policy" in ef_title_lower or ef_cwe_upper == "CWE-693"
            ):
                return None

            # 3. HSTS deduplication (CWE-523 or Strict-Transport-Security)
            if ("strict-transport-security" in title_lower or "hsts" in title_lower or cwe_upper == "CWE-523") and (
                "strict-transport-security" in ef_title_lower or "hsts" in ef_title_lower or ef_cwe_upper == "CWE-523"
            ):
                return None

            # 4. Anti-Clickjacking / X-Frame-Options deduplication (CWE-1021)
            if ("x-frame-options" in title_lower or "clickjacking" in title_lower or cwe_upper == "CWE-1021") and (
                "x-frame-options" in ef_title_lower or "clickjacking" in ef_title_lower or ef_cwe_upper == "CWE-1021"
            ):
                return None

            # 5. X-Content-Type-Options deduplication
            if ("x-content-type-options" in title_lower) and ("x-content-type-options" in ef_title_lower):
                return None

            # 6. Insecure Cookie attributes deduplication (CWE-614 or cookie attributes)
            if (cwe_upper == "CWE-614" or "cookie attributes" in title_lower or "session cookie" in title_lower) and (
                ef_cwe_upper == "CWE-614" or "cookie attributes" in ef_title_lower or "session cookie" in ef_title_lower
            ):
                return None

            # 7. Cleartext HTTP transmission deduplication (CWE-319)
            if (cwe_upper == "CWE-319" and ("unencrypted http" in title_lower or "cleartext http" in title_lower)) and (
                ef_cwe_upper == "CWE-319" and ("unencrypted http" in ef_title_lower or "cleartext http" in ef_title_lower)
            ):
                return None

            # 8. Wildcard CORS deduplication (CWE-942)
            if (cwe_upper == "CWE-942" and "wildcard" in title_lower) and (
                ef_cwe_upper == "CWE-942" and "wildcard" in ef_title_lower
            ):
                return None

        finding = Finding(
            scan_id=u_scan_id,
            target_id=_to_uuid(target_id),
            project_id=_to_uuid(project_id),
            user_id=_to_uuid(user_id),
            title=title,
            description=description,
            severity=severity,
            status=status,
            confidence=confidence,
            category=category,
            owasp_category=owasp_category,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            affected_url=affected_url,
            remediation=remediation,
            proof_of_concept=proof_of_concept,
        )
        self._session.add(finding)
        await self._session.flush()
        await self._session.refresh(finding)
        return finding

    async def get_by_id(self, finding_id: str | UUID) -> Finding | None:
        uid = _to_uuid(finding_id)
        result = await self._session.execute(
            select(Finding).where(Finding.id == uid)
        )
        return result.scalar_one_or_none()

    async def list_for_scan(self, scan_id: str | UUID) -> list[Finding]:
        uid = _to_uuid(scan_id)
        result = await self._session.execute(
            select(Finding).where(Finding.scan_id == uid).order_by(Finding.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_target(self, target_id: str | UUID) -> list[Finding]:
        uid = _to_uuid(target_id)
        result = await self._session.execute(
            select(Finding).where(Finding.target_id == uid).order_by(Finding.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_project(self, project_id: str | UUID) -> list[Finding]:
        uid = _to_uuid(project_id)
        result = await self._session.execute(
            select(Finding).where(Finding.project_id == uid).order_by(Finding.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_user(self, user_id: str | UUID) -> list[Finding]:
        uid = _to_uuid(user_id)
        result = await self._session.execute(
            select(Finding).where(Finding.user_id == uid).order_by(Finding.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_user_paginated(
        self,
        user_id: str | UUID,
        *,
        page: int = 1,
        page_size: int = 20,
        severity: str | None = None,
        confidence: str | None = None,
        owasp_category: str | None = None,
        project_id: str | UUID | None = None,
        scan_id: str | UUID | None = None,
        target_id: str | UUID | None = None,
        status: str | None = None,
    ) -> tuple[list[Finding], int]:
        uid = _to_uuid(user_id)
        query = select(Finding).where(Finding.user_id == uid)

        if severity:
            query = query.where(Finding.severity == severity.lower())
        if confidence:
            query = query.where(Finding.confidence == confidence.upper())
        if owasp_category:
            query = query.where(Finding.owasp_category.ilike(f"%{owasp_category}%"))
        if project_id:
            query = query.where(Finding.project_id == _to_uuid(project_id))
        if scan_id:
            query = query.where(Finding.scan_id == _to_uuid(scan_id))
        if target_id:
            query = query.where(Finding.target_id == _to_uuid(target_id))
        if status:
            query = query.where(Finding.status == status.lower())


        from sqlalchemy import func
        count_query = select(func.count()).select_from(query.subquery())
        total_res = await self._session.execute(count_query)
        total = total_res.scalar_one()

        offset = (max(1, page) - 1) * page_size
        paginated_query = query.order_by(Finding.created_at.desc()).offset(offset).limit(page_size)

        result = await self._session.execute(paginated_query)
        findings = list(result.scalars().all())
        return findings, total

    async def update_status(self, finding: Finding, status: str) -> Finding:
        finding.status = status.lower()
        await self._session.flush()
        await self._session.refresh(finding)
        return finding

    async def delete(self, finding: Finding) -> None:
        await self._session.delete(finding)
        await self._session.flush()

