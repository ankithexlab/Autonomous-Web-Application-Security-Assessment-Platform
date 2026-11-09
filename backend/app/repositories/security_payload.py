"""
SecurityPayload repository.

Provides database access patterns for query, retrieval, pagination,
search, and statistics calculation over the security_payloads table.
"""

from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_payload import SecurityPayload


class SecurityPayloadRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, payload_id: str) -> SecurityPayload | None:
        """Retrieve a single payload by its unique ID."""
        result = await self._session.execute(
            select(SecurityPayload).where(SecurityPayload.id == payload_id.strip())
        )
        return result.scalar_one_or_none()

    async def list_paginated(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        vuln_type: str | None = None,
        severity: str | None = None,
        search: str | None = None,
    ) -> tuple[list[SecurityPayload], int]:
        """
        List payloads with pagination, filtering, and text search.
        Uses parameterized queries to prevent SQL injection.
        """
        query = select(SecurityPayload)

        if vuln_type:
            # Case-insensitive category match
            query = query.where(func.lower(SecurityPayload.type) == vuln_type.strip().lower())

        if severity:
            query = query.where(func.lower(SecurityPayload.severity) == severity.strip().lower())

        if search and search.strip():
            term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    SecurityPayload.id.ilike(term),
                    SecurityPayload.description.ilike(term),
                    SecurityPayload.payload.ilike(term),
                    SecurityPayload.context.ilike(term),
                    SecurityPayload.type.ilike(term),
                )
            )

        # Count total matches
        count_query = select(func.count()).select_from(query.subquery())
        total_res = await self._session.execute(count_query)
        total = total_res.scalar_one()

        # Apply deterministic ordering and pagination offsets
        offset = (max(1, page) - 1) * page_size
        paginated_query = query.order_by(SecurityPayload.id.asc()).offset(offset).limit(page_size)

        result = await self._session.execute(paginated_query)
        items = list(result.scalars().all())
        return items, total

    async def get_stats(self) -> dict[str, Any]:
        """
        Compute category and severity aggregate counts for dashboard/metrics.
        """
        total_query = select(func.count(SecurityPayload.id))
        total = (await self._session.execute(total_query)).scalar_one()

        # Severity breakdown
        sev_query = (
            select(SecurityPayload.severity, func.count(SecurityPayload.id))
            .group_by(SecurityPayload.severity)
        )
        sev_res = await self._session.execute(sev_query)
        by_severity = {str(row[0]): int(row[1]) for row in sev_res.all()}

        # Type breakdown
        type_query = (
            select(SecurityPayload.type, func.count(SecurityPayload.id))
            .group_by(SecurityPayload.type)
            .order_by(func.count(SecurityPayload.id).desc())
        )
        type_res = await self._session.execute(type_query)
        by_type = {str(row[0]): int(row[1]) for row in type_res.all()}

        return {
            "total": total,
            "by_severity": by_severity,
            "by_type": by_type,
        }

    async def get_payloads_by_type(self, vuln_type: str, limit: int = 10) -> list[SecurityPayload]:
        """Fetch a limited subset of payloads for safe scanner probe generation."""
        query = (
            select(SecurityPayload)
            .where(func.lower(SecurityPayload.type) == vuln_type.strip().lower())
            .limit(limit)
        )
        result = await self._session.execute(query)
        return list(result.scalars().all())
