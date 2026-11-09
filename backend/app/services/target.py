"""
Target service.
"""

import ipaddress
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException, NotFoundException
from app.core.ssrf import is_ip_blocked
from app.models.target import Target
from app.repositories.project import ProjectRepository
from app.repositories.target import TargetRepository
from app.schemas.target import TargetCreateRequest, TargetRead


def _normalize_url(raw_url: str) -> str:
    if not raw_url or not raw_url.strip():
        raise BadRequestException("Target URL cannot be empty.")
    url_str = raw_url.strip()
    if "://" in url_str:
        scheme, _, _ = url_str.partition("://")
        if scheme.lower() not in ("http", "https"):
            raise BadRequestException(f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
    else:
        url_str = f"https://{url_str}"

    parsed = urlparse(url_str)
    if parsed.scheme not in ("http", "https"):
        raise BadRequestException(f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")
    if parsed.username or parsed.password:
        raise BadRequestException("Target URL containing embedded user credentials is not permitted.")
    hostname = parsed.hostname
    if not hostname:
        raise BadRequestException(f"Invalid target URL '{raw_url}': missing valid hostname.")

    lower_host = hostname.lower()
    if lower_host in ("metadata.google.internal", "instance-data", "metadata"):
        raise BadRequestException(f"Target hostname '{hostname}' is a restricted host. Access denied for SSRF protection.")

    # Reject localhost if local targets disallowed
    from app.config import get_settings
    settings = get_settings()
    if not settings.ALLOW_LOCAL_TARGETS and lower_host in ("localhost", "127.0.0.1", "::1"):
        raise BadRequestException(f"Target host '{hostname}' resolves to loopback IP address. Access denied.")

    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_blocked(ip_obj):
            raise BadRequestException(f"Target URL resolves to blocked IP address '{hostname}'. Access denied.")
    except ValueError:
        # Not a raw IP literal
        pass

    # Remove redundant trailing slash from root path if no query/fragment
    if parsed.path == "/" and not parsed.query and not parsed.fragment:
        url_str = f"{parsed.scheme}://{parsed.netloc}"
    return url_str


class TargetService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._project_repo = ProjectRepository(session)
        self._target_repo = TargetRepository(session)

    async def create_target(
        self, user_id: UUID, project_id: UUID, payload: TargetCreateRequest
    ) -> TargetRead:
        project = await self._project_repo.get_by_id(project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Project not found.")

        normalized_url = _normalize_url(payload.url)

        # Check for existing target with same URL in this project to reuse
        existing = await self._target_repo.get_by_url_and_project(project_id, normalized_url)
        if existing:
            return TargetRead.model_validate(existing)

        target = await self._target_repo.create(
            project_id=project_id,
            url=normalized_url,
            target_type=payload.type,
        )
        return TargetRead.model_validate(target)

    async def create_or_get_user_target(
        self, user_id: UUID, payload: TargetCreateRequest
    ) -> TargetRead:
        """
        Register a custom/manual URL under the authenticated user's project,
        reusing an existing target if one with the same URL is already present.
        """
        normalized_url = _normalize_url(payload.url)

        # 1. Search existing targets for user across all their projects
        user_targets = await self._target_repo.list_for_user(user_id)
        for t in user_targets:
            if t.url.strip().rstrip("/").lower() == normalized_url.rstrip("/").lower():
                return TargetRead.model_validate(t)

        # 2. Get or create user's primary/default project
        from app.services.seed import ensure_user_default_project_and_targets
        project = await ensure_user_default_project_and_targets(self._session, user_id)

        # 3. Create target under project
        target = await self._target_repo.create(
            project_id=project.id,
            url=normalized_url,
            target_type=payload.type,
        )
        await self._session.commit()
        return TargetRead.model_validate(target)

    async def list_project_targets(self, user_id: UUID, project_id: UUID) -> list[TargetRead]:
        project = await self._project_repo.get_by_id(project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Project not found.")

        targets = await self._target_repo.list_for_project(project_id)
        return [TargetRead.model_validate(t) for t in targets]

    async def list_user_targets(self, user_id: UUID) -> list[TargetRead]:
        targets = await self._target_repo.list_for_user(user_id)
        return [TargetRead.model_validate(t) for t in targets]


    async def get_target(self, user_id: UUID, project_id: UUID, target_id: UUID) -> Target:
        project = await self._project_repo.get_by_id(project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Project not found.")

        target = await self._target_repo.get_by_id(target_id)
        if not target or target.project_id != project_id:
            raise NotFoundException("Target not found.")

        return target

    async def get_user_target(self, user_id: UUID, target_id: UUID) -> Target:
        target = await self._target_repo.get_by_id(target_id)
        if not target:
            raise NotFoundException("Target not found.")
        project = await self._project_repo.get_by_id(target.project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Target not found.")
        return target

    async def delete_target(self, user_id: UUID, project_id: UUID, target_id: UUID) -> None:
        target = await self.get_target(user_id, project_id, target_id)
        await self._target_repo.delete(target)

    async def delete_user_target(self, user_id: UUID, target_id: UUID) -> None:
        target = await self.get_user_target(user_id, target_id)
        await self._target_repo.delete(target)

