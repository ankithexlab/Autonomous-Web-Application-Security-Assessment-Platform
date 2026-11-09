"""
Default data seeder for users, projects, and security assessment targets.
Ensures user accounts have active projects and verified benchmark assessment targets.
"""

import logging
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.project import Project
from app.models.target import Target
from app.models.user import User

logger = logging.getLogger("awsap.seed")

DEFAULT_TARGETS = [
    {
        "url": "http://testphp.vulnweb.com",
        "type": "web",
        "validation_status": "verified",
        "status": "active",
    },
    {
        "url": "http://testhtml5.vulnweb.com",
        "type": "web",
        "validation_status": "verified",
        "status": "active",
    },
    {
        "url": "http://demo.testfire.net",
        "type": "web",
        "validation_status": "verified",
        "status": "active",
    },
]


async def ensure_user_default_project_and_targets(
    session: AsyncSession, user_id: UUID
) -> Project:
    """
    Ensure user has at least one active project with ready-to-scan assessment targets.
    """
    # Check if user has any projects
    res = await session.execute(
        select(Project).where(Project.user_id == user_id).order_by(Project.created_at.asc())
    )
    project = res.scalars().first()

    if not project:
        project = Project(
            user_id=user_id,
            name="Web Security Assessment",
            description="Default assessment workspace with pre-configured vulnerable & benchmark test targets.",
            risk_level="medium",
            status="active",
        )
        session.add(project)
        await session.flush()
        await session.refresh(project)
        logger.info("Created default project '%s' for user %s", project.name, user_id)

    # Check targets in this project
    tgt_res = await session.execute(
        select(Target).where(Target.project_id == project.id)
    )
    existing_targets = {t.url for t in tgt_res.scalars().all()}

    added = 0
    for dt in DEFAULT_TARGETS:
        if dt["url"] not in existing_targets:
            tgt = Target(
                project_id=project.id,
                url=dt["url"],
                type=dt["type"],
                status=dt["status"],
                validation_status=dt["validation_status"],
            )
            session.add(tgt)
            existing_targets.add(dt["url"])
            added += 1

    if added > 0:
        await session.commit()
        await session.refresh(project)
        logger.info("Added %d default target(s) for user %s in project %s", added, user_id, project.id)

    return project


async def seed_all_existing_users(session: AsyncSession) -> int:
    """Ensure all existing users in the system have projects and targets."""
    res = await session.execute(select(User))
    users = res.scalars().all()
    count = 0
    for u in users:
        await ensure_user_default_project_and_targets(session, u.id)
        count += 1
    return count
