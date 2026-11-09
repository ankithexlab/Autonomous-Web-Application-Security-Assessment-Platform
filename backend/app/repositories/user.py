"""
User repository.

Encapsulates all database operations for the User model.
The service layer must go through this repository — never issue
raw queries against the User table from outside this module.
"""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserRole


class UserRepository:
    """Data-access layer for the users table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── Reads ────────────────────────────────────────────────────

    async def get_by_email(self, email: str) -> User | None:
        """
        Return the User with the given email, or None.

        Case-sensitive match (email should be normalised to lowercase
        before calling if case-insensitive lookup is needed).
        """
        result = await self._session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: UUID) -> User | None:
        """Return the User with the given UUID primary key, or None."""
        result = await self._session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    # ── Writes ───────────────────────────────────────────────────

    async def create(
        self,
        *,
        email: str,
        name: str,
        hashed_password: str,
        role: UserRole = UserRole.ANALYST,
    ) -> User:
        """
        Persist a new User row and return the fully-hydrated instance.

        Callers are responsible for hashing the password before passing
        it to this method — plain-text passwords must never reach here.
        """
        user = User(
            email=email,
            name=name,
            hashed_password=hashed_password,
            role=role,
        )
        self._session.add(user)
        # flush so that server-generated defaults (uuid, timestamps) are populated
        await self._session.flush()
        await self._session.refresh(user)
        return user

    async def update_last_login(self, user: User) -> None:
        """Stamp the user's last_login_at with the current UTC time."""
        user.last_login_at = datetime.now(timezone.utc)
        await self._session.flush()

    async def update_password(self, user: User, hashed_password: str) -> None:
        """Update the user's hashed password."""
        user.hashed_password = hashed_password
        await self._session.flush()

    async def update_profile(
        self,
        user: User,
        *,
        name: str | None = None,
        avatar: str | None = None,
    ) -> User:
        """Update the user's name and/or avatar."""
        if name is not None:
            user.name = name
        if avatar is not None:
            user.avatar = avatar
        user.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        await self._session.refresh(user)
        return user

    async def delete(self, user: User) -> None:
        """Delete the user record and cascade deletion of related entities."""
        await self._session.delete(user)
        await self._session.flush()


