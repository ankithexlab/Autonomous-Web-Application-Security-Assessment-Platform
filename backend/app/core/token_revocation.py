"""
Token revocation management.

Provides persistent, shared revocation storage backed by PostgreSQL
for JWT tokens (JTIs) and user-level session revocation timestamps,
guaranteeing revocation persists across application restarts and across multiple workers.
"""

from datetime import datetime, timezone
import logging
import threading
from uuid import UUID

from jose import JWTError, jwt
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import UnauthorizedException
from app.models.security_hardening import RevokedToken, UserRevocation

logger = logging.getLogger("awsap.security.revocation")


class TokenRevocationManager:
    """
    Registry for revoked JWT tokens and user session revocation timestamps.
    Combines an in-memory hot cache with PostgreSQL persistent storage.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Hot-cache map of revoked jti -> expiration datetime
        self._revoked_jtis: dict[str, datetime] = {}
        # Hot-cache map of user_id -> revoked_at datetime
        self._user_revocations: dict[UUID, datetime] = {}

    # ── Persistent Storage Methods ────────────────────────────────────────

    async def is_token_revoked_persistent(
        self,
        db: AsyncSession,
        payload: dict,
    ) -> bool:
        """
        Check if token is revoked against PostgreSQL shared storage and hot cache.
        Guarantees fail-closed behavior on storage errors.
        """
        now = datetime.now(timezone.utc)
        jti = payload.get("jti")
        sub = payload.get("sub")
        iat = payload.get("iat")

        # 1. Hot cache check first for speed
        with self._lock:
            self._prune_expired_memory(now)
            if jti and jti in self._revoked_jtis:
                return True
            if sub:
                try:
                    uid = UUID(str(sub))
                    if uid in self._user_revocations:
                        revoked_at = self._user_revocations[uid]
                        if iat is None:
                            return True
                        token_issued_at = (
                            datetime.fromtimestamp(iat, tz=timezone.utc)
                            if isinstance(iat, (int, float))
                            else iat
                        )
                        if token_issued_at <= revoked_at:
                            return True
                except ValueError:
                    pass

        # 2. Query persistent PostgreSQL store
        try:
            # Check JTI blocklist
            if jti:
                stmt = select(RevokedToken.jti).where(
                    RevokedToken.jti == str(jti),
                    RevokedToken.expires_at > now,
                )
                res = await db.execute(stmt)
                if res.scalar_one_or_none() is not None:
                    # Sync to hot cache
                    exp_ts = payload.get("exp")
                    exp = (
                        datetime.fromtimestamp(exp_ts, tz=timezone.utc)
                        if exp_ts
                        else now
                    )
                    with self._lock:
                        self._revoked_jtis[str(jti)] = exp
                    return True

            # Check User-level session revocation
            if sub:
                try:
                    uid = UUID(str(sub))
                    u_stmt = select(UserRevocation.revoked_at).where(
                        UserRevocation.user_id == uid
                    )
                    u_res = await db.execute(u_stmt)
                    revoked_at = u_res.scalar_one_or_none()
                    if revoked_at is not None:
                        # Normalize timezone if naive
                        if revoked_at.tzinfo is None:
                            revoked_at = revoked_at.replace(tzinfo=timezone.utc)

                        with self._lock:
                            self._user_revocations[uid] = revoked_at

                        if iat is None:
                            return True
                        token_issued_at = (
                            datetime.fromtimestamp(iat, tz=timezone.utc)
                            if isinstance(iat, (int, float))
                            else iat
                        )
                        if (
                            isinstance(token_issued_at, datetime)
                            and token_issued_at.tzinfo is None
                        ):
                            token_issued_at = token_issued_at.replace(tzinfo=timezone.utc)

                        if token_issued_at <= revoked_at:
                            return True
                except ValueError:
                    pass

            return False

        except Exception as e:
            logger.error("Storage error during token revocation verification: %s", e)
            # Fail-closed: Never silently authorize on storage failure
            raise UnauthorizedException(
                "Authentication service temporarily unavailable. Please retry."
            ) from e

    async def revoke_jti_persistent(
        self,
        db: AsyncSession,
        jti: str,
        exp: datetime,
        user_id: UUID | None = None,
    ) -> None:
        """Persist a single token JTI revocation to PostgreSQL and hot cache."""
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune_expired_memory(now)
            self._revoked_jtis[jti] = exp

        # Upsert into PostgreSQL
        stmt = (
            pg_insert(RevokedToken)
            .values(
                jti=jti,
                user_id=user_id,
                expires_at=exp,
                created_at=now,
            )
            .on_conflict_do_update(
                index_elements=["jti"],
                set_={"expires_at": exp},
            )
        )
        await db.execute(stmt)

    async def revoke_user_tokens_persistent(
        self,
        db: AsyncSession,
        user_id: UUID,
    ) -> None:
        """Persist user-level session revocation timestamp to PostgreSQL and hot cache."""
        now = datetime.now(timezone.utc)
        with self._lock:
            self._user_revocations[user_id] = now

        stmt = (
            pg_insert(UserRevocation)
            .values(
                user_id=user_id,
                revoked_at=now,
            )
            .on_conflict_do_update(
                index_elements=["user_id"],
                set_={"revoked_at": now},
            )
        )
        await db.execute(stmt)

    async def cleanup_expired(self, db: AsyncSession) -> int:
        """
        Safely prune expired revocation entries from PostgreSQL.
        Safe because expired tokens are naturally rejected by exp claim verification.
        """
        now = datetime.now(timezone.utc)
        stmt = delete(RevokedToken).where(RevokedToken.expires_at <= now)
        res = await db.execute(stmt)
        return res.rowcount or 0

    # ── Fallback Memory-Only Methods ──────────────────────────────────────

    def revoke_jti(self, jti: str, exp: datetime) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune_expired_memory(now)
            self._revoked_jtis[jti] = exp

    def revoke_token(self, token_str: str) -> None:
        settings = get_settings()
        try:
            payload = jwt.decode(
                token_str,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={"verify_exp": False},
            )
        except JWTError:
            return

        jti = payload.get("jti")
        exp_ts = payload.get("exp")
        exp = (
            datetime.fromtimestamp(exp_ts, tz=timezone.utc)
            if exp_ts
            else datetime.now(timezone.utc)
        )
        if jti:
            self.revoke_jti(jti, exp)

    def revoke_user_tokens(self, user_id: UUID) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._user_revocations[user_id] = now

    def is_token_revoked(self, payload: dict) -> bool:
        now = datetime.now(timezone.utc)
        jti = payload.get("jti")
        sub = payload.get("sub")
        iat = payload.get("iat")

        with self._lock:
            self._prune_expired_memory(now)
            if jti and jti in self._revoked_jtis:
                return True
            if sub:
                try:
                    uid = UUID(str(sub))
                    if uid in self._user_revocations:
                        revoked_at = self._user_revocations[uid]
                        if iat is None:
                            return True
                        token_issued_at = (
                            datetime.fromtimestamp(iat, tz=timezone.utc)
                            if isinstance(iat, (int, float))
                            else iat
                        )
                        if token_issued_at <= revoked_at:
                            return True
                except ValueError:
                    pass
        return False

    def _prune_expired_memory(self, now: datetime) -> None:
        expired = [jti for jti, exp in self._revoked_jtis.items() if exp <= now]
        for jti in expired:
            del self._revoked_jtis[jti]

    def reset_cache(self) -> None:
        """Clear memory cache (for testing server restart simulation)."""
        with self._lock:
            self._revoked_jtis.clear()
            self._user_revocations.clear()


# Global manager singleton
token_revocation = TokenRevocationManager()
