"""
Token revocation cleanup worker.

Provides background scheduled cleanup for expired RevokedToken database records.
Expired tokens are naturally rejected by exp claim verification; deleting them keeps
the revocation blocklist lean and performant over long-term operations.
"""

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import logging

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.token_revocation import token_revocation
from app.database.session import async_session_factory
from app.models.security_hardening import RevokedToken

logger = logging.getLogger("awsap.security.cleanup")

DAILY_CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60  # 86400 seconds = 1 day


async def purge_expired_revoked_tokens(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> int:
    """
    Executes a single atomic cleanup cycle of expired RevokedToken records.

    Guarantees:
      - Only expired rows (expires_at <= now) are deleted.
      - Unexpired tokens (expires_at > now) are preserved.
      - Database session is always closed via async context manager.
      - On exception: transaction is rolled back, error logged, and re-raised.

    Returns:
      int: Number of deleted expired records.
    """
    factory = session_factory or async_session_factory
    now = datetime.now(timezone.utc)

    async with factory() as session:
        try:
            # Also prune in-memory hot cache
            token_revocation._prune_expired_memory(now)

            stmt = delete(RevokedToken).where(RevokedToken.expires_at <= now)
            result = await session.execute(stmt)
            deleted_count = result.rowcount or 0
            await session.commit()

            if deleted_count > 0:
                logger.info(
                    "Expired token cleanup cycle completed: purged %d expired token(s)",
                    deleted_count,
                )
            return deleted_count
        except Exception:
            await session.rollback()
            logger.exception("Database error occurred during expired token cleanup")
            raise


class ExpiredTokenCleanupWorker:
    """
    Periodic background worker managing the daily expired token cleanup loop.
    """

    def __init__(
        self,
        interval_seconds: float = DAILY_CLEANUP_INTERVAL_SECONDS,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.session_factory = session_factory
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    @property
    def is_running(self) -> bool:
        """Return True if background worker task is actively running."""
        return self._task is not None and not self._task.done()

    async def _run_loop(self) -> None:
        """
        Background worker loop. Executes periodic purge cycles while handling
        database errors gracefully to ensure worker resilience.
        """
        logger.info(
            "Expired token cleanup worker started (interval: %.1f seconds)",
            self.interval_seconds,
        )
        try:
            while not self._stop_event.is_set():
                try:
                    await purge_expired_revoked_tokens(self.session_factory)
                except Exception as exc:
                    logger.warning(
                        "Periodic token cleanup iteration failed: %s; worker will retry next cycle.",
                        exc,
                    )

                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.interval_seconds,
                    )
                    break
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            logger.info("Expired token cleanup worker task cancelled.")
            raise
        finally:
            logger.info("Expired token cleanup worker stopped.")

    def start(self) -> asyncio.Task[None]:
        """Start the background cleanup worker task."""
        if self.is_running:
            return self._task  # type: ignore[return-value]
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._run_loop(),
            name="expired_token_cleanup_worker",
        )
        return self._task

    async def stop(self) -> None:
        """
        Stop the background cleanup worker cleanly.
        Signals stop event, cancels task if running, and waits for task termination.
        """
        if not self._task:
            return
        self._stop_event.set()
        if not self._task.done():
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        self._task = None
