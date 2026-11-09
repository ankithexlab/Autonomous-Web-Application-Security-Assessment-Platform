"""
Authentication service.

Orchestrates the authentication business logic by coordinating
between the UserRepository and the security utilities.

Design decisions:
  - Refresh tokens are standard JWTs signed with the same SECRET_KEY but carry
    a "type":"refresh" claim and a longer expiry.  This avoids adding a separate
    token table while still allowing token-type validation.
  - Password reset tokens use "type":"password_reset" claim with a short expiry
    (30 min) for security. The email address is embedded in the token.
  - We reuse create_access_token() and verify_access_token() from core/security.py
    for all JWT operations; we never duplicate hashing or signing logic here.
  - Error messages are intentionally generic for login failures to prevent
    user-enumeration attacks.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from uuid import UUID

from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.token_revocation import token_revocation

from app.config import get_settings
from app.core.exceptions import (
    BadRequestException,
    ConflictException,
    UnauthorizedException,
)
from app.core.security import create_access_token, hash_password, verify_password
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.auth import (
    AccessTokenResponse,
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserRead, UserUpdate
from app.services.email import email_service

from app.core.logging import log_security_event, mask_email

logger = logging.getLogger("awsap.auth")


class AuthService:
    """Business-logic layer for authentication operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._repo = UserRepository(session)
        self._settings = get_settings()

    # ── Public API ───────────────────────────────────────────────

    async def register(self, payload: RegisterRequest) -> TokenResponse:
        """
        Create a new user account and return an authentication token pair.

        Raises:
            ConflictException: if the email is already registered.
        """
        existing = await self._repo.get_by_email(payload.email.lower())
        if existing is not None:
            raise ConflictException("An account with this email already exists.")

        user = await self._repo.create(
            email=payload.email.lower(),
            name=payload.name.strip(),
            hashed_password=hash_password(payload.password),
        )
        log_security_event("auth.register_success", {"user_id": str(user.id), "email": mask_email(user.email)})
        return self._build_token_response(user)

    async def login(self, payload: LoginRequest) -> TokenResponse:
        """
        Verify credentials and return an authentication token pair.

        The error message is intentionally identical for unknown email
        and wrong password to prevent user enumeration.

        Raises:
            UnauthorizedException: if credentials are invalid.
        """
        user = await self._repo.get_by_email(payload.email.lower())
        if user is None or not verify_password(payload.password, user.hashed_password):
            log_security_event(
                "auth.login_failed",
                {"attempted_email": mask_email(payload.email)},
                level=logging.WARNING,
            )
            raise UnauthorizedException("Invalid email or password.")

        await self._repo.update_last_login(user)
        log_security_event("auth.login_success", {"user_id": str(user.id)})
        return self._build_token_response(user)

    async def refresh(self, refresh_token: str) -> AccessTokenResponse:
        """
        Exchange a valid refresh token for a new access token.

        Raises:
            UnauthorizedException: if the token is invalid, expired, or wrong type.
        """
        settings = self._settings
        try:
            payload = jwt.decode(
                refresh_token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
            )
        except JWTError:
            raise UnauthorizedException("Invalid or expired refresh token.")

        if payload.get("type") != "refresh":
            raise UnauthorizedException("Token type is not refresh.")

        if await token_revocation.is_token_revoked_persistent(self._session, payload):
            raise UnauthorizedException("Refresh token has been revoked.")

        subject: str | None = payload.get("sub")
        if not subject:
            raise UnauthorizedException("Malformed token: missing subject.")

        try:
            user_id = UUID(subject)
        except ValueError:
            raise UnauthorizedException("Malformed token: invalid subject.")

        user = await self._repo.get_by_id(user_id)
        if user is None:
            raise UnauthorizedException("User associated with this token no longer exists.")

        # Revoke the used refresh token JTI to ensure single-use refresh token rotation
        jti = payload.get("jti")
        if jti:
            exp_ts = payload.get("exp")
            exp = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else datetime.now(timezone.utc)
            await token_revocation.revoke_jti_persistent(self._session, jti, exp, user.id)
            await self._session.commit()

        access_token = create_access_token(user.id)
        return AccessTokenResponse(access_token=access_token)

    async def get_current_user(self, user_id: UUID) -> UserRead:
        """
        Return the UserRead schema for the given user_id.

        Called by the /auth/me endpoint via the get_current_user dependency.

        Raises:
            UnauthorizedException: if no user exists for the given id.
        """
        user = await self._repo.get_by_id(user_id)
        if user is None:
            raise UnauthorizedException("User not found.")
        return UserRead.model_validate(user)

    async def forgot_password(self, email: str) -> None:
        """
        Generate a password reset token and send it via email.

        Security: Always returns success to prevent user enumeration.
        If the email does not exist, the function silently does nothing.
        """
        user = await self._repo.get_by_email(email.lower())
        if user is None:
            # Silently return — do NOT reveal whether the email exists
            logger.info("Password reset requested for non-existent email: %s", email)
            return

        # Create a short-lived password reset JWT
        reset_token = self._create_password_reset_token(user)

        # Send the email (or log to console if SMTP is not configured)
        email_service.send_password_reset_email(user.email, reset_token)
        log_security_event("auth.password_reset_requested", {"email": mask_email(user.email)})
        logger.info("Password reset email sent to %s", mask_email(user.email))

    async def reset_password(self, token: str, new_password: str) -> None:
        """
        Validate a password reset token and update the user's password.

        Raises:
            UnauthorizedException: if the token is invalid, expired, or wrong type.
        """
        settings = self._settings
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
            )
        except JWTError:
            raise UnauthorizedException("Invalid or expired reset link. Please request a new one.")

        if payload.get("type") != "password_reset":
            raise UnauthorizedException("Invalid token type.")

        if await token_revocation.is_token_revoked_persistent(self._session, payload):
            raise UnauthorizedException("Reset link has already been used or is expired. Please request a new one.")

        subject: str | None = payload.get("sub")
        if not subject:
            raise UnauthorizedException("Malformed reset token.")

        try:
            user_id = UUID(subject)
        except ValueError:
            raise UnauthorizedException("Malformed reset token.")

        user = await self._repo.get_by_id(user_id)
        if user is None:
            raise UnauthorizedException("User associated with this token no longer exists.")

        # Single-Use validation: verify password hash fingerprint matches
        expected_fp = hashlib.sha256(user.hashed_password.encode()).hexdigest()[:16]
        token_fp = payload.get("pwd_fp")
        if token_fp is not None and token_fp != expected_fp:
            raise UnauthorizedException("Reset link has already been used or is expired. Please request a new one.")

        # Update the password
        await self._repo.update_password(user, hash_password(new_password))

        # Revoke the reset token JTI immediately
        jti = payload.get("jti")
        if jti:
            exp_ts = payload.get("exp")
            exp = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else datetime.now(timezone.utc)
            await token_revocation.revoke_jti_persistent(self._session, jti, exp, user.id)

        # Invalidate all prior sessions/tokens for this user
        await token_revocation.revoke_user_tokens_persistent(self._session, user.id)
        await self._session.commit()
        log_security_event("auth.password_reset_completed", {"user_id": str(user.id)})
        logger.info("Password successfully reset for user %s", mask_email(user.email))

    async def update_profile(self, user: User, payload: UserUpdate) -> UserRead:
        """Update profile information (e.g. name, avatar) for the user."""
        updated = await self._repo.update_profile(
            user,
            name=payload.name,
            avatar=payload.avatar,
        )
        await self._session.commit()
        return UserRead.model_validate(updated)

    async def change_password(self, user: User, payload: ChangePasswordRequest) -> None:
        """
        Verify the user's current password and set a new password.

        Raises:
            UnauthorizedException: if the current password is wrong.
            BadRequestException: if the new password is the same as the current password.
        """
        if not verify_password(payload.current_password, user.hashed_password):
            raise UnauthorizedException("Current password is incorrect.")

        if payload.current_password == payload.new_password:
            raise BadRequestException("New password must be different from current password.")

        await self._repo.update_password(user, hash_password(payload.new_password))
        await self._session.commit()

        # Invalidate all prior active tokens across devices immediately
        await token_revocation.revoke_user_tokens_persistent(self._session, user.id)
        await self._session.commit()
        log_security_event("auth.password_changed", {"user_id": str(user.id)})
        logger.info("Password changed successfully for user %s", mask_email(user.email))

    async def delete_account(self, user: User) -> None:
        """Delete the user account and invalidate all tokens."""
        await token_revocation.revoke_user_tokens_persistent(self._session, user.id)
        await self._repo.delete(user)
        await self._session.commit()
        log_security_event("auth.account_deleted", {"user_id": str(user.id)})
        logger.info("Account deleted successfully for user %s", mask_email(user.email))

    # ── Private helpers ──────────────────────────────────────────

    def _build_token_response(self, user: User) -> TokenResponse:
        """
        Construct the full TokenResponse (access + refresh + UserRead).

        Refresh token is a standard JWT with an additional "type":"refresh"
        claim, unique "jti", and a longer expiry controlled by REFRESH_TOKEN_EXPIRE_DAYS.
        """
        settings = self._settings
        access_token = create_access_token(user.id)

        now = datetime.now(timezone.utc)
        refresh_payload = {
            "sub": str(user.id),
            "iat": now.timestamp(),
            "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            "type": "refresh",
            "jti": str(uuid.uuid4()),
        }
        refresh_token = jwt.encode(
            refresh_payload,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user=UserRead.model_validate(user),
        )

    def _create_password_reset_token(self, user: User) -> str:
        """
        Create a short-lived JWT for password reset.

        Contains "type":"password_reset", unique "jti", and a password fingerprint
        "pwd_fp" to ensure the token becomes strictly single-use once the password is changed.
        Expires after PASSWORD_RESET_EXPIRE_MINUTES (default 30 min).
        """
        settings = self._settings
        now = datetime.now(timezone.utc)
        pwd_fp = hashlib.sha256(user.hashed_password.encode()).hexdigest()[:16]
        payload = {
            "sub": str(user.id),
            "iat": now.timestamp(),
            "exp": now + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
            "type": "password_reset",
            "pwd_fp": pwd_fp,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

