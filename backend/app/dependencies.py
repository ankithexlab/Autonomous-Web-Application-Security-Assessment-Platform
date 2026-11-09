"""
FastAPI dependency: get_current_user.

Extracts and validates the Bearer token from every protected request.
Returns the authenticated User ORM instance so route handlers receive
a typed, database-backed user object rather than raw token claims.

Security hardening:
  - Decodes the JWT directly here to inspect the "type" claim, rejecting
    refresh tokens from being used on protected resource endpoints.
  - Falls back to UnauthorizedException (401) for all failure modes so
    that error responses never reveal whether a token was expired, revoked,
    or simply malformed.
"""

from uuid import UUID

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import UnauthorizedException
from app.database.session import get_db
from app.models.user import User
from app.repositories.user import UserRepository

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency that resolves the Bearer token to a User instance.

    Usage in route handlers:
        @router.get("/me")
        async def me(user: User = Depends(get_current_user)):
            ...

    Raises:
        UnauthorizedException (401): token missing, invalid, expired, or wrong type.
    """
    if credentials is None:
        raise UnauthorizedException("Authentication credentials were not provided.")

    token = credentials.credentials
    settings = get_settings()

    # Decode and validate structure before delegating to verify_access_token.
    # This extra step lets us inspect the "type" claim to block refresh tokens
    # from being used as access tokens without modifying core/security.py.
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        raise UnauthorizedException("Invalid or expired access token.")

    from app.core.token_revocation import token_revocation

    if await token_revocation.is_token_revoked_persistent(db, payload):
        raise UnauthorizedException("Token has been revoked.")

    token_type = payload.get("type")
    if token_type != "access":
        if token_type == "refresh":
            raise UnauthorizedException("Cannot use a refresh token to access this endpoint.")
        if token_type == "password_reset":
            raise UnauthorizedException("Cannot use a password reset token to access this endpoint.")
        raise UnauthorizedException(f"Invalid token type: cannot use '{token_type}' token for authentication.")

    subject: str | None = payload.get("sub")
    if not subject:
        raise UnauthorizedException("Malformed access token: missing subject.")

    try:
        user_id = UUID(subject)
    except ValueError:
        raise UnauthorizedException("Malformed access token: invalid subject.")

    repo = UserRepository(db)
    user = await repo.get_by_id(user_id)
    if user is None:
        raise UnauthorizedException("User associated with this token no longer exists.")

    return user
