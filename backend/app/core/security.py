"""
Security utilities: password hashing and JWT token management.

All token subjects use UUID strings to maintain type consistency
with the rest of the application.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings

# ── Password Hashing ─────────────────────────────────────────────

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return _pwd_context.verify(plain_password, hashed_password)


# ── JWT Tokens ───────────────────────────────────────────────────


import uuid
from app.core.token_revocation import token_revocation


def create_access_token(
    subject: UUID,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        subject: The user's UUID, stored as the 'sub' claim.
        expires_delta: Optional custom expiration. Falls back to config default.

    Returns:
        Encoded JWT string.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)

    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload = {
        "sub": str(subject),
        "iat": now.timestamp(),
        "exp": expire,
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_access_token(token: str) -> UUID | None:
    """
    Decode and verify a JWT access token.

    Returns:
        The user UUID from the 'sub' claim, or None if invalid or revoked.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            return None
        if token_revocation.is_token_revoked(payload):
            return None
        subject: str | None = payload.get("sub")
        if subject is None:
            return None
        return UUID(subject)
    except (JWTError, ValueError):
        return None
