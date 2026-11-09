"""
Authentication endpoints.

Routes:
  POST /auth/register          — create account, return token pair
  POST /auth/login             — verify credentials, return token pair
  POST /auth/refresh           — exchange refresh token for a new access token
  GET  /auth/me                — return the currently authenticated user
  POST /auth/forgot-password   — send password reset email
  POST /auth/reset-password    — reset password using token from email
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.auth import (
    AccessTokenResponse,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
)
from app.schemas.user import UserRead, UserUpdate
from app.services.auth import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    """Dependency factory that constructs AuthService with the request-scoped session."""
    return AuthService(db)


from app.core.rate_limiter import rate_limit


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    dependencies=[Depends(rate_limit(max_requests=15, window_seconds=60, scope="auth:register"))],
)
async def register(
    payload: RegisterRequest,
    svc: AuthService = Depends(_get_auth_service),
) -> TokenResponse:
    """
    Create a new user account and immediately issue an access + refresh token pair.

    - Returns **201 Created** on success.
    - Returns **409 Conflict** if the email is already registered.
    - Password is bcrypt-hashed before storage; plaintext is never persisted.
    """
    return await svc.register(payload)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login with email and password",
    dependencies=[Depends(rate_limit(max_requests=15, window_seconds=60, scope="auth:login"))],
)
async def login(
    payload: LoginRequest,
    svc: AuthService = Depends(_get_auth_service),
) -> TokenResponse:
    """
    Authenticate with email and password.

    - Returns **200 OK** with a token pair on success.
    - Returns **401 Unauthorized** for invalid credentials (intentionally vague
      to prevent user enumeration — the error does not reveal whether the email
      exists or the password was wrong).
    """
    return await svc.login(payload)


@router.post(
    "/refresh",
    response_model=AccessTokenResponse,
    summary="Exchange a refresh token for a new access token",
)
async def refresh(
    payload: RefreshRequest,
    svc: AuthService = Depends(_get_auth_service),
) -> AccessTokenResponse:
    """
    Trade a valid refresh token for a new short-lived access token.

    - The refresh token must have `type: "refresh"` in its JWT claims.
    - Returns **401 Unauthorized** if the token is expired, tampered, or wrong type.
    """
    return await svc.refresh(payload.refresh_token)


@router.get(
    "/me",
    response_model=UserRead,
    summary="Get the currently authenticated user",
)
async def me(current_user: User = Depends(get_current_user)) -> UserRead:
    """
    Return the profile of the user identified by the Bearer token.

    - Requires a valid **access** token in the Authorization header.
    - Returns **401 Unauthorized** if the token is missing, expired, or a refresh token.
    """
    return UserRead.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserRead,
    summary="Update current user profile",
)
async def update_me(
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    svc: AuthService = Depends(_get_auth_service),
) -> UserRead:
    """
    Update profile details (e.g. name, avatar) for the currently authenticated user.
    """
    return await svc.update_profile(current_user, payload)


@router.delete(
    "/me",
    response_model=MessageResponse,
    summary="Delete currently authenticated user account",
)
async def delete_me(
    current_user: User = Depends(get_current_user),
    svc: AuthService = Depends(_get_auth_service),
) -> MessageResponse:
    """
    Permanently delete the user's account, cascade all related entities, and revoke sessions.
    """
    await svc.delete_account(current_user)
    return MessageResponse(message="Account successfully deleted.")



@router.post(
    "/change-password",
    response_model=MessageResponse,
    summary="Change password for current user",
)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    svc: AuthService = Depends(_get_auth_service),
) -> MessageResponse:
    """
    Change password for the currently authenticated user.
    Requires current password verification and password complexity validation.
    """
    await svc.change_password(current_user, payload)
    return MessageResponse(message="Password changed successfully.")



@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request a password reset email",
    dependencies=[Depends(rate_limit(max_requests=10, window_seconds=60, scope="auth:forgot-password"))],
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    svc: AuthService = Depends(_get_auth_service),
) -> MessageResponse:
    """
    Send a password reset link to the provided email address.

    - **Always returns 200 OK** regardless of whether the email exists,
      to prevent user enumeration.
    - If the email exists, a reset link is sent via SMTP (or logged to console
      in development when SMTP is not configured).
    - Reset tokens expire after 30 minutes.
    """
    await svc.forgot_password(payload.email)
    return MessageResponse(
        message="If an account with that email exists, a password reset link has been sent."
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using token from email",
    dependencies=[Depends(rate_limit(max_requests=10, window_seconds=60, scope="auth:reset-password"))],
)
async def reset_password(
    payload: ResetPasswordRequest,
    svc: AuthService = Depends(_get_auth_service),
) -> MessageResponse:
    """
    Reset the user's password using the token received via email.

    - The token must be a valid password_reset JWT (not expired).
    - Returns **401 Unauthorized** if the token is invalid or expired.
    - On success, the user can log in with their new password.
    """
    await svc.reset_password(payload.token, payload.password)
    return MessageResponse(message="Password has been reset successfully.")


from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.core.token_revocation import token_revocation
from jose import jwt
from app.config import get_settings
from uuid import UUID

_bearer = HTTPBearer(auto_error=False)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Log out user session",
)
async def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Clear user session on the client and invalidate tokens server-side across workers."""
    if credentials and credentials.credentials:
        try:
            settings = get_settings()
            payload = jwt.decode(
                credentials.credentials,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={"verify_exp": False},
            )
            jti = payload.get("jti")
            sub = payload.get("sub")
            exp_ts = payload.get("exp")
            from datetime import datetime, timezone
            exp = (
                datetime.fromtimestamp(exp_ts, tz=timezone.utc)
                if exp_ts
                else datetime.now(timezone.utc)
            )
            uid = UUID(sub) if sub else None

            if jti:
                await token_revocation.revoke_jti_persistent(db, jti, exp, uid)
            if uid:
                await token_revocation.revoke_user_tokens_persistent(db, uid)
            await db.commit()
        except Exception:
            token_revocation.revoke_token(credentials.credentials)

    return MessageResponse(message="Logged out successfully.")

