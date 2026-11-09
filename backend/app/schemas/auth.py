"""
Authentication request / response schemas.

All schemas use strict validation to prevent malformed input from
reaching the service layer.
"""

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.user import UserRead


# ── Request Schemas ──────────────────────────────────────────────


class RegisterRequest(BaseModel):
    """Payload for POST /auth/register."""

    name: str = Field(min_length=1, max_length=255, examples=["Alice Smith"])
    email: EmailStr = Field(examples=["alice@example.com"])
    password: str = Field(
        min_length=8,
        max_length=128,
        examples=["S3cur3P@ssw0rd"],
    )

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() or not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one digit or special character.")
        return v


class LoginRequest(BaseModel):
    """Payload for POST /auth/login."""

    email: EmailStr = Field(examples=["alice@example.com"])
    password: str = Field(examples=["S3cur3P@ssw0rd"])


class RefreshRequest(BaseModel):
    """Payload for POST /auth/refresh."""

    refresh_token: str = Field(description="A valid refresh JWT obtained from login or register.")


# ── Response Schemas ─────────────────────────────────────────────


class TokenResponse(BaseModel):
    """
    Full authentication response returned after register or login.

    Matches the frontend AuthResponse interface:
        { user: User, token: string }
    We extend it with refresh_token for complete session management.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserRead


class AccessTokenResponse(BaseModel):
    """Slim token response returned by the refresh endpoint."""

    access_token: str
    token_type: str = "bearer"


# ── Password Reset Schemas ───────────────────────────────────────


class ForgotPasswordRequest(BaseModel):
    """Payload for POST /auth/forgot-password."""

    email: EmailStr = Field(examples=["alice@example.com"])


class ResetPasswordRequest(BaseModel):
    """Payload for POST /auth/reset-password."""

    token: str = Field(description="Password reset JWT received via email.")
    password: str = Field(
        min_length=8,
        max_length=128,
        examples=["N3wS3cur3P@ss"],
    )

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() or not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one digit or special character.")
        return v


class MessageResponse(BaseModel):
    """Simple message response for operations without data payload."""

    message: str


class ChangePasswordRequest(BaseModel):
    """Payload for POST /auth/change-password."""

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(
        min_length=8,
        max_length=128,
        examples=["N3wS3cur3P@ss"],
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() or not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one digit or special character.")
        return v

