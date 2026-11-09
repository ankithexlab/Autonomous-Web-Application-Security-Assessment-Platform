"""
Authentication endpoint tests.

Coverage:
  1. App liveness — GET /health
  2. Register success
  3. Register duplicate email → 409
  4. Login success
  5. Login wrong password → 401
  6. Login unknown email → 401
  7. GET /auth/me with valid access token
  8. GET /auth/me with invalid token → 401
  9. POST /auth/refresh with valid refresh token
 10. POST /auth/refresh with access token (wrong type) → 401
"""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ── 1. Health ────────────────────────────────────────────────────


async def test_health(client: AsyncClient) -> None:
    """Application is running and health endpoint returns 200."""
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


# ── 2. Register success ──────────────────────────────────────────


async def test_register_success(client: AsyncClient) -> None:
    """Registering a new user returns 201 with tokens and safe user data."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "name": "Alice Smith",
            "email": "alice@example.com",
            "password": "SecurePass1!",
        },
    )
    assert response.status_code == 201, response.text

    body = response.json()

    # Token fields present
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"

    # User fields present and correct
    user = body["user"]
    assert user["email"] == "alice@example.com"
    assert user["name"] == "Alice Smith"
    assert "id" in user
    assert "role" in user

    # Password must NEVER appear in the response
    assert "password" not in body
    assert "hashed_password" not in body
    assert "password" not in str(user)
    assert "hashed_password" not in str(user)


# ── 3. Register duplicate email ──────────────────────────────────


async def test_register_duplicate_email(client: AsyncClient) -> None:
    """Registering with an already-used email returns 409 Conflict."""
    payload = {
        "name": "Bob",
        "email": "bob@example.com",
        "password": "SecurePass1!",
    }
    first = await client.post("/api/v1/auth/register", json=payload)
    assert first.status_code == 201

    second = await client.post("/api/v1/auth/register", json=payload)
    assert second.status_code == 409

    error = second.json()
    assert "message" in error
    assert "code" in error


# ── 4. Login success ─────────────────────────────────────────────


async def test_login_success(client: AsyncClient, registered_user: dict) -> None:
    """Login with correct credentials returns 200 with token pair."""
    email = registered_user["user"]["email"]
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "TestPass123!",
        },
    )
    assert response.status_code == 200, response.text

    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == email


# ── 5. Login wrong password ──────────────────────────────────────


async def test_login_wrong_password(client: AsyncClient, registered_user: dict) -> None:
    """Login with wrong password returns 401."""
    email = registered_user["user"]["email"]
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "WrongPassword999",
        },
    )
    assert response.status_code == 401

    error = response.json()
    assert "message" in error
    # Error message must be generic — it intentionally does not reveal
    # whether the email doesn't exist or the password was wrong.
    # "Invalid email or password." satisfies this: one message, both cases.
    assert len(error["message"]) > 0


# ── 6. Login unknown email ───────────────────────────────────────


async def test_login_unknown_email(client: AsyncClient) -> None:
    """Login with an email that was never registered returns 401."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "nobody@nowhere.com",
            "password": "AnyPassword1!",
        },
    )
    assert response.status_code == 401


# ── 7. GET /auth/me with valid token ────────────────────────────


async def test_me_with_valid_token(client: AsyncClient, registered_user: dict) -> None:
    """GET /auth/me with a valid access token returns the authenticated user."""
    access_token = registered_user["access_token"]
    email = registered_user["user"]["email"]

    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200, response.text

    user = response.json()
    assert user["email"] == email
    assert "id" in user
    assert "hashed_password" not in user


# ── 8. GET /auth/me with invalid token ──────────────────────────


async def test_me_with_invalid_token(client: AsyncClient) -> None:
    """GET /auth/me with a garbage token returns 401."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer this.is.not.a.real.jwt"},
    )
    assert response.status_code == 401


# ── 9. Refresh token → new access token ─────────────────────────


async def test_refresh_token(client: AsyncClient, registered_user: dict) -> None:
    """A valid refresh token can be exchanged for a new access token."""
    refresh_token = registered_user["refresh_token"]

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200, response.text

    body = response.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    # Refresh endpoint should NOT return a refresh_token in its response
    assert "refresh_token" not in body

    # The new access token should work for /auth/me
    me_response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert me_response.status_code == 200


# ── 10. Access token rejected as refresh token ──────────────────


async def test_access_token_rejected_as_refresh(
    client: AsyncClient, registered_user: dict
) -> None:
    """Submitting an access token to /auth/refresh returns 401 (wrong type)."""
    access_token = registered_user["access_token"]

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": access_token},
    )
    assert response.status_code == 401


# ── 11. Profile update (PATCH /auth/me) ──────────────────────────


async def test_update_profile_success(
    client: AsyncClient, registered_user: dict
) -> None:
    """Authenticated user can update their display name and avatar."""
    token = registered_user["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = await client.patch(
        "/api/v1/auth/me",
        headers=headers,
        json={"name": "Alice Wonderland", "avatar": "https://example.com/avatar.png"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "Alice Wonderland"
    assert body["avatar"] == "https://example.com/avatar.png"
    assert body["email"] == registered_user["user"]["email"]

    # Verify persistent change via GET /auth/me
    get_res = await client.get("/api/v1/auth/me", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "Alice Wonderland"


async def test_update_profile_unauthenticated(client: AsyncClient) -> None:
    """Unauthenticated profile update returns 401."""
    response = await client.patch(
        "/api/v1/auth/me",
        json={"name": "Hacker"},
    )
    assert response.status_code == 401


# ── 12. Password change (POST /auth/change-password) ─────────────


async def test_change_password_success(
    client: AsyncClient, registered_user: dict
) -> None:
    """Authenticated user can change password and log in with new password."""
    token = registered_user["access_token"]
    email = registered_user["user"]["email"]
    headers = {"Authorization": f"Bearer {token}"}

    # Change password
    res = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "current_password": "TestPass123!",
            "new_password": "BrandNewPass2@",
        },
    )
    assert res.status_code == 200, res.text
    assert "message" in res.json()

    # Login with old password must fail
    old_login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "TestPass123!"},
    )
    assert old_login.status_code == 401

    # Login with new password must succeed
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "BrandNewPass2@"},
    )
    assert new_login.status_code == 200


async def test_change_password_wrong_current(
    client: AsyncClient, registered_user: dict
) -> None:
    """Wrong current password returns 401."""
    token = registered_user["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "current_password": "WrongPassword1!",
            "new_password": "BrandNewPass2@",
        },
    )
    assert res.status_code == 401


async def test_change_password_weak_new(
    client: AsyncClient, registered_user: dict
) -> None:
    """Weak new password fails schema validation with 422."""
    token = registered_user["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "current_password": "TestPass123!",
            "new_password": "weak",
        },
    )
    assert res.status_code == 422


async def test_change_password_same_as_current(
    client: AsyncClient, registered_user: dict
) -> None:
    """Attempting to set the identical password returns 400."""
    token = registered_user["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={
            "current_password": "TestPass123!",
            "new_password": "TestPass123!",
        },
    )
    assert res.status_code == 400


async def test_logout_success(client: AsyncClient) -> None:
    """POST /auth/logout acknowledges session termination with 200 OK."""
    res = await client.post("/api/v1/auth/logout")
    assert res.status_code == 200
    assert res.json()["message"] == "Logged out successfully."


