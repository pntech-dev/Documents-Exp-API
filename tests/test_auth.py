import pytest
import re
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import User
from utils import hash_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_code_from_mock(mock_resend: object) -> str:
    """Extracts OTP code from HTML passed to resend.Emails.send."""
    # Try positional args, then keyword args
    call_args = mock_resend.call_args
    params = call_args.args[0] if call_args.args else call_args.kwargs.get("params", {})
    html_content = params.get("html", "")
    match = re.search(r'<span class="code">(\d+)</span>', html_content)
    assert match is not None, (
        f"Could not find code in email HTML. HTML: {html_content!r}"
    )
    return match.group(1)


async def _create_active_user(
    db_session: AsyncSession, email: str, password: str
) -> User:
    hashed = hash_password(password)
    user = User(email=email, password_hash=hashed, is_active=True)
    db_session.add(user)
    await db_session.commit()
    return user


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_signup_flow(client: AsyncClient, db_session: AsyncSession, mock_resend):
    email = "newuser@example.com"
    password = "StrongPassword123!"

    # 1. Send verification code
    response = await client.post("/auth/signup/send-code", json={"email": email})
    assert response.status_code == 200, response.text
    assert mock_resend.called, "resend.Emails.send was not called"

    code = _extract_code_from_mock(mock_resend)

    # 2. Verify code and register
    response = await client.patch(
        "/auth/signup/verify-code",
        json={"email": email, "code": code, "password": password},
    )
    assert response.status_code == 200, response.text

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == email

    # Check for user existence in DB
    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    assert user is not None
    assert user.is_active is True


@pytest.mark.asyncio
async def test_login(client: AsyncClient, db_session: AsyncSession):
    email = "loginuser@example.com"
    password = "LoginPass123!"
    await _create_active_user(db_session, email, password)

    response = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == email


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, db_session: AsyncSession):
    email = "wrongpass@example.com"
    password = "CorrectPass123!"
    await _create_active_user(db_session, email, password)

    response = await client.post(
        "/auth/login", json={"email": email, "password": "WrongPassword!"}
    )
    assert response.status_code == 400, response.text


@pytest.mark.asyncio
async def test_refresh_token(client: AsyncClient, db_session: AsyncSession):
    email = "refresh@example.com"
    password = "Pass123!"
    await _create_active_user(db_session, email, password)

    # Login and get refresh_token
    login_res = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert login_res.status_code == 200, login_res.text
    refresh_token = login_res.json()["refresh_token"]

    # Refresh token
    response = await client.post(
        "/auth/token/refresh", json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200, response.text

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    # Rotation: new refresh_token must differ from the old one
    assert data["refresh_token"] != refresh_token


@pytest.mark.asyncio
async def test_password_reset_flow(
    client: AsyncClient, db_session: AsyncSession, mock_resend
):
    email = "reset@example.com"
    old_password = "OldPassword123!"
    new_password = "NewPassword123!"
    await _create_active_user(db_session, email, old_password)

    # 1. Password reset request
    response = await client.post(
        "/auth/forgot-password/request-reset", json={"email": email}
    )
    assert response.status_code == 200, response.text

    code = _extract_code_from_mock(mock_resend)

    # 2. Verify code
    response = await client.post(
        "/auth/forgot-password/confirm-email",
        json={"email": email, "code": code},
    )
    assert response.status_code == 200, response.text
    reset_token = response.json()["reset_token"]

    # 3. Set new password
    response = await client.patch(
        "/auth/forgot-password/reset-password",
        json={"reset_token": reset_token, "password": new_password},
    )
    assert response.status_code == 200, response.text

    # 4. Login with new password
    login_res = await client.post(
        "/auth/login", json={"email": email, "password": new_password}
    )
    assert login_res.status_code == 200, login_res.text

    # 5. Ensure old password no longer works
    old_login_res = await client.post(
        "/auth/login", json={"email": email, "password": old_password}
    )
    assert old_login_res.status_code == 400, old_login_res.text