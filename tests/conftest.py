import pytest
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool
from unittest.mock import AsyncMock, MagicMock

from main import app
from db.base import Base
from db.deps import get_db, get_redis_client

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = async_sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
async def close_engine():
    """Closes the engine after each test to ensure the process terminates correctly."""
    yield
    await engine.dispose()


@pytest.fixture(autouse=True)
def mock_external_services(mocker):
    """Mock Redis and disable email domain whitelist."""
    mock_redis = MagicMock()
    mocker.patch("redis.asyncio.from_url", return_value=mock_redis)
    mocker.patch("fastapi_limiter.FastAPILimiter.init", return_value=None)
    mocker.patch("services.auth_service.settings.ALLOWED_EMAIL_DOMAINS", [])


@pytest.fixture(autouse=True)
def mock_resend(mocker):
    """Global mock for sending emails via Resend."""
    mock_send = mocker.patch("services.auth_service.resend.Emails.send")
    mock_send.return_value = {"id": "mock_email_id"}
    return mock_send


@pytest.fixture()
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Creates DB schema before test and drops it after.
    The same session is used in both the test and the HTTP client.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestingSessionLocal() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture()
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client with overridden DB, Redis, and RateLimiter dependencies."""

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    async def override_get_redis():
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        mock_redis.delete.return_value = True
        return mock_redis

    async def noop_rate_limiter():
        return None

    from routers.auth_router import rate_limit_default, rate_limit_strict

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis_client] = override_get_redis
    app.dependency_overrides[rate_limit_default] = noop_rate_limiter
    app.dependency_overrides[rate_limit_strict] = noop_rate_limiter

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

    app.dependency_overrides.clear()