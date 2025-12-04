from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=True, future=True)

SessionLocal = async_sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)