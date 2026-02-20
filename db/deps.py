from fastapi import Request
from db.session import SessionLocal


async def get_db():
    async with SessionLocal() as session:
        yield session

async def get_redis_client(request: Request):
    return request.app.state.redis