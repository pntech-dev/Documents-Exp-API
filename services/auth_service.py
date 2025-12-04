from sqlalchemy.ext.asyncio import AsyncSession

from repositories import AuthRepository


class AuthService:
    def __init__(self, db: AsyncSession):
        self.repo = AuthRepository(db)