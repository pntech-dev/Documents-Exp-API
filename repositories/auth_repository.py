import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import User, RefreshToken


class AuthRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    
    async def get_user_by_id(self, user_id: int) -> User | None:
        """Return User by id or None"""

        query = select(User).where(User.id == user_id)
        result = await self.session.execute(query)

        return result.scalar_one_or_none()
    

    async def get_user_by_username(self, username: str) -> User | None:
        """Return User by username or None"""

        query = select(User).where(User.username == username)
        result = await self.session.execute(query)

        return result.scalar_one_or_none()
    

    async def get_user_by_email(self, email: str) -> User | None:
        """Return User by email or None"""

        query = select(User).where(User.email == email)
        result = await self.session.execute(query)

        return result.scalar_one_or_none()
    

    async def create_user(self, user: User) -> User:
        """Create new user in db"""

        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)

        return user
    
 
    # === Refresh token ===

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        """Return refresh token or None"""

        query = select(RefreshToken).where(RefreshToken.token == token)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    

    async def get_active_token(self, token: str) -> RefreshToken | None:
        """Return active refresh token or None"""
        
        query = select(RefreshToken).where(
            RefreshToken.token == token,
            RefreshToken.used == False
        )

        result = await self.session.execute(query)
        
        return result.scalar_one_or_none()


    async def save_refresh_token(self, refresh_token: RefreshToken) -> RefreshToken:
        """Save refresh token in db"""

        self.session.add(refresh_token)
        await self.session.commit()
        await self.session.refresh(refresh_token)

        return refresh_token
    

    async def invalidate(self, token: RefreshToken):
        token.used = True
        await self.session.commit()