import logging
from models import User
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class AuthRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    
    async def get_user_by_id(self, user_id: int) -> User | None:
        """
        Return User by id or None
        """

        query = select(User).where(User.id == user_id)
        result = await self._execute_user(query)

        return result
    

    async def get_user_by_username(self, username: str) -> User | None:
        """
        Return User by username or None
        """

        query = select(User).where(User.username == username)
        result = await self._execute_user(query)

        return result
    

    async def get_user_by_email(self, email: str) -> User | None:
        """
        Return User by email or None
        """

        query = select(User).where(User.email == email)
        result = await self._execute_user(query)

        return result
    

    async def create_user(self, user: User) -> User:
        """
        Create new user in db
        """

        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)

        return user
    

    async def _execute_user(self, query) -> User | None:
        """
        Make a query to db and return User or None
        """
        
        try:
            result = await self.session.execute(query)
            user = result.scalar_one_or_none()

            if user is None:
                return None

            return user
        
        except Exception as e:
            logging.error(e)
            return None
