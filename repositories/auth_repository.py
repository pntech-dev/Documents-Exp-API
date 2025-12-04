import logging
from models import User
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class AuthRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    
    async def get_user_by_id(self, user_id: str) -> User | None:
        """
        Return User by id or None
        """

        query = select(User).where(User.id == user_id)
        result = await self._execute_user(query)

        return result
    

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