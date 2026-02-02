from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Group


class AppRepository:
    def __init__(self, session: AsyncSession):
        self.session = session


    async def get_departments(self) -> list[Group]:
        query = select(Group)
        departments = await self.session.execute(query)
        return departments.scalars().all()