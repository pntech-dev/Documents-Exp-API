from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from models import Group, Category


class AppRepository:
    def __init__(self, session: AsyncSession):
        self.session = session
    

    """=== Departments ==="""

    async def get_groups(self) -> list[Group]:
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        )
        departments = await self.session.execute(query)
        return departments.scalars().all()
    

    async def get_group_categories(self, group_id: int) -> list[Category]:
        query = select(Category).options(selectinload(Category.documents)).where(
            Category.group_id == group_id
        )
        categories = await self.session.execute(query)
        return categories.scalars().all()
    

    """=== Categories ==="""

    async def get_category(self, id: int) -> Category:
        query = select(Category).options(selectinload(Category.documents)).where(Category.id == id)
        category = await self.session.execute(query)
        return category.scalar_one_or_none()


    async def get_categories(self) -> list[Category]:
        query = select(Category).options(selectinload(Category.documents))
        categories = await self.session.execute(query)
        return categories.scalars().all()