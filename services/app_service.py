from sqlalchemy.ext.asyncio import AsyncSession

from schemas import DepartmentsResponse
from repositories import AppRepository


class AppService:
    def __init__(self, db: AsyncSession) -> None:
        self.repo = AppRepository(db)

    async def get_departments(self) -> DepartmentsResponse:
        departments = await self.repo.get_departments()
        return DepartmentsResponse(departments=departments)