from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from repositories import AppRepository
from schemas import (
    DepartmentsResponse, DepartmentResponse,
    CategoriesResponse, CategoryResponse
)



class AppService:
    def __init__(self, db: AsyncSession) -> None:
        self.repo = AppRepository(db)


    """=== Departments ===="""

    async def get_groups(self) -> DepartmentsResponse:
        departments = await self.repo.get_groups()
        return DepartmentsResponse(
            departments=[DepartmentResponse.model_validate(d) for d in departments]
        )
    

    async def get_group_categories(self, group_id: int) -> CategoriesResponse:
        categories = await self.repo.get_group_categories(group_id=group_id)
        return CategoriesResponse(
            categories=[CategoryResponse.model_validate(c) for c in categories]
        )
    

    """=== Categories ===="""

    async def get_category(self, id: int) -> CategoryResponse:
        category = await self.repo.get_category(id=id)
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")

        return CategoryResponse.model_validate(category)
    

    async def get_categories(self) -> CategoriesResponse:
        categories = await self.repo.get_categories()
        return CategoriesResponse(
            categories=[CategoryResponse.model_validate(c) for c in categories]
        )