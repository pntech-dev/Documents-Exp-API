from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from repositories import AppRepository
from schemas import (
    DepartmentResponse, DepartmentsResponse,
    CategoryResponse, CategoriesResponse,
    DocumentResponse, DocumentsResponse,
    PageResponse, PagesResponse
)



class AppService:
    def __init__(self, db: AsyncSession) -> None:
        self.repo = AppRepository(db)


    # ====================
    # Departments
    # ====================

    async def get_groups(self) -> DepartmentsResponse:
        groups = await self.repo.get_groups()
        return DepartmentsResponse(
            departments=[DepartmentResponse.model_validate(g) for g in groups]
        )


    # ====================
    # Categories
    # ====================

    async def get_categories(self) -> CategoriesResponse:
        categories = await self.repo.get_categories()
        return CategoriesResponse(
            categories=[CategoryResponse.model_validate(c) for c in categories]
        )

    async def get_category(self, id: int) -> CategoryResponse:
        category = await self.repo.get_category(id=id)
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")

        return CategoryResponse.model_validate(category)


    async def get_group_categories(self, group_id: int) -> CategoriesResponse:
        categories = await self.repo.get_group_categories(group_id=group_id)
        return CategoriesResponse(
            categories=[CategoryResponse.model_validate(c) for c in categories]
        )


    # ====================
    # Documents
    # ====================

    async def get_documents(self) -> DocumentsResponse:
        documents = await self.repo.get_documents()
        return DocumentsResponse(
            documents=[DocumentResponse.model_validate(d) for d in documents]
        )
    

    # ====================
    # Pages
    # ====================

    async def get_pages(self) -> PagesResponse:
        pages = await self.repo.get_pages()
        return PagesResponse(
            pages=[PageResponse.model_validate(p) for p in pages]
        )
    

    async def get_document_pages(self, document_id: int) -> PagesResponse:
        pages = await self.repo.get_document_pages(document_id=document_id)
        return PagesResponse(
            pages=[PageResponse.model_validate(p) for p in pages]
        )