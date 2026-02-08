from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from repositories import AppRepository
from schemas import (
    DepartmentResponse, DepartmentsResponse,
    CategoryResponse, CategoriesResponse,
    DocumentResponse, DocumentsResponse,
    DocumentUpdateSchema,
    PageResponse, PagesResponse
)
from models import Page



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
    
    async def update_document(self, id: int, data: DocumentUpdateSchema) -> DocumentResponse:
        # Save document data
        document = await self.repo.get_document(id=id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        document.code = data.code or document.code
        document.name = data.name or document.name

        await self.repo.save_document(document=document)

        # Save document pages data
        if data.pages is not None:
            existing_pages = await self.repo.get_document_pages(document_id=id)
            existing_pages_map = {p.id: p for p in existing_pages}
            incoming_ids = set()

            for page_update in data.pages:
                if page_update.id:
                    incoming_ids.add(page_update.id)
                    if page_update.id in existing_pages_map:
                        page = existing_pages_map[page_update.id]
                        page.order_index = page_update.order_index
                        page.designation = page_update.designation
                        page.name = page_update.name
                        await self.repo.save_page(page)
                else:
                    page = Page(
                        document_id=id,
                        order_index=page_update.order_index,
                        designation=page_update.designation,
                        name=page_update.name
                    )
                    await self.repo.save_page(page)
            
            # Delete pages that are missing in the incoming data
            for page in existing_pages:
                if page.id not in incoming_ids:
                    await self.repo.delete_page(page)

        return DocumentResponse.model_validate(document)
    

    async def delete_document(self, id: int) -> dict:
        document = await self.repo.get_document(id=id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        # Delete document pages
        pages = await self.repo.get_document_pages(document_id=id)
        for page in pages:
            await self.repo.delete_page(page=page)
        
        # Delete document
        await self.repo.delete_document(document=document)

        return {"detail": "Document deleted"}
    

    # ====================
    # Pages
    # ====================

    async def get_pages(self) -> PagesResponse:
        pages = await self.repo.get_pages()
        return PagesResponse(
            pages=[PageResponse.model_validate(p) for p in pages]
        )
    
    async def get_page(self, id: int) -> PageResponse:
        page = await self.repo.get_page(id=id)
        if not page:
            raise HTTPException(status_code=404, detail="Page not found")
        
        return PageResponse.model_validate(page)
    

    async def get_document_pages(self, document_id: int) -> PagesResponse:
        pages = await self.repo.get_document_pages(document_id=document_id)
        return PagesResponse(
            pages=[PageResponse.model_validate(p) for p in pages]
        )