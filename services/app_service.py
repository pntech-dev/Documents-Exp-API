from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from repositories import AppRepository
from schemas import (
    SearchResponse,
    DepartmentResponse, DepartmentsResponse,
    DepartmentCreateSchema, DepartmentUpdate,
    CategoryResponse, CategoriesResponse,
    CategoryCreateSchema,
    DocumentResponse, DocumentsResponse,
    DocumentUpdateSchema, DocumentCreateSchema,
    PageResponse, PagesResponse
)
from models import Page



class AppService:
    def __init__(self, db: AsyncSession) -> None:
        self.repo = AppRepository(db)


    async def search_in_category(
            self, 
            category_id: int, 
            query: str
    ) -> SearchResponse:
        query_words = query.split()
        
        documents = await self.repo.search_documents(category_id=category_id, query_words=query_words)
        pages = await self.repo.search_pages(category_id=category_id, query_words=query_words)

        search_results = []

        for document in documents:
            search_results.append(DocumentResponse.model_validate(document).model_dump())
        
        for page in pages:
            search_results.append(PageResponse.model_validate(page).model_dump())

        return SearchResponse(result=search_results)


    # ====================
    # Departments
    # ====================

    async def get_groups(self) -> DepartmentsResponse:
        groups = await self.repo.get_groups()
        return DepartmentsResponse(
            departments=[DepartmentResponse.model_validate(g) for g in groups]
        )
    
    
    async def create_group(self, data: DepartmentCreateSchema) -> DepartmentResponse:
        group = await self.repo.get_group_by_name(name=data.name)
        if group:
            raise HTTPException(status_code=400, detail="Group already exists")
        
        group = await self.repo.create_group(group_data=data.model_dump())
        return DepartmentResponse.model_validate(group)
    

    async def update_group(self, id: int, data: DepartmentUpdate) -> DepartmentResponse:
        group = await self.repo.get_group_by_id(id=id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        group.name = data.name
        await self.repo.save_group(group=group)

        return DepartmentResponse.model_validate(group)
    

    async def delete_group(self, id: int) -> dict:
        group = await self.repo.get_group_by_id(id=id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        for category in group.categories:
            for document in category.documents:
                await self.delete_document(id=document.id)
            await self.repo.delete_category(category=category)

        await self.repo.delete_group(group=group)

        return {"detail": "Group deleted"}


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
    

    async def create_category(self, data: CategoryCreateSchema) -> CategoryResponse:
        category = await self.repo.get_category_by_data(name=data.name, group_id=data.group_id)
        if category:
            raise HTTPException(status_code=400, detail="Category already exists")

        category = await self.repo.create_category(category_data=data.model_dump())

        return CategoryResponse.model_validate(category)
    

    async def update_category(self, id: int, data: CategoryCreateSchema) -> CategoryResponse:
        category = await self.repo.get_category(id=id)
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")
        
        category.name = data.name
        await self.repo.save_category(category=category)

        return CategoryResponse.model_validate(category)
    

    async def delete_category(self, id: int) -> dict:
        category = await self.repo.get_category(id=id)
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")
        
        # Delete all documents in category
        documents = await self.repo.get_category_documents(category_id=id)
        for document in documents:
            await self.delete_document(id=document.id)
        
        # Delete category
        await self.repo.delete_category(category=category)

        return {"detail": "Category deleted"}


    # ====================
    # Documents
    # ====================

    async def get_documents(self) -> DocumentsResponse:
        documents = await self.repo.get_documents()
        return DocumentsResponse(
            documents=[DocumentResponse.model_validate(d) for d in documents]
        )
    

    async def create_document(self, data: DocumentCreateSchema) -> DocumentResponse:
        document = await self.repo.get_document_by_data(
            name=data.name, 
            code=data.code,
            category_id=data.category_id
        )
        if document:
            raise HTTPException(status_code=400, detail="Document already exists")
        
        # Create document
        document_data = data.model_dump(exclude={"pages"})
        document = await self.repo.create_document(document_data=document_data)

        if data.pages:
            for page_data in data.pages:
                page = Page(
                    document_id=document.id,
                    order_index=page_data.order_index,
                    designation=page_data.designation,
                    name=page_data.name
                )
                await self.repo.save_page(page)
        
        return DocumentResponse.model_validate(document)

    
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