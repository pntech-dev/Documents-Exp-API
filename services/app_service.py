from fastapi import HTTPException
import logging
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from repositories import AppRepository
from schemas import (
    SearchResponse,
    DepartmentResponse, DepartmentsResponse,
    DepartmentCreateSchema, DepartmentUpdate,
    CategoryResponse, CategoriesResponse,
    CategoryCreateSchema, CategoryUpdateSchema,
    DocumentResponse, DocumentsResponse,
    DocumentUpdateSchema, DocumentCreateSchema,
    PageResponse, PagesResponse
)
from models import Page


logger = logging.getLogger(__name__)

class AppService:
    """
    Service layer for application business logic.

    Handles operations related to groups (departments), categories,
    documents, and pages, including search functionality.
    """
    def __init__(self, db: AsyncSession, redis: Redis = None) -> None:
        self.repo = AppRepository(db)
        self.redis = redis


    async def search(
            self, 
            query: str,
            tags: list[str] | None = None,
            group_id: int | None = None,
            category_id: int | None = None,
            exact_match: bool = False,
            include_pages: bool = True,
            search_fields: list[str] = ["code", "name"],
            is_guest: bool = False
    ) -> SearchResponse:
        """
        Searches for documents and pages within a specific category or group.

        Args:
            query (str): The search query string.
            category_id (int | None): The ID of the category to search in.
            group_id (int | None): The ID of the group to search in.

        Returns:
            SearchResponse: A response object containing the search results.
        """
        # Clean tags: remove whitespace and empty strings just in case
        clean_tags = [
            tag.strip() for tag in tags if tag.strip()
        ] if tags else None

        # 1. Generate Cache Key
        tags_str = ",".join(sorted(clean_tags)) if clean_tags else "None"
        fields_str = ",".join(sorted(search_fields)) if search_fields else "None"
        cache_key = f"search:{query}:{tags_str}:{group_id}:{category_id}:{exact_match}:{include_pages}:{fields_str}:{is_guest}"

        # 2. Try Cache
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return SearchResponse.model_validate_json(cached_data)

        if not category_id and not group_id:
            raise HTTPException(
                status_code=400, 
                detail="Either category_id or group_id must be provided"
            )

        documents = await self.repo.search_documents(
            query=query, 
            category_id=category_id, 
            group_id=group_id, 
            tags=clean_tags,
            exact_match=exact_match,
            search_fields=search_fields,
            show_for_guest=is_guest
        )
        
        pages = []
        if include_pages and query.strip():
            pages = await self.repo.search_pages(
                query=query, 
                category_id=category_id, 
                group_id=group_id, 
                tags=clean_tags,
                exact_match=exact_match,
                search_fields=search_fields,
                show_for_guest=is_guest
            )

        search_results = []

        for document in documents:
            search_results.append(
                DocumentResponse.model_validate(document).model_dump()
            )
        
        for page in pages:
            search_results.append(
                PageResponse.model_validate(page).model_dump()
            )

        response = SearchResponse(result=search_results)

        # 3. Save Cache (Short TTL: 5 minutes = 300 seconds)
        await self._save_cache(cache_key, response, expire=300)

        return response


    # ====================
    # Departments
    # ====================

    async def get_groups(
            self, 
            limit: int | None, 
            offset: int, 
            is_guest: bool = False
    ) -> DepartmentsResponse:
        """
        Retrieves a list of groups (departments).

        Args:
            limit (int | None): The maximum number of groups to return.
            offset (int): The number of groups to skip.
            is_guest (bool): Whether the requester is a guest.

        Returns:
            DepartmentsResponse: A response object containing the list of groups.
        """
        # 1. Create a unique cache key
        cache_key = f"groups:{limit}:{offset}:{is_guest}"

        # 2. Get cached data from Redis (Cache Hit)
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return DepartmentsResponse.model_validate_json(cached_data)

        # 3. If havent found it - get it from DB (Cache Miss)
        groups = await self.repo.get_groups(
            limit=limit, 
            offset=offset, 
            show_for_guest=is_guest
        )
        response = DepartmentsResponse(
            departments=[DepartmentResponse.model_validate(g) for g in groups]
        )

        # 4. Save the result in Redis for one hour (3600 sec.)
        await self._save_cache(cache_key, response)
            
        return response
    

    async def create_group(
            self, 
            data: DepartmentCreateSchema
    ) -> DepartmentResponse:
        """
        Creates a new group (department).

        Args:
            data (DepartmentCreateSchema): The data for the new group.

        Returns:
            DepartmentResponse: The created group.

        Raises:
            HTTPException: If a group with the same name already exists.
        """
        group = await self.repo.get_group_by_name(name=data.name)
        if group:
            raise HTTPException(status_code=400, detail="Group already exists")
        
        group = await self.repo.create_group(
            name=data.name, 
            show_for_guest=data.show_for_guest,
            has_all_docs_search=data.has_all_docs_search
        )
        await self.repo.session.commit()
        await self._clear_cache(cache_key="groups:*")
        return DepartmentResponse.model_validate(group)
    

    async def update_group(
            self, 
            id: int, 
            data: DepartmentUpdate
    ) -> DepartmentResponse:
        """
        Updates an existing group.

        Args:
            id (int): The ID of the group to update.
            data (DepartmentUpdate): The new data for the group.

        Returns:
            DepartmentResponse: The updated group.

        Raises:
            HTTPException: If the group is not found.
        """
        group = await self.repo.get_group_by_id(id=id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        group.name = data.name
        group.show_for_guest = data.show_for_guest
        group.has_all_docs_search = data.has_all_docs_search
        await self.repo.save_group(group=group)
        await self.repo.session.commit()
        await self._clear_cache(cache_key="groups:*")

        return DepartmentResponse.model_validate(group)
    

    async def delete_group(self, id: int) -> dict:
        """
        Deletes a group and all its associated content (categories, documents, pages).

        Args:
            id (int): The ID of the group to delete.

        Returns:
            dict: A confirmation message.

        Raises:
            HTTPException: If the group is not found.
        """
        group = await self.repo.get_group_by_id(id=id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        
        # Bulk delete optimization
        category_ids = await self.repo.get_category_ids_by_group(group_id=id)
        if category_ids:
            document_ids = await self.repo.get_document_ids_by_categories(
                category_ids=category_ids
            )
            if document_ids:
                await self.repo.delete_pages_by_document_ids(
                    document_ids=document_ids
                )
                await self.repo.delete_documents_by_ids(
                    document_ids=document_ids
                )
            await self.repo.delete_categories_by_ids(category_ids=category_ids)

        await self.repo.delete_group(group=group)
        await self.repo.session.commit()
        await self._clear_cache(cache_key="groups:*")
        await self._clear_cache(cache_key="documents:*")
        await self._clear_cache(cache_key="search:*")
        await self._clear_cache(cache_key="pages:*")

        return {"detail": "Group deleted"}


    # ====================
    # Categories
    # ====================

    async def get_categories(
            self, 
            limit: int | None, 
            offset: int, 
            is_guest: bool = False
    ) -> CategoriesResponse:
        """
        Retrieves a list of all categories.

        Args:
            limit (int | None): The maximum number of categories to return.
            offset (int): The number of categories to skip.
            is_guest (bool): Whether the requester is a guest.

        Returns:
            CategoriesResponse: A response object containing the list of categories.
        """
        # 1. Create a unique cache key
        cache_key = f"categories:{limit}:{offset}:{is_guest}"

        # 2. Get cached data from Redis (Cache Hit)
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return CategoriesResponse.model_validate_json(cached_data)

        # 3. If havent found it - get it from DB (Cache Miss)
        categories = await self.repo.get_categories(
            limit=limit, 
            offset=offset, 
            show_for_guest=is_guest
        )

        response =  CategoriesResponse(
            categories=[CategoryResponse.model_validate(c) for c in categories]
        )

        # 4. Save the result in Redis for one hour (3600 sec.)
        await self._save_cache(cache_key, response)

        return response


    async def get_category(self, id: int) -> CategoryResponse:
        """
        Retrieves a specific category by ID.

        Args:
            id (int): The ID of the category.

        Returns:
            CategoryResponse: The requested category.

        Raises:
            HTTPException: If the category is not found.
        """
        # 1. Create a unique cache key
        cache_key = f"categories:{id}"

        # 2. Get cached data from Redis (Cache Hit)
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return CategoryResponse.model_validate_json(cached_data)

        # 3. If havent found it - get it from DB (Cache Miss)
        category = await self.repo.get_category(id=id)
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")

        response = CategoryResponse.model_validate(category)

        # 4. Save the result in Redis for one hour (3600 sec.)
        await self._save_cache(cache_key, response)

        return response


    async def get_group_categories(
            self, 
            group_id: int, 
            limit: int | None, 
            offset: int, 
            is_guest: bool = False
    ) -> CategoriesResponse:
        """
        Retrieves categories belonging to a specific group.

        Args:
            group_id (int): The ID of the group.
            limit (int | None): The maximum number of categories to return.
            offset (int): The number of categories to skip.
            is_guest (bool): Whether the requester is a guest.

        Returns:
            CategoriesResponse: A response object containing the list of categories.
        """
        # 1. Create a unique cache key
        cache_key = f"categories:{group_id}:{limit}:{offset}:{is_guest}"

        # 2. Get cached data from Redis (Cache Hit)
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return CategoriesResponse.model_validate_json(cached_data)

        # 3. If havent found it - get it from DB (Cache Miss)
        categories = await self.repo.get_group_categories(
            group_id=group_id, 
            limit=limit, 
            offset=offset, 
            show_for_guest=is_guest
        )
        response = CategoriesResponse(
            categories=[CategoryResponse.model_validate(c) for c in categories]
        )

        # 4. Save the result in Redis for one hour (3600 sec.)
        await self._save_cache(cache_key, response)

        return response
    

    async def create_category(self, data: CategoryCreateSchema) -> CategoryResponse:
        """
        Creates a new category within a group.

        Args:
            data (CategoryCreateSchema): The data for the new category.

        Returns:
            CategoryResponse: The created category.

        Raises:
            HTTPException: If a category with the same name already exists in the group.
        """
        category = await self.repo.get_category_by_data(name=data.name, group_id=data.group_id)
        if category:
            raise HTTPException(status_code=400, detail="Category already exists")

        category = await self.repo.create_category(
            name=data.name, 
            group_id=data.group_id,
            show_for_guest=data.show_for_guest,
        )
        await self.repo.session.commit()
        await self._clear_cache(cache_key="categories:*")

        return CategoryResponse.model_validate(category)
    

    async def update_category(
            self, id: int, 
            data: CategoryUpdateSchema
    ) -> CategoryResponse:
        """
        Updates an existing category.

        Args:
            id (int): The ID of the category to update.
            data (CategoryUpdateSchema): The new data for the category.

        Returns:
            CategoryResponse: The updated category.

        Raises:
            HTTPException: If the category is not found.
        """
        category = await self.repo.get_category(id=id)
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")
        
        category.name = data.name
        category.show_for_guest = data.show_for_guest
        await self.repo.save_category(category=category)
        await self.repo.session.commit()
        await self._clear_cache(cache_key="categories:*")

        return CategoryResponse.model_validate(category)
    

    async def delete_category(self, id: int) -> dict:
        """
        Deletes a category and all its associated documents and pages.

        Args:
            id (int): The ID of the category to delete.

        Returns:
            dict: A confirmation message.

        Raises:
            HTTPException: If the category is not found.
        """
        category = await self.repo.get_category(id=id)
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")
        
        # Bulk delete optimization
        document_ids = await self.repo.get_document_ids_by_categories(category_ids=[id])
        if document_ids:
            await self.repo.delete_pages_by_document_ids(document_ids=document_ids)
            await self.repo.delete_documents_by_ids(document_ids=document_ids)

        # Delete category
        await self.repo.delete_category(category=category)
        await self.repo.session.commit()
        await self._clear_cache(cache_key="categories:*")
        await self._clear_cache(cache_key="documents:*")
        await self._clear_cache(cache_key="search:*")
        await self._clear_cache(cache_key="pages:*")

        return {"detail": "Category deleted"}


    # ====================
    # Documents
    # ====================

    async def get_documents(
        self, 
        limit: int | None, 
        offset: int,
        category_id: int | None = None,
        group_id: int | None = None,
        is_guest: bool = False
    ) -> DocumentsResponse:
        """
        Retrieves a list of all documents.

        Args:
            limit (int | None): The maximum number of documents to return.
            offset (int): The number of documents to skip.
            category_id (int | None): Filter by category ID.
            group_id (int | None): Filter by group ID.

        Returns:
            DocumentsResponse: A response object containing the list of documents.
        """
        # 1. Create a unique cache key
        cache_key = f"documents:{limit}:{offset}:{category_id}:{group_id}:{is_guest}"

        # 2. Get cached data from Redis (Cache Hit)
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return DocumentsResponse.model_validate_json(cached_data)

        # 3. If havent found it - get it from DB (Cache Miss)
        documents = await self.repo.get_documents(
            limit=limit, 
            offset=offset, 
            category_id=category_id,
            group_id=group_id,
            show_for_guest=is_guest
        )
        response = DocumentsResponse(
            documents=[DocumentResponse.model_validate(d) for d in documents]
        )

        # 4. Save the result in Redis for one hour (3600 sec.)
        await self._save_cache(cache_key, response)

        return response
    
    async def get_document(self, id: int) -> DocumentResponse:
        """
        Retrieves a specific document by ID.

        Args:
            id (int): The ID of the document.

        Returns:
            DocumentResponse: The requested document.

        Raises:
            HTTPException: If the document is not found.
        """
        # 1. Create a unique cache key
        cache_key = f"documents:{id}"

        # 2. Get cached data from Redis (Cache Hit)
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return DocumentResponse.model_validate_json(cached_data)

        # 3. If havent found it - get it from DB (Cache Miss)
        document = await self.repo.get_document(id=id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        response = DocumentResponse.model_validate(document)

        # 4. Save the result in Redis for one hour (3600 sec.)
        await self._save_cache(cache_key, response)

        return response

    async def create_document(self, data: DocumentCreateSchema) -> DocumentResponse:
        """
        Creates a new document with optional pages.

        Args:
            data (DocumentCreateSchema): The data for the new document.

        Returns:
            DocumentResponse: The created document.

        Raises:
            HTTPException: If a document with the same name and code already exists in the category.
        """
        document = await self.repo.get_document_by_data(
            name=data.name, 
            code=data.code,
            category_id=data.category_id
        )
        if document:
            raise HTTPException(status_code=400, detail="Document already exists")
        
        # Handle tags
        tags = []
        if data.tags:
            tags = await self.repo.get_or_create_tags(data.tags)

        # Create document
        document = await self.repo.create_document(
            name=data.name,
            code=data.code,
            category_id=data.category_id,
            tags=tags
        )

        if data.pages:
            for page_data in data.pages:
                page = Page(
                    document_id=document.id,
                    order_index=page_data.order_index,
                    designation=page_data.designation,
                    name=page_data.name
                )
                await self.repo.save_page(page)
        
        await self.repo.session.commit()
        await self._clear_cache(cache_key="documents:*")
        await self._clear_cache(cache_key="search:*")
        await self._clear_cache(cache_key="pages:*")

        return DocumentResponse.model_validate(document)

    
    async def update_document(self, id: int, data: DocumentUpdateSchema) -> DocumentResponse:
        """
        Updates an existing document and its pages.

        Args:
            id (int): The ID of the document to update.
            data (DocumentUpdateSchema): The new data for the document and pages.

        Returns:
            DocumentResponse: The updated document.

        Raises:
            HTTPException: If the document is not found.
        """
        # Save document data
        document = await self.repo.get_document(id=id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        document.code = data.code or document.code
        document.name = data.name or document.name

        # Update tags if provided
        if data.tags is not None:
            tags = await self.repo.get_or_create_tags(data.tags)
            document.tags = tags

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

        await self.repo.session.commit()
        await self._clear_cache(cache_key="documents:*")
        await self._clear_cache(cache_key="search:*")
        await self._clear_cache(cache_key="pages:*")

        return DocumentResponse.model_validate(document)
    

    async def delete_document(self, id: int) -> dict:
        """
        Deletes a document and all its pages.

        Args:
            id (int): The ID of the document to delete.

        Returns:
            dict: A confirmation message.

        Raises:
            HTTPException: If the document is not found.
        """
        document = await self.repo.get_document(id=id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        # Bulk delete pages
        await self.repo.delete_pages_by_document_ids(document_ids=[id])
        # Delete document
        await self.repo.delete_document(document=document)
        await self.repo.session.commit()
        await self._clear_cache(cache_key="documents:*")
        await self._clear_cache(cache_key="search:*")
        await self._clear_cache(cache_key="pages:*")

        return {"detail": "Document deleted"}
    

    # ====================
    # Pages
    # ====================

    async def get_pages(self, limit: int | None, offset: int) -> PagesResponse:
        """
        Retrieves a list of all pages.

        Args:
            limit (int | None): The maximum number of pages to return.
            offset (int): The number of pages to skip.

        Returns:
            PagesResponse: A response object containing the list of pages.
        """
        # 1. Cache Key
        cache_key = f"pages:list:{limit}:{offset}"

        # 2. Try Cache
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return PagesResponse.model_validate_json(cached_data)

        pages = await self.repo.get_pages(limit=limit, offset=offset)
        response = PagesResponse(
            pages=[PageResponse.model_validate(p) for p in pages]
        )
        await self._save_cache(cache_key, response)
        return response
    
    async def get_page(self, id: int) -> PageResponse:
        """
        Retrieves a specific page by ID.

        Args:
            id (int): The ID of the page.

        Returns:
            PageResponse: The requested page.

        Raises:
            HTTPException: If the page is not found.
        """
        # 1. Cache Key
        cache_key = f"pages:{id}"

        # 2. Try Cache
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return PageResponse.model_validate_json(cached_data)

        page = await self.repo.get_page(id=id)
        if not page:
            raise HTTPException(status_code=404, detail="Page not found")
        
        response = PageResponse.model_validate(page)
        await self._save_cache(cache_key, response)
        return response
    

    async def get_document_pages(self, document_id: int, limit: int | None, offset: int) -> PagesResponse:
        """
        Retrieves pages belonging to a specific document.

        Args:
            document_id (int): The ID of the document.
            limit (int | None): The maximum number of pages to return.
            offset (int): The number of pages to skip.

        Returns:
            PagesResponse: A response object containing the list of pages.
        """
        # 1. Cache Key
        cache_key = f"pages:doc:{document_id}:{limit}:{offset}"

        # 2. Try Cache
        cached_data = await self._get_cache(cache_key)
        if cached_data:
            return PagesResponse.model_validate_json(cached_data)

        pages = await self.repo.get_document_pages(document_id=document_id, limit=limit, offset=offset)
        response = PagesResponse(
            pages=[PageResponse.model_validate(p) for p in pages]
        )
        await self._save_cache(cache_key, response)
        return response
    

    # ====================
    # Service methods
    # ====================


    async def _get_cache(self, cache_key: str) -> Any | None:
            """Helper to get cached data"""
            if not self.redis:
                return None
            
            try:
                cached_data = await self.redis.get(cache_key)
                return cached_data
            except Exception as e:
                logger.error(f"Redis error on get key {cache_key}: {e}")
            return None
    

    async def _save_cache(self, cache_key: str, data_to_save: Any, expire: int = 3600) -> None:
            """Helper to save cached data"""
            if not self.redis:
                return
            
            try:
                await self.redis.set(cache_key, data_to_save.model_dump_json(), ex=expire)
            except Exception as e:
                logger.error(f"Redis error on set key {cache_key}: {e}")


    async def _clear_cache(self, cache_key: str):
        """Helper to clear all related cache keys"""
        if not self.redis:
            return
        
        try:
            # Find all keys starting with cache_key using scan_iter (non-blocking)
            # Using match=cache_key explicitly is safer
            keys = [key async for key in self.redis.scan_iter(match=cache_key)]
            if keys:
                await self.redis.delete(*keys)
        except Exception as e:
            logger.error(f"Redis error on clear pattern {cache_key}: {e}")