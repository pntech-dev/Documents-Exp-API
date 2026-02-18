from fastapi import APIRouter, Depends, Query
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt, JWTError
from fastapi_limiter import FastAPILimiter
from redis.asyncio import Redis

from schemas import *
from db.deps import get_db
from services import AppService
from utils import get_current_user
from core.config import settings
from repositories import AuthRepository


router = APIRouter(prefix="/app", tags=["App"])


async def get_redis() -> Redis:
    return FastAPILimiter.redis


def get_app_service(db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis)) -> AppService:
    return AppService(db, redis)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

async def get_optional_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> UserResponse | None:
    """
    Returns the current user if the token is valid, otherwise returns None.
    Does not raise 401 error.
    """
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None
    
    repo = AuthRepository(db)
    user = await repo.get_user_by_id(int(user_id))
    if not user:
        return None
    return UserResponse.model_validate(user)


# ====================
# Search
# ====================

@router.get("/search", response_model=SearchResponse)
async def search(
    query: str,
    tags: list[str] | None = Query(None),
    group_id: int | None = Query(None),
    category_id: int | None = Query(None),
    exact_match: bool = False,
    include_pages: bool = True,
    search_fields: list[str] = Query(default=["code", "name"]),
    user: UserResponse | None = Depends(get_optional_current_user),
    service: AppService = Depends(get_app_service)
):
    """
    Searches for documents and pages within a specific category or group.
    """
    is_guest = user is None
    return await service.search(
        query=query, 
        tags=tags,
        group_id=group_id, 
        category_id=category_id, 
        exact_match=exact_match, 
        include_pages=include_pages, 
        search_fields=search_fields,
        is_guest=is_guest
    )


# ====================
# Departments
# ====================

@router.get("/groups", response_model=DepartmentsResponse)
async def get_groups(
    offset: int = 0,
    limit: int | None = None,
    user: UserResponse | None = Depends(get_optional_current_user),
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves a list of groups (departments).
    """
    is_guest = user is None
    return await service.get_groups(limit=limit, offset=offset, is_guest=is_guest)


@router.post("/groups", response_model=DepartmentResponse)
async def create_group(
    data: DepartmentCreateSchema,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Creates a new group (department).
    """
    return await service.create_group(data=data)


@router.patch("/groups/{id}", response_model=DepartmentResponse)
async def update_group(
    id: int,
    data: DepartmentUpdate,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Updates an existing group.
    """
    return await service.update_group(id=id, data=data)


@router.delete("/groups/{id}")
async def delete_group(
    id: int,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Deletes a group and all its associated content.
    """
    return await service.delete_group(id=id)


# ====================
# Categories
# ====================

@router.get("/categories", response_model=CategoriesResponse)
async def get_categories(
    offset: int = 0,
    limit: int | None = None,
    user: UserResponse | None = Depends(get_optional_current_user),
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves a list of all categories.
    """
    is_guest = user is None
    return await service.get_categories(limit=limit, offset=offset, is_guest=is_guest)


@router.get("/categories/{id}", response_model=CategoryResponse)
async def get_category(
    id: int,
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves a specific category by ID.
    """
    return await service.get_category(id=id)


@router.get("/groups/{group_id}/categories", response_model=CategoriesResponse)
async def get_group_categories(
    group_id: int,
    offset: int = 0,
    limit: int | None = None,
    user: UserResponse | None = Depends(get_optional_current_user),
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves categories belonging to a specific group.
    """
    is_guest = user is None
    return await service.get_group_categories(
        group_id=group_id, 
        limit=limit, 
        offset=offset,
        is_guest=is_guest
    )


@router.post("/categories", response_model=CategoryResponse)
async def create_category(
    data: CategoryCreateSchema,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Creates a new category.
    """
    return await service.create_category(data=data)


@router.patch("/categories/{id}", response_model=CategoryResponse)
async def update_category(
    id: int,
    data: CategoryUpdateSchema,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Updates an existing category.
    """
    return await service.update_category(id=id, data=data)


@router.delete("/categories/{id}")
async def delete_category(
    id: int,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Deletes a category.
    """
    return await service.delete_category(id=id)


# ====================
# Documents
# ====================

@router.get("/documents", response_model=DocumentsResponse)
async def get_documents(
    offset: int = 0,
    limit: int | None = None,
    category_id: int | None = None,
    group_id: int | None = Query(None),
    user: UserResponse | None = Depends(get_optional_current_user),
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves a list of documents. Can be filtered by category or group.
    """
    is_guest = user is None
    return await service.get_documents(
        limit=limit, 
        offset=offset,
        category_id=category_id,
        group_id=group_id,
        is_guest=is_guest
    )


@router.get("/documents/{id}", response_model=DocumentResponse)
async def get_document(
    id: int,
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves a specific document by ID.
    """
    return await service.get_document(id=id)


@router.post("/documents", response_model=DocumentResponse)
async def create_document(
    data: DocumentCreateSchema,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Creates a new document.
    """
    return await service.create_document(data=data)


@router.patch("/documents/{id}", response_model=DocumentResponse)
async def update_document(
    id: int,
    data: DocumentUpdateSchema,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Updates an existing document.
    """
    return await service.update_document(id=id, data=data)


@router.delete("/documents/{id}")
async def delete_document(
    id: int,
    service: AppService = Depends(get_app_service),
    user: UserResponse = Depends(get_current_user)
):
    """
    Deletes a document.
    """
    return await service.delete_document(id=id)


# ====================
# Pages
# ====================

@router.get("/pages", response_model=PagesResponse)
async def get_pages(
    offset: int = 0,
    limit: int | None = None,
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves a list of all pages.
    """
    return await service.get_pages(limit=limit, offset=offset)


@router.get("/pages/{id}", response_model=PageResponse)
async def get_page(
    id: int,
    service: AppService = Depends(get_app_service)
    ):
    """
    Retrieves a specific page by ID.
    """
    return await service.get_page(id=id)


@router.get("/documents/{document_id}/pages", response_model=PagesResponse)
async def get_document_pages(
    document_id: int,
    offset: int = 0,
    limit: int | None = None,
    service: AppService = Depends(get_app_service)
):
    """
    Retrieves pages belonging to a specific document.
    """
    return await service.get_document_pages(
        document_id=document_id, 
        limit=limit, 
        offset=offset
    )