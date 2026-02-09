from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import *
from db.deps import get_db
from services import AppService
from utils import get_current_user


router = APIRouter(prefix="/app", tags=["App"])


def get_app_service(db: AsyncSession = Depends(get_db)) -> AppService:
    return AppService(db)


# ====================
# Departments
# ====================

@router.get("/groups", response_model=DepartmentsResponse)
async def get_groups(service: AppService = Depends(get_app_service)):
    return await service.get_groups()


@router.post("/groups", response_model=DepartmentResponse)
async def create_group(
    data: DepartmentCreateSchema,
    service: AppService = Depends(get_app_service)
):
    return await service.create_group(data=data)


@router.patch("/groups/{id}", response_model=DepartmentUpdate)
async def update_group(
    id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.update_group(id=id)


@router.delete("/groups/{id}")
async def delete_group(
    id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.delete_group(id=id)


# ====================
# Categories
# ====================

@router.get("/categories", response_model=CategoriesResponse)
async def get_categories(service: AppService = Depends(get_app_service)):
    return await service.get_categories()


@router.get("/categories/{id}", response_model=CategoryResponse)
async def get_category(
    id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.get_category(id=id)


@router.get("/groups/{group_id}/categories", response_model=CategoriesResponse)
async def get_group_categories(
    group_id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.get_group_categories(group_id=group_id)


@router.post("/categories", response_model=CategoryResponse)
async def create_category(
    data: CategoryCreateSchema,
    service: AppService = Depends(get_app_service)
):
    return await service.create_category(data=data)


@router.patch("/categories/{id}", response_model=CategoryResponse)
async def update_category(
    id: int,
    data: CategoryUpdateSchema,
    service: AppService = Depends(get_app_service)
):
    return await service.update_category(id=id, data=data)


@router.delete("/categories/{id}")
async def delete_category(
    id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.delete_category(id=id)


# ====================
# Documents
# ====================

@router.get("/documents", response_model=DocumentsResponse)
async def get_documents(service: AppService = Depends(get_app_service)):
    return await service.get_documents()


@router.patch("/documents/{id}", response_model=DocumentResponse)
async def update_document(
    id: int,
    data: DocumentUpdateSchema,
    service: AppService = Depends(get_app_service)
):
    return await service.update_document(id=id, data=data)


@router.delete("/documents/{id}")
async def delete_document(
    id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.delete_document(id=id)


# ====================
# Pages
# ====================

@router.get("/pages", response_model=PagesResponse)
async def get_pages(service: AppService = Depends(get_app_service)):
    return await service.get_pages()


@router.get("/pages/{id}", response_model=PageResponse)
async def get_page(
    id: int,
    service: AppService = Depends(get_app_service)
    ):
    return await service.get_page(id=id)


@router.get("/documents/{document_id}/pages", response_model=PagesResponse)
async def get_document_pages(
    document_id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.get_document_pages(document_id=document_id)