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


# ====================
# Pages
# ====================

@router.get("/pages", response_model=PagesResponse)
async def get_pages(service: AppService = Depends(get_app_service)):
    return await service.get_pages()


@router.get("/documents/{document_id}/pages", response_model=PagesResponse)
async def get_document_pages(
    document_id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.get_document_pages(document_id=document_id)