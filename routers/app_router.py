from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import *
from db.deps import get_db
from services import AppService
from utils import get_current_user


router = APIRouter(prefix="/app", tags=["App"])


def get_app_service(db: AsyncSession = Depends(get_db)) -> AppService:
    return AppService(db)


"""=== Groups ==="""

@router.get("/groups", response_model=DepartmentsResponse)
async def get_groups(service: AppService = Depends(get_app_service)):
    return await service.get_groups()


@router.get("/groups/{group_id}/categories", response_model=CategoriesResponse)
async def get_group_categories(
    group_id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.get_group_categories(group_id=group_id)



"""=== Categories ==="""

@router.get("/category/{id}", response_model=CategoryResponse)
async def get_category(
    id: int,
    service: AppService = Depends(get_app_service)
):
    return await service.get_category(id=id)


@router.get("/categories", response_model=CategoriesResponse)
async def get_categories(service: AppService = Depends(get_app_service)):
    return await service.get_categories()