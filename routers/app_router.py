from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import *
from db.deps import get_db
from services import AppService
from utils import get_current_user


router = APIRouter(prefix="/app", tags=["App"])


def get_app_service(db: AsyncSession = Depends(get_db)) -> AppService:
    return AppService(db)


"""=== Departments ==="""

@router.get("/departments", response_model=DepartmentsResponse)
async def get_departments(service: AppService = Depends(get_app_service)):
    return await service.get_departments()