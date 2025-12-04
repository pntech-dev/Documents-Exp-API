from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from db.deps import get_db
from services import AuthService


router = APIRouter(prefix="/auth", tags=["Auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)