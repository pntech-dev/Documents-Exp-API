from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from db.deps import get_db
from services import AuthService
from schemas import UserSignUp, UserSignUpResponse


router = APIRouter(prefix="/auth", tags=["Auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)


@router.post("/signup", response_model=UserSignUpResponse)
async def signup(
    data: UserSignUp,
    service: AuthService = Depends(get_auth_service),
):
    return await service.register_new_user(data=data)