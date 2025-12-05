from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from db.deps import get_db
from services import AuthService
from schemas import UserSignUp, UserTokenResponse, UserLogin


router = APIRouter(prefix="/auth", tags=["Auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)


@router.post("/signup", response_model=UserTokenResponse)
async def signup(
    data: UserSignUp,
    service: AuthService = Depends(get_auth_service),
):
    return await service.signup(data=data)


@router.post("/login", response_model=UserTokenResponse)
async def login(
    data: UserLogin,
    service: AuthService = Depends(get_auth_service),
):
    return await service.login(data=data)