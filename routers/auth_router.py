from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from db.deps import get_db
from services import AuthService
from schemas import (
    UserSignUp, 
    UserTokenResponse, 
    UserLogin, 
    UserResponse, 
    RefreshTokenSchema, 
    ForgotPasswordSchema, 
    EmailConfirmSchema, 
    ChangePasswordSchema
)
from utils import get_current_user


router = APIRouter(prefix="/auth", tags=["Auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)


@router.get("/user", response_model=UserResponse)
async def get_user(
    service: AuthService = Depends(get_auth_service),
    current_user = Depends(get_current_user)
):
    return await service.get_user(user_id=current_user.id)


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


@router.post("/refresh", response_model=UserTokenResponse)
async def refresh(
    data: RefreshTokenSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.refresh_token(refresh_token=data.refresh_token)


# Password

@router.post("/forgot-password")
async def forgot_password(
    data: ForgotPasswordSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.forgot_password(data=data)


@router.post("/confirm-email")
async def confirm_email(
    data: EmailConfirmSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.confirm_email(data=data)


@router.patch("/reset-password")
async def reset_password(
    data: ChangePasswordSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.change_password(data=data)