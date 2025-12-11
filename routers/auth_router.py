from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import *
from db.deps import get_db
from services import AuthService
from utils import get_current_user


router = APIRouter(prefix="/auth", tags=["Auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)



"""=== Users ==="""

@router.get("/user", response_model=UserResponse)
async def get_user(
    service: AuthService = Depends(get_auth_service),
    current_user = Depends(get_current_user)
):
    return await service.get_user(user_id=current_user.id)



"""=== Login ==="""

@router.post("/login", response_model=UserTokenResponse)
async def login(
    data: LoginSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.login(data=data)



"""=== Signup ==="""

@router.post("/signup/send-code")
async def send_code(
    data: SignupEmailConfirmSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.signup_send_code(data=data)


@router.patch("/signup/verify-code", response_model=UserTokenResponse)
async def signup(
    data: SignupSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.signup(data=data)



"""=== Tokens ==="""

@router.post("/refresh", response_model=UserTokenResponse)
async def refresh(
    data: RefreshTokenSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.refresh_token(refresh_token=data.refresh_token)



"""=== Password ==="""

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