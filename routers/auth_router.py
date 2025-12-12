from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import *
from db.deps import get_db
from services import AuthService


router = APIRouter(prefix="/auth", tags=["Auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)


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

@router.post("/token/refresh", response_model=UserTokenResponse)
async def refresh(
    data: RefreshTokenSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.refresh_token(token=data)



"""=== Password ==="""

@router.post("/forgot-password/request-reset")
async def request_password_reset(
    data: RequestPasswordResetSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.request_password_reset(data=data)


@router.post("/forgot-password/confirm-email")
async def verify_reset_code(
    data: VerefyResetCodeSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.verify_reset_code(data=data)


@router.patch("/forgot-password/reset-password")
async def reset_password(
    data: ResetPasswordSchema,
    service: AuthService = Depends(get_auth_service),
):
    return await service.reset_password(data=data)