from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi_limiter.depends import RateLimiter

from schemas import *
from db.deps import get_db
from services import AuthService
from utils import get_current_user
from core.config import settings


router = APIRouter(prefix="/auth", tags=["Auth"])


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(db)


"""=== User ==="""

@router.get("/user", response_model=UserResponse)
async def get_user(
    user: UserResponse = Depends(get_current_user),
):
    """
    Retrieves the currently authenticated user's profile information.
    """
    return user



"""=== Login ==="""

@router.post(
        "/login", 
        response_model=UserTokenResponse, 
        dependencies=[Depends(RateLimiter(
            times=settings.RATE_LIMIT_TIMES, 
            seconds=settings.RATE_LIMIT_SECONDS
        ))]
)
async def login(
    data: LoginSchema,
    service: AuthService = Depends(get_auth_service),
):
    """
    Authenticates a user and returns access and refresh tokens.
    """
    return await service.login(data=data)



"""=== Signup ==="""

@router.post(
        "/signup/send-code", 
        dependencies=[Depends(RateLimiter(times=3, seconds=600))] # Stricter limit for sending codes
)
async def send_code(
    data: SignupEmailConfirmSchema,
    service: AuthService = Depends(get_auth_service),
):
    """
    Sends a verification code to the provided email address for signup.
    """
    return await service.signup_send_code(
        data=data
    )


@router.patch(
        "/signup/verify-code", 
        response_model=UserTokenResponse, 
        dependencies=[Depends(RateLimiter(
            times=settings.RATE_LIMIT_TIMES, 
            seconds=settings.RATE_LIMIT_SECONDS
        ))]
)
async def signup(
    data: SignupSchema,
    service: AuthService = Depends(get_auth_service),
):
    """
    Completes the signup process by verifying the code and creating the user.
    """
    return await service.signup(data=data)



"""=== Tokens ==="""

@router.post("/token/refresh", response_model=UserTokenResponse)
async def refresh(
    data: RefreshTokenSchema,
    service: AuthService = Depends(get_auth_service),
):
    """
    Refreshes the access token using a valid refresh token.
    """
    return await service.refresh_token(token=data)



"""=== Password ==="""

@router.post(
        "/forgot-password/request-reset", 
        dependencies=[Depends(RateLimiter(times=3, seconds=600))] # Stricter limit for sending codes
)
async def request_password_reset(
    data: RequestPasswordResetSchema,
    service: AuthService = Depends(get_auth_service),
):
    """
    Initiates the password reset process by sending a verification code.
    """
    return await service.request_password_reset(
        data=data
    )


@router.post(
        "/forgot-password/confirm-email", 
        dependencies=[Depends(RateLimiter(
            times=settings.RATE_LIMIT_TIMES, 
            seconds=settings.RATE_LIMIT_SECONDS
        ))]
)
async def verify_reset_code(
    data: VerifyResetCodeSchema,
    service: AuthService = Depends(get_auth_service),
):
    """
    Verifies the password reset code and returns a reset token.
    """
    return await service.verify_reset_code(data=data)


@router.patch("/forgot-password/reset-password")
async def reset_password(
    data: ResetPasswordSchema,
    service: AuthService = Depends(get_auth_service),
):
    """
    Resets the user's password using the provided reset token.
    """
    return await service.reset_password(data=data)