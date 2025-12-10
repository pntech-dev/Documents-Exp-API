import secrets
import hashlib

from random import randint
from fastapi import HTTPException
from datetime import timedelta, datetime
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from repositories import AuthRepository
from models import User, RefreshToken, VerificationCode, ResetToken
from utils import hash_password, create_access_token, verify_password
from schemas import (
    UserSignUp, 
    UserTokenResponse, 
    UserLogin, 
    UserResponse,
    ForgotPasswordSchema, 
    EmailConfirmSchema, 
    ChangePasswordSchema
)


class AuthService:
    def __init__(self, db: AsyncSession):
        self.repo = AuthRepository(db)


    async def login(self, data: UserLogin) -> UserTokenResponse | None:
        """Login user and return token"""

        # Check if user exists
        user = await self.repo.get_user_by_email(email=data.email)
        if user is None:
            raise HTTPException(
                status_code=400,
                detail="Email or password is incorrect"
            )
        
        # Check if password is correct
        is_password_correct = verify_password(data.password, user.password_hash)
        if not is_password_correct:
            raise HTTPException(
                status_code=400,
                detail="Email or password is incorrect"
            )
        
        # Create tokens
        tokens = await self._create_tokens(user=user)

        # Invalidate all previous refresh tokens for user
        await self.repo.invalidate_all_user_refresh_tokens(user_id=user.id)

        # Create a refresh token record for the database
        refresh_token_record = RefreshToken(
            token=tokens[1],
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
            )
        )

        # Save the refresh token record
        await self.repo.save_refresh_token(refresh_token=refresh_token_record)

        # Create response
        response = await self._create_token_response(user=user, tokens=tokens)

        return response

    
    async def signup(self, data: UserSignUp) -> UserTokenResponse | None:
        """Register new user and return token"""

        # Check if user already exists
        user_exists = await self.repo.get_user_by_email(email=data.email)
        if user_exists is not None:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Hash user password
        password_hash = hash_password(data.password)

        # Create new user
        user = User(
            email=data.email,
            password_hash=password_hash,
        )

        created_user = await self.repo.create_user(user=user)

        # Create tokens
        tokens = await self._create_tokens(user=created_user)

        # Invalidate all previous refresh tokens for user
        await self.repo.invalidate_all_user_refresh_tokens(user_id=created_user.id)

        # Create a refresh token record for the database
        refresh_token_record = RefreshToken(
            token=tokens[1],
            user_id=created_user.id,
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
            )
        )

        # Save the refresh token record
        await self.repo.save_refresh_token(refresh_token=refresh_token_record)

        # Create response
        response = await self._create_token_response(user=user, tokens=tokens)

        return response
    

    async def get_user(self, user_id: int) -> UserResponse | None:
        """Return user by id"""

        user = await self.repo.get_user_by_id(user_id=user_id)
        await self._check_404_error(object=user, detail="Not found")
        
        response = UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            department=user.department
        )

        return response
    

    async def refresh_token(self, refresh_token: str) -> UserTokenResponse:
        "Refresh access and refresh tokens"

        # Get the refresh token from the database
        db_refresh_token = await self.repo.get_active_token(token=refresh_token)
        if db_refresh_token is None:
            raise HTTPException(
                status_code=401,
                detail="Refresh token is invalid or has been used"
            )
        
        # Invalidate the old refresh token
        await self.repo.invalidate(token=db_refresh_token)

        # Get the associated user
        user = await self.repo.get_user_by_id(user_id=db_refresh_token.user_id)
        if user is None:
            raise HTTPException(
                status_code=401,
                detail="User associated with the token not found"
            )

        # Create new tokens
        tokens = await self._create_tokens(user=user)

        # Save new refresh token
        refresh_token = RefreshToken(
            token=tokens[1],
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
            )
        )
        await self.repo.save_refresh_token(refresh_token=refresh_token)

        # Return refreshed tokens
        response = await self._create_token_response(user=user, tokens=tokens)

        return response
    

    async def _create_tokens(self, user: User) -> list[str]:
        """Create access and refresh tokens"""

        try:
            access_token = create_access_token(data={"sub": str(user.id)})
            refresh_token = create_access_token(
                data={"sub": str(user.id)},
                expires_delta=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
            )

            return [access_token, refresh_token]
        
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    

    async def _create_token_response(
            self, 
            user: User, 
            tokens: list[str]
    ) -> UserTokenResponse:
        
        """Create token response"""

        try:
            response = UserTokenResponse(
                access_token=tokens[0],
                refresh_token=tokens[1],
                token_type="bearer",
                user=UserResponse(
                    id=user.id,
                    email=user.email,
                    username=user.username,
                    department=user.department
                )
            )

            return response

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        

    # Password

    async def forgot_password(self, data: ForgotPasswordSchema) -> dict:
        """Forgot password"""
        user = await self.repo.get_user_by_email(email=data.email)

        # To prevent user enumeration, we perform the logic only if the user
        # exists, but we return a generic message regardless.
        if user:
            # Create email verification code
            code = randint(100000, 999999)
            code_hash = hash_password(str(code))

            # Send email with verification code
            print(f"Verification code: {code}")

            # Invalidate all previous verification codes for user
            await self.repo.invalidate_all_user_verification_codes(user_id=user.id)

            # Save a hash of verification code in DB
            verification_code = VerificationCode(
                user_id=user.id,
                code=code_hash,
                expires_at=datetime.utcnow() + timedelta(
                    minutes=settings.EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES
                )
            )
            await self.repo.save_verification_code(code=verification_code)

        return {"detail": "If an account with this email exists, a verification code has been sent."}


    async def confirm_email(self, data: EmailConfirmSchema) -> dict:
        """Confirm email"""
        # Get user by email
        user = await self.repo.get_user_by_email(email=data.email)
        
        # To prevent user enumeration, we check for the user first. If they don't exist,
        # we can't proceed, but we must return an error that is indistinguishable
        # from a failed code verification to avoid leaking information.
        if not user:
            raise HTTPException(
                status_code=400,
                detail="Verification code is incorrect or has expired"
            )
        
        # Get code hash
        code = await self.repo.get_verification_code(user_id=user.id)
        if not code:
            raise HTTPException(
                status_code=400,
                detail="Verification code is incorrect or has expired"
            )

        # Check if code is correct
        is_code_correct = verify_password(data.code, code.code)
        if not is_code_correct:
            raise HTTPException(
                status_code=400,
                detail="Verification code is incorrect or has expired"
            )
        
        # Invalidate code
        await self.repo.invalidate_verification_code(code=code)

        # Create reset token
        reset_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(reset_token.encode('utf-8')).hexdigest()

        # Save a reset_token
        token = ResetToken(
            user_id=user.id,
            token=token_hash,
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES
            )
        )

        await self.repo.save_reset_token(token=token)

        return {"reset_token": reset_token}


    async def change_password(self, data: ChangePasswordSchema) -> dict:
        """Reset password"""
        # Get reset token
        token_hash = hashlib.sha256(data.reset_token.encode('utf-8')).hexdigest()
        token = await self.repo.get_reset_token(token=token_hash)
        self._check_404_error(object=token, detail="Not found")
        
        # Get user
        user = await self.repo.get_user_by_id(user_id=token.user_id)
        self._check_404_error(object=user, detail="Not found")
        
        # Create password hash
        password_hash = hash_password(data.password)

        # Update user
        user.password_hash = password_hash
        await self.repo.update_user(user=user)

        # Invalidate reset token
        await self.repo.invalidate_reset_token(token=token)

        return {"detail": "Password changed"}
    

    async def _check_404_error(self, object, detail: str) -> bool:
        """Check if object exists"""
        if object is None:
            raise HTTPException(
                status_code=404,
                detail=detail
            )
        
        return True