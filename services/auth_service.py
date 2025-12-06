from datetime import timedelta, datetime
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from models import User, RefreshToken
from core.config import settings
from repositories import AuthRepository
from utils import hash_password, create_access_token, verify_password
from schemas import UserSignUp, UserTokenResponse, UserResponse, UserLogin


class AuthService:
    def __init__(self, db: AsyncSession):
        self.repo = AuthRepository(db)


    async def login(self, data: UserLogin) -> UserTokenResponse | None:
        """Login user and return token"""

        # Check if user exists
        user = await self.repo.get_user_by_email(email=data.email)
        if user is None:
            raise HTTPException(status_code=400, detail="Email or password is incorrect")
        
        # Check if password is correct
        is_password_correct = verify_password(data.password, user.password_hash)
        if not is_password_correct:
            raise HTTPException(status_code=400, detail="Email or password is incorrect")
        
        # Create tokens
        tokens = await self._create_tokens(user=user)

        # Create a refresh token record for the database
        refresh_token_record = RefreshToken(
            token=tokens[1],
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
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

        # Create a refresh token record for the database
        refresh_token_record = RefreshToken(
            token=tokens[1],
            user_id=created_user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
        )

        # Save the refresh token record
        await self.repo.save_refresh_token(refresh_token=refresh_token_record)

        # Create response
        response = await self._create_token_response(user=user, tokens=tokens)

        return response
    

    async def get_user(self, user_id: int) -> UserResponse | None:
        """Return user by id"""

        user = await self.repo.get_user_by_id(user_id=user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        
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
        db_refresh_token = await self.repo.get_refresh_token(token=refresh_token)
        if db_refresh_token is None:
            raise HTTPException(status_code=401, detail="Refresh token is invalid or has been used")
        
        # Invalidate the old refresh token
        await self.repo.invalidate(token=db_refresh_token)

        # Get the associated user
        user = await self.repo.get_user_by_id(user_id=db_refresh_token.user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="User associated with the token not found")

        # Create new tokens
        tokens = await self._create_tokens(user=user)

        # Save new refresh token
        refresh_token = RefreshToken(
            token=tokens[1],
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
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
    

    async def _create_token_response(self, user: User, tokens: list[str]) -> UserTokenResponse:
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