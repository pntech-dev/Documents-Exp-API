from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from repositories import AuthRepository
from utils import hash_password, create_access_token
from schemas import UserSignUp, UserSignUpResponse, UserResponse
from models import User


class AuthService:
    def __init__(self, db: AsyncSession):
        self.repo = AuthRepository(db)

    
    async def register_new_user(self, data: UserSignUp) -> UserSignUpResponse | None:
        """
        Register new user and return token
        """
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

        # Create token
        token = create_access_token(data={"sub": str(created_user.id)})

        # Create response
        response = UserSignUpResponse(
            access_token=token,
            token_type="bearer",
            user=UserResponse(
                id=created_user.id,
                email=created_user.email
            )
        )

        return response