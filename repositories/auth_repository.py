import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import User, RefreshToken, VerificationCode, ResetToken


class AuthRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    
    async def get_user_by_id(self, user_id: int) -> User | None:
        """Return User by id or None"""

        query = select(User).where(User.id == user_id)
        result = await self.session.execute(query)

        return result.scalar_one_or_none()
    

    async def get_user_by_username(self, username: str) -> User | None:
        """Return User by username or None"""

        query = select(User).where(User.username == username)
        result = await self.session.execute(query)

        return result.scalar_one_or_none()
    

    async def get_user_by_email(self, email: str) -> User | None:
        """Return User by email or None"""

        query = select(User).where(
            User.email == email,
            User.is_active == True
        )
        result = await self.session.execute(query)

        return result.scalar_one_or_none()
    

    async def create_user(self, user: User) -> User:
        """Create new user in db"""

        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)

        return user
    

    async def update_user(self, user: User) -> User:
        """Update user in db"""

        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)

        return user
    

    # === Password ===

    async def get_verification_code(self, user_id: int) -> VerificationCode | None:
        """Return verification code or None"""

        query = select(VerificationCode).where(
            VerificationCode.user_id == user_id,
            VerificationCode.expires_at > datetime.datetime.utcnow(),
            VerificationCode.used == False
        )

        code = await self.session.execute(query)

        return code.scalar_one_or_none()
    

    async def get_reset_token(self, token: str) -> ResetToken | None:
        """Return reset token or None"""

        query = select(ResetToken).where(
            ResetToken.token == token,
            ResetToken.expires_at > datetime.datetime.utcnow(),
            ResetToken.used == False
        )

        token = await self.session.execute(query)

        return token.scalar_one_or_none()


    async def save_reset_token(self, token: ResetToken) -> None:
        """Save reset token in db"""

        self.session.add(token)
        await self.session.commit()
    

    async def invalidate_verification_code(self, code: VerificationCode) -> None:
        """Invalidate verification code"""

        code.used = True
        await self.session.commit()
        await self.session.refresh(code)


    async def invalidate_all_user_verification_codes(self, user_id: int) -> None:
        """Invalidate all verification codes for user"""

        stmt = (
            update(VerificationCode)
            .where(VerificationCode.user_id == user_id, VerificationCode.used == False)
            .values(used=True)
        )
        await self.session.execute(stmt)
        await self.session.commit()


    async def invalidate_reset_token(self, token: ResetToken) -> None:
        """Invalidate reset token"""

        token.used = True
        await self.session.commit()
        await self.session.refresh(token)

 
    # === Refresh token ===

    async def get_active_token(self, token: str) -> RefreshToken | None:
        """Return active refresh token or None"""
        
        query = select(RefreshToken).where(
            RefreshToken.token == token,
            RefreshToken.used == False,
            RefreshToken.expires_at > datetime.datetime.utcnow()
        )

        result = await self.session.execute(query)
        
        return result.scalar_one_or_none()


    async def save_refresh_token(self, refresh_token: RefreshToken) -> RefreshToken:
        """Save refresh token in db"""

        self.session.add(refresh_token)
        await self.session.commit()
        await self.session.refresh(refresh_token)

        return refresh_token
    

    async def invalidate(self, token: RefreshToken) -> None:
        token.used = True
        await self.session.commit()


    async def invalidate_all_user_refresh_tokens(self, user_id: int) -> None:
        """Invalidate all refresh tokens for user"""

        stmt = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.used == False)
            .values(used=True)
        )
        await self.session.execute(stmt)
        await self.session.commit()




    """=== Email verifications ==="""
    async def get_verification_code_by_email(self, email: str) -> VerificationCode | None:
        """
        Return verification code by email or None.
        
        Args:
            email (str): Email address.
            
        Returns:
            VerificationCode | None
        """

        query = select(VerificationCode).where(
            VerificationCode.email == email,
            VerificationCode.used == False,
            VerificationCode.expires_at > datetime.datetime.utcnow()
        )

        result =await self.session.execute(query)

        return result.scalar_one_or_none()

    async def save_verification_code(self, code: VerificationCode) -> None:
        """
        Save verification code in database.
        
        Args:
            code (VerificationCode): Verification code object.
            
        Returns:
            None
        """
        self.session.add(code)
        await self.session.commit()
        await self.session.refresh(code)

    async def invalidate_all_verifications_codes_by_email(self, email: str) -> None:
        """
        Invalidate all verification code by email.
        
        Args:
            email (str): Email address.
            
        Returns:
            None
        """

        stmt = (
            update(VerificationCode)
            .where(VerificationCode.email == email, VerificationCode.used == False)
            .values(used=True)
        )
        await self.session.execute(stmt)
        await self.session.commit()