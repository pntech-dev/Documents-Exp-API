import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import User, RefreshToken, VerificationCode, ResetToken


class AuthRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    """=== User ==="""
    
    async def get_user_by_id(self, user_id: int) -> User | None:
        """Retrieves a user from the database by their unique ID.

        Args:
            user_id: The unique identifier of the user to retrieve.

        Returns:
            The User object if found, otherwise None.
        """

        query = select(User).where(User.id == user_id)
        result = await self.session.execute(query)

        return result.scalar_one_or_none()


    async def get_user_by_email(self, email: str) -> User | None:
        """Retrieves a user from the database by their email address.

        Note:
            This method does not check the `is_active` status of the user.
            The calling service is responsible for handling active and inactive users.

        Args:
            email: The email address of the user to retrieve.

        Returns:
            The User object if found, otherwise None.
        """

        query = select(User).where(User.email == email)
        result = await self.session.execute(query)

        return result.scalar_one_or_none()
    

    async def save_user(self, user: User) -> User:
        """Saves a user to the database, either creating or updating it.

        This method handles both the creation of a new user and the update
        of an existing one. It adds the user object to the session, commits the
        transaction, and refreshes the object to get the latest state from the

        Args:
            user: The User object to be saved.

        Returns:
            The saved User object, refreshed from the database.
        """

        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)

        return user
    

    
    """=== Token ==="""

    async def get_reset_token(self, token: str) -> ResetToken | None:
        """Retrieves an active, un-used password reset token.

        Args:
            token: The reset token string to search for.

        Returns:
            The ResetToken object if a valid token is found, otherwise None.
        """

        query = select(ResetToken).where(
            ResetToken.token == token,
            ResetToken.expires_at > datetime.datetime.utcnow(),
            ResetToken.used == False
        )

        token = await self.session.execute(query)

        return token.scalar_one_or_none()
    

    async def get_active_token(self, token: str) -> RefreshToken | None:
        """Retrieves an active, un-used refresh token from the database.

        Args:
            token: The refresh token string to search for.

        Returns:
            The RefreshToken object if a valid token is found, otherwise None.
        """
        
        query = select(RefreshToken).where(
            RefreshToken.token == token,
            RefreshToken.used == False,
            RefreshToken.expires_at > datetime.datetime.utcnow()
        )

        result = await self.session.execute(query)
        
        return result.scalar_one_or_none()


    async def save_reset_token(self, token: ResetToken) -> None:
        """Saves a password reset token to the database.

        Args:
            token: The ResetToken object to save.
        """

        self.session.add(token)
        await self.session.commit()


    async def save_refresh_token(self, refresh_token: RefreshToken) -> RefreshToken:
        """Saves a refresh token to the database.

        Args:
            refresh_token: The RefreshToken object to save.

        Returns:
            The saved RefreshToken object, refreshed from the database.
        """

        self.session.add(refresh_token)
        await self.session.commit()
        await self.session.refresh(refresh_token)

        return refresh_token


    async def invalidate_reset_token(self, token: ResetToken) -> None:
        """Marks a password reset token as used in the database.

        Args:
            token: The ResetToken object to invalidate.
        """

        token.used = True
        await self.session.commit()
        await self.session.refresh(token)


    async def invalidate_refresh_token(self, token: RefreshToken) -> None:
        """Marks a refresh token as used in the database.

        Args:
            token: The RefreshToken object to invalidate.
        """
        token.used = True
        await self.session.commit()
        await self.session.refresh(token)


    async def invalidate_all_user_refresh_tokens(self, user_id: int) -> None:
        """Marks all of a user's refresh tokens as used in the database.

        This is used to invalidate all active sessions for a user, for example,
        after a password change.

        Args:
            user_id: The ID of the user whose tokens are to be invalidated.
        """

        stmt = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.used == False)
            .values(used=True)
        )
        await self.session.execute(stmt)
        await self.session.commit()



    """=== Email verification ==="""

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