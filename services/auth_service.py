import secrets
import hashlib

from random import randint
from fastapi import HTTPException
from datetime import timedelta, datetime
from sqlalchemy.ext.asyncio import AsyncSession

from schemas import *
from core.config import settings
from repositories import AuthRepository
from models import User, RefreshToken, VerificationCode, ResetToken
from utils import hash_password, create_access_token, verify_password


class AuthService:
    def __init__(self, db: AsyncSession) -> None:
        self.repo = AuthRepository(db)
    
    
    # ===============
    # Public methods
    # ===============


    """=== Users ==="""

    async def get_user(self, user_id: int) -> UserResponse | None:
        """Return user by id"""
        # Get user
        user = await self.repo.get_user_by_id(user_id=user_id)
        await self._check_http_error(
            condition=user is None,
            status_code=404,
            msg="Not found"
        )
        
        # Create response
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
        await self._check_http_error(
            condition=db_refresh_token is None,
            status_code=401,
            msg="Refresh token is invalid or has been used"
        )
        
        # Invalidate the old refresh token
        await self.repo.invalidate(token=db_refresh_token)

        # Get the associated user
        user = await self.repo.get_user_by_id(user_id=db_refresh_token.user_id)  
        await self._check_http_error(
            condition=user is None,
            status_code=401,
            msg="User associated with the token not found"
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
        response = await self._create_token_response(tokens=tokens, user=user)

        return response
        


    """=== Password ==="""

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
            await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

            # Save a hash of verification code in DB
            verification_code = VerificationCode(
                email=data.email,
                code_hash=code_hash,
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
        await self._check_http_error(
            condition=not user,
            status_code=400,
            msg="Verification code is incorrect or has expired"
        )
        
        # Get code hash
        code = await self.repo.get_verification_code_by_email(email=data.email)
        await self._check_http_error(
            condition=not code,
            status_code=400,
            msg="Verification code is incorrect or has expired"
        )

        # Check if code is correct
        is_code_correct = verify_password(data.code, code.code_hash)
        await self._check_http_error(
            condition=not is_code_correct,
            status_code=400,
            msg="Verification code is incorrect or has expired"
        )
        
        # Invalidate code
        await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

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
        await self._check_http_error(
            condition=token is None,
            status_code=404,
            msg="Not found"
        )
        
        # Get user
        user = await self.repo.get_user_by_id(user_id=token.user_id)
        await self._check_http_error(
            condition=user is None,
            status_code=404,
            msg="Not found"
        )
        
        # Create password hash
        password_hash = hash_password(data.password)

        # Update user
        user.password_hash = password_hash
        await self.repo.update_user(user=user)

        # Invalidate reset token
        await self.repo.invalidate_reset_token(token=token)

        return {"detail": "Password changed"}
    

    
    """=== Login ==="""

    async def login(self, data: LoginSchema) -> UserTokenResponse | None:
        """
        Login user and return tokens.
        The function receives login information, 
        receives the user by the received email, 
        verifies the password and creates tokens.
        
        Args:
            data (LoginSchema): Data with email and password.

        Returns:
            UserTokenResponse: User data and tokens
        """

        # Check if user exists
        user = await self.repo.get_user_by_email(email=data.email)
        await self._check_http_error(
            condition=user is None,
            status_code=400,
            msg="Email or password is incorrect"
        )

        # Check if user is_active
        await self._check_http_error(
            condition=not user.is_active,
            status_code=400,
            msg="Email or password is incorrect"
        )
        
        # Check if password is correct
        is_password_correct = verify_password(data.password, user.password_hash)
        await self._check_http_error(
            condition=not is_password_correct,
            status_code=400,
            msg="Email or password is incorrect"
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
        response = await self._create_token_response(tokens=tokens, user=user)

        return response
    


    """=== Signup ==="""

    async def signup(self, data: SignupSchema) -> UserTokenResponse:
        """
        Registering a new user
        The function verifies the correctness of the email verification code, 
        modifies the empty (reserved) account of a new user, 
        and creates access codes.

        Args:
            data (SignupSchema): Data with new user verification code, email and password.

        Returns:
            UserTokenResponse: User data and tokens
        """
    
        # Check verification code
        code = await self.repo.get_verification_code_by_email(email=data.email)
        await self._check_http_error(
            condition=not code,
            status_code=400,
            msg="Verification code is incorrect or has expired"
        )
        
        # Check if code is correct
        is_code_correct = verify_password(data.code, code.code_hash)
        await self._check_http_error(
            condition=not is_code_correct,
            status_code=400,
            msg="Verification code is incorrect or has expired"
        )
        
        # Get reserver user profile
        user = await self.repo.get_user_by_email(email=data.email)
        
        # Invalidate all verifications codes
        await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

        # Update user data
        password_hash = hash_password(data.password)

        user.password_hash = password_hash

        await self.repo.update_user(user=user)

        # Create tokens
        tokens = await self._create_tokens(user=user)

        # Save refresh token
        await self.repo.save_refresh_token(
            refresh_token=RefreshToken(
                token=tokens[1],
                user_id=user.id
            )
        )

        # Create response
        response = await self._create_token_response(tokens=tokens, user=user)

        return response


    async def signup_send_code(self, data: SignupEmailConfirmSchema) -> dict:
        """
        Sending the email verification code for the new registering user.
        The function checks for a user with such an email, 
        reserves the mail (creates an empty account), 
        and creates a verification code

        Args:
            data (SignupEmailConfirmSchema): Data with new user email.

        Returns:
            dict: Detail message.
        """

        # Check if a user with the same email address already exists
        user = await self.repo.get_user_by_email(email=data.email)
        await self._check_http_error(
            condition=user is not None,
            status_code=400,
            msg="User with this email already exists"
        )
        
        # Create verification code
        code = randint(100000, 999999)
        code_hash = hash_password(str(code))

        # Invalidate all verifications codes
        await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

        # Save verification code
        verification_code = VerificationCode(
            email=data.email,
            code_hash=code_hash,
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES
            )
        )

        await self.repo.save_verification_code(code=verification_code)

        # Send email with verification code (=== TEMP ===)
        print(f"Verification code: {code}")

        # Reserve user email (Create empty profile)
        user = User(
            email=data.email,
            password_hash=""
        )

        await self.repo.create_user(user=user)
        
        return {"detail": f"Verification code sent. CODE: {code}"}


    # ===============
    # Service methods
    # ===============


    """=== Responses """

    async def _create_token_response(self, tokens: list, user: User) -> UserTokenResponse:
        """
        The function generates a response in the UserTokenResponse format.

        Args:
            tokens (list): List of access and refresh tokens.
            user (User): User object.

        Returns:
            UserTokenResponse: Response in the UserTokenResponse format.
        """
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
            raise e
    


    """=== Tokens ==="""

    async def _create_tokens(self, user: User) -> list:
        """
        Creates access and refresh tokens

        Args:
            user (User): User object

        Returns:
            list: List of access and refresh tokens
        """
        try:
            access_token = create_access_token(data={"sub": str(user.id)})
            refresh_token = create_access_token(
                data={"sub": str(user.id)},
                expires_delta=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
            )

            return [access_token, refresh_token]

        except Exception as e:
            raise e



    """=== Errors ==="""

    async def _check_http_error(
            self,
            condition: bool,
            status_code: int,
            msg: str,
    ) -> None:
        """
        Raise HTTPException if the condition is True.

        Args:
            condition (bool): The condition to check.
            status_code (int): HTTP status code for the exception.
            msg (str): Detail message for the exception.
        """
        try:
            if condition:
                raise HTTPException(
                    status_code=status_code,
                    detail=msg
                )
            
        except Exception as e:
            raise e