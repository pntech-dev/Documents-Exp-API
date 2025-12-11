from fastapi import HTTPException
from datetime import timedelta, datetime
from sqlalchemy.ext.asyncio import AsyncSession

from utils import *
from schemas import *
from core.config import settings
from repositories import AuthRepository
from models import User, RefreshToken, VerificationCode, ResetToken


class AuthService:
    def __init__(self, db: AsyncSession) -> None:
        self.repo = AuthRepository(db)
    

    # ===============
    # Public methods
    # ===============


    """=== Login ==="""

    async def login(self, data: LoginSchema) -> UserTokenResponse | None:
        """
        Authenticates a user with email and password.

        On success, it invalidates all previous refresh tokens and returns a new 
        pair of access and refresh tokens.

        Args:
            data (LoginSchema): User's login credentials.

        Returns:
            UserTokenResponse: User data and a new set of tokens.
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
            token=tokens["refresh_token"],
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
        Finalizes the user registration process.

        Verifies the provided signup code, sets the user's password on the 
        pre-registered account, and issues the first pair of tokens.

        Args:
            data (SignupSchema): Email, verification code, and new password.

        Returns:
            UserTokenResponse: User data and the initial set of tokens.
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

        # Update user data
        password_hash = hash_password(data.password)

        user.password_hash = password_hash

        await self.repo.update_user(user=user)

        # Create tokens
        tokens = await self._create_tokens(user=user)

        # Save refresh token
        await self.repo.save_refresh_token(
            refresh_token=RefreshToken(
                token=tokens["refresh_token"],
                user_id=user.id
            )
        )

        # Create response
        response = await self._create_token_response(tokens=tokens, user=user)

        # Invalidate all verifications codes
        await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

        return response


    async def signup_send_code(self, data: SignupEmailConfirmSchema) -> dict:
        """
        Initiates the signup process for a new user.

        Checks if the email is available, creates a temporary user profile to 
        reserve the email, and sends a verification code.

        Args:
            data (SignupEmailConfirmSchema): The new user's email.

        Returns:
            dict: A confirmation message.
        """

        # Check if a user with the same email address already exists
        user = await self.repo.get_user_by_email(email=data.email)
        await self._check_http_error(
            condition=user is not None,
            status_code=400,
            msg="User with this email already exists"
        )
        
        # Create verification code
        code = generate_verification_code()

        # Invalidate all verifications codes
        await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

        # Save verification code
        verification_code = VerificationCode(
            email=data.email,
            code_hash=code["code_hash"],
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES
            )
        )

        await self.repo.save_verification_code(code=verification_code)

        # Send email with verification code (=== TEMP ===)
        print(f"Verification code: {code["code"]}")

        # Reserve user email (Create empty profile)
        user = User(
            email=data.email,
            password_hash=""
        )

        await self.repo.create_user(user=user)
        
        return {"detail": f"Verification code sent. CODE: {code["code"]}"}
    


    """=== Reset password ==="""

    async def request_password_reset(self, data: ForgotPasswordSchema) -> dict:
        """
        Initiates the password reset process.

        Generates a verification code and sends it to the user's email 
        if an account with that email exists.

        Args:
            data (EmailConfirmSchema): Data with user's email.

        Returns:
            dict: A generic confirmation message.
        """
        # Get user by email
        user = await self.repo.get_user_by_email(email=data.email)

        # To prevent user enumeration, we perform the logic only if the user
        # exists, but we return a generic message regardless.
        if user:
            # Create email verification code
            code = generate_verification_code()

            # Send email with verification code
            print(f"Verification code: {code['code']}")

            # Save a hash of verification code in DB
            verification_code = VerificationCode(
                email=data.email,
                code_hash=code['code_hash'],
                expires_at=datetime.utcnow() + timedelta(
                    minutes=settings.EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES
                )
            )
            await self.repo.save_verification_code(code=verification_code)

            # Invalidate all previous verification codes for user
            await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

        return {"detail": "If an account with this email exists, a verification code has been sent."}


    async def verify_reset_code(self, data: EmailConfirmSchema) -> dict:
        """
        Verifies the password reset code.

        Exchanges a valid verification code for a single-use, secure reset token.

        Args:
            data (EmailConfirmSchema): Data with email and verification code.

        Returns:
            dict: The new, secure reset token.
        """
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

        # Create reset token
        reset_token = create_reset_token(
            nbytes=settings.NUMBER_OF_BYTES_FOR_RESET_TOKEN_GENERATION
        )
        token_hash = hash_token(token=reset_token)

        # Save a reset_token
        token = ResetToken(
            user_id=user.id,
            token=token_hash,
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.RESET_TOKEN_EXPIRE_MINUTES
            )
        )

        await self.repo.save_reset_token(token=token)

        # Invalidate code
        await self.repo.invalidate_all_verifications_codes_by_email(email=data.email)

        return {"reset_token": reset_token}


    async def reset_password(self, data: ChangePasswordSchema) -> dict:
        """
        Finalizes the password reset process.

        Sets a new password for the user using a valid reset token.

        Args:
            data (ChangePasswordSchema): Data with reset token and new password.

        Returns:
            dict: A success message.
        """
        # Get reset token
        token_hash = hash_token(token=data.reset_token)
        token = await self.repo.get_reset_token(token=token_hash)
        await self._check_http_error(
            condition=token is None,
            status_code=400,
            msg="Reset token is invalid or expired."
        )
        
        # Get user
        user = await self.repo.get_user_by_id(user_id=token.user_id)
        await self._check_http_error(
            condition=user is None,
            status_code=400,
            msg="Reset token is invalid or expired."
        )
        
        # Create password hash
        password_hash = hash_password(data.password)

        # Update user
        user.password_hash = password_hash
        await self.repo.update_user(user=user)

        # Invalidate reset token
        await self.repo.invalidate_reset_token(token=token)

        return {"detail": "Password changed"}
    


    """=== Tokens ==="""

    async def refresh_token(self, provided_token: str) -> UserTokenResponse:
        """
        Rotates the refresh token (Token Rotation).

        Consumes a valid refresh token and returns a new pair of access and 
        refresh tokens, invalidating the used token.

        Args:
            provided_token (str): The refresh token to be rotated.

        Returns:
            UserTokenResponse: User data and a new set of tokens.
        """

        # Find the active token in the database.
        token_from_db = await self.repo.get_active_token(token=provided_token)

        # Use a single, clear error message to avoid leaking information
        # about whether a token exists but is expired, or never existed at all.
        await self._check_http_error(
            condition=token_from_db is None,
            status_code=401,
            msg="Refresh token is invalid or has expired"
        )
        
        # Immediately invalidate the old refresh token to prevent reuse (Token Rotation).
        await self.repo.invalidate(token=token_from_db)

        # Get the user associated with the now-invalidated token.
        user = await self.repo.get_user_by_id(user_id=token_from_db.user_id)
        await self._check_http_error(
            condition=user is None,
            status_code=401, # 401 Unauthorized, as the token is effectively invalid if the user is gone.
            msg="User associated with the token not found"
        )

        # Create a new pair of tokens.
        new_tokens = await self._create_tokens(user=user)

        # Save the new refresh token to the database.
        new_refresh_token = RefreshToken(
            token=new_tokens["refresh_token"],
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(
                minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
            )
        )
        await self.repo.save_refresh_token(refresh_token=new_refresh_token)

        # Build and return the final response.
        response = await self._create_token_response(tokens=new_tokens, user=user)

        return response


    # ===============
    # Service methods
    # ===============


    """=== Responses """

    async def _create_token_response(
        self, 
        tokens: dict[str, str], 
        user: User
    ) -> UserTokenResponse:
        """
        Helper function to build the standard `UserTokenResponse` object.

        Args:
            tokens (dict[str, str]): Dictionary of access and refresh tokens.
            user (User): User object.

        Returns:
            UserTokenResponse: Response in the UserTokenResponse format.
        """
        response = UserTokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            user=UserResponse(
                id=user.id,
                email=user.email,
                username=user.username,
                department=user.department
            )
        )

        return response
    


    """=== Tokens ==="""

    async def _create_tokens(self, user: User) -> dict[str, str]:
        """
        Creates access and refresh tokens and returns them as a dictionary.

        Args:
            user (User): User object

        Returns:
            dict[str, str]: A dictionary containing 'access_token' and 'refresh_token'.
        """
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_access_token(
            data={"sub": str(user.id)},
            expires_delta=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
        )

        return {"access_token": access_token, "refresh_token": refresh_token}



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
        if condition:
            raise HTTPException(
                status_code=status_code,
                detail=msg
            )