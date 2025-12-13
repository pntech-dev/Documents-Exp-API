from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status


from db import get_db
from core.config import settings
from models.user_model import User
from repositories import AuthRepository


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)



"""=== User ==="""

async def get_current_user(
        token: str = Depends(oauth2_scheme),
        session: AsyncSession = Depends(get_db)
) -> User:
    """Authenticates and retrieves a user based on a JWT.

    This function serves as a FastAPI dependency. It validates the provided
    OAuth2 bearer token (JWT), decodes it to extract the user ID, and
    fetches the corresponding user from the database.

    Args:
        token: The OAuth2 bearer token provided in the request headers.
        session: The database session dependency.

    Returns:
        The authenticated User object corresponding to the token.

    Raises:
        HTTPException: If credentials cannot be validated (e.g., invalid
            token format, signature, or non-existent user).
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        user_id = int(payload.get("sub"))

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    repo = AuthRepository(session)
    user = await repo.get_user_by_id(user_id=user_id)

    if user is None:
        raise credentials_exception

    return user



"""=== Token ==="""

def create_token(data: dict, expires_delta: timedelta) -> str:
    """Creates a new JWT with a specified payload and expiration.

    Encodes a payload dictionary into a JSON Web Token (JWT) string, including
    an expiration claim ('exp').

    Args:
        data: A dictionary containing the payload to encode in the token.
        expires_delta: A timedelta object representing the token's lifespan.

    Returns:
        An encoded JWT string.
    """
    to_encode = data.copy()

    now = datetime.now(timezone.utc)

    to_encode.update({"exp": now + expires_delta})

    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    return encoded_jwt