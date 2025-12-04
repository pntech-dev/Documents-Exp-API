from db import get_db
from jose import jwt, JWTError
from repositories import AuthRepository
from sqlalchemy.ext.asyncio import AsyncSession
from utils.security_util import security_settings
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer


oauth2_scheme = OAuth2AuthorizationCodeBearer(tokenUrl="/auth/login")

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def create_access_token(
        data: dict, 
        expires_delta: timedelta | None = None
) -> str:
    """
    Create and return access token
    """

    to_encode = data.copy()

    now = datetime.now(timezone.utc)
    
    if expires_delta is None:
        expires_delta = timedelta(minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": now + expires_delta})

    encoded_jwt = jwt.encode(
        to_encode,
        security_settings.SECRET_KEY,
        algorithm=security_settings.ALGHORITM,
    )

    return encoded_jwt


async def get_current_user(
        token: str = Depends(oauth2_scheme),
        session: AsyncSession = Depends(get_db)
) -> dict:
    """
    Check the token and return the user if the token is valid
    """
    try:
        payload = jwt.decode(
            token,
            security_settings.SECRET_KEY,
            algorithms=[security_settings.ALGHORITM]
        )

        user_id: str = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    repo = AuthRepository(session)
    user = await repo.get_user_by_id(user_id=user_id)

    if user is None:
        raise credentials_exception

    return user