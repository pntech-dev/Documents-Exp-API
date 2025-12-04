from passlib.context import CryptContext
from pydantic_settings import BaseSettings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class SecuritySettings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    class Config:
        env_file = ".env"
        extra = "ignore"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
    

security_settings = SecuritySettings()