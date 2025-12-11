from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str

    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_MINUTES: int
    EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES: int
    RESET_TOKEN_EXPIRE_MINUTES: int

    NUMBER_OF_BYTES_FOR_RESET_TOKEN_GENERATION: int = 32

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
