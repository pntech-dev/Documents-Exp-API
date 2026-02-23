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

    RESEND_API_KEY: str
    EMAIL_SENDER: str
    ALLOWED_EMAIL_DOMAINS: list[str] = []

    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000

    # Rate Limiting
    RATE_LIMIT_TIMES: int = 5
    RATE_LIMIT_SECONDS: int = 60

    REDIS_URL: str = "redis://localhost:6379"

    # S3 / MinIO Storage
    S3_ENDPOINT_URL: str = "http://minio:9000"
    S3_ACCESS_KEY: str
    S3_SECRET_KEY: str
    S3_BUCKET_NAME: str = "documents"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
