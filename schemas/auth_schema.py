from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from utils import validate_password

    
    
"""=== User ==="""
class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    username: str | None = None
    department: str | None = None


class UserTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user: UserResponse
    


"""=== Login ==="""
class LoginSchema(BaseModel):
    email: EmailStr
    password: str



"""=== Signup ==="""
class SignupSchema(BaseModel):
    code: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return validate_password(password)


class SignupEmailConfirmSchema(BaseModel):
    email: EmailStr



"""=== Tokens ==="""
class RefreshTokenSchema(BaseModel):
    refresh_token: str
    


"""=== Reset Password ==="""
class RequestPasswordResetSchema(BaseModel):
    email: EmailStr


class VerifyResetCodeSchema(BaseModel):
    email: EmailStr
    code: str


class ResetPasswordSchema(BaseModel):
    reset_token: str
    password: str = Field(min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return validate_password(password)