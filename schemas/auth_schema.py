from pydantic import BaseModel, EmailStr, Field, field_validator


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserSignUp(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        if any(char.isspace() for char in password):
            raise ValueError("Password cannot contain whitespace characters")
        
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one digit")

        if not any(char.isalpha() for char in password):
            raise ValueError("Password must contain at least one letter")
        
        if not any(char.isupper() for char in password):
            raise ValueError("Password must contain at least one uppercase letter")

        return password


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    username: str | None = None
    department: str | None = None


class UserSignUpResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse