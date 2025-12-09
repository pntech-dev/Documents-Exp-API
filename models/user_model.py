from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean


class User(Base):
    __tablename__ = "users" # Table name in database

    # Evry column names has the same name as in SQL
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=True)
    email = Column(String(100), unique=True, nullable=False)
    department = Column(String(100), default=None, nullable=True)

    is_admin = Column(Boolean, default=False)

    password_hash = Column(String, nullable=False)
    
    refresh_tokens = relationship('RefreshToken', back_populates='user')
    verification_codes = relationship('VerificationCode', back_populates='user')
    reset_tokens = relationship('ResetToken', back_populates='user')