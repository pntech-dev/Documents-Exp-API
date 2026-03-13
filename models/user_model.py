from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=True)
    email = Column(String(100), unique=True, nullable=False)
    
    department_id = Column(Integer, ForeignKey('groups.id'), nullable=True)
    department = relationship('Group', back_populates='users')

    is_active = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)

    password_hash = Column(String, nullable=False)
    
    refresh_tokens = relationship('RefreshToken', back_populates='user')
    reset_tokens = relationship('ResetToken', back_populates='user')