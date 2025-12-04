from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean


class User(Base):
    __tablename__ = "users" # Table name in database

    # Evry column names has the same name as in SQL
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100))
    is_active = Column(Boolean, default=True)

    password_hash = Column(String, nullable=False)