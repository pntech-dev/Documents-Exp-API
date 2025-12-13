from db.base import Base
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime


class VerificationCode(Base):
    __tablename__ = 'verification_codes'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), nullable=False)
    code_hash = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    used = Column(Boolean, default=False)