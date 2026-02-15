from db.base import Base
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime


class ResetToken(Base):
    __tablename__ = 'reset_tokens'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token = Column(String, nullable=True, unique=True)
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    used = Column(Boolean, default=False)

    user = relationship('User', back_populates='reset_tokens')