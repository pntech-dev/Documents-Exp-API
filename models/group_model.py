from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String


class Group(Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    
    categories = relationship('Category', back_populates='group')