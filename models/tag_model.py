from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String


class Tag(Base):
    __tablename__ = 'tags'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    
    documents = relationship('Document', secondary='document_tags', back_populates='tags')