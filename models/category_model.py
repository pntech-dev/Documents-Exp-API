from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, ForeignKey


class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey('groups.id'), nullable=False)
    name = Column(String, nullable=False)
    
    group = relationship('Group', back_populates='categories')
    documents = relationship('Document', back_populates='category')