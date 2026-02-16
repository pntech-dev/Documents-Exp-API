from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, ForeignKey, Table


document_tags = Table(
    'document_tags',
    Base.metadata,
    Column('document_id', Integer, ForeignKey('documents.id'), primary_key=True),
    Column('tag_id', Integer, ForeignKey('tags.id'), primary_key=True)
)


class Document(Base):
    __tablename__ = 'documents'
    id = Column(Integer, primary_key=True)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=False)
    code = Column(String, nullable=False)
    name = Column(String, nullable=False)
    
    category = relationship('Category', back_populates='documents')
    pages = relationship('Page', back_populates='document')
    tags = relationship('Tag', secondary=document_tags, back_populates='documents')