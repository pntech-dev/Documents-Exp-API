from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean


class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey('groups.id'), nullable=False)
    name = Column(String, nullable=False)
    show_for_guest = Column(Boolean, default=False)
    
    group = relationship('Group', back_populates='categories')
    documents = relationship('Document', back_populates='category')

    @property
    def documents_count(self) -> int:
        return len(self.documents)