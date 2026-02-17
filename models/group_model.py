from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean


class Group(Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    show_for_guest = Column(Boolean, default=False)
    has_all_docs_search = Column(Boolean, default=False)
    
    categories = relationship('Category', back_populates='group')

    @property
    def documents_count(self) -> int:
        return sum(len(category.documents) for category in self.categories)