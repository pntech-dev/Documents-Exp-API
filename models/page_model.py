from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, ForeignKey


class Page(Base):
    __tablename__ = 'pages'
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    order_index = Column(Integer, nullable=False)
    designation = Column(String, nullable=False)
    name = Column(String, nullable=False)

    document = relationship('Document', back_populates='pages')