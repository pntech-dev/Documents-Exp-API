from db.base import Base
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, BigInteger
from datetime import datetime, timezone


class DocumentFile(Base):
    __tablename__ = 'document_files'
    
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey('documents.id'), nullable=False)
    
    file_path = Column(String, nullable=False) # Path (Key) in MinIO
    filename = Column(String, nullable=False)  # Original filename
    content_type = Column(String, nullable=False) # MIME type (e.g. application/pdf)
    size = Column(BigInteger, nullable=False) # Size in bytes
    
    created_at = Column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        nullable=False
    )

    document = relationship('Document', back_populates='files')