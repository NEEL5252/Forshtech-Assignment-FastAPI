from sqlalchemy import Column, Integer, String, JSON, DateTime, func
from .database import Base

class VirusTotalReport(Base):
    __tablename__ = "virustotal_reports"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_type = Column(String, index=True)
    endpoint_value = Column(String, unique=True, index=True)
    data = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

