from sqlalchemy import Column, Integer, String, JSON, DateTime, func
from .database import Base
from datetime import datetime, timedelta

class VirusTotalReport(Base):
    __tablename__ = "virustotal_reports"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_type = Column(String, index=True)
    endpoint_value = Column(String, unique=True, index=True)
    data = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(hours=12))
