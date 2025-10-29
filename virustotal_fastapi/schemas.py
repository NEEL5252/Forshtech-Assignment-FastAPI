from pydantic import BaseModel
from typing import Any, Optional
from datetime import datetime

class VirusTotalReportSchema(BaseModel):
    id: int
    endpoint_type: str
    endpoint_value: str
    data: Any
    created_at: datetime

    class Config:
        orm_mode = True

class FetchRequest(BaseModel):
    endpoint_type: str
    endpoint_value: Optional[str] = None

