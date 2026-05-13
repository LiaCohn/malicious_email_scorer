from typing import Optional
from pydantic import BaseModel, Field


class EmailPayload(BaseModel):
    message_id: str
    from_email: str
    from_name: Optional[str] = ""
    subject: Optional[str] = ""
    body: Optional[str] = ""
    headers: dict = Field(default_factory=dict)
    urls: list[str] = Field(default_factory=list)


class SignalResult(BaseModel):
    name: str
    score: int          # contribution to total (0-100)
    weight: float       # how much this signal counts
    passed: bool        # True = safe, False = suspicious/malicious
    detail: str         # human-readable explanation


class ScanResult(BaseModel):
    message_id: str
    from_email: str
    subject: str
    total_score: int    # 0-100
    verdict: str        # SAFE / SUSPICIOUS / MALICIOUS
    signals: list[SignalResult]
    scanned_at: str
