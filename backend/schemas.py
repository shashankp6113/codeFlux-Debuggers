"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class EmailResponse(BaseModel):
    """Response schema returned after a successful .eml upload."""

    id: int
    email_account_id: int
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender: str
    recipient: str
    cc: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    received_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}
