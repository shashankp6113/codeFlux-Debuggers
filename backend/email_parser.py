"""Email parsing utilities using Python's standard-library email package."""

from __future__ import annotations

import email
import email.policy
import email.utils
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ParsedEmail:
    """Structured result of parsing a raw .eml file."""

    message_id: Optional[str]
    subject: Optional[str]
    sender: str
    recipient: str
    cc: Optional[str]
    body_text: Optional[str]
    body_html: Optional[str]
    raw_headers: str
    received_at: Optional[datetime]


def parse_eml(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml bytes and extract structured fields.

    Args:
        raw_bytes: The complete raw bytes of an .eml file.

    Returns:
        A ParsedEmail dataclass with all extracted fields.

    Raises:
        ValueError: If the bytes cannot be parsed into a valid email
                    or if required From/To headers are missing.
    """
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    sender = msg.get("From", "")
    recipient = msg.get("To", "")

    if not sender or not recipient:
        raise ValueError(
            "Invalid .eml file: missing required From and/or To headers."
        )

    # Parse the Date header into a datetime
    received_at: Optional[datetime] = None
    date_str = msg.get("Date")
    if date_str:
        parsed = email.utils.parsedate_to_datetime(date_str)
        # Normalise to UTC if timezone-aware, otherwise keep as-is
        if parsed.tzinfo is not None:
            received_at = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            received_at = parsed

    # Extract body parts
    body_text: Optional[str] = None
    body_html: Optional[str] = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and body_text is None:
                body_text = part.get_content()
            elif content_type == "text/html" and body_html is None:
                body_html = part.get_content()
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_text = msg.get_content()
        elif content_type == "text/html":
            body_html = msg.get_content()

    # Build raw headers string
    full = msg.as_string()
    sep = full.find("\n\n")
    raw_headers = full[:sep] if sep != -1 else full

    return ParsedEmail(
        message_id=msg.get("Message-ID"),
        subject=msg.get("Subject"),
        sender=sender,
        recipient=recipient,
        cc=msg.get("Cc"),
        body_text=body_text,
        body_html=body_html,
        raw_headers=raw_headers,
        received_at=received_at,
    )
