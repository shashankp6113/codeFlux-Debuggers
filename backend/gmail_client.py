"""Gmail API client for retrieving and converting messages.

Uses the stored OAuth credentials from ``EmailAccount`` to interact
with the Gmail API v1.  Messages are retrieved in ``format=raw``
(base64url-encoded RFC 2822) and converted through the existing
``email_parser.parse_eml`` function.

No real Gmail API calls are made when running tests — all HTTP
interactions are mocked.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from email_parser import ParsedEmail, parse_eml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
_DEFAULT_LIMIT = 10
_MAX_LIMIT = 50
_HTTP_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GmailAPIError(Exception):
    """Raised when a Gmail API request fails."""
    pass


class GmailMessageError(Exception):
    """Raised when a single message cannot be processed."""
    pass


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class GmailMessageRef:
    """Lightweight reference returned by the Gmail list endpoint."""

    id: str
    thread_id: str = ""


@dataclass
class GmailSyncResult:
    """Result of a batch Gmail message retrieval operation."""

    fetched: int = 0
    persisted: int = 0
    skipped_duplicate: int = 0
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Gmail API helpers
# ---------------------------------------------------------------------------

def _auth_headers(access_token: str) -> dict:
    """Build authorization headers — token is NEVER logged."""
    return {"Authorization": f"Bearer {access_token}"}


def list_message_ids(
    access_token: str,
    max_results: int = _DEFAULT_LIMIT,
) -> List[GmailMessageRef]:
    """List message IDs from the user's Gmail inbox.

    Args:
        access_token: A valid OAuth 2.0 access token.
        max_results:  Maximum number of message refs to return.

    Returns:
        A list of ``GmailMessageRef`` objects.

    Raises:
        GmailAPIError: On HTTP or API errors.
    """
    url = f"{_GMAIL_API_BASE}/users/me/messages"
    params = {"maxResults": min(max_results, _MAX_LIMIT)}

    try:
        resp = httpx.get(
            url,
            headers=_auth_headers(access_token),
            params=params,
            timeout=_HTTP_TIMEOUT,
        )
    except Exception as exc:
        raise GmailAPIError(f"Network error listing messages: {exc}")

    if resp.status_code == 401:
        raise GmailAPIError("Gmail API authentication failed (401)")
    if resp.status_code == 429:
        raise GmailAPIError("Gmail API rate limit exceeded (429)")
    if resp.status_code != 200:
        raise GmailAPIError(
            f"Gmail API error listing messages (HTTP {resp.status_code})"
        )

    data = resp.json()
    messages = data.get("messages", [])
    return [
        GmailMessageRef(
            id=m["id"],
            thread_id=m.get("threadId", ""),
        )
        for m in messages
    ]


def get_raw_message(access_token: str, message_id: str) -> bytes:
    """Retrieve a single Gmail message as raw RFC 2822 bytes.

    Args:
        access_token: A valid OAuth 2.0 access token.
        message_id:   The Gmail message ID.

    Returns:
        The decoded RFC 2822 message bytes.

    Raises:
        GmailAPIError:    On HTTP or API errors.
        GmailMessageError: If the response is malformed or decode fails.
    """
    url = f"{_GMAIL_API_BASE}/users/me/messages/{message_id}"
    params = {"format": "raw"}

    try:
        resp = httpx.get(
            url,
            headers=_auth_headers(access_token),
            params=params,
            timeout=_HTTP_TIMEOUT,
        )
    except Exception as exc:
        raise GmailAPIError(f"Network error retrieving message {message_id}: {exc}")

    if resp.status_code == 401:
        raise GmailAPIError("Gmail API authentication failed (401)")
    if resp.status_code == 429:
        raise GmailAPIError("Gmail API rate limit exceeded (429)")
    if resp.status_code != 200:
        raise GmailAPIError(
            f"Gmail API error retrieving message {message_id} "
            f"(HTTP {resp.status_code})"
        )

    data = resp.json()
    raw_b64 = data.get("raw")
    if not raw_b64:
        raise GmailMessageError(
            f"Gmail message {message_id} has no 'raw' field"
        )

    try:
        # Gmail uses base64url encoding (RFC 4648 §5)
        # Add padding if needed
        padded = raw_b64 + "=" * (4 - len(raw_b64) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise GmailMessageError(
            f"Failed to decode base64url for message {message_id}: {exc}"
        )


# ---------------------------------------------------------------------------
# Conversion: Gmail raw → ParsedEmail
# ---------------------------------------------------------------------------

def convert_raw_to_parsed(raw_bytes: bytes) -> ParsedEmail:
    """Convert raw RFC 2822 bytes to a ``ParsedEmail``.

    Reuses the existing ``parse_eml`` function — the same logic that
    handles uploaded ``.eml`` files.

    Args:
        raw_bytes: Decoded RFC 2822 message bytes.

    Returns:
        A ``ParsedEmail`` with all extracted fields.

    Raises:
        GmailMessageError: If the message cannot be parsed.
    """
    try:
        return parse_eml(raw_bytes)
    except (ValueError, Exception) as exc:
        raise GmailMessageError(f"Failed to parse raw message: {exc}")


# ---------------------------------------------------------------------------
# Batch sync service
# ---------------------------------------------------------------------------

def sync_gmail_messages(
    account_id: int,
    access_token: str,
    db_session,
    limit: int = _DEFAULT_LIMIT,
) -> GmailSyncResult:
    """Retrieve and persist Gmail messages for an EmailAccount.

    Args:
        account_id:   The EmailAccount.id to associate messages with.
        access_token: A valid OAuth 2.0 access token.
        db_session:   A SQLAlchemy session.
        limit:        Maximum number of messages to fetch.

    Returns:
        A ``GmailSyncResult`` summarising the operation.
    """
    from models import Email

    effective_limit = max(1, min(limit, _MAX_LIMIT))
    result = GmailSyncResult()

    # 1. List message IDs
    try:
        refs = list_message_ids(access_token, max_results=effective_limit)
    except GmailAPIError as exc:
        result.errors.append(str(exc))
        return result

    # 2. Retrieve and convert each message
    for ref in refs:
        result.fetched += 1

        try:
            raw_bytes = get_raw_message(access_token, ref.id)
        except (GmailAPIError, GmailMessageError) as exc:
            result.errors.append(f"Message {ref.id}: {exc}")
            continue

        try:
            parsed = convert_raw_to_parsed(raw_bytes)
        except GmailMessageError as exc:
            result.errors.append(f"Message {ref.id}: {exc}")
            continue

        # 3. Duplicate detection by message_id within the same account
        if parsed.message_id:
            existing = db_session.query(Email).filter_by(
                email_account_id=account_id,
                message_id=parsed.message_id,
            ).first()
            if existing:
                result.skipped_duplicate += 1
                continue

        # 4. Persist
        db_email = Email(
            email_account_id=account_id,
            message_id=parsed.message_id,
            subject=parsed.subject,
            sender=parsed.sender,
            recipient=parsed.recipient,
            cc=parsed.cc,
            body_text=parsed.body_text,
            body_html=parsed.body_html,
            raw_headers=parsed.raw_headers,
            received_at=parsed.received_at,
        )
        db_session.add(db_email)
        result.persisted += 1

    if result.persisted > 0:
        db_session.commit()

    return result
