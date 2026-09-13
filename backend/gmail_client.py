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


class GmailAuthError(GmailAPIError):
    """Raised specifically for 401 Unauthorized API failures."""
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
        raise GmailAuthError("Gmail API authentication failed (401)")
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
        raise GmailAuthError("Gmail API authentication failed (401)")
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



import asyncio
from typing import Tuple, Dict, Optional
import httpx

async def _fetch_raw_message_async(client: httpx.AsyncClient, access_token: str, message_id: str, semaphore: asyncio.Semaphore) -> Tuple[str, Optional[bytes], Optional[Exception]]:
    async with semaphore:
        url = f"{_GMAIL_API_BASE}/users/me/messages/{message_id}"
        params = {"format": "raw"}
        try:
            resp = await client.get(
                url,
                headers=_auth_headers(access_token),
                params=params,
                timeout=_HTTP_TIMEOUT,
            )
            if resp.status_code == 401:
                return message_id, None, GmailAuthError("Gmail API authentication failed (401)")
            if resp.status_code == 429:
                return message_id, None, GmailAPIError("Gmail API rate limit exceeded (429)")
            if resp.status_code != 200:
                return message_id, None, GmailAPIError(f"Gmail API error retrieving message {message_id} (HTTP {resp.status_code})")
                
            data = resp.json()
            raw_b64 = data.get("raw")
            if not raw_b64:
                return message_id, None, GmailMessageError(f"Gmail message {message_id} has no 'raw' field")
                
            padded = raw_b64 + "=" * (4 - len(raw_b64) % 4)
            return message_id, base64.urlsafe_b64decode(padded), None
        except Exception as exc:
            return message_id, None, GmailAPIError(f"Network error retrieving message {message_id}: {exc}")

async def _fetch_all_raw_messages_async(access_token: str, message_ids: List[str], max_concurrent: int) -> Dict[str, Tuple[Optional[bytes], Optional[Exception]]]:
    results = {}
    semaphore = asyncio.Semaphore(max_concurrent)
    async with httpx.AsyncClient() as client:
        tasks = [
            _fetch_raw_message_async(client, access_token, mid, semaphore)
            for mid in message_ids
        ]
        completed = await asyncio.gather(*tasks)
        for mid, raw_bytes, exc in completed:
            results[mid] = (raw_bytes, exc)
    return results

def get_raw_messages_batch(access_token: str, message_ids: List[str], max_concurrent: int = 5) -> Dict[str, Tuple[Optional[bytes], Optional[Exception]]]:
    """Bridge to async concurrent fetcher, safe for standard synchronous threads."""
    if not message_ids:
        return {}
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # Fallback if somehow called from an active event loop
        import threading
        result = {}
        def _run_in_thread():
            nonlocal result
            result = asyncio.run(_fetch_all_raw_messages_async(access_token, message_ids, max_concurrent))
        t = threading.Thread(target=_run_in_thread)
        t.start()
        t.join()
        return result
    return asyncio.run(_fetch_all_raw_messages_async(access_token, message_ids, max_concurrent))

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
    """Retrieve, persist, and analyse Gmail messages for an EmailAccount."""
    from models import Email
    from analysis import run_email_analysis
    from sync_manager import record_progress

    effective_limit = max(1, min(limit, _MAX_LIMIT))
    result = GmailSyncResult()

    try:
        refs = list_message_ids(access_token, max_results=effective_limit)
        record_progress(account_id, db_session, total_discovered=len(refs))
    except GmailAuthError:
        raise
    except GmailAPIError as exc:
        result.errors.append(str(exc))
        return result

    # Bulk deduplication lookup
    ref_ids = [r.id for r in refs]
    from models import ForensicAnalysis
    existing_emails = db_session.query(Email).filter(
        Email.email_account_id == account_id,
        Email.message_id.in_(ref_ids)
    ).all()
    existing_map = {e.message_id: e for e in existing_emails}
    
    analysis_set = set()
    if existing_emails:
        existing_analyses = db_session.query(ForensicAnalysis.email_id).filter(
            ForensicAnalysis.email_id.in_([e.id for e in existing_emails])
        ).all()
        analysis_set = {fa[0] for fa in existing_analyses}

    # Phase 1: Determine which refs actually need to be fetched
    missing_refs = []
    for ref in refs:
        result.fetched += 1
        existing = existing_map.get(ref.id)
        if existing and existing.id in analysis_set:
            result.skipped_duplicate += 1
            record_progress(account_id, db_session, skipped=1)
            continue
        missing_refs.append(ref)

    # Release DB connection to pool during slow external HTTP batch fetch
    db_session.commit()

    # Bounded concurrent fetching of missing raw bytes (limit 5)
    missing_ids = [ref.id for ref in missing_refs]
    raw_results = get_raw_messages_batch(access_token, missing_ids, max_concurrent=5)

    # Phase 2: Process sequentially (preserves sync AI/VT/DB limits)
    for ref in missing_refs:
        
        raw_bytes, exc = raw_results.get(ref.id, (None, Exception("Failed to fetch message.")))
        if exc:
            if isinstance(exc, GmailAuthError):
                raise exc # Preserve token refresh logic bubble-up
            result.errors.append(f"Message {ref.id}: {exc}")
            record_progress(account_id, db_session, failed=1)
            continue
            
        try:
            parsed = convert_raw_to_parsed(raw_bytes)
        except GmailMessageError as exc:
            result.errors.append(f"Message {ref.id}: {exc}")
            record_progress(account_id, db_session, failed=1)
            continue

        existing = existing_map.get(ref.id)
        if existing:
            if existing.id in analysis_set:
                result.skipped_duplicate += 1
                record_progress(account_id, db_session, skipped=1)
                continue
            else:
                # Zombie state self-healing: Email exists but analysis failed previously
                try:
                    run_email_analysis(parsed, existing, db_session)
                    record_progress(account_id, db_session, newly_added=1)
                except Exception as exc:
                    db_session.rollback()
                    result.errors.append(f"Message {ref.id}: analysis retry failed: {exc}")
                    record_progress(account_id, db_session, failed=1)
                continue

        # If it doesn't exist, store it using Gmail's ref.id
        db_email = Email(
            email_account_id=account_id,
            message_id=ref.id,
            subject=parsed.subject,
            sender=parsed.sender,
            recipient=parsed.recipient,
            cc=parsed.cc,
            body_text=parsed.body_text,
            body_html=parsed.body_html,
            raw_headers=parsed.raw_headers,
            received_at=parsed.received_at,
        )
        
        try:
            db_session.add(db_email)
            db_session.commit()
            db_session.refresh(db_email)
            result.persisted += 1
        except Exception as exc:
            db_session.rollback()
            result.errors.append(f"Message {ref.id}: failed to save to database: {exc}")
            record_progress(account_id, db_session, failed=1)
            continue

        try:
            run_email_analysis(parsed, db_email, db_session)
            record_progress(account_id, db_session, newly_added=1)
        except Exception as exc:
            db_session.rollback()
            result.errors.append(f"Message {ref.id}: analysis failed: {exc}")
            record_progress(account_id, db_session, failed=1)

    return result
