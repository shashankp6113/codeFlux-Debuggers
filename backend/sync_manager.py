from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.exc import IntegrityError
from models import EmailAccountSyncState

class SyncStatusResponse(BaseModel):
    status: str  # "idle", "syncing", "completed", "failed"
    total_discovered: int = 0
    processed: int = 0
    newly_added: int = 0
    skipped_duplicate: int = 0
    failed_count: int = 0
    errors: List[str] = []

def get_sync_status(account_id: int, db) -> SyncStatusResponse:
    state = db.query(EmailAccountSyncState).filter_by(email_account_id=account_id).first()
    if not state:
        return SyncStatusResponse(status="idle")
    return SyncStatusResponse(
            status=state.status,
            total_discovered=state.total_discovered,
            processed=state.processed,
            newly_added=state.newly_added,
            skipped_duplicate=state.skipped_duplicate,
            failed_count=state.failed_count,
            errors=state.errors or []
        )

def _get_or_create_state_for_update(account_id: int, db) -> EmailAccountSyncState:
    state = db.query(EmailAccountSyncState).filter_by(email_account_id=account_id).with_for_update().first()
    if not state:
        try:
            db.begin_nested()
            new_state = EmailAccountSyncState(email_account_id=account_id, status="idle")
            db.add(new_state)
            db.commit()
        except IntegrityError:
            db.rollback()
        state = db.query(EmailAccountSyncState).filter_by(email_account_id=account_id).with_for_update().first()
    return state

def start_sync(account_id: int, db) -> bool:
    """Marks account as syncing. Returns False if already syncing."""
    state = _get_or_create_state_for_update(account_id, db)
        
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if state.status == "syncing":
        if state.updated_at and (now - state.updated_at) < timedelta(minutes=5):
            db.rollback()
            return False
                
    state.status = "syncing"
    state.total_discovered = 0
    state.processed = 0
    state.newly_added = 0
    state.skipped_duplicate = 0
    state.failed_count = 0
    state.errors = []
    state.updated_at = now

    db.commit()
    return True

def finish_sync(account_id: int, db, status: str, errors: List[str] = None):
    state = _get_or_create_state_for_update(account_id, db)
    state.status = status
    if errors:
        current_errors = list(state.errors) if state.errors else []
        current_errors.extend(errors)
        state.errors = current_errors
    state.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

def record_progress(account_id: int, db, total_discovered: int = None, newly_added: int = 0, skipped: int = 0, failed: int = 0):
    state = _get_or_create_state_for_update(account_id, db)
    if total_discovered is not None:
        state.total_discovered = total_discovered
    if newly_added or skipped or failed:
        state.newly_added += newly_added
        state.skipped_duplicate += skipped
        state.failed_count += failed
        state.processed += (newly_added + skipped + failed)
    state.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
