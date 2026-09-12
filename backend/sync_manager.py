from pydantic import BaseModel
from typing import Dict, List, Optional
import threading

class SyncStatusResponse(BaseModel):
    status: str  # "idle", "syncing", "completed", "failed"
    total_discovered: int = 0
    processed: int = 0
    newly_added: int = 0
    skipped_duplicate: int = 0
    failed_count: int = 0
    errors: List[str] = []

_sync_states: Dict[int, SyncStatusResponse] = {}
_sync_lock = threading.Lock()

def get_sync_status(account_id: int) -> SyncStatusResponse:
    with _sync_lock:
        if account_id not in _sync_states:
            return SyncStatusResponse(status="idle")
        # Return a copy to avoid mutation issues during serialization
        return _sync_states[account_id].model_copy()

def start_sync(account_id: int) -> bool:
    """Marks account as syncing. Returns False if already syncing."""
    with _sync_lock:
        current = _sync_states.get(account_id)
        if current and current.status == "syncing":
            return False
        _sync_states[account_id] = SyncStatusResponse(status="syncing")
        return True

def finish_sync(account_id: int, status: str, errors: List[str] = None):
    with _sync_lock:
        if account_id in _sync_states:
            _sync_states[account_id].status = status
            if errors is not None:
                _sync_states[account_id].errors.extend(errors)

def record_progress(account_id: int, total_discovered: int = None, newly_added: int = 0, skipped: int = 0, failed: int = 0):
    with _sync_lock:
        if account_id in _sync_states:
            state = _sync_states[account_id]
            if total_discovered is not None:
                state.total_discovered = total_discovered
            if newly_added or skipped or failed:
                state.newly_added += newly_added
                state.skipped_duplicate += skipped
                state.failed_count += failed
                state.processed += (newly_added + skipped + failed)
