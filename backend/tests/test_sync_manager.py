import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from models import Base

TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)

@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

from datetime import datetime, timedelta, timezone
from models import EmailAccount, User
from sync_manager import start_sync, finish_sync, record_progress, get_sync_status, _get_or_create_state_for_update


def test_sync_manager_flow(db_session):
    u = User(email="sm@test.com")
    db_session.add(u)
    db_session.commit()
    
    acc = EmailAccount(user_id=u.id, provider="gmail", email_address="sm@test.com", access_token="t")
    db_session.add(acc)
    db_session.commit()
    
    # 1. Initially idle
    status = get_sync_status(acc.id, db_session)
    assert status.status == "idle"
    
    # 2. Acquire lock successfully
    assert start_sync(acc.id, db_session) is True
    status = get_sync_status(acc.id, db_session)
    assert status.status == "syncing"
    
    # 3. Second acquisition rejected
    assert start_sync(acc.id, db_session) is False
    
    # 4. Progress updates
    record_progress(acc.id, db_session, total_discovered=10, newly_added=2, skipped=3)
    status = get_sync_status(acc.id, db_session)
    assert status.total_discovered == 10
    assert status.processed == 5
    assert status.newly_added == 2
    assert status.skipped_duplicate == 3
    
    # 5. Finish sync
    finish_sync(acc.id, db_session, "completed")
    status = get_sync_status(acc.id, db_session)
    assert status.status == "completed"

def test_stale_sync_recovery(db_session):
    u = User(email="stale@test.com")
    db_session.add(u)
    db_session.commit()
    acc = EmailAccount(user_id=u.id, provider="gmail", email_address="stale@test.com", access_token="t")
    db_session.add(acc)
    db_session.commit()
    
    assert start_sync(acc.id, db_session) is True
    
    # Manually backdate updated_at
    state = _get_or_create_state_for_update(acc.id, db_session)
    state.updated_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=6)
    db_session.commit()
        
    # Should recover stale sync
    assert start_sync(acc.id, db_session) is True
