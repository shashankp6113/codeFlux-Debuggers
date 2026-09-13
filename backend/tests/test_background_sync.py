import os
os.environ.setdefault("POSTGRES_USER", "x")
os.environ.setdefault("POSTGRES_PASSWORD", "x")
os.environ.setdefault("POSTGRES_HOST", "x")
os.environ.setdefault("POSTGRES_PORT", "5432")

import pytest
from fastapi.testclient import TestClient
from main import app
from models import Base
from database import get_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from models import User, EmailAccount
from auth import create_access_token
from sync_manager import get_sync_status, start_sync, finish_sync


TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()



@pytest.fixture(autouse=True)
def override_dependencies():
    old = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    yield
    if old is not None:
        app.dependency_overrides[get_db] = old
    else:
        app.dependency_overrides.pop(get_db, None)

client = TestClient(app)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=TEST_ENGINE)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=TEST_ENGINE)
    # Clear sync state between tests

@pytest.fixture(scope="function")
def test_user(db_session):
    u = User(email="test@gmail.com", name="Test")
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u

@pytest.fixture(scope="function")
def test_account(db_session, test_user):
    acc = EmailAccount(user_id=test_user.id, provider="gmail", email_address="test@gmail.com", access_token="fake")
    db_session.add(acc)
    db_session.commit()
    db_session.refresh(acc)
    return acc

def test_sync_request_returns_quickly(test_user, test_account, monkeypatch):
    monkeypatch.setattr('main.run_sync_job', lambda *args, **kwargs: None)
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Trigger sync
    response = client.post(f"/api/gmail/{test_account.id}/messages", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Sync started"

def test_cannot_start_concurrent_sync(db_session, test_user, test_account, monkeypatch):
    monkeypatch.setattr('main.run_sync_job', lambda *args, **kwargs: None)
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Start sync manually in state
    start_sync(test_account.id, db_session)
    
    # Trigger sync
    response = client.post(f"/api/gmail/{test_account.id}/messages", headers=headers)
    assert response.status_code == 409
    assert "already in progress" in response.json()["detail"]

def test_sync_status_endpoint(db_session, test_user, test_account, monkeypatch):
    monkeypatch.setattr('main.run_sync_job', lambda *args, **kwargs: None)
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    start_sync(test_account.id, db_session)
    
    response = client.get(f"/api/gmail/{test_account.id}/sync-status", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "syncing"
    
    finish_sync(test_account.id, db_session, status="completed")
    
    response = client.get(f"/api/gmail/{test_account.id}/sync-status", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "completed"

def test_status_authorization(db_session, test_account):
    u2 = User(email="other@gmail.com")
    db_session.add(u2)
    db_session.commit()
    db_session.refresh(u2)
    
    token = create_access_token(u2.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get(f"/api/gmail/{test_account.id}/sync-status", headers=headers)
    assert response.status_code == 404


def test_fixture_isolation(db_session):
    """Verify the test uses SQLite in-memory, not Postgres."""
    assert TEST_ENGINE.url.drivername == "sqlite"
    assert "postgres" not in str(TEST_ENGINE.url)


def test_sync_refreshes_expired_access_token(db_session, test_user, monkeypatch):
    import main
    from gmail_client import GmailAuthError, GmailSyncResult
    import database
    
    # Setup account with refresh token
    acc = EmailAccount(user_id=test_user.id, provider="gmail", email_address="ref@test", access_token="expired", refresh_token="valid_rt")
    db_session.add(acc)
    db_session.commit()
    db_session.refresh(acc)
    
    calls = []
    def mock_sync(account_id, access_token, db_session, limit):
        calls.append(access_token)
        if access_token == "expired":
            raise GmailAuthError("401")
        return GmailSyncResult()
        
    def mock_refresh(config, refresh_token):
        assert refresh_token == "valid_rt"
        return "new_access", "new_rt"
        
    def mock_config():
        return None

    class DummySession:
        def __init__(self, s):
            self._s = s
        def __getattr__(self, name):
            return getattr(self._s, name)
        def close(self):
            pass
            
    import gmail_client
    monkeypatch.setattr(gmail_client, "sync_gmail_messages", mock_sync)
    monkeypatch.setattr(database, "SessionLocal", lambda: DummySession(db_session))
    
    import gmail_oauth
    monkeypatch.setattr(gmail_oauth, "refresh_access_token", mock_refresh)
    monkeypatch.setattr(gmail_oauth, "get_oauth_config", mock_config)
    
    acc_id = acc.id
    start_sync(acc_id, db_session)
    main.run_sync_job(acc_id, "expired", 5)
    
    assert len(calls) == 2
    assert calls[0] == "expired"
    assert calls[1] == "new_access"
    
    db_session.refresh(acc)
    assert acc.access_token == "new_access"
    assert acc.refresh_token == "new_rt"
    
    status = get_sync_status(acc_id, db_session)
    assert status.status == "completed"

def test_sync_does_not_retry_401_more_than_once(db_session, test_user, monkeypatch):
    import main
    from gmail_client import GmailAuthError
    import database
    
    acc = EmailAccount(user_id=test_user.id, provider="gmail", email_address="ref@test", access_token="expired", refresh_token="valid_rt")
    db_session.add(acc)
    db_session.commit()
    db_session.refresh(acc)
    
    calls = []
    def mock_sync(account_id, access_token, db_session, limit):
        calls.append(access_token)
        raise GmailAuthError("401")
        
    def mock_refresh(config, refresh_token):
        return "new_access", "new_rt"
        
    def mock_config():
        return None
        
    class DummySession:
        def __init__(self, s):
            self._s = s
        def __getattr__(self, name):
            return getattr(self._s, name)
        def close(self):
            pass

    import gmail_client
    monkeypatch.setattr(gmail_client, "sync_gmail_messages", mock_sync)
    monkeypatch.setattr(database, "SessionLocal", lambda: DummySession(db_session))
    
    import gmail_oauth
    monkeypatch.setattr(gmail_oauth, "refresh_access_token", mock_refresh)
    monkeypatch.setattr(gmail_oauth, "get_oauth_config", mock_config)
    
    acc_id = acc.id
    start_sync(acc_id, db_session)
    main.run_sync_job(acc_id, "expired", 5)
    
    assert len(calls) == 2
    
    status = get_sync_status(acc_id, db_session)
    assert status.status == "failed"
    assert "401" in status.errors[0]

def test_sync_without_refresh_token(db_session, test_user, monkeypatch):
    import main
    from gmail_client import GmailAuthError
    import database
    
    acc = EmailAccount(user_id=test_user.id, provider="gmail", email_address="ref@test", access_token="expired", refresh_token=None)
    db_session.add(acc)
    db_session.commit()
    db_session.refresh(acc)
    
    calls = []
    def mock_sync(account_id, access_token, db_session, limit):
        calls.append(access_token)
        raise GmailAuthError("401")
        
    class DummySession:
        def __init__(self, s):
            self._s = s
        def __getattr__(self, name):
            return getattr(self._s, name)
        def close(self):
            pass

    import gmail_client
    monkeypatch.setattr(gmail_client, "sync_gmail_messages", mock_sync)
    monkeypatch.setattr(database, "SessionLocal", lambda: DummySession(db_session))
    
    acc_id = acc.id
    start_sync(acc_id, db_session)
    main.run_sync_job(acc_id, "expired", 5)
    
    assert len(calls) == 1
    
    status = get_sync_status(acc_id, db_session)
    assert status.status == "failed"
    assert "no refresh token is available" in status.errors[0]
