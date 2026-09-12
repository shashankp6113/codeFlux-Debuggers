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
from sync_manager import _sync_states, get_sync_status, start_sync, finish_sync


TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)

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
    _sync_states.clear()

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

def test_sync_request_returns_quickly(test_user, test_account):
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Trigger sync
    response = client.post(f"/api/gmail/{test_account.id}/messages", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Sync started"

def test_cannot_start_concurrent_sync(test_user, test_account):
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Start sync manually in state
    start_sync(test_account.id)
    
    # Trigger sync
    response = client.post(f"/api/gmail/{test_account.id}/messages", headers=headers)
    assert response.status_code == 409
    assert "already in progress" in response.json()["detail"]

def test_sync_status_endpoint(test_user, test_account):
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    start_sync(test_account.id)
    
    response = client.get(f"/api/gmail/{test_account.id}/sync-status", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "syncing"
    
    finish_sync(test_account.id, status="completed")
    
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
