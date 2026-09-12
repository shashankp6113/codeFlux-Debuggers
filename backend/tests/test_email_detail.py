import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from main import app
from database import get_db
from models import Base, User, EmailAccount, Email, ForensicAnalysis
from auth import create_access_token
import json

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


client = TestClient(app)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=TEST_ENGINE)
    old = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    
    session = TestingSessionLocal()
    yield session
    session.close()
    
    if old is not None:
        app.dependency_overrides[get_db] = old
    else:
        app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=TEST_ENGINE)

def test_fixture_isolation(db_session):
    """Verify the test uses SQLite in-memory, not Postgres."""
    assert TEST_ENGINE.url.drivername == "sqlite"
    assert TEST_ENGINE.url.database is None
    # We ensure we are NOT connected to the Postgres db
    assert "postgres" not in str(TEST_ENGINE.url)

@pytest.fixture(scope="function")
def test_user(db_session):
    u = User(email="test@gmail.com", name="Test")
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u

@pytest.fixture(scope="function")
def other_user(db_session):
    u = User(email="other@gmail.com", name="Other")
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

@pytest.fixture(scope="function")
def test_email(db_session, test_account):
    eml = Email(
        email_account_id=test_account.id,
        message_id="msg123",
        subject="Test Subject",
        sender="sender@test.com",
        recipient="test@gmail.com",
    )
    db_session.add(eml)
    db_session.commit()
    db_session.refresh(eml)
    
    fa = ForensicAnalysis(
        email_id=eml.id,
        analysis={"test": "data"}
    )
    db_session.add(fa)
    db_session.commit()
    
    return eml

def test_get_email_authenticated(test_user, test_email):
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get(f"/api/emails/{test_email.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == test_email.id
    assert data["subject"] == "Test Subject"
    assert "forensics" in data
    assert "access_token" not in data # Ensure tokens aren't leaked

def test_get_email_unauthenticated(test_email):
    response = client.get(f"/api/emails/{test_email.id}")
    assert response.status_code == 401

def test_get_email_cross_user(other_user, test_email):
    token = create_access_token(other_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get(f"/api/emails/{test_email.id}", headers=headers)
    assert response.status_code == 404 # Should be 404, not 401/403 to prevent enum

def test_get_email_not_found(test_user):
    token = create_access_token(test_user.id)
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/api/emails/9999", headers=headers)
    assert response.status_code == 404
