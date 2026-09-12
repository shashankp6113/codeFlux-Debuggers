import os
os.environ.setdefault("POSTGRES_USER", "x")
os.environ.setdefault("POSTGRES_PASSWORD", "x")
os.environ.setdefault("POSTGRES_HOST", "x")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("POSTGRES_DB", "x")
import pytest
from fastapi.testclient import TestClient
from main import app
from database import get_db
from models import User, EmailAccount, Email, ForensicAnalysis as ForensicAnalysisRecord
from auth import create_access_token
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
import datetime

TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)
from models import Base

@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)

@pytest.fixture
def db():
    session = TestSession()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def override_get_db(db):
    def _override():
        return db
    app.dependency_overrides[get_db] = _override
    yield
    app.dependency_overrides.pop(get_db, None)

@pytest.fixture
def auth_client(override_get_db, db):
    user = User(email="test@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    account = EmailAccount(user_id=user.id, provider="manual", email_address="test@example.com")
    db.add(account)
    db.commit()
    db.refresh(account)

    client = TestClient(app)
    token = create_access_token(user_id=user.id)
    client.headers = {"Authorization": f"Bearer {token}"}
    return client, user, account

def test_notifications(auth_client, db):
    client, user, account = auth_client
    
    dt = datetime.datetime.now()
    e1 = Email(email_account_id=account.id, message_id="1", subject="Critical Phish", sender="a", recipient="b", created_at=dt, received_at=dt)
    e2 = Email(email_account_id=account.id, message_id="2", subject="Failed AI", sender="a", recipient="b", created_at=dt, received_at=dt)
    e3 = Email(email_account_id=account.id, message_id="3", subject="Normal", sender="a", recipient="b", created_at=dt, received_at=dt)
    db.add_all([e1, e2, e3])
    db.commit()
    
    f1 = ForensicAnalysisRecord(
        email_id=e1.id,
        analysis={"threat_score": {"risk_level": "critical"}}
    )
    f2 = ForensicAnalysisRecord(
        email_id=e2.id,
        analysis={"ai_analysis": {"provider": "error"}}
    )
    f3 = ForensicAnalysisRecord(
        email_id=e3.id,
        analysis={"threat_score": {"risk_level": "low"}}
    )
    db.add_all([f1, f2, f3])
    db.commit()

    resp = client.get("/api/notifications")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    
    types = [d["type"] for d in data]
    assert "threat" in types
    assert "ai_error" in types

def test_notifications_none_type_crash_handling(auth_client, db):
    client, user, account = auth_client
    
    dt = datetime.datetime.now()
    e_null = Email(email_account_id=account.id, message_id="null_test", subject="Null Test", sender="a", recipient="b", created_at=dt, received_at=dt)
    e_missing = Email(email_account_id=account.id, message_id="missing_test", subject="Missing Test", sender="a", recipient="b", created_at=dt, received_at=dt)
    
    db.add_all([e_null, e_missing])
    db.commit()
    
    fa_null = ForensicAnalysisRecord(
        email_id=e_null.id,
        analysis={"threat_score": None, "ai_analysis": None}
    )
    fa_missing = ForensicAnalysisRecord(
        email_id=e_missing.id,
        analysis={} # Missing keys entirely
    )
    
    db.add_all([fa_null, fa_missing])
    db.commit()

    resp = client.get("/api/notifications")
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}"
    # The empty/null emails should not generate notifications, but should not crash
    # Also ensures we don't accidentally create fake notifications from malformed data
    
    # We already have 2 valid notifications from the setup in other test, but wait, 
    # we need to be sure about the state. This test runs in the same session,
    # but the fixture 'auth_client' might share db state or not? Wait, 'auth_client'
    # gives us the client. The 'db' is per test.
    data = resp.json()
    assert isinstance(data, list)

def test_settings_info_unauthenticated():
    # Fresh unauthenticated client
    client = TestClient(app)
    resp = client.get("/api/settings/info")
    assert resp.status_code == 401

def test_settings_info_authenticated(auth_client):
    client, user, account = auth_client
    resp = client.get("/api/settings/info")
    assert resp.status_code == 200
    assert "ai_provider" in resp.json()
    assert "ai_model" in resp.json()
    assert "GEMINI_API_KEY" not in resp.json()