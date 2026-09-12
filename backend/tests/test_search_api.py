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
from models import User, EmailAccount, Email
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

os.environ.setdefault("POSTGRES_USER", "x")
os.environ.setdefault("POSTGRES_PASSWORD", "x")
os.environ.setdefault("POSTGRES_HOST", "x")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("POSTGRES_DB", "x")

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

    # other user
    other = User(email="other@example.com")
    db.add(other)
    db.commit()
    db.refresh(other)

    other_account = EmailAccount(user_id=other.id, provider="manual", email_address="other@example.com")
    db.add(other_account)
    db.commit()

    client = TestClient(app)
    token = create_access_token(user_id=user.id)
    client.headers = {"Authorization": f"Bearer {token}"}
    return client, user, account, other_account

def test_search_emails(auth_client, db):
    client, user, account, other_account = auth_client
    
    # Add emails
    e1 = Email(email_account_id=account.id, message_id="1", subject="Invoice attached", sender="billing@acme.com", recipient="x", created_at=datetime.datetime.now())
    e2 = Email(email_account_id=account.id, message_id="2", subject="Team meeting", sender="boss@company.com", recipient="x", created_at=datetime.datetime.now())
    e3 = Email(email_account_id=other_account.id, message_id="3", subject="Invoice overdue", sender="billing@acme.com", recipient="x", created_at=datetime.datetime.now())
    
    db.add_all([e1, e2, e3])
    db.commit()

    # Search for invoice (case insensitive)
    resp = client.get("/api/emails?search=INVOICE")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["subject"] == "Invoice attached"
    
    # Search for boss sender
    resp2 = client.get("/api/emails?search=boss")
    assert resp2.status_code == 200
    assert len(resp2.json()) == 1
    assert resp2.json()[0]["subject"] == "Team meeting"
    
    # Empty search returns all for user
    resp3 = client.get("/api/emails")
    assert resp3.status_code == 200
    assert len(resp3.json()) == 2
