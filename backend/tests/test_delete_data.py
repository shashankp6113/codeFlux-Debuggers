import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from main import app
from models import Base, User, EmailAccount, Email, ForensicAnalysis
from database import get_db
from auth import create_access_token

engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def setup_db_and_app():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()

def test_delete_email_account_cascades_and_revokes(monkeypatch):
    revoked_tokens = []
    def mock_revoke(token):
        revoked_tokens.append(token)
        return True
    monkeypatch.setattr("gmail_oauth.revoke_google_token", mock_revoke)

    db = TestingSessionLocal()
    user = User(email="delete_test@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    account = EmailAccount(
        user_id=user.id, provider="gmail", email_address="delete_test@example.com",
        access_token="acc123", refresh_token="ref123"
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    email = Email(
        email_account_id=account.id, sender="a@b.com", recipient="c@d.com",
        subject="Test", message_id="msg123"
    )
    db.add(email)
    db.commit()
    db.refresh(email)

    fa = ForensicAnalysis(email_id=email.id, analysis={"test": 1})
    db.add(fa)
    db.commit()

    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    assert db.query(EmailAccount).filter_by(id=account.id).count() == 1
    assert db.query(Email).filter_by(id=email.id).count() == 1
    assert db.query(ForensicAnalysis).filter_by(email_id=email.id).count() == 1

    res = client.delete(f"/api/gmail/{account.id}", headers=headers)
    assert res.status_code == 200

    assert "ref123" in revoked_tokens
    assert db.query(EmailAccount).filter_by(id=account.id).count() == 0
    assert db.query(Email).filter_by(id=email.id).count() == 0
    assert db.query(ForensicAnalysis).filter_by(email_id=email.id).count() == 0
    assert db.query(User).filter_by(id=user.id).count() == 1
    db.close()

def test_delete_user_cascades_and_revokes(monkeypatch):
    revoked_tokens = []
    def mock_revoke(token):
        revoked_tokens.append(token)
        return True
    monkeypatch.setattr("gmail_oauth.revoke_google_token", mock_revoke)

    db = TestingSessionLocal()
    user = User(email="del_user@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    account = EmailAccount(
        user_id=user.id, provider="gmail", email_address="del_user@example.com",
        access_token="acc999"
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.delete("/api/users/me", headers=headers)
    assert res.status_code == 200

    assert "acc999" in revoked_tokens
    assert db.query(User).filter_by(id=user.id).count() == 0
    assert db.query(EmailAccount).filter_by(id=account.id).count() == 0
    db.close()

def test_delete_email_account_unauthorized_ownership(monkeypatch):
    revoked_tokens = []
    def mock_revoke(token):
        revoked_tokens.append(token)
        return True
    monkeypatch.setattr("gmail_oauth.revoke_google_token", mock_revoke)

    db = TestingSessionLocal()
    
    # Create User A
    user_a = User(email="user_a@example.com")
    db.add(user_a)
    db.commit()
    db.refresh(user_a)

    # Create User B
    user_b = User(email="user_b@example.com")
    db.add(user_b)
    db.commit()
    db.refresh(user_b)

    # Create EmailAccount for User B
    account_b = EmailAccount(
        user_id=user_b.id, provider="gmail", email_address="user_b@example.com",
        access_token="acc_b", refresh_token="ref_b"
    )
    db.add(account_b)
    db.commit()
    db.refresh(account_b)

    # Authenticate as User A
    token_a = create_access_token(user_a.id)
    headers = {"Authorization": f"Bearer {token_a}"}

    # Attempt to delete User B's account
    res = client.delete(f"/api/gmail/{account_b.id}", headers=headers)
    
    # Assert HTTP 404
    assert res.status_code == 404

    # Assert no revocation occurred
    assert len(revoked_tokens) == 0

    # Assert User B's account still exists
    assert db.query(EmailAccount).filter_by(id=account_b.id).count() == 1
    
    db.close()
