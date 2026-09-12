import pytest
from fastapi.testclient import TestClient
from auth import create_access_token
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os

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

from models import Base, User, EmailAccount, Email, ForensicAnalysis
from database import get_db
from main import app
from ai_analysis import AIAnalysisResult

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
    user = User(email="retry_user@test.local")
    db.add(user)
    db.commit()
    db.refresh(user)

    account = EmailAccount(user_id=user.id, provider="manual_upload", email_address="retry@test.local")
    db.add(account)
    db.commit()
    db.refresh(account)

    client = TestClient(app)
    token = create_access_token(user_id=user.id)
    client.headers = {"Authorization": f"Bearer {token}"}
    return client, user, account

def test_retry_ai_success(auth_client, db, monkeypatch):
    client, user, account = auth_client
    
    email = Email(
        email_account_id=account.id,
        message_id="test_retry_1",
        subject="Test Retry",
        sender="sender@test.local",
        recipient="recipient@test.local",
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    
    fa = ForensicAnalysis(
        email_id=email.id,
        analysis={
            "threat_score": {"score": 50, "risk_level": "medium", "rule_contributions": [], "category_scores": {}},
            "ioc_extraction": {"iocs": [], "stats": {}},
            "threat_intelligence": {"enrichments": [], "stats": {}, "provider": "noop"},
            "geolocation": {"results": [], "stats": {}, "provider": "noop"},
            "ai_analysis": {
                "classification": "unknown",
                "provider": "error",
                "error": "Previous failure"
            }
        }
    )
    db.add(fa)
    db.commit()
    
    class FakeSuccessProvider:
        def analyze(self, evidence):
            return AIAnalysisResult(
                classification="suspicious",
                confidence=0.8,
                summary="Retried successfully",
                provider="gemini",
            )
            
    def mock_get_ai_provider():
        return FakeSuccessProvider()
        
    monkeypatch.setattr("ai_analysis.get_ai_provider", mock_get_ai_provider)
    
    resp = client.post(f"/api/emails/{email.id}/retry-ai")
    assert resp.status_code == 200
    data = resp.json()
    
    assert data["forensics"]["ai_analysis"]["classification"] == "suspicious"
    assert data["forensics"]["ai_analysis"]["summary"] == "Retried successfully"
    assert "error" not in data["forensics"]["ai_analysis"] or not data["forensics"]["ai_analysis"]["error"]
    assert data["forensics"]["threat_score"]["score"] == 50
    
def test_retry_ai_failure(auth_client, db, monkeypatch):
    client, user, account = auth_client
    
    email = Email(
        email_account_id=account.id,
        message_id="test_retry_2", sender="a", recipient="b", subject="Test Retry",
    )
    db.add(email)
    db.commit()
    
    fa = ForensicAnalysis(
        email_id=email.id,
        analysis={
            "threat_score": {"score": 50, "risk_level": "medium", "rule_contributions": [], "category_scores": {}},
            "ioc_extraction": {"iocs": [], "stats": {}},
            "threat_intelligence": {"enrichments": [], "stats": {}, "provider": "noop"},
            "geolocation": {"results": [], "stats": {}, "provider": "noop"},
            "ai_analysis": {
                "classification": "unknown",
                "provider": "error",
                "error": "Initial failure",
                "summary": "",
                "explanation": "",
                "recommended_actions": []
            }
        }
    )
    db.add(fa)
    db.commit()
    
    def mock_get_ai_provider():
        raise ValueError("Simulated provider crash")
        
    monkeypatch.setattr("ai_analysis.get_ai_provider", mock_get_ai_provider)
    
    resp = client.post(f"/api/emails/{email.id}/retry-ai")
    assert resp.status_code == 200
    data = resp.json()
    
    assert data["forensics"]["ai_analysis"]["provider"] == "error"
    assert "Simulated provider crash" in data["forensics"]["ai_analysis"]["error"]

def test_retry_unauthenticated():
    client = TestClient(app)
    resp = client.post("/api/emails/999/retry-ai")
    assert resp.status_code == 401
    
def test_retry_wrong_user(auth_client, db):
    client, user, account = auth_client
    
    other_user = User(email="other@test.local")
    db.add(other_user)
    db.commit()
    
    other_account = EmailAccount(user_id=other_user.id, provider="manual_upload", email_address="other@test.local")
    db.add(other_account)
    db.commit()
    
    email = Email(email_account_id=other_account.id, message_id="other", sender="a", recipient="b", subject="c")
    db.add(email)
    db.commit()
    
    resp = client.post(f"/api/emails/{email.id}/retry-ai")
    assert resp.status_code == 404

def test_retry_missing_analysis(auth_client, db):
    client, user, account = auth_client
    
    email = Email(email_account_id=account.id, message_id="missing", sender="a", recipient="b", subject="c")
    db.add(email)
    db.commit()
    
    resp = client.post(f"/api/emails/{email.id}/retry-ai")
    assert resp.status_code == 404
