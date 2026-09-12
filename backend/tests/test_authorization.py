import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from main import app
from database import get_db
from models import Base, User, EmailAccount, Email, ForensicAnalysis
from auth import create_access_token
from datetime import datetime, timezone

engine = create_engine(
    "sqlite://",
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

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    old = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    
    db = TestingSessionLocal()
    
    user_a = User(id=1, email="user_a@example.com")
    db.add(user_a)
    acc_a = EmailAccount(id=1, user_id=1, provider="gmail", email_address="user_a@example.com")
    db.add(acc_a)
    email_a = Email(id=1, email_account_id=1, sender="a", recipient="a", received_at=datetime.now(timezone.utc))
    db.add(email_a)
    fa_a_data = {
        "threat_score": {"score": 90, "risk_level": "critical", "factors": []},
        "ioc_extraction": {
            "iocs": [
                {"ioc_type": "ip", "value": "1.1.1.1", "source": "header", "context": "Received"}
            ]
        },
        "threat_intelligence": {
            "enrichments": [
                {"ioc_type": "ip", "ioc_value": "1.1.1.1", "verdict": "malicious", "confidence": 0.99, "country": "US", "asn": "AS13335"}
            ]
        }
    }
    fa_a = ForensicAnalysis(id=1, email_id=1, analysis=fa_a_data)
    db.add(fa_a)
    
    user_b = User(id=2, email="user_b@example.com")
    db.add(user_b)
    acc_b = EmailAccount(id=2, user_id=2, provider="gmail", email_address="user_b@example.com")
    db.add(acc_b)
    email_b = Email(id=2, email_account_id=2, sender="b", recipient="b", received_at=datetime.now(timezone.utc))
    db.add(email_b)
    fa_b = ForensicAnalysis(id=2, email_id=2, analysis={"threat_score": {"score": 10, "risk_level": "low", "factors": []}})
    db.add(fa_b)
    
    db.commit()
    db.close()
    
    yield
    
    if old is not None:
        app.dependency_overrides[get_db] = old
    else:
        app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=engine)

def test_unauthenticated_request():
    r = client.get("/api/emails")
    assert r.status_code == 401

def test_user_a_sees_only_user_a_emails():
    token = create_access_token(1)
    r = client.get("/api/emails", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["id"] == 1
    
def test_user_b_sees_only_user_b_emails():
    token = create_access_token(2)
    r = client.get("/api/emails", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["id"] == 2

def test_user_a_cannot_use_user_b_account_for_sync(monkeypatch):
    monkeypatch.setattr("main.sync_gmail_messages", lambda *a, **kw: None)
    token = create_access_token(1)
    r = client.get("/api/gmail/2/messages", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404
    assert r.json()["detail"] == "EmailAccount not found"

def test_user_a_dashboard_isolation():
    token = create_access_token(1)
    r = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["total_emails"] == 1
    assert data["critical"] == 1
    
    token_b = create_access_token(2)
    r_b = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {token_b}"})
    assert r_b.status_code == 200
    data_b = r_b.json()
    assert data_b["total_emails"] == 1
    assert data_b["critical"] == 0

def test_upload_fallback_scoped_to_user(monkeypatch):
    from email_parser import ParsedEmail
    monkeypatch.setattr("main.run_email_analysis", lambda *a, **kw: {"threat_score": {"score": 0, "risk_level": "low", "factors": []}})
    parsed_mock = ParsedEmail(
        message_id="test",
        subject="test",
        sender="a@a.com",
        recipient="b@b.com",
        cc=None,
        body_text="test",
        body_html="",
        raw_headers="",
        received_at=datetime.now(timezone.utc)
    )
    monkeypatch.setattr("main.parse_eml", lambda x: parsed_mock)
    
    token = create_access_token(1)
    r = client.post(
        "/api/emails/upload", 
        files={"file": ("test.eml", b"test")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200
    data = r.json()
    
    db = TestingSessionLocal()
    email = db.query(Email).filter_by(id=data["id"]).first()
    assert email.email_account.user_id == 1
    assert email.email_account.provider == "manual_upload"
    db.close()

def test_user_a_threats_isolation():
    token = create_access_token(1)
    r = client.get("/api/threats", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["id"] == 1
    assert data[0]["risk_level"] == "critical"

def test_user_b_threats_isolation():
    token = create_access_token(2)
    # User B has risk_level="low", and our default filter requires risk in [medium, high, critical] or score > 0
    # Wait, in setup_db we gave user B threat_score={"score": 10, "risk_level": "low"}
    # Since score=10 is > 0, it WILL be returned as a threat.
    r = client.get("/api/threats", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["id"] == 2
    assert data[0]["risk_level"] == "low"

def test_threats_unauthenticated():
    r = client.get("/api/threats")
    assert r.status_code == 401

def test_user_a_iocs_isolation():
    token = create_access_token(1)
    r = client.get("/api/iocs", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert "iocs" in data
    assert len(data["iocs"]) == 1
    assert data["iocs"][0]["value"] == "1.1.1.1"
    assert data["iocs"][0]["verdict"] == "malicious"
    assert data["iocs"][0]["country"] == "US"
    assert data["stats"]["total"] == 1
    assert data["stats"]["ip"] == 1

def test_iocs_unauthenticated():
    r = client.get("/api/iocs")
    assert r.status_code == 401

def test_user_a_can_get_report_for_email_a():
    token = create_access_token(1)
    r = client.get("/api/emails/1/report", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == 1
    assert "forensics" in data

def test_user_a_cannot_get_report_for_email_b():
    token = create_access_token(1)
    r = client.get("/api/emails/2/report", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404

def test_get_report_unauthenticated():
    r = client.get("/api/emails/1/report")
    assert r.status_code == 401
