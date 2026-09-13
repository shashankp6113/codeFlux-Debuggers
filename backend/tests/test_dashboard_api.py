"""API tests for the read-only dashboard and emails endpoints."""

import os
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Use in-memory SQLite with StaticPool so all connections share one DB
TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)

# Patch env vars before importing app modules
os.environ.setdefault("POSTGRES_USER", "x")
os.environ.setdefault("POSTGRES_PASSWORD", "x")
os.environ.setdefault("POSTGRES_HOST", "x")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("POSTGRES_DB", "x")
os.environ.setdefault("GEOLOCATION_PROVIDER", "noop")

from models import Base, User, EmailAccount, Email, ForensicAnalysis as ForensicAnalysisRecord
from database import get_db
from main import app
from auth import create_access_token


def override_get_db():
    try:
        db = TestSession()
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    """Create fresh tables for every test and set dependency override locally."""
    Base.metadata.create_all(bind=TEST_ENGINE)
    
    old_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    
    db = TestSession()
    
    # Create required parent records
    user = User(email="test@example.com", name="Test User")
    db.add(user)
    db.commit()
    
    account = EmailAccount(user_id=user.id, provider="gmail", email_address="test@example.com")
    db.add(account)
    db.commit()
    
    yield
    
    db.close()
    
    # Restore previous override to avoid breaking other test modules
    if old_override:
        app.dependency_overrides[get_db] = old_override
    else:
        app.dependency_overrides.pop(get_db, None)
        
    Base.metadata.drop_all(bind=TEST_ENGINE)


def _create_mock_email(db, account_id, subject, risk_level, ai_classification, iocs=None, threat_intel=None):
    """Helper to insert an email with some forensic data."""
    if iocs is None:
        iocs = []
    # Ensure required fields for Pydantic schema
    for ioc in iocs:
        if "value" not in ioc: ioc["value"] = ioc.get("ioc_value", "unknown")
        if "source" not in ioc: ioc["source"] = "mock"
        if "context" not in ioc: ioc["context"] = "mock context"
    if threat_intel is None:
        threat_intel = []
        
    email = Email(
        email_account_id=account_id,
        message_id=f"<{subject.replace(' ', '')}@test.local>",
        subject=subject,
        sender="sender@example.com",
        recipient="recipient@example.com",
        received_at=datetime.now(timezone.utc)
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    
    analysis_data = {
        "threat_score": {
            "score": 100 if risk_level == "critical" else 75 if risk_level == "high" else 50 if risk_level == "medium" else 0,
            "risk_level": risk_level,
            "category_scores": {},
            "rule_contributions": []
        },
        "ai_analysis": {
            "classification": ai_classification,
            "confidence": 0.9,
            "provider": "mock",
            "error": None
        },
        "ioc_extraction": {
            "iocs": iocs,
            "stats": {}
        },
        "threat_intelligence": {
            "enrichments": threat_intel,
            "stats": {},
            "provider": "mock"
        }
    }
    
    fa = ForensicAnalysisRecord(
        email_id=email.id,
        analysis=analysis_data
    )
    db.add(fa)
    db.commit()
    
    return email


class TestDashboardAPI:
    """Tests for GET /api/dashboard/summary and GET /api/emails."""

    def test_get_emails_empty(self):
        """GET /api/emails returns empty list when no data."""
        r = client.get("/api/emails", headers={"Authorization": f"Bearer {create_access_token(1)}"})
        assert r.status_code == 200
        assert r.json() == []
        
    def test_get_dashboard_empty(self):
        """GET /api/dashboard/summary handles empty database."""
        r = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {create_access_token(1)}"})
        assert r.status_code == 200
        data = r.json()
        assert data["total_emails"] == 0
        assert data["threats_detected"] == 0
        assert data["high_risk"] == 0
        assert data["critical"] == 0
        assert data["recent_investigations"] == []
        assert data["threat_distribution"] == {}
        assert data["ioc_summary"] == {}

    def test_dashboard_with_data(self):
        """GET /api/dashboard/summary aggregates data correctly, including new multi-engine threat counts."""
        db = TestSession()
        account = db.query(EmailAccount).first()
        
        # 1. Benign / Safe -> not a threat
        _create_mock_email(db, account.id, "Normal 1", "low", "benign")
        _create_mock_email(db, account.id, "Normal 2", "low", "unknown")
        
        # 2. AI Suspicious with low rule score -> is a threat
        _create_mock_email(db, account.id, "AI Suspicious", "low", "suspicious")
        
        # 3. AI Malicious -> is a threat
        _create_mock_email(db, account.id, "AI Malicious", "low", "malicious")
        
        # 4. Medium risk deterministic -> is a threat
        _create_mock_email(db, account.id, "Medium Risk", "medium", "unknown")
        
        # 5. Threat Intel malicious -> is a threat
        _create_mock_email(db, account.id, "TI Malicious", "low", "unknown", threat_intel=[
            {"ioc_type": "domain", "ioc_value": "bad.com", "verdict": "malicious"}
        ])
        
        # 6. High risk (counts as threat and high_risk)
        _create_mock_email(db, account.id, "High Risk", "high", "unknown")
        
        # 7. Critical risk (counts as threat and critical)
        _create_mock_email(db, account.id, "Critical Risk", "critical", "unknown")
        
        db.close()
        
        r = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {create_access_token(1)}"})
        assert r.status_code == 200
        data = r.json()
        
        assert data["total_emails"] == 8
        # Threats: AI Suspicious(1), AI Malicious(1), Medium(1), TI Malicious(1), High(1), Critical(1) = 6
        assert data["threats_detected"] == 6
        assert data["high_risk"] == 1
        assert data["critical"] == 1
        
        assert len(data["recent_investigations"]) == 5
        
        assert data["threat_distribution"] == {
            "benign": 1,
            "unknown": 5,
            "suspicious": 1,
            "malicious": 1
        }
        

    def test_ioc_summary_and_missing_fields(self):
        """GET /api/dashboard/summary handles exact IOC summary and missing fields gracefully."""
        db = TestSession()
        account = db.query(EmailAccount).first()
        
        # Email with some IOCs
        _create_mock_email(db, account.id, "IOC Email 1", "low", "benign", iocs=[
            {"ioc_type": "ip", "ioc_value": "1.1.1.1"},
            {"ioc_type": "ip", "ioc_value": "2.2.2.2"},
            {"ioc_type": "domain", "ioc_value": "example.com"}
        ])
        
        # Email with overlapping IOC types
        _create_mock_email(db, account.id, "IOC Email 2", "low", "benign", iocs=[
            {"ioc_type": "domain", "ioc_value": "test.com"},
            {"ioc_type": "hash", "ioc_value": "abcdef"}
        ])
        
        # Email with completely missing analysis fields (to simulate old/corrupt data)
        email_missing = Email(
            email_account_id=account.id,
            message_id="<missing@test.local>",
            subject="Missing Fields",
            sender="sender@example.com",
            recipient="recipient@example.com",
        )
        db.add(email_missing)
        db.commit()
        db.refresh(email_missing)
        
        fa_missing = ForensicAnalysisRecord(
            email_id=email_missing.id,
            analysis={"random_other_field": "test"} # Missing all 4 required fields
        )
        db.add(fa_missing)
        db.commit()
        
        db.close()
        
        r = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {create_access_token(1)}"})
        assert r.status_code == 200
        data = r.json()
        
        assert data["ioc_summary"] == {
            "ip": 2,
            "domain": 2,
            "hash": 1
        }
        assert data["total_emails"] == 3
        
    def test_user_isolation(self):
        """GET /api/dashboard/summary isolates data per user."""
        db = TestSession()
        
        # User 1 is created by the fixture. Create User 2.
        user2 = User(email="user2@example.com", name="User 2")
        db.add(user2)
        db.commit()
        
        account2 = EmailAccount(user_id=user2.id, provider="gmail", email_address="user2@example.com")
        db.add(account2)
        db.commit()
        
        # User 2 gets a critical email
        _create_mock_email(db, account2.id, "User 2 Critical", "critical", "malicious")
        
        # User 1 gets a benign email
        account1 = db.query(EmailAccount).filter_by(user_id=1).first()
        _create_mock_email(db, account1.id, "User 1 Benign", "low", "benign")
        
        user2_id = user2.id
        db.close()
        
        # Request as User 1
        r1 = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {create_access_token(1)}"})
        data1 = r1.json()
        assert data1["total_emails"] == 1
        assert data1["critical"] == 0
        
        # Request as User 2
        user2_id = 2 # hardcoded or extracted before close
        r2 = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {create_access_token(user2_id)}"})
        data2 = r2.json()
        assert data2["total_emails"] == 1
        assert data2["critical"] == 1


    def test_get_emails_ordering_and_limit(self):
        """GET /api/emails respects ordering and limit."""
        db = TestSession()
        account = db.query(EmailAccount).first()
        
        for i in range(10):
            _create_mock_email(db, account.id, f"Msg {i}", "low", "benign")
        db.close()
        
        r = client.get("/api/emails?limit=5", headers={"Authorization": f"Bearer {create_access_token(1)}"})
        assert r.status_code == 200
        data = r.json()
        
        assert len(data) == 5
        # The newest (last created) should be first, i.e., "Msg 9"
        assert data[0]["subject"] == "Msg 9"
        assert data[-1]["subject"] == "Msg 5"
        
        # Verify forensics is included
        assert "forensics" in data[0]
        assert data[0]["forensics"]["ai_analysis"]["classification"] == "benign"
