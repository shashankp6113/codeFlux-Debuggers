"""API-level tests for POST /api/emails/upload with forensic analysis."""

import os
import pytest
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

from models import Base, User, EmailAccount, Email, ForensicAnalysis  # noqa: F401
from database import get_db
from main import app

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_EML = os.path.join(FIXTURES_DIR, "sample.eml")


# ---------------------------------------------------------------------------
# Test database setup
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_db():
    """Create tables and seed a test EmailAccount for each test."""
    Base.metadata.create_all(bind=TEST_ENGINE)
    db = TestSession()
    # Seed test user + email account if not present
    user = db.query(User).first()
    if not user:
        user = User(email="test@test.local", name="Test")
        db.add(user)
        db.commit()
        db.refresh(user)
        account = EmailAccount(
            user_id=user.id,
            provider="test",
            email_address="test@test.local",
        )
        db.add(account)
        db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


def _override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app)


# ---------------------------------------------------------------------------
# Tests: Forensics field in upload response
# ---------------------------------------------------------------------------

class TestUploadForensics:
    """Verify that uploading sample.eml returns a forensics field."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_upload_returns_200(self):
        resp = self._upload()
        assert resp.status_code == 200

    def test_response_has_forensics_field(self):
        data = self._upload().json()
        assert "forensics" in data
        assert data["forensics"] is not None

    def test_forensics_has_received_hops(self):
        forensics = self._upload().json()["forensics"]
        assert "received_hops" in forensics
        assert isinstance(forensics["received_hops"], list)
        assert len(forensics["received_hops"]) == 2

    def test_forensics_has_authentication(self):
        forensics = self._upload().json()["forensics"]
        assert "authentication" in forensics
        assert isinstance(forensics["authentication"], dict)

    def test_forensics_has_identity(self):
        forensics = self._upload().json()["forensics"]
        assert "identity" in forensics
        assert isinstance(forensics["identity"], dict)

    def test_forensics_has_flags(self):
        forensics = self._upload().json()["forensics"]
        assert "flags" in forensics
        assert isinstance(forensics["flags"], list)

    def test_received_hop_fields(self):
        hops = self._upload().json()["forensics"]["received_hops"]
        hop = hops[0]
        assert "hop_number" in hop
        assert "source_host" in hop
        assert "destination_host" in hop
        assert "ipv4" in hop
        assert "raw" in hop

    def test_hop_1_values(self):
        hops = self._upload().json()["forensics"]["received_hops"]
        assert hops[0]["source_host"] == "mx2.acmecorp.test"
        assert hops[0]["ipv4"] == "198.51.100.42"

    def test_identity_from(self):
        identity = self._upload().json()["forensics"]["identity"]
        assert "john.smith@acmecorp.test" in identity["from_header"]

    def test_identity_to(self):
        identity = self._upload().json()["forensics"]["identity"]
        assert "jane.doe@globex.test" in identity["to_header"]

    def test_flags_include_missing_auth(self):
        """sample.eml has no auth headers, so MISSING_AUTH_HEADERS fires."""
        flags = self._upload().json()["forensics"]["flags"]
        rule_ids = [f["rule_id"] for f in flags]
        assert "MISSING_AUTH_HEADERS" in rule_ids

    def test_existing_email_fields_preserved(self):
        data = self._upload().json()
        assert data["sender"] == "John Smith <john.smith@acmecorp.test>"
        assert data["recipient"] == "Jane Doe <jane.doe@globex.test>"
        assert data["subject"] == "Q3 Budget Review - Action Required"
        assert "id" in data
        assert "email_account_id" in data
        assert "created_at" in data


class TestUploadExistingEndpoints:
    """Verify existing endpoints still work."""

    def test_root(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["message"] == "MailForensics AI Backend is running"


# ---------------------------------------------------------------------------
# Tests: ForensicAnalysis model persistence
# ---------------------------------------------------------------------------

class TestForensicAnalysisModel:
    """Tests for the ForensicAnalysis SQLAlchemy model (one-to-one with Email)."""

    def _seed_email(self, db):
        """Create and return a minimal Email for testing."""
        email = Email(
            email_account_id=1,
            sender="a@test.local",
            recipient="b@test.local",
        )
        db.add(email)
        db.commit()
        db.refresh(email)
        return email

    def test_create_forensic_analysis(self):
        db = TestSession()
        email = self._seed_email(db)
        fa = ForensicAnalysis(
            email_id=email.id,
            analysis={"received_hops": [], "flags": []},
        )
        db.add(fa)
        db.commit()
        db.refresh(fa)
        assert fa.id is not None
        assert fa.email_id == email.id
        assert fa.created_at is not None
        db.close()

    def test_analysis_json_roundtrip(self):
        """Verify JSONB data survives a write-read cycle."""
        db = TestSession()
        email = self._seed_email(db)
        payload = {
            "received_hops": [{"hop_number": 1, "source_host": "mx.test"}],
            "authentication": {"dkim_signature": "v=1; a=rsa-sha256"},
            "identity": {"from_header": "sender@test.local"},
            "flags": [{"rule_id": "TEST_RULE", "severity": "info",
                        "description": "test", "evidence": "test"}],
        }
        fa = ForensicAnalysis(email_id=email.id, analysis=payload)
        db.add(fa)
        db.commit()

        loaded = db.query(ForensicAnalysis).filter_by(email_id=email.id).one()
        assert loaded.analysis["received_hops"][0]["source_host"] == "mx.test"
        assert loaded.analysis["flags"][0]["rule_id"] == "TEST_RULE"
        assert loaded.analysis["authentication"]["dkim_signature"] == "v=1; a=rsa-sha256"
        db.close()

    def test_one_to_one_relationship_from_email(self):
        db = TestSession()
        email = self._seed_email(db)
        fa = ForensicAnalysis(
            email_id=email.id,
            analysis={"test": True},
        )
        db.add(fa)
        db.commit()
        db.refresh(email)
        assert email.forensic_analysis is not None
        assert email.forensic_analysis.id == fa.id
        db.close()

    def test_one_to_one_relationship_from_forensic(self):
        db = TestSession()
        email = self._seed_email(db)
        fa = ForensicAnalysis(
            email_id=email.id,
            analysis={"test": True},
        )
        db.add(fa)
        db.commit()
        db.refresh(fa)
        assert fa.email is not None
        assert fa.email.id == email.id
        db.close()

    def test_email_without_forensic_is_valid(self):
        """Emails created without forensic analysis should work fine."""
        db = TestSession()
        email = self._seed_email(db)
        db.refresh(email)
        assert email.forensic_analysis is None
        db.close()


class TestUploadPersistsForensic:
    """Verify that the upload endpoint persists a ForensicAnalysis record."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_upload_creates_forensic_record(self):
        self._upload()
        db = TestSession()
        count = db.query(ForensicAnalysis).count()
        assert count >= 1
        db.close()

    def test_forensic_record_linked_to_email(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).first()
        assert fa is not None
        assert fa.analysis is not None
        db.close()

    def test_forensic_record_has_received_hops(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert "received_hops" in fa.analysis
        assert len(fa.analysis["received_hops"]) == 2
        db.close()

    def test_forensic_record_has_flags(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert "flags" in fa.analysis
        rule_ids = [f["rule_id"] for f in fa.analysis["flags"]]
        assert "MISSING_AUTH_HEADERS" in rule_ids
        db.close()
