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

from models import Base, User, EmailAccount, Email  # noqa: F401 – import all models
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
