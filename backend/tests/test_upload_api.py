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


# ---------------------------------------------------------------------------
# Tests: Threat score in upload response
# ---------------------------------------------------------------------------

class TestUploadThreatScore:
    """Verify that uploading sample.eml returns threat_score in forensics."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_threat_score_present_in_response(self):
        forensics = self._upload().json()["forensics"]
        assert "threat_score" in forensics
        assert forensics["threat_score"] is not None

    def test_score_is_integer(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert isinstance(ts["score"], int)

    def test_score_in_range(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert 0 <= ts["score"] <= 100

    def test_risk_level_present(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert "risk_level" in ts
        assert ts["risk_level"] in ("low", "medium", "high", "critical")

    def test_category_scores_present(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert "category_scores" in ts
        assert isinstance(ts["category_scores"], dict)

    def test_rule_contributions_present(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert "rule_contributions" in ts
        assert isinstance(ts["rule_contributions"], list)

    def test_rule_contribution_fields(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        for contrib in ts["rule_contributions"]:
            assert "rule_id" in contrib
            assert "category" in contrib
            assert "severity" in contrib
            assert "points" in contrib

    def test_existing_forensic_fields_preserved(self):
        """Existing forensic fields must still be present alongside threat_score."""
        forensics = self._upload().json()["forensics"]
        assert "received_hops" in forensics
        assert "authentication" in forensics
        assert "identity" in forensics
        assert "flags" in forensics
        assert "threat_score" in forensics

    def test_existing_email_fields_still_present(self):
        """Top-level email fields must be unaffected by threat_score addition."""
        data = self._upload().json()
        assert "id" in data
        assert "sender" in data
        assert "recipient" in data
        assert "subject" in data
        assert "forensics" in data


# ---------------------------------------------------------------------------
# Tests: Deterministic threat score for sample.eml
# ---------------------------------------------------------------------------

class TestSampleEmlThreatScore:
    """sample.eml has only MISSING_AUTH_HEADERS (info) → score=10, risk=low."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_deterministic_score(self):
        """MISSING_AUTH_HEADERS (info): base 10 × 1.0 = 10."""
        ts = self._upload().json()["forensics"]["threat_score"]
        assert ts["score"] == 10

    def test_deterministic_risk_level(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert ts["risk_level"] == "low"

    def test_authentication_category_score(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert ts["category_scores"]["authentication"] == 10

    def test_only_authentication_category(self):
        """Only the authentication category should appear."""
        ts = self._upload().json()["forensics"]["threat_score"]
        assert list(ts["category_scores"].keys()) == ["authentication"]

    def test_single_rule_contribution(self):
        ts = self._upload().json()["forensics"]["threat_score"]
        assert len(ts["rule_contributions"]) == 1
        c = ts["rule_contributions"][0]
        assert c["rule_id"] == "MISSING_AUTH_HEADERS"
        assert c["category"] == "authentication"
        assert c["severity"] == "info"
        assert c["points"] == 10


# ---------------------------------------------------------------------------
# Tests: Threat score persistence in database
# ---------------------------------------------------------------------------

class TestThreatScorePersistence:
    """Verify threat_score is persisted inside forensic_analyses.analysis JSON."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_persisted_json_contains_threat_score(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert "threat_score" in fa.analysis
        db.close()

    def test_persisted_threat_score_has_score(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        ts = fa.analysis["threat_score"]
        assert isinstance(ts["score"], int)
        assert 0 <= ts["score"] <= 100
        db.close()

    def test_persisted_threat_score_has_risk_level(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        ts = fa.analysis["threat_score"]
        assert ts["risk_level"] in ("low", "medium", "high", "critical")
        db.close()

    def test_persisted_threat_score_has_category_scores(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        ts = fa.analysis["threat_score"]
        assert isinstance(ts["category_scores"], dict)
        db.close()

    def test_persisted_threat_score_has_rule_contributions(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        ts = fa.analysis["threat_score"]
        assert isinstance(ts["rule_contributions"], list)
        db.close()

    def test_persisted_score_matches_response(self):
        """The persisted threat_score must match what the API returned."""
        resp = self._upload()
        email_id = resp.json()["id"]
        api_ts = resp.json()["forensics"]["threat_score"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        db_ts = fa.analysis["threat_score"]
        assert db_ts["score"] == api_ts["score"]
        assert db_ts["risk_level"] == api_ts["risk_level"]
        assert db_ts["category_scores"] == api_ts["category_scores"]
        db.close()

    def test_persisted_json_still_has_existing_keys(self):
        """Adding threat_score must not remove existing keys from the JSON."""
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert "received_hops" in fa.analysis
        assert "authentication" in fa.analysis
        assert "identity" in fa.analysis
        assert "flags" in fa.analysis
        assert "threat_score" in fa.analysis
        db.close()


# ---------------------------------------------------------------------------
# Tests: IOC extraction in upload response
# ---------------------------------------------------------------------------

class TestUploadIOCExtraction:
    """Verify that uploading sample.eml returns IOC extraction data."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_ioc_extraction_present_in_response(self):
        resp = self._upload()
        forensics = resp.json()["forensics"]
        assert "ioc_extraction" in forensics
        assert forensics["ioc_extraction"] is not None

    def test_ioc_extraction_has_iocs_list(self):
        resp = self._upload()
        ioc_data = resp.json()["forensics"]["ioc_extraction"]
        assert "iocs" in ioc_data
        assert isinstance(ioc_data["iocs"], list)

    def test_ioc_extraction_has_stats(self):
        resp = self._upload()
        ioc_data = resp.json()["forensics"]["ioc_extraction"]
        assert "stats" in ioc_data
        assert isinstance(ioc_data["stats"], dict)

    def test_each_ioc_has_required_fields(self):
        resp = self._upload()
        ioc_data = resp.json()["forensics"]["ioc_extraction"]
        for ioc in ioc_data["iocs"]:
            assert "ioc_type" in ioc
            assert "value" in ioc
            assert "source" in ioc
            assert "context" in ioc

    def test_existing_forensic_fields_still_present(self):
        """IOC extraction must not remove existing forensic fields."""
        resp = self._upload()
        forensics = resp.json()["forensics"]
        assert "received_hops" in forensics
        assert "authentication" in forensics
        assert "identity" in forensics
        assert "flags" in forensics
        assert "threat_score" in forensics

    def test_threat_score_unchanged_by_ioc_extraction(self):
        """IOC extraction must not affect the threat score calculation."""
        resp = self._upload()
        ts = resp.json()["forensics"]["threat_score"]
        # sample.eml: score=10, risk_level=low (only MISSING_AUTH_HEADERS)
        assert ts["score"] == 10
        assert ts["risk_level"] == "low"


# ---------------------------------------------------------------------------
# Tests: sample.eml IOC content
# ---------------------------------------------------------------------------

class TestSampleEmlIOCContent:
    """Verify specific IOCs extracted from the sample.eml fixture."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def _get_iocs(self):
        resp = self._upload()
        return resp.json()["forensics"]["ioc_extraction"]

    def test_sender_email_extracted(self):
        ioc_data = self._get_iocs()
        values = [i["value"] for i in ioc_data["iocs"]
                  if i["ioc_type"] == "email"]
        assert "john.smith@acmecorp.test" in values

    def test_recipient_email_extracted(self):
        ioc_data = self._get_iocs()
        values = [i["value"] for i in ioc_data["iocs"]
                  if i["ioc_type"] == "email"]
        assert "jane.doe@globex.test" in values

    def test_cc_email_extracted(self):
        ioc_data = self._get_iocs()
        values = [i["value"] for i in ioc_data["iocs"]
                  if i["ioc_type"] == "email"]
        assert "alex.rivera@acmecorp.test" in values

    def test_received_ipv4_extracted(self):
        ioc_data = self._get_iocs()
        values = [i["value"] for i in ioc_data["iocs"]
                  if i["ioc_type"] == "ipv4"]
        assert "198.51.100.42" in values
        assert "203.0.113.17" in values

    def test_domains_extracted(self):
        ioc_data = self._get_iocs()
        values = [i["value"] for i in ioc_data["iocs"]
                  if i["ioc_type"] == "domain"]
        assert any("acmecorp.test" in v for v in values)

    def test_stats_reflect_extraction(self):
        ioc_data = self._get_iocs()
        stats = ioc_data["stats"]
        assert stats.get("email", 0) >= 3
        assert stats.get("ipv4", 0) >= 2

    def test_no_false_positive_domains(self):
        ioc_data = self._get_iocs()
        domains = [i["value"] for i in ioc_data["iocs"]
                   if i["ioc_type"] == "domain"]
        for d in domains:
            tld = d.rsplit(".", 1)[-1]
            assert tld not in ("pdf", "csv", "txt", "html", "css")


# ---------------------------------------------------------------------------
# Tests: IOC extraction persistence
# ---------------------------------------------------------------------------

class TestIOCPersistence:
    """Verify IOC extraction data is persisted in the database."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_persisted_json_contains_ioc_extraction(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert "ioc_extraction" in fa.analysis
        db.close()

    def test_persisted_ioc_has_iocs_list(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        ioc_data = fa.analysis["ioc_extraction"]
        assert isinstance(ioc_data["iocs"], list)
        assert len(ioc_data["iocs"]) > 0
        db.close()

    def test_persisted_ioc_has_stats(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        ioc_data = fa.analysis["ioc_extraction"]
        assert isinstance(ioc_data["stats"], dict)
        assert len(ioc_data["stats"]) > 0
        db.close()

    def test_persisted_ioc_matches_response(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        response_iocs = resp.json()["forensics"]["ioc_extraction"]["iocs"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        persisted_iocs = fa.analysis["ioc_extraction"]["iocs"]
        assert len(persisted_iocs) == len(response_iocs)
        db.close()

    def test_persisted_json_still_has_all_keys(self):
        """IOC extraction must not remove existing keys from the persisted JSON."""
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert "received_hops" in fa.analysis
        assert "authentication" in fa.analysis
        assert "identity" in fa.analysis
        assert "flags" in fa.analysis
        assert "threat_score" in fa.analysis
        assert "ioc_extraction" in fa.analysis
        db.close()


# ---------------------------------------------------------------------------
# Tests: Minimal email with no meaningful IOCs
# ---------------------------------------------------------------------------

class TestMinimalEmailIOC:
    """An email with minimal content should still return valid IOC structure."""

    def _upload_minimal(self):
        """Upload a minimal .eml with only From/To (no body, no received)."""
        minimal_eml = (
            b"From: min@test.local\r\n"
            b"To: dest@test.local\r\n"
            b"Subject: Minimal\r\n"
            b"Date: Tue, 08 Jul 2025 10:00:00 +0000\r\n"
            b"\r\n"
            b"Empty body.\r\n"
        )
        return client.post(
            "/api/emails/upload",
            files={"file": ("minimal.eml", minimal_eml, "message/rfc822")},
            data={"email_account_id": "1"},
        )

    def test_minimal_returns_200(self):
        resp = self._upload_minimal()
        assert resp.status_code == 200

    def test_minimal_has_ioc_extraction(self):
        resp = self._upload_minimal()
        forensics = resp.json()["forensics"]
        assert "ioc_extraction" in forensics
        assert forensics["ioc_extraction"] is not None

    def test_minimal_iocs_structure_valid(self):
        resp = self._upload_minimal()
        ioc_data = resp.json()["forensics"]["ioc_extraction"]
        assert isinstance(ioc_data["iocs"], list)
        assert isinstance(ioc_data["stats"], dict)

    def test_minimal_extracts_from_to_emails(self):
        resp = self._upload_minimal()
        ioc_data = resp.json()["forensics"]["ioc_extraction"]
        values = [i["value"] for i in ioc_data["iocs"]
                  if i["ioc_type"] == "email"]
        assert "min@test.local" in values
        assert "dest@test.local" in values

    def test_minimal_no_ipv4(self):
        resp = self._upload_minimal()
        ioc_data = resp.json()["forensics"]["ioc_extraction"]
        ipv4s = [i for i in ioc_data["iocs"] if i["ioc_type"] == "ipv4"]
        assert len(ipv4s) == 0

