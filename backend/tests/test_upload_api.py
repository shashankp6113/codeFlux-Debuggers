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


class _MockAIProvider:
    def analyze(self, evidence):
        from ai_analysis import AIAnalysisResult
        return AIAnalysisResult(
            classification="suspicious",
            confidence=0.82,
            summary="Test AI summary",
            explanation="Test AI explanation",
            recommended_actions=["Test AI action 1", "Test AI action 2"],
            provider="mock-gemini",
            error=None
        )

@pytest.fixture(autouse=True)
def mock_gemini_globally(monkeypatch):
    """Ensure no test in this file hits the live Gemini API."""
    monkeypatch.setattr("analysis.get_ai_provider", lambda: _MockAIProvider())


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
            "authentication": {"all_dkim_signatures": ["v=1; a=rsa-sha256"]},
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
        assert loaded.analysis["authentication"]["all_dkim_signatures"] == ["v=1; a=rsa-sha256"]
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


# ---------------------------------------------------------------------------
# Tests: Threat intelligence in upload response
# ---------------------------------------------------------------------------

class TestUploadThreatIntelligence:
    """Verify threat intelligence data appears in upload response."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_threat_intelligence_present(self):
        resp = self._upload()
        forensics = resp.json()["forensics"]
        assert "threat_intelligence" in forensics
        assert forensics["threat_intelligence"] is not None

    def test_has_enrichments_list(self):
        resp = self._upload()
        ti = resp.json()["forensics"]["threat_intelligence"]
        assert "enrichments" in ti
        assert isinstance(ti["enrichments"], list)

    def test_has_stats(self):
        resp = self._upload()
        ti = resp.json()["forensics"]["threat_intelligence"]
        assert "stats" in ti
        assert isinstance(ti["stats"], dict)

    def test_provider_is_noop(self):
        resp = self._upload()
        ti = resp.json()["forensics"]["threat_intelligence"]
        assert ti["provider"] == "noop"

    def test_enrichments_have_required_fields(self):
        resp = self._upload()
        ti = resp.json()["forensics"]["threat_intelligence"]
        for e in ti["enrichments"]:
            assert "ioc_type" in e
            assert "ioc_value" in e
            assert "verdict" in e
            assert "provider" in e

    def test_all_verdicts_are_not_enriched(self):
        """NoOpProvider must never claim anything is malicious."""
        resp = self._upload()
        ti = resp.json()["forensics"]["threat_intelligence"]
        for e in ti["enrichments"]:
            assert e["verdict"] == "not_enriched"

    def test_stats_reflect_not_enriched(self):
        resp = self._upload()
        ti = resp.json()["forensics"]["threat_intelligence"]
        if ti["enrichments"]:
            assert ti["stats"].get("not_enriched", 0) == len(ti["enrichments"])

    def test_existing_forensic_fields_preserved(self):
        resp = self._upload()
        forensics = resp.json()["forensics"]
        assert "received_hops" in forensics
        assert "authentication" in forensics
        assert "identity" in forensics
        assert "flags" in forensics
        assert "threat_score" in forensics
        assert "ioc_extraction" in forensics

    def test_threat_score_unchanged(self):
        """Threat intelligence must NOT affect threat score."""
        resp = self._upload()
        ts = resp.json()["forensics"]["threat_score"]
        assert ts["score"] == 10
        assert ts["risk_level"] == "low"


# ---------------------------------------------------------------------------
# Tests: sample.eml threat intelligence enrichment content
# ---------------------------------------------------------------------------

class TestSampleEmlThreatIntel:
    """Verify specific enrichments from sample.eml IOCs."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def _get_ti(self):
        resp = self._upload()
        return resp.json()["forensics"]["threat_intelligence"]

    def test_ipv4_enrichments_present(self):
        ti = self._get_ti()
        ipv4_enrichments = [e for e in ti["enrichments"]
                            if e["ioc_type"] == "ipv4"]
        # sample.eml has 2 unique IPv4s: 198.51.100.42 and 203.0.113.17
        assert len(ipv4_enrichments) >= 2

    def test_domain_enrichments_present(self):
        ti = self._get_ti()
        domain_enrichments = [e for e in ti["enrichments"]
                              if e["ioc_type"] == "domain"]
        assert len(domain_enrichments) >= 1

    def test_email_iocs_not_enriched(self):
        """Email IOCs should be skipped by enrichment."""
        ti = self._get_ti()
        email_enrichments = [e for e in ti["enrichments"]
                             if e["ioc_type"] == "email"]
        assert len(email_enrichments) == 0

    def test_enrichment_values_match_iocs(self):
        """Enriched ioc_values should correspond to extracted IOCs."""
        resp = self._upload()
        forensics = resp.json()["forensics"]
        ioc_values = {i["value"].lower()
                      for i in forensics["ioc_extraction"]["iocs"]
                      if i["ioc_type"] in ("ipv4", "ipv6", "domain", "url")}
        ti_values = {e["ioc_value"].lower()
                     for e in forensics["threat_intelligence"]["enrichments"]}
        # Every enriched value must come from extracted IOCs
        assert ti_values.issubset(ioc_values)

    def test_enrichment_count_matches_unique_enrichable_iocs(self):
        """Enrichment count should equal deduplicated enrichable IOC count."""
        resp = self._upload()
        forensics = resp.json()["forensics"]
        # Build deduplicated enrichable set from IOC extraction
        enrichable = set()
        for i in forensics["ioc_extraction"]["iocs"]:
            if i["ioc_type"] in ("ipv4", "ipv6", "domain", "url"):
                enrichable.add((i["ioc_type"], i["value"].lower()))
        ti_count = len(forensics["threat_intelligence"]["enrichments"])
        assert ti_count == len(enrichable)

    def test_no_confidence_from_noop(self):
        ti = self._get_ti()
        for e in ti["enrichments"]:
            assert e["confidence"] is None

    def test_no_geo_from_noop(self):
        ti = self._get_ti()
        for e in ti["enrichments"]:
            assert e["country"] is None
            assert e["country_code"] is None

    def test_no_asn_from_noop(self):
        ti = self._get_ti()
        for e in ti["enrichments"]:
            assert e["asn"] is None
            assert e["organization"] is None


# ---------------------------------------------------------------------------
# Tests: Threat intelligence persistence
# ---------------------------------------------------------------------------

class TestThreatIntelPersistence:
    """Verify threat intelligence data is persisted in the database."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
                data={"email_account_id": "1"},
            )

    def test_persisted_json_contains_threat_intelligence(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert "threat_intelligence" in fa.analysis
        db.close()

    def test_persisted_has_enrichments(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        ti = fa.analysis["threat_intelligence"]
        assert isinstance(ti["enrichments"], list)
        assert len(ti["enrichments"]) > 0
        db.close()

    def test_persisted_has_provider(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        assert fa.analysis["threat_intelligence"]["provider"] == "noop"
        db.close()

    def test_persisted_matches_response(self):
        resp = self._upload()
        email_id = resp.json()["id"]
        response_ti = resp.json()["forensics"]["threat_intelligence"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).one()
        persisted_ti = fa.analysis["threat_intelligence"]
        assert len(persisted_ti["enrichments"]) == len(response_ti["enrichments"])
        assert persisted_ti["provider"] == response_ti["provider"]
        db.close()

    def test_persisted_json_has_all_keys(self):
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
        assert "threat_intelligence" in fa.analysis
        db.close()


# ---------------------------------------------------------------------------
# Tests: No-raw-headers emails still get IOC + threat intel
# ---------------------------------------------------------------------------

# Minimal .eml that produces an empty raw_headers string after parsing.
# Python's email parser always produces *some* raw headers from From/To,
# so we use a body containing IOCs to verify extraction runs regardless.
# To truly test the "no raw_headers" branch we create a body-only email
# with IOC data to confirm IOC extraction works for all emails.

BODY_WITH_IOCS_EML = b"""\
From: attacker@evil.test
To: victim@company.test
Subject: Check this
Content-Type: text/plain

Visit http://malware.evil.test/payload and contact admin@evil.test
Also check 192.168.1.100 for details.
"""


class TestUploadNoHeaderForensics:
    """Emails always get IOC extraction and threat-intel enrichment."""

    def _upload_inline(self, eml_bytes):
        import io
        return client.post(
            "/api/emails/upload",
            data={"email_account_id": 1},
            files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )

    def test_returns_200(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        assert r.status_code == 200

    def test_forensics_present(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        assert r.json()["forensics"] is not None

    def test_ioc_extraction_present(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        forensics = r.json()["forensics"]
        assert "ioc_extraction" in forensics
        assert forensics["ioc_extraction"] is not None

    def test_ioc_extraction_has_iocs(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        iocs = r.json()["forensics"]["ioc_extraction"]["iocs"]
        assert len(iocs) > 0

    def test_ioc_extraction_finds_url(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        iocs = r.json()["forensics"]["ioc_extraction"]["iocs"]
        urls = [i for i in iocs if i["ioc_type"] == "url"]
        assert any("malware.evil.test" in u["value"] for u in urls)

    def test_ioc_extraction_finds_email(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        iocs = r.json()["forensics"]["ioc_extraction"]["iocs"]
        emails = [i for i in iocs if i["ioc_type"] == "email"]
        assert any("admin@evil.test" in e["value"] for e in emails)

    def test_threat_intelligence_present(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        forensics = r.json()["forensics"]
        assert "threat_intelligence" in forensics
        assert forensics["threat_intelligence"] is not None

    def test_threat_intelligence_has_enrichments(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        ti = r.json()["forensics"]["threat_intelligence"]
        assert "enrichments" in ti

    def test_threat_intelligence_provider_noop(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        ti = r.json()["forensics"]["threat_intelligence"]
        assert ti["provider"] == "noop"

    def test_persisted_record_has_iocs(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        email_id = r.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).first()
        assert fa is not None
        assert "ioc_extraction" in fa.analysis
        assert len(fa.analysis["ioc_extraction"]["iocs"]) > 0
        db.close()

    def test_persisted_record_has_threat_intel(self):
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        email_id = r.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).first()
        assert fa is not None
        assert "threat_intelligence" in fa.analysis
        db.close()


# ---------------------------------------------------------------------------
# Tests: Provider integration in upload pipeline
# ---------------------------------------------------------------------------

class TestUploadProviderIntegration:
    """Verify get_provider() integration in the upload endpoint."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                data={"email_account_id": 1},
                files={"file": ("test.eml", f, "message/rfc822")},
            )

    def test_no_api_key_uses_noop(self, monkeypatch):
        """Without VIRUSTOTAL_API_KEY, upload uses NoOpProvider."""
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        r = self._upload()
        assert r.status_code == 200
        ti = r.json()["forensics"]["threat_intelligence"]
        assert ti["provider"] == "noop"

    def test_no_api_key_upload_succeeds(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        r = self._upload()
        assert r.status_code == 200
        assert r.json()["forensics"] is not None

    def test_configured_key_selects_vt(self, monkeypatch):
        """With VIRUSTOTAL_API_KEY set, upload uses VirusTotalProvider."""
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
        # Mock httpx.get so no real request is made — return not_enriched
        def _mock_get(*args, **kwargs):
            class _Resp:
                status_code = 200
                def json(self):
                    return {"data": {"attributes": {"last_analysis_stats": {}}}}
                def raise_for_status(self):
                    pass
            return _Resp()
        monkeypatch.setattr("httpx.get", _mock_get)
        r = self._upload()
        assert r.status_code == 200
        ti = r.json()["forensics"]["threat_intelligence"]
        assert ti["provider"] == "virustotal"

    def test_provider_error_does_not_break_upload(self, monkeypatch):
        """If VT provider errors, upload still succeeds with error info."""
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
        import httpx as _httpx
        def _mock_timeout(*args, **kwargs):
            raise _httpx.TimeoutException("timed out")
        monkeypatch.setattr("httpx.get", _mock_timeout)
        r = self._upload()
        assert r.status_code == 200
        ti = r.json()["forensics"]["threat_intelligence"]
        assert ti["provider"] == "virustotal"
        # Enrichments should have errors but upload should not fail
        for e in ti.get("enrichments", []):
            assert e["verdict"] == "not_enriched"
            assert e["error"] is not None

    def test_configured_provider_passed_to_pipeline(self, monkeypatch):
        """Verify the selected provider is actually used by enrich_iocs."""
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
        # Track that httpx.get is actually called (VT provider used)
        calls = []
        def _mock_get(*args, **kwargs):
            calls.append(True)
            class _Resp:
                status_code = 200
                def json(self):
                    return {"data": {"attributes": {
                        "last_analysis_stats": {"harmless": 70, "undetected": 10},
                    }}}
                def raise_for_status(self):
                    pass
            return _Resp()
        monkeypatch.setattr("httpx.get", _mock_get)
        r = self._upload()
        assert r.status_code == 200
        # If there are enrichable IOCs, httpx.get should have been called
        ti = r.json()["forensics"]["threat_intelligence"]
        if ti.get("enrichments"):
            assert len(calls) > 0


# ---------------------------------------------------------------------------
# Tests: Geolocation integration in upload pipeline
# ---------------------------------------------------------------------------

class TestUploadGeolocation:
    """Verify geolocation is integrated into the upload pipeline."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                data={"email_account_id": 1},
                files={"file": ("test.eml", f, "message/rfc822")},
            )

    def _upload_inline(self, eml_bytes):
        import io
        return client.post(
            "/api/emails/upload",
            data={"email_account_id": 1},
            files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )

    def test_geolocation_present_in_response(self):
        r = self._upload()
        assert r.status_code == 200
        forensics = r.json()["forensics"]
        assert "geolocation" in forensics
        assert forensics["geolocation"] is not None

    def test_geolocation_has_provider(self):
        r = self._upload()
        geo = r.json()["forensics"]["geolocation"]
        assert geo["provider"] in {"noop", "ipwho"}

    def test_geolocation_has_results_list(self):
        r = self._upload()
        geo = r.json()["forensics"]["geolocation"]
        assert "results" in geo
        assert isinstance(geo["results"], list)

    def test_geolocation_has_stats(self):
        r = self._upload()
        geo = r.json()["forensics"]["geolocation"]
        assert "stats" in geo

    def test_geolocation_persisted(self):
        r = self._upload()
        email_id = r.json()["id"]
        db = TestSession()
        fa = db.query(ForensicAnalysis).filter_by(email_id=email_id).first()
        assert fa is not None
        assert "geolocation" in fa.analysis
        assert fa.analysis["geolocation"]["provider"] in {"noop", "ipwho"}
        db.close()

    def test_no_ip_email_still_succeeds(self):
        """Email with no IP IOCs → geolocation with empty results."""
        eml = b"""\
From: sender@example.test
To: recipient@dest.test
Subject: No IPs here
Content-Type: text/plain

Just some plain text with no IP addresses.
"""
        r = self._upload_inline(eml)
        assert r.status_code == 200
        geo = r.json()["forensics"]["geolocation"]
        assert geo["results"] == []

    def test_no_header_email_has_geolocation(self):
        """Email uploaded with body IOCs still gets geolocation."""
        r = self._upload_inline(BODY_WITH_IOCS_EML)
        assert r.status_code == 200
        geo = r.json()["forensics"]["geolocation"]
        assert geo is not None
        assert geo["provider"] in {"noop", "ipwho"}

    def test_existing_fields_unchanged(self):
        """Adding geolocation did not break existing response fields."""
        r = self._upload()
        forensics = r.json()["forensics"]
        assert "ioc_extraction" in forensics
        assert "threat_intelligence" in forensics
        assert "received_hops" in forensics
        assert "authentication" in forensics
        assert "flags" in forensics


# ---------------------------------------------------------------------------
# Tests: AI analysis in upload response
# ---------------------------------------------------------------------------

from ai_analysis import AIAnalysisProvider, AIAnalysisResult  # noqa: E402


class _MockAIProvider(AIAnalysisProvider):
    """Mock AI provider returning a successful result."""

    @property
    def name(self):
        return "mock-ai"

    def analyze(self, evidence):
        return AIAnalysisResult(
            classification="suspicious",
            confidence=0.82,
            summary="Test AI summary",
            explanation="Test AI explanation",
            recommended_actions=["Review sender", "Check links"],
            provider="mock-ai",
        )


class _FailAIProvider(AIAnalysisProvider):
    """Mock AI provider that always raises."""

    @property
    def name(self):
        return "fail-ai"

    def analyze(self, evidence):
        raise RuntimeError("AI crash")


class TestUploadAIAnalysis:
    """AI analysis appears in the upload response."""

    def _upload(self):
        with open(SAMPLE_EML, "rb") as f:
            return client.post(
                "/api/emails/upload",
                data={"email_account_id": 1},
                files={"file": ("test.eml", f, "message/rfc822")},
            )

    def _upload_inline(self, eml_bytes):
        import io
        return client.post(
            "/api/emails/upload",
            data={"email_account_id": 1},
            files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )

    def test_ai_analysis_present(self):
        """ai_analysis key exists in forensics response."""
        r = self._upload()
        assert r.status_code == 200
        forensics = r.json()["forensics"]
        assert "ai_analysis" in forensics

    def test_ai_success_fields(self, monkeypatch):
        """Mocked AI provider result appears in response."""
        monkeypatch.setattr("analysis.get_ai_provider", lambda: _MockAIProvider())
        r = self._upload()
        ai = r.json()["forensics"]["ai_analysis"]
        assert ai["classification"] == "suspicious"
        assert ai["confidence"] == pytest.approx(0.82)
        assert ai["summary"] == "Test AI summary"
        assert ai["explanation"] == "Test AI explanation"
        assert ai["recommended_actions"] == ["Review sender", "Check links"]
        assert ai["provider"] == "mock-ai"
        assert ai["error"] is None

    def test_ai_only_expected_fields(self, monkeypatch):
        """AI response contains only the intended fields — no secrets."""
        monkeypatch.setattr("analysis.get_ai_provider", lambda: _MockAIProvider())
        r = self._upload()
        ai = r.json()["forensics"]["ai_analysis"]
        allowed = {
            "classification", "confidence", "summary", "explanation",
            "recommended_actions", "provider", "error",
        }
        assert set(ai.keys()) == allowed

    def test_ai_failure_returns_unknown(self, monkeypatch):
        """AI provider crash → classification unknown with error."""
        monkeypatch.setattr("analysis.get_ai_provider", lambda: _FailAIProvider())
        r = self._upload()
        assert r.status_code == 200
        ai = r.json()["forensics"]["ai_analysis"]
        assert ai["classification"] == "unknown"
        assert ai["error"] is not None

    def test_noop_ai_response(self, monkeypatch):
        """NoOp provider → unknown classification, no error."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        from ai_analysis import NoOpAIProvider
        monkeypatch.setattr("analysis.get_ai_provider", lambda: NoOpAIProvider())
        r = self._upload()
        ai = r.json()["forensics"]["ai_analysis"]
        assert ai["classification"] == "unknown"
        assert ai["provider"] == "noop"
        assert ai["error"] is None

    def test_existing_fields_still_present(self, monkeypatch):
        """AI addition does not break existing forensic response fields."""
        monkeypatch.setattr("analysis.get_ai_provider", lambda: _MockAIProvider())
        r = self._upload()
        forensics = r.json()["forensics"]
        assert "received_hops" in forensics
        assert "authentication" in forensics
        assert "identity" in forensics
        assert "flags" in forensics
        assert "threat_score" in forensics
        assert "ioc_extraction" in forensics
        assert "threat_intelligence" in forensics
        assert "geolocation" in forensics
        assert "ai_analysis" in forensics

    def test_no_secrets_in_ai_response(self, monkeypatch):
        """AI response must not contain API keys or tokens."""
        monkeypatch.setattr("analysis.get_ai_provider", lambda: _MockAIProvider())
        r = self._upload()
        import json
        response_str = json.dumps(r.json()["forensics"]["ai_analysis"])
        for sensitive in ["api_key", "access_token", "refresh_token",
                          "client_secret", "password", "bearer"]:
            assert sensitive not in response_str.lower()

def test_upload_with_ai_failure():
    """Test that a 429/failure from Gemini is handled gracefully and returns the error in the API response."""
    sample_path = os.path.join(FIXTURES_DIR, "sample.eml")
    
    # We patch the global client fixture logic temporarily for this test
    # by mocking get_ai_provider to fail
    class _FailAIProvider:
        @property
        def name(self): return "gemini"
        def analyze(self, evidence):
            from ai_analysis import AIAnalysisResult
            return AIAnalysisResult(
                classification="unknown",
                confidence=None,
                summary=None,
                explanation=None,
                recommended_actions=[],
                provider="gemini",
                error="Gemini rate limit exceeded (HTTP 429)"
            )
            
    import pytest
    from unittest import mock
    
    with mock.patch("analysis.get_ai_provider", return_value=_FailAIProvider()):
        with open(sample_path, "rb") as f:
            response = client.post(
                "/api/emails/upload",
                files={"file": ("sample.eml", f, "message/rfc822")},
            )
            
    assert response.status_code == 200
    data = response.json()
    ai = data["forensics"]["ai_analysis"]
    
    assert ai["classification"] == "unknown"
    assert "429" in ai["error"]
    assert data["forensics"]["threat_score"]["score"] is not None # Deterministic pipeline survived
