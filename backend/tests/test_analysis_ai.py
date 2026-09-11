"""Tests for AI analysis integration into run_email_analysis()."""

import json
import os
import pytest

from dataclasses import asdict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# In-memory SQLite for testing
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

from models import Base, User, EmailAccount, Email, ForensicAnalysis
from email_parser import parse_eml
from analysis import run_email_analysis
from ai_analysis import (
    AIAnalysisResult,
    AIAnalysisProvider,
    NoOpAIProvider,
    GeminiAIProvider,
    build_ai_evidence,
    get_ai_provider,
)


# ---------------------------------------------------------------------------
# Test database setup
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_EML_WITH_HEADERS = b"""\
From: sender@example.com
To: recipient@dest.com
Subject: Test with auth headers
Date: Thu, 01 Jan 2026 12:00:00 +0000
Message-ID: <msg-ai-001@example.com>
Authentication-Results: mx.dest.com; spf=pass smtp.mailfrom=example.com
Received: from mail.example.com (mail.example.com [8.8.8.8])
        by mx.dest.com with ESMTP; Thu, 01 Jan 2026 12:00:00 +0000
Content-Type: text/plain

Body with an IP 8.8.8.8 and a URL http://evil.test/payload
"""

SAMPLE_EML_NO_HEADERS = b"""\
From: sender@example.com
To: recipient@dest.com
Subject: Minimal email
Date: Thu, 01 Jan 2026 12:00:00 +0000
Message-ID: <msg-ai-002@example.com>
Content-Type: text/plain

Just a plain body with 10.0.0.1 for IOC testing.
"""


def _seed_email(db, raw_bytes):
    """Parse, persist, and return (parsed, db_email)."""
    parsed = parse_eml(raw_bytes)
    user = User(email="test-ai@test.com", name="Test")
    db.add(user)
    db.commit()
    db.refresh(user)
    acct = EmailAccount(user_id=user.id, provider="test", email_address="t@t.com")
    db.add(acct)
    db.commit()
    db.refresh(acct)
    db_email = Email(
        email_account_id=acct.id,
        message_id=parsed.message_id,
        subject=parsed.subject,
        sender=parsed.sender,
        recipient=parsed.recipient,
        cc=parsed.cc,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
        raw_headers=parsed.raw_headers,
        received_at=parsed.received_at,
    )
    db.add(db_email)
    db.commit()
    db.refresh(db_email)
    return parsed, db_email


class _MockGeminiProvider(AIAnalysisProvider):
    """A mock Gemini-like provider for testing."""

    def __init__(self, classification="suspicious", confidence=0.75):
        self._classification = classification
        self._confidence = confidence
        self.last_evidence = None  # capture what was sent

    @property
    def name(self):
        return "mock-gemini"

    def analyze(self, evidence):
        self.last_evidence = evidence
        return AIAnalysisResult(
            classification=self._classification,
            confidence=self._confidence,
            summary="Mock AI summary",
            explanation="Mock AI explanation",
            recommended_actions=["Review email", "Check sender"],
            provider="mock-gemini",
        )


class _FailingProvider(AIAnalysisProvider):
    """Provider that always raises."""

    @property
    def name(self):
        return "failing"

    def analyze(self, evidence):
        raise RuntimeError("Simulated AI crash")


class _ErrorProvider(AIAnalysisProvider):
    """Provider that returns an error result (not an exception)."""

    @property
    def name(self):
        return "error-provider"

    def analyze(self, evidence):
        return AIAnalysisResult(
            classification="unknown",
            provider="gemini",
            error="Gemini request timed out",
        )


# ---------------------------------------------------------------------------
# Tests: NoOp AI integration
# ---------------------------------------------------------------------------

class TestNoOpAIIntegration:
    """When GEMINI_API_KEY is missing, AI analysis uses NoOp."""

    def test_ai_analysis_present(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)
        assert "ai_analysis" in result
        db.close()

    def test_noop_classification(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)
        assert result["ai_analysis"]["classification"] == "unknown"
        assert result["ai_analysis"]["provider"] == "noop"
        db.close()

    def test_noop_no_error(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)
        assert result["ai_analysis"]["error"] is None
        db.close()


# ---------------------------------------------------------------------------
# Tests: Mocked Gemini AI integration
# ---------------------------------------------------------------------------

class TestGeminiAIIntegration:
    """AI analysis with a mocked Gemini-like provider."""

    def test_ai_classification_persisted(self, monkeypatch):
        mock = _MockGeminiProvider(classification="malicious", confidence=0.92)
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert result["ai_analysis"]["classification"] == "malicious"
        assert result["ai_analysis"]["confidence"] == pytest.approx(0.92)
        assert result["ai_analysis"]["provider"] == "mock-gemini"
        db.close()

    def test_ai_summary_and_explanation(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert result["ai_analysis"]["summary"] == "Mock AI summary"
        assert result["ai_analysis"]["explanation"] == "Mock AI explanation"
        db.close()

    def test_ai_recommended_actions(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert result["ai_analysis"]["recommended_actions"] == [
            "Review email", "Check sender"
        ]
        db.close()


# ---------------------------------------------------------------------------
# Tests: AI result persisted in ForensicAnalysis
# ---------------------------------------------------------------------------

class TestAIResultPersistence:
    """AI result is stored in the database."""

    def test_ai_analysis_in_db(self, monkeypatch):
        mock = _MockGeminiProvider(classification="suspicious")
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        fa = db.query(ForensicAnalysis).filter_by(email_id=db_email.id).first()
        assert fa is not None
        assert "ai_analysis" in fa.analysis
        assert fa.analysis["ai_analysis"]["classification"] == "suspicious"
        db.close()

    def test_exactly_one_forensic_record(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        count = db.query(ForensicAnalysis).filter_by(email_id=db_email.id).count()
        assert count == 1
        db.close()


# ---------------------------------------------------------------------------
# Tests: Deterministic results unchanged after AI
# ---------------------------------------------------------------------------

class TestDeterministicUnchanged:
    """AI analysis must NOT modify deterministic results."""

    def test_threat_score_unchanged(self, monkeypatch):
        mock = _MockGeminiProvider(classification="malicious", confidence=0.99)
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        # Threat score must exist and be deterministic, not influenced by AI
        assert "threat_score" in result
        assert isinstance(result["threat_score"]["score"], int)
        assert result["threat_score"]["risk_level"] in {
            "low", "medium", "high", "critical"
        }
        db.close()

    def test_forensic_flags_unchanged(self, monkeypatch):
        mock = _MockGeminiProvider(classification="malicious")
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        # Flags must be a list from the deterministic layer
        assert "flags" in result
        assert isinstance(result["flags"], list)
        db.close()

    def test_ioc_extraction_unchanged(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert "ioc_extraction" in result
        assert "iocs" in result["ioc_extraction"]
        db.close()

    def test_threat_intelligence_unchanged(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert "threat_intelligence" in result
        assert "provider" in result["threat_intelligence"]
        db.close()

    def test_geolocation_unchanged(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert "geolocation" in result
        assert "provider" in result["geolocation"]
        db.close()


# ---------------------------------------------------------------------------
# Tests: AI failure handling
# ---------------------------------------------------------------------------

class TestAIFailureHandling:
    """AI failures must not break run_email_analysis()."""

    def test_exception_does_not_fail_pipeline(self, monkeypatch):
        failing = _FailingProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: failing)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)

        # Must not raise
        result = run_email_analysis(parsed, db_email, db)
        assert "ai_analysis" in result
        assert result["ai_analysis"]["classification"] == "unknown"
        assert result["ai_analysis"]["error"] is not None
        db.close()

    def test_error_result_stored_safely(self, monkeypatch):
        error_prov = _ErrorProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: error_prov)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert result["ai_analysis"]["error"] == "Gemini request timed out"
        assert result["ai_analysis"]["classification"] == "unknown"
        assert result["ai_analysis"]["provider"] == "gemini"
        db.close()

    def test_deterministic_analysis_still_persisted(self, monkeypatch):
        failing = _FailingProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: failing)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        fa = db.query(ForensicAnalysis).filter_by(email_id=db_email.id).first()
        assert fa is not None
        # Deterministic parts are intact
        assert "ioc_extraction" in fa.analysis
        assert "threat_intelligence" in fa.analysis
        assert "geolocation" in fa.analysis
        assert "threat_score" in fa.analysis
        db.close()


# ---------------------------------------------------------------------------
# Tests: Emails without raw headers
# ---------------------------------------------------------------------------

class TestNoHeadersAIAnalysis:
    """Emails without auth headers still receive AI analysis."""

    def test_ai_analysis_present(self, monkeypatch):
        mock = _MockGeminiProvider(classification="benign", confidence=0.9)
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_NO_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert "ai_analysis" in result
        assert result["ai_analysis"]["classification"] == "benign"
        db.close()

    def test_ioc_ti_geo_still_present(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_NO_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        assert "ioc_extraction" in result
        assert "threat_intelligence" in result
        assert "geolocation" in result
        db.close()

    def test_minimal_email_gets_low_threat_score(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_NO_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        # Minimal emails still have raw headers (From/To/Subject), so
        # the forensic analyzer runs.  Score should be low.
        assert result["threat_score"]["risk_level"] == "low"
        db.close()


# ---------------------------------------------------------------------------
# Tests: Evidence content verification
# ---------------------------------------------------------------------------

class TestAIEvidenceContent:
    """Verify what evidence the AI provider receives."""

    def test_evidence_has_threat_score(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev = mock.last_evidence
        assert "threat_score" in ev
        assert ev["threat_score"]["source"] == "threat_score"
        db.close()

    def test_evidence_has_authentication(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev = mock.last_evidence
        assert "authentication" in ev
        assert ev["authentication"]["source"] == "authentication"
        db.close()

    def test_evidence_has_email_metadata(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev = mock.last_evidence
        assert "email_metadata" in ev
        assert ev["email_metadata"]["sender"] == "sender@example.com"
        assert ev["email_metadata"]["subject"] == "Test with auth headers"
        db.close()

    def test_evidence_has_iocs(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev = mock.last_evidence
        assert "iocs" in ev
        assert ev["iocs"]["source"] == "ioc_extraction"
        db.close()

    def test_evidence_no_raw_body(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev_str = json.dumps(mock.last_evidence)
        # The actual email body content must not appear in evidence
        assert "Body with an IP" not in ev_str
        # Raw HTML must not appear
        assert "<html>" not in ev_str
        db.close()

    def test_evidence_no_tokens(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev_str = json.dumps(mock.last_evidence)
        assert "access_token" not in ev_str
        assert "refresh_token" not in ev_str
        assert "api_key" not in ev_str
        assert "password" not in ev_str
        db.close()

    def test_evidence_has_received_hops(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev = mock.last_evidence
        assert "received_hops" in ev
        db.close()

    def test_evidence_has_geolocation(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev = mock.last_evidence
        assert "geolocation" in ev
        db.close()

    def test_evidence_has_threat_intel(self, monkeypatch):
        mock = _MockGeminiProvider()
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)
        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        run_email_analysis(parsed, db_email, db)

        ev = mock.last_evidence
        assert "threat_intelligence" in ev
        db.close()


# ---------------------------------------------------------------------------
# Tests: Comprehensive end-to-end AI integration
# ---------------------------------------------------------------------------

class TestEndToEndAIIntegration:
    """Single comprehensive test verifying the full AI integration path."""

    def test_full_pipeline_with_mocked_gemini(self, monkeypatch):
        """Verify all six integration requirements in one flow:

        1. Deterministic forensic analysis runs
        2. build_ai_evidence() is used (evidence has provenance source tags)
        3. The AI provider is called with evidence
        4. The returned AIAnalysisResult is stored under analysis["ai_analysis"]
        5. The persisted ForensicAnalysis contains the ai_analysis result
        6. (covered by the companion test below)
        """
        mock = _MockGeminiProvider(classification="malicious", confidence=0.93)
        monkeypatch.setattr("analysis.get_ai_provider", lambda: mock)

        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)
        result = run_email_analysis(parsed, db_email, db)

        # --- 1. Deterministic forensic analysis ran ---
        assert "threat_score" in result
        assert isinstance(result["threat_score"]["score"], int)
        assert result["threat_score"]["risk_level"] in {
            "low", "medium", "high", "critical"
        }
        assert "flags" in result
        assert "ioc_extraction" in result
        assert "threat_intelligence" in result
        assert "geolocation" in result

        # --- 2. build_ai_evidence() was used ---
        # Evidence produced by build_ai_evidence has "source" provenance tags
        ev = mock.last_evidence
        assert ev is not None
        assert ev["threat_score"]["source"] == "threat_score"
        assert ev["authentication"]["source"] == "authentication"
        assert ev["email_metadata"]["source"] == "email_metadata"
        # Sensitive fields must be absent (scrubbing worked)
        ev_str = json.dumps(ev)
        assert "access_token" not in ev_str
        assert "refresh_token" not in ev_str
        assert "Body with an IP" not in ev_str  # raw body excluded

        # --- 3. AI provider was called with evidence ---
        assert "threat_score" in ev
        assert "iocs" in ev
        assert "email_metadata" in ev
        assert ev["email_metadata"]["sender"] == "sender@example.com"

        # --- 4. AIAnalysisResult stored under analysis["ai_analysis"] ---
        ai = result["ai_analysis"]
        assert ai["classification"] == "malicious"
        assert ai["confidence"] == pytest.approx(0.93)
        assert ai["summary"] == "Mock AI summary"
        assert ai["explanation"] == "Mock AI explanation"
        assert ai["recommended_actions"] == ["Review email", "Check sender"]
        assert ai["provider"] == "mock-gemini"
        assert ai["error"] is None

        # --- 5. Persisted ForensicAnalysis contains ai_analysis ---
        fa = db.query(ForensicAnalysis).filter_by(email_id=db_email.id).one()
        assert "ai_analysis" in fa.analysis
        assert fa.analysis["ai_analysis"]["classification"] == "malicious"
        assert fa.analysis["ai_analysis"]["confidence"] == pytest.approx(0.93)
        # Deterministic results also persisted alongside AI
        assert "threat_score" in fa.analysis
        assert "ioc_extraction" in fa.analysis

        db.close()

    def test_ai_failure_preserves_deterministic_pipeline(self, monkeypatch):
        """Requirement 6: AI failure does not break deterministic analysis."""
        monkeypatch.setattr(
            "analysis.get_ai_provider", lambda: _FailingProvider()
        )

        db = TestSession()
        parsed, db_email = _seed_email(db, SAMPLE_EML_WITH_HEADERS)

        # Must not raise despite the AI provider crashing
        result = run_email_analysis(parsed, db_email, db)

        # Deterministic analysis is fully intact
        assert "threat_score" in result
        assert "flags" in result
        assert "ioc_extraction" in result
        assert "threat_intelligence" in result
        assert "geolocation" in result

        # AI failure captured safely
        assert result["ai_analysis"]["classification"] == "unknown"
        assert result["ai_analysis"]["error"] is not None

        # Persisted correctly — exactly one row
        fa = db.query(ForensicAnalysis).filter_by(email_id=db_email.id).one()
        assert "ai_analysis" in fa.analysis
        assert "threat_score" in fa.analysis

        db.close()
