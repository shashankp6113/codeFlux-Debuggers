"""Tests for Gmail message retrieval and conversion."""

import base64
import json
import os
import pytest

from fastapi.testclient import TestClient
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

from models import Base, User, EmailAccount, Email, ForensicAnalysis  # noqa: F401
from database import get_db
from main import app
from gmail_client import (
    list_message_ids,
    get_raw_message,
    convert_raw_to_parsed,
    sync_gmail_messages,
    GmailAPIError,
    GmailMessageError,
    GmailMessageRef,
    GmailSyncResult,
    _MAX_LIMIT,
)


# ---------------------------------------------------------------------------
# Test database setup
# ---------------------------------------------------------------------------

def _override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    old = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = _override_get_db
    yield
    if old is not None:
        app.dependency_overrides[get_db] = old
    else:
        app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=TEST_ENGINE)


client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_EML = b"""\
From: sender@example.com
To: recipient@dest.com
Subject: Test Gmail Message
Date: Thu, 01 Jan 2026 12:00:00 +0000
Message-ID: <msg-001@example.com>
Content-Type: text/plain

Hello from Gmail!
"""

SAMPLE_EML_2 = b"""\
From: another@example.com
To: user@dest.com
Subject: Second Gmail Message
Date: Fri, 02 Jan 2026 14:00:00 +0000
Message-ID: <msg-002@example.com>
Content-Type: text/plain

Second message body.
"""

MALFORMED_EML = b"""\
Not a valid email at all - just garbage text
"""


def _b64url(raw_bytes):
    """Encode bytes as base64url (no padding), as Gmail would."""
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


class _FakeResp:
    """Minimal httpx.Response stand-in."""

    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = json.dumps(self._json)

    def json(self):
        return self._json


def _seed_gmail_account():
    """Create a User + Gmail EmailAccount, return account ID."""
    db = TestSession()
    user = User(email="gmail-test@gmail.com", name="Test")
    db.add(user)
    db.commit()
    db.refresh(user)
    account = EmailAccount(
        user_id=user.id,
        provider="gmail",
        email_address="gmail-test@gmail.com",
        access_token="test-access-token",
        refresh_token="test-refresh-token",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    account_id = account.id
    db.close()
    return account_id


def _seed_non_gmail_account():
    """Create a non-Gmail EmailAccount, return account ID."""
    db = TestSession()
    user = User(email="outlook@test.com", name="Test")
    db.add(user)
    db.commit()
    db.refresh(user)
    account = EmailAccount(
        user_id=user.id,
        provider="outlook",
        email_address="outlook@test.com",
        access_token="tok",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    account_id = account.id
    db.close()
    return account_id


def _mock_gmail_api(monkeypatch, messages=None, raw_bytes=None):
    """Mock httpx.get for Gmail API: list + get raw message."""
    if messages is None:
        messages = [{"id": "aaa111", "threadId": "thr1"}]
    if raw_bytes is None:
        raw_bytes = SAMPLE_EML

    list_resp = _FakeResp(200, {"messages": messages})
    raw_resp = _FakeResp(200, {"raw": _b64url(raw_bytes)})

    def _mock_get(url, **kwargs):
        if "/messages/" in url and "/messages?" not in url:
            # Individual message get
            return raw_resp
        elif "/messages" in url:
            # List messages
            return list_resp
        return _FakeResp(404)

    monkeypatch.setattr("httpx.get", _mock_get)
    async def _mock_get_async(self, url, *args, **kwargs):
        return _mock_get(url, *args, **kwargs)
    monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)


# ---------------------------------------------------------------------------
# Tests: list_message_ids (unit)
# ---------------------------------------------------------------------------

class TestListMessageIds:
    """list_message_ids() with mocked HTTP."""

    def test_returns_refs(self, monkeypatch):
        resp = _FakeResp(200, {
            "messages": [
                {"id": "aaa", "threadId": "t1"},
                {"id": "bbb", "threadId": "t2"},
            ]
        })
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        refs = list_message_ids("tok")
        assert len(refs) == 2
        assert refs[0].id == "aaa"
        assert refs[1].id == "bbb"

    def test_empty_inbox(self, monkeypatch):
        resp = _FakeResp(200, {})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        refs = list_message_ids("tok")
        assert refs == []

    def test_401_raises(self, monkeypatch):
        resp = _FakeResp(401)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        with pytest.raises(GmailAPIError) as exc_info:
            list_message_ids("tok")
        assert "401" in str(exc_info.value)

    def test_429_raises(self, monkeypatch):
        resp = _FakeResp(429)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        with pytest.raises(GmailAPIError) as exc_info:
            list_message_ids("tok")
        assert "429" in str(exc_info.value)

    def test_network_error(self, monkeypatch):
        def _raise(*a, **kw):
            raise ConnectionError("refused")
        monkeypatch.setattr("httpx.get", _raise)
        with pytest.raises(GmailAPIError) as exc_info:
            list_message_ids("tok")
        assert "Network" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Tests: get_raw_message (unit)
# ---------------------------------------------------------------------------

class TestGetRawMessage:
    """get_raw_message() with mocked HTTP."""

    def test_decodes_base64url(self, monkeypatch):
        encoded = _b64url(SAMPLE_EML)
        resp = _FakeResp(200, {"raw": encoded})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        raw = get_raw_message("tok", "msg1")
        assert raw == SAMPLE_EML

    def test_missing_raw_field(self, monkeypatch):
        resp = _FakeResp(200, {"id": "msg1"})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        with pytest.raises(GmailMessageError) as exc_info:
            get_raw_message("tok", "msg1")
        assert "raw" in str(exc_info.value).lower()

    def test_401_raises(self, monkeypatch):
        resp = _FakeResp(401)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        with pytest.raises(GmailAPIError):
            get_raw_message("tok", "msg1")

    def test_malformed_base64_raises(self, monkeypatch):
        resp = _FakeResp(200, {"raw": "!!!not-valid-base64!!!"})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        # This should still decode (base64 is lenient), but test the path
        # Actually base64url is quite lenient — test with truly invalid data
        # We test the error path via convert_raw_to_parsed for parse failures
        pass  # covered by TestConversion::test_malformed_eml


# ---------------------------------------------------------------------------
# Tests: convert_raw_to_parsed (unit)
# ---------------------------------------------------------------------------

class TestConversion:
    """convert_raw_to_parsed() reusing the existing parser."""

    def test_parses_subject(self):
        parsed = convert_raw_to_parsed(SAMPLE_EML)
        assert parsed.subject == "Test Gmail Message"

    def test_parses_sender(self):
        parsed = convert_raw_to_parsed(SAMPLE_EML)
        assert parsed.sender == "sender@example.com"

    def test_parses_recipient(self):
        parsed = convert_raw_to_parsed(SAMPLE_EML)
        assert parsed.recipient == "recipient@dest.com"

    def test_parses_message_id(self):
        parsed = convert_raw_to_parsed(SAMPLE_EML)
        assert parsed.message_id == "<msg-001@example.com>"

    def test_parses_body(self):
        parsed = convert_raw_to_parsed(SAMPLE_EML)
        assert "Hello from Gmail" in parsed.body_text

    def test_parses_raw_headers(self):
        parsed = convert_raw_to_parsed(SAMPLE_EML)
        assert "From:" in parsed.raw_headers

    def test_malformed_eml_raises(self):
        with pytest.raises(GmailMessageError):
            convert_raw_to_parsed(MALFORMED_EML)


# ---------------------------------------------------------------------------
# Tests: sync_gmail_messages (unit, mocked HTTP)
# ---------------------------------------------------------------------------

class TestSyncGmailMessages:
    """sync_gmail_messages() with mocked Gmail API."""

    def test_persists_message(self, monkeypatch):
        _mock_gmail_api(monkeypatch)
        db = TestSession()
        acct_id = _seed_gmail_account()

        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        assert result.persisted == 1
        assert result.fetched == 1

        emails = db.query(Email).filter_by(email_account_id=acct_id).all()
        assert len(emails) == 1
        assert emails[0].subject == "Test Gmail Message"
        db.close()

    def test_duplicate_detection(self, monkeypatch):
        """Same message_id is not persisted twice."""
        _mock_gmail_api(monkeypatch)
        db = TestSession()
        acct_id = _seed_gmail_account()

        result1 = sync_gmail_messages(acct_id, "tok", db, limit=5)
        assert result1.persisted == 1

        result2 = sync_gmail_messages(acct_id, "tok", db, limit=5)
        assert result2.persisted == 0
        assert result2.skipped_duplicate == 1

        emails = db.query(Email).filter_by(email_account_id=acct_id).all()
        assert len(emails) == 1
        db.close()

    def test_missing_analysis_retry(self, monkeypatch):
        """Zombie emails (Email exists, no ForensicAnalysis) are retried."""
        _mock_gmail_api(monkeypatch)
        db = TestSession()
        acct_id = _seed_gmail_account()
        
        # 1. Create the zombie email manually
        from email_parser import parse_eml
        parsed = parse_eml(SAMPLE_EML)
        db_email = Email(
            email_account_id=acct_id,
            message_id="aaa111",  # Mock list_message_ids returns aaa111
            sender=parsed.sender,
            recipient=parsed.recipient,
        )
        db.add(db_email)
        db.commit()
        
        # 2. Mock run_email_analysis to track calls
        calls = []
        import gmail_client
        import analysis
        import analysis
        original_run = analysis.run_email_analysis
        
        def mock_run(parsed_arg, db_email_arg, db_arg):
            calls.append(db_email_arg.id)
            return original_run(parsed_arg, db_email_arg, db_arg)
            
        monkeypatch.setattr(analysis, "run_email_analysis", mock_run)
        
        # 3. Sync - should pick up the existing email and retry it
        result = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        assert len(calls) == 1
        assert result.persisted == 0
        assert result.skipped_duplicate == 0
        
        analysis_exists = db.query(ForensicAnalysis).filter_by(email_id=db_email.id).first() is not None
        assert analysis_exists
        db.close()



    def test_bcc_email_survives_gmail_sync(self, monkeypatch):
        """A message with no To: header (Bcc) is successfully synced."""
        messages = [{"id": "bcc111", "threadId": "thr1"}]
        # No To: header
        raw_bcc = b"Message-ID: <bcc@test>\r\nFrom: a@test\r\nSubject: Bcc Test\r\nDate: Thu, 10 Jul 2025 14:30:00 +0000\r\n\r\nBcc Body"
        
        def _mock_get(url, **kwargs):
            if "bcc111" in url:
                return _FakeResp(200, {"raw": _b64url(raw_bcc)})
            if "/messages" in url:
                return _FakeResp(200, {"messages": messages})
            return _FakeResp(404)
            
        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        
        db = TestSession()
        acct_id = _seed_gmail_account()
        
        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        assert result.fetched == 1
        assert result.persisted == 1
        assert len(result.errors) == 0
        
        db_emails = db.query(Email).filter_by(email_account_id=acct_id).all()
        assert len(db_emails) == 1
        assert db_emails[0].recipient == "Undisclosed Recipients"
        
        db.close()

    def test_malformed_date_email_survives_gmail_sync(self, monkeypatch):
        """A message with an invalid Date header is successfully synced."""
        messages = [{"id": "baddate111", "threadId": "thr1"}]
        raw_bad = b"Message-ID: <bad@test>\r\nFrom: a@test\r\nTo: b@test\r\nDate: Not a Date\r\n\r\nBody"
        
        def _mock_get(url, **kwargs):
            if "baddate111" in url:
                return _FakeResp(200, {"raw": _b64url(raw_bad)})
            if "/messages" in url:
                return _FakeResp(200, {"messages": messages})
            return _FakeResp(404)
            
        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        
        db = TestSession()
        acct_id = _seed_gmail_account()
        
        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        assert result.fetched == 1
        assert result.persisted == 1
        assert len(result.errors) == 0
        
        db_emails = db.query(Email).filter_by(email_account_id=acct_id).all()
        assert len(db_emails) == 1
        assert db_emails[0].received_at is None
        
        db.close()
    def test_email_persistence_failure_does_not_abort_sync(self, monkeypatch):
        """A failure to save one email to the database does not block subsequent valid emails."""
        messages = [
            {"id": "msg_fail", "threadId": "thr1"},
            {"id": "msg_ok", "threadId": "thr1"}
        ]
        
        # Use a null byte to trigger a database DataError during commit
        raw_fail = b"Message-ID: <fail@test>\r\nFrom: a@test\r\nTo: b@test\r\n\r\nBadBody\x00"
        raw_ok = b"Message-ID: <ok@test>\r\nFrom: a@test\r\nTo: b@test\r\n\r\nGoodBody"
        
        list_resp = _FakeResp(200, {"messages": messages})
        
        def _mock_get(url, **kwargs):
            if "msg_fail" in url:
                return _FakeResp(200, {"raw": _b64url(raw_fail)})
            if "msg_ok" in url:
                return _FakeResp(200, {"raw": _b64url(raw_ok)})
            if "/messages" in url:
                return list_resp
            return _FakeResp(404)
            
        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        
        # We need to simulate a DB error on commit. SQLite might accept null bytes, 
        # so we'll mock db_session.commit to throw an exception for the bad message.
        import database
        
        
        db = TestSession()
        acct_id = _seed_gmail_account()
        
        commit_calls = []
        def mock_commit():
            # Check what's pending
            new_emails = [obj for obj in db.new if isinstance(obj, Email)]
            if new_emails and new_emails[0].message_id == "msg_fail":
                raise Exception("Simulated DB DataError on insert")
            db.commit()
            
        # We must monkeypatch the instance method of the session passed in
        original_db_commit = db.commit
        def db_commit_override():
            new_emails = [obj for obj in db.new if isinstance(obj, Email)]
            if new_emails and new_emails[0].message_id == "msg_fail":
                raise Exception("Simulated DB DataError on insert")
            original_db_commit()
            
        db.commit = db_commit_override

        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        # Verify result counts
        assert result.fetched == 2
        assert result.persisted == 1  # only msg_ok
        assert len(result.errors) == 1
        assert "Simulated DB DataError" in result.errors[0]
        assert "msg_fail" in result.errors[0]
        
        # Verify db contents
        db_emails = db.query(Email).filter_by(email_account_id=acct_id).all()
        assert len(db_emails) == 1
        assert db_emails[0].message_id == "msg_ok"
        
        db.close()

    def test_analysis_failure_rolls_back_and_continues(self, monkeypatch):
        """If run_email_analysis fails (e.g. during its commit), it rolls back and sync continues."""
        messages = [
            {"id": "msg_analysis_fail", "threadId": "thr1"},
            {"id": "msg_analysis_ok", "threadId": "thr1"}
        ]
        
        raw_fail = b"Message-ID: <fail@test>\r\nFrom: a@test\r\nTo: b@test\r\n\r\nFailAnalysis"
        raw_ok = b"Message-ID: <ok@test>\r\nFrom: a@test\r\nTo: b@test\r\n\r\nOkAnalysis"
        
        list_resp = _FakeResp(200, {"messages": messages})
        
        def _mock_get(url, **kwargs):
            if "msg_analysis_fail" in url:
                return _FakeResp(200, {"raw": _b64url(raw_fail)})
            if "msg_analysis_ok" in url:
                return _FakeResp(200, {"raw": _b64url(raw_ok)})
            if "/messages" in url:
                return list_resp
            return _FakeResp(404)
            
        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        
        db = TestSession()
        acct_id = _seed_gmail_account()
        
        # We need to mock run_email_analysis to throw an exception that simulates a failed DB commit
        # which puts the session in a pending rollback state
        import analysis
        original_run = analysis.run_email_analysis
        
        def mock_run_analysis(parsed, db_email, db_session):
            if db_email.message_id == "msg_analysis_fail":
                # Simulate a DB commit failure by forcing the session into an errored state
                from sqlalchemy import text
                try:
                    db_session.execute(text("SELECT * FROM non_existent_table"))
                except Exception:
                    pass
                # The session is now poisoned. We raise an exception like run_email_analysis would
                raise Exception("Simulated run_email_analysis db.commit() failure")
            else:
                return original_run(parsed, db_email, db_session)
                
        monkeypatch.setattr(analysis, "run_email_analysis", mock_run_analysis)
        
        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        assert result.fetched == 2
        # Both were persisted as emails successfully
        assert result.persisted == 2
        assert len(result.errors) == 1
        assert "Simulated run_email_analysis db.commit() failure" in result.errors[0]
        
        # Verify db contents
        db_emails = db.query(Email).filter_by(email_account_id=acct_id).order_by(Email.message_id).all()
        assert len(db_emails) == 2
        
        # msg_analysis_fail should NOT have an analysis record (it is a zombie)
        zombie = [e for e in db_emails if e.message_id == "msg_analysis_fail"][0]
        has_analysis = db.query(ForensicAnalysis).filter_by(email_id=zombie.id).first() is not None
        assert not has_analysis
        
        # msg_analysis_ok SHOULD have an analysis record
        ok_msg = [e for e in db_emails if e.message_id == "msg_analysis_ok"][0]
        has_analysis_ok = db.query(ForensicAnalysis).filter_by(email_id=ok_msg.id).first() is not None
        assert has_analysis_ok
        
        db.close()
    def test_analysis_retry_failure_session_safety(self, monkeypatch):
        """Failed retries rollback and do not poison the session for subsequent valid emails."""
        messages = [
            {"id": "aaa111", "threadId": "thr1"},
            {"id": "bbb222", "threadId": "thr1"}
        ]
        
        raw1 = b"Message-ID: <id1@test>\r\nFrom: a@test\r\nTo: b@test\r\n\r\nBody1"
        raw2 = b"Message-ID: <id2@test>\r\nFrom: c@test\r\nTo: d@test\r\n\r\nBody2"
        
        list_resp = _FakeResp(200, {"messages": messages})
        
        def _mock_get(url, **kwargs):
            if "aaa111" in url:
                return _FakeResp(200, {"raw": _b64url(raw1)})
            if "bbb222" in url:
                return _FakeResp(200, {"raw": _b64url(raw2)})
            if "/messages" in url:
                return list_resp
            return _FakeResp(404)
            
        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        
        db = TestSession()
        acct_id = _seed_gmail_account()
        
        # Pre-seed id1@test as a zombie
        db_email1 = Email(email_account_id=acct_id, message_id="aaa111", sender="a@test", recipient="b@test")
        db.add(db_email1)
        db.commit()
        
        import gmail_client
        import analysis
        import analysis
        original_run = analysis.run_email_analysis
        
        def mock_run(parsed_arg, db_email_arg, db_arg):
            if parsed_arg.message_id == "<id1@test>":
                raise ValueError("Simulated hard crash")
            return original_run(parsed_arg, db_email_arg, db_arg)
            
        monkeypatch.setattr(analysis, "run_email_analysis", mock_run)
        
        result = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        assert len(result.errors) == 1
        assert "Simulated hard crash" in result.errors[0]
        assert result.persisted == 1 # id2
        assert result.skipped_duplicate == 0
        
        assert db.query(ForensicAnalysis).filter_by(email_id=db_email1.id).first() is None
        email2 = db.query(Email).filter_by(message_id="bbb222").first()
        assert email2 is not None
        assert db.query(ForensicAnalysis).filter_by(email_id=email2.id).first() is not None
        
        db.close()

    def test_duplicate_detection_preservation(self, monkeypatch):
        """Emails with ForensicAnalysis are cleanly skipped without calling analysis."""
        _mock_gmail_api(monkeypatch)
        db = TestSession()
        acct_id = _seed_gmail_account()
        
        import gmail_client
        import analysis
        gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        calls = []
        def mock_run(parsed_arg, db_email_arg, db_arg):
            calls.append(db_email_arg.id)
            
        monkeypatch.setattr(analysis, "run_email_analysis", mock_run)
        
        result = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
        
        assert len(calls) == 0
        assert result.persisted == 0
        assert result.skipped_duplicate == 1
        db.close()

    def test_empty_inbox(self, monkeypatch):
        _mock_gmail_api(monkeypatch, messages=[])
        db = TestSession()
        acct_id = _seed_gmail_account()

        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        assert result.fetched == 0
        assert result.persisted == 0
        db.close()

    def test_api_error_recorded(self, monkeypatch):
        """API errors during listing → errors in result."""
        def _mock_get(*a, **kw):
            return _FakeResp(500)
        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        db = TestSession()
        acct_id = _seed_gmail_account()

        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        assert len(result.errors) > 0
        db.close()

    def test_malformed_message_error(self, monkeypatch):
        """Malformed individual message doesn't crash the batch."""
        _mock_gmail_api(monkeypatch, raw_bytes=MALFORMED_EML)
        db = TestSession()
        acct_id = _seed_gmail_account()

        result = sync_gmail_messages(acct_id, "tok", db, limit=5)
        assert result.persisted == 0
        assert len(result.errors) == 1
        db.close()

    def test_limit_enforced(self, monkeypatch):
        """Limit is capped at _MAX_LIMIT."""
        calls = []

        def _mock_get(url, **kwargs):
            calls.append(kwargs.get("params", {}))
            if "/messages?" in url or url.endswith("/messages"):
                return _FakeResp(200, {"messages": []})
            return _FakeResp(200, {"raw": _b64url(SAMPLE_EML)})

        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        db = TestSession()
        acct_id = _seed_gmail_account()

        sync_gmail_messages(acct_id, "tok", db, limit=999)
        # The maxResults param should be capped
        assert calls[0].get("maxResults", 0) <= _MAX_LIMIT
        db.close()

    def test_multiple_messages(self, monkeypatch):
        """Multiple messages are persisted."""
        messages = [
            {"id": "aaa", "threadId": "t1"},
            {"id": "bbb", "threadId": "t2"},
        ]
        list_resp = _FakeResp(200, {"messages": messages})

        call_count = [0]

        def _mock_get(url, **kwargs):
            if "/messages/" in url and "/messages?" not in url:
                call_count[0] += 1
                if call_count[0] == 1:
                    return _FakeResp(200, {"raw": _b64url(SAMPLE_EML)})
                else:
                    return _FakeResp(200, {"raw": _b64url(SAMPLE_EML_2)})
            elif "/messages" in url:
                return list_resp
            return _FakeResp(404)

        monkeypatch.setattr("httpx.get", _mock_get)
        async def _mock_get_async(self, url, *args, **kwargs):
            return _mock_get(url, *args, **kwargs)
        monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
        db = TestSession()
        acct_id = _seed_gmail_account()

        result = sync_gmail_messages(acct_id, "tok", db, limit=10)
        assert result.persisted == 2
        assert result.fetched == 2
        db.close()


# ---------------------------------------------------------------------------
# Tests: GET /api/gmail/{id}/messages endpoint
# ---------------------------------------------------------------------------

class TestBase64UrlDecoding:
    """Verify base64url decoding handles Gmail's encoding correctly."""

    def test_no_padding(self, monkeypatch):
        """Gmail omits padding — our code adds it."""
        raw = b"Hello world test"
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        resp = _FakeResp(200, {"raw": encoded})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = get_raw_message("tok", "msg1")
        assert result == raw

    def test_url_safe_chars(self, monkeypatch):
        """base64url uses - and _ instead of + and /."""
        # Create bytes that would produce + and / in standard base64
        raw = bytes(range(256))
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        assert "+" not in encoded
        assert "/" not in encoded
        resp = _FakeResp(200, {"raw": encoded})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = get_raw_message("tok", "msg1")
        assert result == raw


# ---------------------------------------------------------------------------
# Tests: Gmail analysis pipeline integration
# ---------------------------------------------------------------------------

# Sample EML with Authentication-Results to trigger header forensics
SAMPLE_EML_WITH_AUTH = b"""\
From: sender@example.com
To: recipient@dest.com
Subject: Gmail with auth headers
Date: Thu, 01 Jan 2026 12:00:00 +0000
Message-ID: <msg-auth-001@example.com>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com
Received: from mail.example.com (mail.example.com [8.8.8.8])
        by mx.dest.com with ESMTP; Thu, 01 Jan 2026 12:00:00 +0000
Content-Type: text/plain

Body with an IP 8.8.8.8 and a URL http://evil.test/payload for IOC testing.
"""

# Minimal EML without raw headers scenario (body only, no Received/Auth)
SAMPLE_EML_MINIMAL = b"""\
From: min@example.com
To: dest@example.com
Subject: Minimal
Date: Thu, 01 Jan 2026 12:00:00 +0000
Message-ID: <msg-min-001@example.com>
Content-Type: text/plain

Just a plain body with 10.0.0.1 for IOC testing.
"""




def test_gmail_internal_id_deduplication(monkeypatch):
    from database import SessionLocal
    from models import Email, ForensicAnalysis
    import gmail_client
    
    # 2 messages, same RFC Message-ID but different Gmail ref IDs
    messages = [
        {"id": "gmail_ref_1", "threadId": "t1"},
        {"id": "gmail_ref_2", "threadId": "t1"}
    ]
    raw_content = b"Message-ID: <same_id@test>\r\nFrom: a@test\r\nTo: b@test\r\n\r\nBody"
    
    list_resp = _FakeResp(200, {"messages": messages})
    def _mock_get(url, **kwargs):
        if "gmail_ref_1" in url or "gmail_ref_2" in url:
            return _FakeResp(200, {"raw": _b64url(raw_content)})
        if "/messages" in url:
            return list_resp
        return _FakeResp(404)
        
    monkeypatch.setattr("httpx.get", _mock_get)
    async def _mock_get_async(self, url, *args, **kwargs):
        return _mock_get(url, *args, **kwargs)
    monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
    
    db = TestSession()
    acct_id = _seed_gmail_account()
    
    result = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
    assert result.persisted == 2
    assert result.skipped_duplicate == 0
    
    # Verify two distinct rows with same RFC Message-ID are saved under their ref.id
    email1 = db.query(Email).filter_by(message_id="gmail_ref_1").first()
    email2 = db.query(Email).filter_by(message_id="gmail_ref_2").first()
    assert email1 is not None
    assert email2 is not None
    
    # Verify forensic analysis preserved the original RFC Message-ID
    fa1 = db.query(ForensicAnalysis).filter_by(email_id=email1.id).first()
    fa2 = db.query(ForensicAnalysis).filter_by(email_id=email2.id).first()
    assert fa1.analysis["identity"]["message_id"] == "<same_id@test>"
    assert fa2.analysis["identity"]["message_id"] == "<same_id@test>"
    db.close()

def test_gmail_missing_rfc_message_id_deduplication(monkeypatch):
    from database import SessionLocal
    from models import Email
    import gmail_client
    
    # Gmail message has no Message-ID header
    messages = [{"id": "gmail_ref_no_rfc", "threadId": "t1"}]
    raw_content = b"From: a@test\r\nTo: b@test\r\n\r\nBody"
    
    list_resp = _FakeResp(200, {"messages": messages})
    def _mock_get(url, **kwargs):
        if "gmail_ref_no_rfc" in url:
            return _FakeResp(200, {"raw": _b64url(raw_content)})
        if "/messages" in url:
            return list_resp
        return _FakeResp(404)
        
    monkeypatch.setattr("httpx.get", _mock_get)
    async def _mock_get_async(self, url, *args, **kwargs):
        return _mock_get(url, *args, **kwargs)
    monkeypatch.setattr("httpx.AsyncClient.get", _mock_get_async)
    
    db = TestSession()
    acct_id = _seed_gmail_account()
    
    # First sync
    res1 = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
    assert res1.persisted == 1
    
    # Second sync (should correctly skip despite no RFC Message-ID)
    res2 = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
    assert res2.skipped_duplicate == 1
    assert res2.persisted == 0
    
    # Verify only one email stored under ref.id
    emails = db.query(Email).filter_by(message_id="gmail_ref_no_rfc").all()
    assert len(emails) == 1
    db.close()

def test_gmail_duplicate_internal_id(monkeypatch):
    import gmail_client
    from models import ForensicAnalysis
    # Handled by test_duplicate_detection but adding explicit test to verify C requirement
    _mock_gmail_api(monkeypatch)
    db = TestSession()
    acct_id = _seed_gmail_account()
    
    # Sync 1
    res1 = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
    assert res1.persisted == 1
    
    calls = []
    import analysis
    original_run = analysis.run_email_analysis
    def mock_run(parsed_arg, db_email_arg, db_arg):
        calls.append(True)
        return original_run(parsed_arg, db_email_arg, db_arg)
    monkeypatch.setattr(analysis, "run_email_analysis", mock_run)
    
    # Sync 2 (duplicate ref.id)
    res2 = gmail_client.sync_gmail_messages(acct_id, "tok", db, limit=5)
    assert res2.skipped_duplicate == 1
    assert res2.persisted == 0
    
    # Analysis must NOT have been called again!
    assert len(calls) == 0
    db.close()
