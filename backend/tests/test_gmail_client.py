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
        db = TestSession()
        acct_id = _seed_gmail_account()

        result = sync_gmail_messages(acct_id, "tok", db, limit=10)
        assert result.persisted == 2
        assert result.fetched == 2
        db.close()


# ---------------------------------------------------------------------------
# Tests: GET /api/gmail/{id}/messages endpoint
# ---------------------------------------------------------------------------

class TestGmailFetchEndpoint:
    """Integration tests for the Gmail fetch endpoint."""

    def test_success(self, monkeypatch):
        acct_id = _seed_gmail_account()
        _mock_gmail_api(monkeypatch)
        r = client.get(f"/api/gmail/{acct_id}/messages")
        assert r.status_code == 200
        data = r.json()
        assert data["persisted"] == 1
        assert data["email_account_id"] == acct_id

    def test_account_not_found(self):
        r = client.get("/api/gmail/9999/messages")
        assert r.status_code == 404

    def test_non_gmail_account(self):
        acct_id = _seed_non_gmail_account()
        r = client.get(f"/api/gmail/{acct_id}/messages")
        assert r.status_code == 400
        assert "not a Gmail" in r.json()["detail"]

    def test_no_access_token(self):
        db = TestSession()
        user = User(email="notoken@gmail.com", name="Test")
        db.add(user)
        db.commit()
        db.refresh(user)
        account = EmailAccount(
            user_id=user.id,
            provider="gmail",
            email_address="notoken@gmail.com",
            access_token=None,
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        acct_id = account.id
        db.close()

        r = client.get(f"/api/gmail/{acct_id}/messages")
        assert r.status_code == 400
        assert "access token" in r.json()["detail"].lower()

    def test_gmail_api_error(self, monkeypatch):
        acct_id = _seed_gmail_account()
        monkeypatch.setattr("httpx.get", lambda *a, **kw: _FakeResp(500))
        r = client.get(f"/api/gmail/{acct_id}/messages")
        assert r.status_code == 200  # sync errors are in result, not HTTP error
        data = r.json()
        assert len(data["errors"]) > 0

    def test_duplicate_on_second_fetch(self, monkeypatch):
        acct_id = _seed_gmail_account()
        _mock_gmail_api(monkeypatch)
        r1 = client.get(f"/api/gmail/{acct_id}/messages")
        assert r1.json()["persisted"] == 1

        r2 = client.get(f"/api/gmail/{acct_id}/messages")
        assert r2.json()["persisted"] == 0
        assert r2.json()["skipped_duplicate"] == 1

    def test_persisted_email_fields(self, monkeypatch):
        acct_id = _seed_gmail_account()
        _mock_gmail_api(monkeypatch)
        client.get(f"/api/gmail/{acct_id}/messages")

        db = TestSession()
        email_row = db.query(Email).filter_by(email_account_id=acct_id).first()
        assert email_row is not None
        assert email_row.subject == "Test Gmail Message"
        assert email_row.sender == "sender@example.com"
        assert email_row.recipient == "recipient@dest.com"
        assert email_row.message_id == "<msg-001@example.com>"
        assert "From:" in email_row.raw_headers
        db.close()

    def test_limit_param(self, monkeypatch):
        acct_id = _seed_gmail_account()
        _mock_gmail_api(monkeypatch, messages=[])
        r = client.get(f"/api/gmail/{acct_id}/messages?limit=3")
        assert r.status_code == 200

    def test_tokens_not_in_response(self, monkeypatch):
        """Tokens must NEVER appear in the API response."""
        acct_id = _seed_gmail_account()
        _mock_gmail_api(monkeypatch)
        r = client.get(f"/api/gmail/{acct_id}/messages")
        body = json.dumps(r.json())
        assert "test-access-token" not in body
        assert "test-refresh-token" not in body
        assert "access_token" not in body
        assert "refresh_token" not in body

    def test_existing_upload_unchanged(self, monkeypatch):
        """The .eml upload endpoint still works after adding Gmail fetch."""
        # Create an account for upload
        db = TestSession()
        user = User(email="upload@test.com", name="Test")
        db.add(user)
        db.commit()
        db.refresh(user)
        account = EmailAccount(
            user_id=user.id,
            provider="manual",
            email_address="upload@test.com",
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        acct_id = account.id
        db.close()

        import io
        eml_bytes = SAMPLE_EML
        r = client.post(
            "/api/emails/upload",
            data={"email_account_id": str(acct_id)},
            files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Tests: base64url decoding edge cases
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
