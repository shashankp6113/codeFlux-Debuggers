"""Tests for Gmail OAuth 2.0 foundation."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

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
from gmail_oauth import (
    get_oauth_config,
    build_authorization_url,
    exchange_code_for_tokens,
    get_gmail_user_email,
    OAuthConfig,
    OAuthConfigError,
    TokenExchangeError,
    UserInfoError,
    GMAIL_READONLY_SCOPE,
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


client = TestClient(app, follow_redirects=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OAUTH_ENV = {
    "GOOGLE_CLIENT_ID": "test-client-id",
    "GOOGLE_CLIENT_SECRET": "test-client-secret",
    "GOOGLE_REDIRECT_URI": "http://localhost:8000/api/auth/gmail/callback",
}


def _set_oauth_env(monkeypatch):
    for k, v in _OAUTH_ENV.items():
        monkeypatch.setenv(k, v)


def _clear_oauth_env(monkeypatch):
    for k in _OAUTH_ENV:
        monkeypatch.delenv(k, raising=False)


class _FakeHTTPResponse:
    """Minimal httpx.Response stand-in."""

    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = json.dumps(self._json)

    def json(self):
        return self._json

    def raise_for_status(self):
        pass


# ---------------------------------------------------------------------------
# Tests: OAuth configuration
# ---------------------------------------------------------------------------

class TestOAuthConfig:
    """get_oauth_config() and OAuthConfig."""

    def test_loads_all_vars(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        assert config.client_id == "test-client-id"
        assert config.client_secret == "test-client-secret"
        assert config.redirect_uri == "http://localhost:8000/api/auth/gmail/callback"

    def test_missing_client_id(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        monkeypatch.delenv("GOOGLE_CLIENT_ID")
        with pytest.raises(OAuthConfigError) as exc_info:
            get_oauth_config()
        assert "GOOGLE_CLIENT_ID" in str(exc_info.value)

    def test_missing_client_secret(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        monkeypatch.delenv("GOOGLE_CLIENT_SECRET")
        with pytest.raises(OAuthConfigError) as exc_info:
            get_oauth_config()
        assert "GOOGLE_CLIENT_SECRET" in str(exc_info.value)

    def test_missing_redirect_uri(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        monkeypatch.delenv("GOOGLE_REDIRECT_URI")
        with pytest.raises(OAuthConfigError) as exc_info:
            get_oauth_config()
        assert "GOOGLE_REDIRECT_URI" in str(exc_info.value)

    def test_missing_all(self, monkeypatch):
        _clear_oauth_env(monkeypatch)
        with pytest.raises(OAuthConfigError) as exc_info:
            get_oauth_config()
        msg = str(exc_info.value)
        assert "GOOGLE_CLIENT_ID" in msg
        assert "GOOGLE_CLIENT_SECRET" in msg
        assert "GOOGLE_REDIRECT_URI" in msg

    def test_empty_vars_are_missing(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        monkeypatch.setenv("GOOGLE_CLIENT_ID", "  ")
        with pytest.raises(OAuthConfigError):
            get_oauth_config()


# ---------------------------------------------------------------------------
# Tests: Authorization URL
# ---------------------------------------------------------------------------

class TestAuthorizationURL:
    """build_authorization_url() behavior."""

    def test_contains_client_id(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        url = build_authorization_url(config)
        assert "test-client-id" in url

    def test_contains_redirect_uri(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        url = build_authorization_url(config)
        assert "localhost" in url

    def test_contains_gmail_scope(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        url = build_authorization_url(config)
        assert "gmail.readonly" in url
        

    def test_scope_is_readonly(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        url = build_authorization_url(config)
        # Must NOT request write scope
        assert "gmail.modify" not in url
        assert "gmail.compose" not in url

    def test_requests_offline_access(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        url = build_authorization_url(config)
        assert "access_type=offline" in url

    def test_response_type_code(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        url = build_authorization_url(config)
        assert "response_type=code" in url

    def test_starts_with_google_auth(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        url = build_authorization_url(config)
        assert url.startswith("https://accounts.google.com/")


# ---------------------------------------------------------------------------
# Tests: Token exchange (unit)
# ---------------------------------------------------------------------------

class TestTokenExchange:
    """exchange_code_for_tokens() with mocked HTTP."""

    def test_successful_exchange(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        resp = _FakeHTTPResponse(200, {
            "access_token": "ya29.test-access",
            "refresh_token": "1//test-refresh",
            "expires_in": 3600,
            "token_type": "Bearer",
        })
        monkeypatch.setattr("httpx.post", lambda *a, **kw: resp)
        result = exchange_code_for_tokens("test-code", config)
        assert result.access_token == "ya29.test-access"
        assert result.refresh_token == "1//test-refresh"
        assert result.expires_in == 3600

    def test_invalid_code_raises(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        resp = _FakeHTTPResponse(400, {
            "error": "invalid_grant",
            "error_description": "Code expired",
        })
        monkeypatch.setattr("httpx.post", lambda *a, **kw: resp)
        with pytest.raises(TokenExchangeError) as exc_info:
            exchange_code_for_tokens("bad-code", config)
        assert "400" in str(exc_info.value)

    def test_missing_access_token_raises(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        resp = _FakeHTTPResponse(200, {})
        monkeypatch.setattr("httpx.post", lambda *a, **kw: resp)
        with pytest.raises(TokenExchangeError) as exc_info:
            exchange_code_for_tokens("test-code", config)
        assert "access_token" in str(exc_info.value)

    def test_network_error_raises(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        config = get_oauth_config()
        import httpx as _httpx
        def _raise(*a, **kw):
            raise _httpx.ConnectError("refused")
        monkeypatch.setattr("httpx.post", _raise)
        with pytest.raises(TokenExchangeError) as exc_info:
            exchange_code_for_tokens("test-code", config)
        assert "Network error" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Tests: User identity (unit)
# ---------------------------------------------------------------------------

class TestGetGmailProfileEmail:
    """get_gmail_user_email() with mocked HTTP."""

    def test_returns_email(self, monkeypatch):
        resp = _FakeHTTPResponse(200, {"emailAddress": "user@gmail.com"})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        assert get_gmail_user_email("token") == "user@gmail.com"

    def test_missing_email_raises(self, monkeypatch):
        resp = _FakeHTTPResponse(200, {"name": "Test"})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        with pytest.raises(UserInfoError) as exc_info:
            get_gmail_user_email("token")
        assert "email" in str(exc_info.value).lower()

    def test_http_error_raises(self, monkeypatch):
        resp = _FakeHTTPResponse(401, {})
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        with pytest.raises(UserInfoError):
            get_gmail_user_email("token")


# ---------------------------------------------------------------------------
# Tests: /api/auth/gmail endpoint
# ---------------------------------------------------------------------------

class TestGmailAuthEndpoint:
    """GET /api/auth/gmail redirects to Google."""

    def test_redirects(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        r = client.get("/api/auth/gmail")
        assert r.status_code == 307
        assert "accounts.google.com" in r.headers["location"]

    def test_redirect_contains_scope(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        r = client.get("/api/auth/gmail")
        assert "gmail.readonly" in r.headers["location"]

    def test_missing_config_returns_500(self, monkeypatch):
        _clear_oauth_env(monkeypatch)
        r = client.get("/api/auth/gmail")
        assert r.status_code == 500
        assert "GOOGLE_CLIENT_ID" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Tests: /api/auth/gmail/callback endpoint
# ---------------------------------------------------------------------------

def _mock_successful_flow(monkeypatch):
    """Set up mocks for a successful OAuth flow."""
    _set_oauth_env(monkeypatch)

    # Mock token exchange
    token_resp = _FakeHTTPResponse(200, {
        "access_token": "ya29.test-access",
        "refresh_token": "1//test-refresh",
        "expires_in": 3600,
        "token_type": "Bearer",
    })

    # Mock userinfo
    profile_resp = _FakeHTTPResponse(200, {"emailAddress": "user@gmail.com"})

    def _mock_post(*args, **kwargs):
        return token_resp

    def _mock_get(url, **kwargs):
        if "profile" in url:
            return profile_resp
        return _FakeHTTPResponse(404)

    monkeypatch.setattr("httpx.post", _mock_post)
    monkeypatch.setattr("httpx.get", _mock_get)


class TestGmailCallbackEndpoint:
    """GET /api/auth/gmail/callback behavior."""

    def test_successful_callback(self, monkeypatch):
        _mock_successful_flow(monkeypatch)
        r = client.get("/api/auth/gmail/callback?code=test-auth-code&state=test-state", cookies={"oauth_state": "test-state"})
        assert r.status_code == 200
        data = r.json()
        assert data["message"] == "Gmail account authorized successfully"
        assert data["email_address"] == "user@gmail.com"
        assert data["provider"] == "gmail"
        assert "token" in data
        assert "user_id" in data
        assert "access_token" not in data
        assert "refresh_token" not in data
        
        import jwt
        from auth import JWT_SECRET_KEY, JWT_ALGORITHM
        payload = jwt.decode(data["token"], JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == str(data["user_id"])
    def test_creates_email_account(self, monkeypatch):
        _mock_successful_flow(monkeypatch)
        client.get("/api/auth/gmail/callback?code=test-auth-code&state=test-state", cookies={"oauth_state": "test-state"})
        db = TestSession()
        account = db.query(EmailAccount).filter_by(
            provider="gmail",
            email_address="user@gmail.com",
        ).first()
        assert account is not None
        assert account.access_token == "ya29.test-access"
        assert account.refresh_token == "1//test-refresh"
        db.close()

    def test_creates_user(self, monkeypatch):
        _mock_successful_flow(monkeypatch)
        client.get("/api/auth/gmail/callback?code=test-auth-code&state=test-state", cookies={"oauth_state": "test-state"})
        db = TestSession()
        user = db.query(User).filter_by(email="user@gmail.com").first()
        assert user is not None
        db.close()

    def test_updates_existing_account(self, monkeypatch):
        """Re-authorizing updates tokens on the existing account."""
        _mock_successful_flow(monkeypatch)
        # First auth
        r1 = client.get("/api/auth/gmail/callback?code=test-auth-code&state=test-state", cookies={"oauth_state": "test-state"})
        account_id = r1.json()["email_account_id"]

        # Update mock with new tokens
        new_token_resp = _FakeHTTPResponse(200, {
            "access_token": "ya29.new-access",
            "refresh_token": "1//new-refresh",
            "expires_in": 3600,
        })
        monkeypatch.setattr("httpx.post", lambda *a, **kw: new_token_resp)

        # Second auth
        r2 = client.get("/api/auth/gmail/callback?code=test-auth-code-2&state=test-state", cookies={"oauth_state": "test-state"})
        assert r2.json()["email_account_id"] == account_id

        # Verify tokens updated
        db = TestSession()
        account = db.get(EmailAccount, account_id)
        assert account.access_token == "ya29.new-access"
        assert account.refresh_token == "1//new-refresh"
        db.close()

    def test_error_param_returns_400(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        r = client.get("/api/auth/gmail/callback?error=access_denied&state=test-state", cookies={"oauth_state": "test-state"})
        assert r.status_code == 400
        assert "access_denied" in r.json()["detail"]

    def test_missing_code_returns_400(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        r = client.get("/api/auth/gmail/callback")
        assert r.status_code == 400
        assert "Missing" in r.json()["detail"]

    def test_token_exchange_failure(self, monkeypatch):
        _set_oauth_env(monkeypatch)
        token_resp = _FakeHTTPResponse(400, {
            "error": "invalid_grant",
            "error_description": "Code expired",
        })
        monkeypatch.setattr("httpx.post", lambda *a, **kw: token_resp)
        r = client.get("/api/auth/gmail/callback?code=bad-code&state=test-state", cookies={"oauth_state": "test-state"})
        assert r.status_code == 400

    def test_missing_config_returns_500(self, monkeypatch):
        _clear_oauth_env(monkeypatch)
        r = client.get("/api/auth/gmail/callback?code=test-code&state=test-state", cookies={"oauth_state": "test-state"})
        assert r.status_code == 500

    def test_tokens_not_in_response(self, monkeypatch):
        """Access and refresh tokens must NEVER be in the API response."""
        _mock_successful_flow(monkeypatch)
        r = client.get("/api/auth/gmail/callback?code=test-auth-code&state=test-state", cookies={"oauth_state": "test-state"})
        body = json.dumps(r.json())
        assert "ya29" not in body
        assert "test-access" not in body
        assert "test-refresh" not in body
        assert "access_token" not in body
        assert "refresh_token" not in body

    def test_provider_is_gmail(self, monkeypatch):
        _mock_successful_flow(monkeypatch)
        r = client.get("/api/auth/gmail/callback?code=test-auth-code&state=test-state", cookies={"oauth_state": "test-state"})
        assert r.json()["provider"] == "gmail"

    def test_has_email_account_id(self, monkeypatch):
        _mock_successful_flow(monkeypatch)
        r = client.get("/api/auth/gmail/callback?code=test-auth-code&state=test-state", cookies={"oauth_state": "test-state"})
        assert "email_account_id" in r.json()
        assert isinstance(r.json()["email_account_id"], int)


# ---------------------------------------------------------------------------
# Tests: GMAIL_READONLY_SCOPE constant
# ---------------------------------------------------------------------------

class TestGmailScope:
    """Verify the scope constant."""

    def test_scope_value(self):
        assert GMAIL_READONLY_SCOPE == "https://www.googleapis.com/auth/gmail.readonly"

    def test_scope_is_readonly(self):
        assert "readonly" in GMAIL_READONLY_SCOPE
        assert "modify" not in GMAIL_READONLY_SCOPE


# ---------------------------------------------------------------------------
# Tests: Account isolation
# ---------------------------------------------------------------------------

class TestAccountIsolation:
    """Prove that different Gmail addresses cannot overwrite each other."""

    def _mock_flow_for(self, monkeypatch, gmail_address, access_token="tok"):
        """Set up mocks so the callback resolves to *gmail_address*."""
        _set_oauth_env(monkeypatch)
        token_resp = _FakeHTTPResponse(200, {
            "access_token": access_token,
            "refresh_token": f"rt-{gmail_address}",
            "expires_in": 3600,
        })
        profile_resp = _FakeHTTPResponse(200, {"emailAddress": gmail_address})
        monkeypatch.setattr("httpx.post", lambda *a, **kw: token_resp)
        monkeypatch.setattr(
            "httpx.get",
            lambda url, **kw: profile_resp if "profile" in url
            else _FakeHTTPResponse(404),
        )

    def test_two_addresses_create_separate_users(self, monkeypatch):
        self._mock_flow_for(monkeypatch, "alice@gmail.com", "tok-alice")
        r1 = client.get("/api/auth/gmail/callback?code=code-a&state=test-state", cookies={"oauth_state": "test-state"})
        assert r1.status_code == 200

        self._mock_flow_for(monkeypatch, "bob@gmail.com", "tok-bob")
        r2 = client.get("/api/auth/gmail/callback?code=code-b&state=test-state", cookies={"oauth_state": "test-state"})
        assert r2.status_code == 200

        db = TestSession()
        alice = db.query(User).filter_by(email="alice@gmail.com").first()
        bob = db.query(User).filter_by(email="bob@gmail.com").first()
        assert alice is not None
        assert bob is not None
        assert alice.id != bob.id
        db.close()

    def test_two_addresses_create_separate_accounts(self, monkeypatch):
        self._mock_flow_for(monkeypatch, "alice@gmail.com", "tok-alice")
        r1 = client.get("/api/auth/gmail/callback?code=code-a&state=test-state", cookies={"oauth_state": "test-state"})

        self._mock_flow_for(monkeypatch, "bob@gmail.com", "tok-bob")
        r2 = client.get("/api/auth/gmail/callback?code=code-b&state=test-state", cookies={"oauth_state": "test-state"})

        assert r1.json()["email_account_id"] != r2.json()["email_account_id"]

    def test_reauth_does_not_overwrite_other_user(self, monkeypatch):
        """Re-authorizing alice does NOT touch bob's tokens."""
        # Create both
        self._mock_flow_for(monkeypatch, "alice@gmail.com", "tok-alice-1")
        client.get("/api/auth/gmail/callback?code=code-a1&state=test-state", cookies={"oauth_state": "test-state"})
        self._mock_flow_for(monkeypatch, "bob@gmail.com", "tok-bob")
        client.get("/api/auth/gmail/callback?code=code-b&state=test-state", cookies={"oauth_state": "test-state"})

        # Re-auth alice with new token
        self._mock_flow_for(monkeypatch, "alice@gmail.com", "tok-alice-2")
        client.get("/api/auth/gmail/callback?code=code-a2&state=test-state", cookies={"oauth_state": "test-state"})

        db = TestSession()
        alice_acct = db.query(EmailAccount).filter_by(
            email_address="alice@gmail.com", provider="gmail"
        ).first()
        bob_acct = db.query(EmailAccount).filter_by(
            email_address="bob@gmail.com", provider="gmail"
        ).first()

        # Alice's token updated
        assert alice_acct.access_token == "tok-alice-2"
        # Bob's token unchanged
        assert bob_acct.access_token == "tok-bob"
        db.close()

    def test_account_scoped_to_user_id(self, monkeypatch):
        """EmailAccount lookup is scoped by user_id — isolation guarantee."""
        self._mock_flow_for(monkeypatch, "alice@gmail.com", "tok-alice")
        r = client.get("/api/auth/gmail/callback?code=code-a&state=test-state", cookies={"oauth_state": "test-state"})

        db = TestSession()
        alice_acct = db.query(EmailAccount).filter_by(
            email_address="alice@gmail.com", provider="gmail"
        ).first()
        alice_user = db.query(User).filter_by(email="alice@gmail.com").first()
        assert alice_acct.user_id == alice_user.id
        db.close()


class TestOAuthCSRF:
    def test_redirect_sets_cookie_and_state(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-id")
        monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-secret")
        monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://test")
        
        r = client.get("/api/auth/gmail", follow_redirects=False)
        assert r.status_code == 307
        
        # Check cookie
        assert "oauth_state" in r.cookies
        cookie_val = r.cookies["oauth_state"]
        
        # Check URL
        loc = r.headers["Location"]
        assert f"state={cookie_val}" in loc
        
    def test_callback_without_cookie_fails(self, monkeypatch):
        from fastapi.testclient import TestClient
        from main import app
        fresh_client = TestClient(app)
        r = fresh_client.get("/api/auth/gmail/callback?code=test&state=test-state")
        assert r.status_code == 400
        assert "Missing or expired OAuth state cookie" in r.json()["detail"]

    def test_callback_without_state_param_fails(self, monkeypatch):
        r = client.get("/api/auth/gmail/callback?code=test", cookies={"oauth_state": "test-state"})
        assert r.status_code == 400
        assert "Missing OAuth state parameter" in r.json()["detail"]

    def test_callback_mismatched_state_fails(self, monkeypatch):
        r = client.get("/api/auth/gmail/callback?code=test&state=wrong-state", cookies={"oauth_state": "test-state"})
        assert r.status_code == 400
        assert "Invalid OAuth state parameter" in r.json()["detail"]

    def test_callback_clears_cookie_on_success(self, monkeypatch):
        
        _mock_successful_flow(monkeypatch)
        r = client.get("/api/auth/gmail/callback?code=test&state=test-state", cookies={"oauth_state": "test-state"})
        assert r.status_code == 200
        # Cookie is cleared
        cookie_header = r.headers.get("set-cookie", "")
        assert "oauth_state=" in cookie_header
        assert "Max-Age=0" in cookie_header or "expires=" in cookie_header.lower()

    def test_callback_clears_cookie_on_error(self, monkeypatch):
        r = client.get("/api/auth/gmail/callback?code=test&state=wrong", cookies={"oauth_state": "test-state"})
        assert r.status_code == 400
        cookie_header = r.headers.get("set-cookie", "")
        assert "oauth_state=" in cookie_header
        assert "Max-Age=0" in cookie_header or "expires=" in cookie_header.lower()


def test_refresh_access_token_success(monkeypatch):
    from gmail_oauth import refresh_access_token, OAuthConfig
    config = OAuthConfig(client_id="cid", client_secret="csec", redirect_uri="uri")
    
    class FakeResp:
        status_code = 200
        def json(self):
            return {"access_token": "new-acc", "refresh_token": "new-ref"}
            
    def mock_post(url, data, **kwargs):
        assert data["grant_type"] == "refresh_token"
        assert data["refresh_token"] == "old-ref"
        assert data["client_id"] == "cid"
        assert data["client_secret"] == "csec"
        return FakeResp()
        
    monkeypatch.setattr("httpx.post", mock_post)
    
    acc, ref = refresh_access_token(config, "old-ref")
    assert acc == "new-acc"
    assert ref == "new-ref"

def test_refresh_access_token_failure(monkeypatch):
    from gmail_oauth import refresh_access_token, OAuthConfig, TokenExchangeError
    config = OAuthConfig(client_id="cid", client_secret="csec", redirect_uri="uri")
    
    # Missing refresh token
    with pytest.raises(TokenExchangeError, match="No refresh token available"):
        refresh_access_token(config, "")
        
    class FakeRespError:
        status_code = 400
        
    def mock_post_err(*args, **kwargs):
        return FakeRespError()
        
    monkeypatch.setattr("httpx.post", mock_post_err)
    with pytest.raises(TokenExchangeError, match="HTTP 400"):
        refresh_access_token(config, "old")
        
    class FakeRespMalformed:
        status_code = 200
        def json(self):
            return {"not_access_token": "x"}
            
    def mock_post_mal(*args, **kwargs):
        return FakeRespMalformed()
        
    monkeypatch.setattr("httpx.post", mock_post_mal)
    with pytest.raises(TokenExchangeError, match="missing 'access_token'"):
        refresh_access_token(config, "old")
