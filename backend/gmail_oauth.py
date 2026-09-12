"""Gmail OAuth 2.0 authorization-code flow for MailForensics AI.

Implements the server-side OAuth 2.0 flow using Google's authorization
endpoints directly via ``httpx``.  No Google SDK dependencies required.

Environment variables
~~~~~~~~~~~~~~~~~~~~~
- ``GOOGLE_CLIENT_ID``     – OAuth 2.0 client ID
- ``GOOGLE_CLIENT_SECRET`` – OAuth 2.0 client secret
- ``GOOGLE_REDIRECT_URI``  – Registered redirect URI
                             (e.g. ``http://localhost:8000/api/auth/gmail/callback``)

All three must be set for the OAuth flow to work.  If any are missing
the endpoints return a clear error rather than crashing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GMAIL_PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class OAuthConfig:
    """Google OAuth 2.0 application credentials from environment."""

    client_id: str
    client_secret: str
    redirect_uri: str


class OAuthConfigError(Exception):
    """Raised when required OAuth configuration is missing."""
    pass


def get_oauth_config() -> OAuthConfig:
    """Load OAuth configuration from environment variables.

    Raises:
        OAuthConfigError: If any required variable is missing or empty.
    """
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()

    missing = []
    if not client_id:
        missing.append("GOOGLE_CLIENT_ID")
    if not client_secret:
        missing.append("GOOGLE_CLIENT_SECRET")
    if not redirect_uri:
        missing.append("GOOGLE_REDIRECT_URI")

    if missing:
        raise OAuthConfigError(
            f"Missing required OAuth environment variable(s): "
            f"{', '.join(missing)}"
        )

    return OAuthConfig(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )


# ---------------------------------------------------------------------------
# Authorization URL
# ---------------------------------------------------------------------------

def build_authorization_url(config: OAuthConfig, state: str = None) -> str:
    """Build the Google OAuth 2.0 authorization URL.

    Requests offline access so a refresh token is included in the
    token response.

    Args:
        config: OAuth application credentials.
        state: Optional CSRF protection state string.

    Returns:
        The full authorization URL the user should be redirected to.
    """
    params = {
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READONLY_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    return f"{_GOOGLE_AUTH_URL}?{urlencode(params)}"



# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------

@dataclass
class TokenResult:
    """Result of exchanging an authorization code for tokens."""

    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: str = "Bearer"


class TokenExchangeError(Exception):
    """Raised when the token exchange fails."""
    pass


def exchange_code_for_tokens(
    code: str,
    config: OAuthConfig,
) -> TokenResult:
    """Exchange an authorization code for access/refresh tokens.

    Args:
        code:   The authorization code from Google's callback.
        config: OAuth application credentials.

    Returns:
        A ``TokenResult`` with access and refresh tokens.

    Raises:
        TokenExchangeError: If the exchange fails for any reason.
    """
    import httpx

    try:
        resp = httpx.post(
            _GOOGLE_TOKEN_URL,
            data={
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": config.redirect_uri,
            },
            timeout=15,
        )
    except Exception as exc:
        raise TokenExchangeError(f"Network error during token exchange: {exc}")

    if resp.status_code != 200:
        try:
            detail = resp.json().get("error_description", resp.text)
        except Exception:
            detail = resp.text
        raise TokenExchangeError(
            f"Token exchange failed (HTTP {resp.status_code}): {detail}"
        )

    data = resp.json()
    access_token = data.get("access_token")
    if not access_token:
        raise TokenExchangeError("Token response missing access_token")

    return TokenResult(
        access_token=access_token,
        refresh_token=data.get("refresh_token"),
        expires_in=data.get("expires_in"),
        token_type=data.get("token_type", "Bearer"),
    )


# ---------------------------------------------------------------------------
# User identity
# ---------------------------------------------------------------------------

class UserInfoError(Exception):
    """Raised when fetching user info fails."""
    pass



def refresh_access_token(config: OAuthConfig, refresh_token: str) -> tuple[str, str]:
    """Exchange a refresh token for a new access token.

    Args:
        config: OAuth application credentials.
        refresh_token: The user's stored refresh token.

    Returns:
        A tuple of (new_access_token, optional_new_refresh_token).

    Raises:
        TokenExchangeError: If the refresh fails or the response is malformed.
    """
    import httpx

    if not refresh_token:
        raise TokenExchangeError("No refresh token available.")

    try:
        resp = httpx.post(
            _GOOGLE_TOKEN_URL,
            data={
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=15.0,
        )
    except Exception as exc:
        raise TokenExchangeError(f"Network error during token refresh: {exc}")

    if resp.status_code != 200:
        raise TokenExchangeError(f"Token refresh failed with HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        raise TokenExchangeError("Invalid JSON response from token endpoint.")

    access_token = data.get("access_token")
    if not access_token:
        raise TokenExchangeError("Token endpoint response missing 'access_token'.")

    return access_token, data.get("refresh_token")


def get_gmail_user_email(access_token: str) -> str:
    """Fetch the authenticated user's email address from Google.

    Args:
        access_token: A valid Google OAuth 2.0 access token.

    Returns:
        The user's Gmail email address.

    Raises:
        UserInfoError: If the request fails or email is not available.
    """
    import httpx

    try:
        resp = httpx.get(
            _GMAIL_PROFILE_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
    except Exception as exc:
        raise UserInfoError(f"Network error fetching user info: {exc}")

    if resp.status_code != 200:
        raise UserInfoError(
            f"Failed to fetch user info (HTTP {resp.status_code})"
        )

    data = resp.json()
    email = data.get("emailAddress")
    if not email:
        raise UserInfoError("Gmail profile response missing emailAddress")

    return email
