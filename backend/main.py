from dataclasses import asdict

from fastapi import FastAPI, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db
from models import Email, EmailAccount, User, ForensicAnalysis as ForensicAnalysisRecord
from schemas import EmailResponse, ForensicAnalysisSchema
from email_parser import parse_eml
from analysis import run_email_analysis
from gmail_oauth import (
    get_oauth_config,
    build_authorization_url,
    exchange_code_for_tokens,
    get_gmail_user_email,
    OAuthConfigError,
    TokenExchangeError,
    UserInfoError,
)

app=FastAPI()

@app.get("/")
def root():
    return {"message":"MailForensics AI Backend is running"}

@app.get("/db-test")
def db_test(db: Session=Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"message":"Database connection successful"}


# ---------------------------------------------------------------------------
# Gmail OAuth 2.0 endpoints
# ---------------------------------------------------------------------------

@app.get("/api/auth/gmail")
def gmail_auth_redirect():
    """Redirect the user to Google's OAuth 2.0 authorization page."""
    try:
        config = get_oauth_config()
    except OAuthConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    url = build_authorization_url(config)
    return RedirectResponse(url=url)


@app.get("/api/auth/gmail/callback")
def gmail_auth_callback(
    code: str = None,
    error: str = None,
    db: Session = Depends(get_db),
):
    """Handle Google's OAuth 2.0 callback.

    Exchanges the authorization code for tokens, fetches the user's
    Gmail address, and creates or updates the corresponding
    EmailAccount record.
    """
    # Handle user denial or Google-side errors
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"OAuth authorization failed: {error}",
        )

    if not code:
        raise HTTPException(
            status_code=400,
            detail="Missing authorization code",
        )

    # Load config
    try:
        config = get_oauth_config()
    except OAuthConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    # Exchange code for tokens
    try:
        tokens = exchange_code_for_tokens(code, config)
    except TokenExchangeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Get the user's Gmail email address
    try:
        gmail_address = get_gmail_user_email(tokens.access_token)
    except UserInfoError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Find or create the MailForensics user.
    #
    # DEV-ONLY LIMITATION:
    # The user is identified by matching the Google-verified Gmail
    # address to User.email (which has a UNIQUE constraint).  This
    # means:
    #   1. Each Gmail address maps to exactly one User — safe.
    #   2. A user cannot link a *different* Gmail address to their
    #      existing MailForensics account (it would create a new User).
    #   3. No cross-user contamination is possible because the
    #      EmailAccount lookup is scoped to user_id.
    #
    # In production this will be replaced by proper application-level
    # authentication (JWT/session) so the authenticated MailForensics
    # user is known *before* the OAuth flow starts.
    user = db.query(User).filter_by(email=gmail_address).first()
    if not user:
        user = User(email=gmail_address, name=gmail_address)
        db.add(user)
        db.commit()
        db.refresh(user)

    # Find or create the EmailAccount for this Gmail address
    account = db.query(EmailAccount).filter_by(
        user_id=user.id,
        provider="gmail",
        email_address=gmail_address,
    ).first()

    if account:
        # Update tokens on existing account
        account.access_token = tokens.access_token
        if tokens.refresh_token:
            account.refresh_token = tokens.refresh_token
    else:
        account = EmailAccount(
            user_id=user.id,
            provider="gmail",
            email_address=gmail_address,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
        )
        db.add(account)

    db.commit()
    db.refresh(account)

    # Return success — NEVER expose tokens in the response
    return {
        "message": "Gmail account authorized successfully",
        "email_account_id": account.id,
        "email_address": account.email_address,
        "provider": account.provider,
    }

@app.post("/api/emails/upload", response_model=EmailResponse)
async def upload_email(
    file: UploadFile=File(...),
    email_account_id: int=Form(
        ...,
        description=(
            "DEV-ONLY: The EmailAccount ID to associate this email with. "
            "In production this will be derived from the authenticated user. "
            "For development testing, create an EmailAccount row first and "
            "supply its ID here."
        ),
    ),
    db: Session=Depends(get_db),
):
    """Upload and parse a single .eml file.

    Accepts a multipart/form-data request with:
    - **file**: the .eml file (required)
    - **email_account_id**: the EmailAccount to associate with (required, dev-only)

    Returns the parsed and stored email record with forensic analysis.
    """
    # Validate filename
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file: please upload a .eml file.",
        )

    # Read raw bytes
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Parse the .eml content
    try:
        parsed = parse_eml(raw_bytes)
    except (ValueError, Exception) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Failed to parse .eml file: {exc}",
        )

    # Store in database
    db_email = Email(
        email_account_id=email_account_id,
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

    # Run unified analysis pipeline
    analysis_dict = run_email_analysis(parsed, db_email, db)

    forensics_result = ForensicAnalysisSchema.model_validate(analysis_dict)

    # Build response combining ORM attributes with forensic analysis
    response = EmailResponse.model_validate(db_email)
    response.forensics = forensics_result

    return response


# ---------------------------------------------------------------------------
# Gmail message retrieval endpoint
# ---------------------------------------------------------------------------

from gmail_client import sync_gmail_messages, GmailAPIError  # noqa: E402

@app.get("/api/gmail/{email_account_id}/messages")
def gmail_fetch_messages(
    email_account_id: int,
    limit: int = 10,
    db: Session = Depends(get_db),
):
    """Retrieve Gmail messages for an authorized EmailAccount.

    Fetches up to *limit* messages from the Gmail API, converts them
    through the existing email parser, and persists them as Email rows.

    Does NOT run forensic analysis — that will be connected later.

    Args:
        email_account_id: The EmailAccount to fetch messages for.
        limit:            Maximum messages to fetch (default 10, max 50).
    """
    # Verify account exists
    account = db.query(EmailAccount).filter_by(id=email_account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="EmailAccount not found")

    # Verify it's a Gmail account
    if account.provider != "gmail":
        raise HTTPException(
            status_code=400,
            detail=f"Account {email_account_id} is not a Gmail account "
                   f"(provider: {account.provider})",
        )

    # Verify we have an access token
    if not account.access_token:
        raise HTTPException(
            status_code=400,
            detail="Gmail account has no access token — re-authorize first",
        )

    # Sync messages
    try:
        result = sync_gmail_messages(
            account_id=account.id,
            access_token=account.access_token,
            db_session=db,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Gmail sync failed: {exc}",
        )

    return {
        "message": "Gmail messages synced",
        "email_account_id": account.id,
        "fetched": result.fetched,
        "persisted": result.persisted,
        "skipped_duplicate": result.skipped_duplicate,
        "errors": result.errors,
    }