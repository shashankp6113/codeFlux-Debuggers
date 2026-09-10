from dataclasses import asdict

from fastapi import FastAPI, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db
from models import Email
from schemas import EmailResponse, ForensicAnalysisSchema
from email_parser import parse_eml
from forensics import analyze_headers

app=FastAPI()

@app.get("/")
def root():
    return {"message":"MailForensics AI Backend is running"}

@app.get("/db-test")
def db_test(db: Session=Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"message":"Database connection successful"}

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

    # Run forensic analysis on the raw headers
    forensics_result = None
    if parsed.raw_headers:
        analysis = analyze_headers(parsed.raw_headers)
        forensics_result = ForensicAnalysisSchema.model_validate(asdict(analysis))

    # Build response combining ORM attributes with forensic analysis
    response = EmailResponse.model_validate(db_email)
    response.forensics = forensics_result

    return response