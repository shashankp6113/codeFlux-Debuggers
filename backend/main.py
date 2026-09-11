from dataclasses import asdict

from fastapi import FastAPI, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db
from models import Email, ForensicAnalysis as ForensicAnalysisRecord
from schemas import EmailResponse, ForensicAnalysisSchema
from email_parser import parse_eml
from forensics import analyze_headers
from scoring import calculate_threat_score
from ioc_extractor import extract_iocs
from threat_intel import enrich_iocs

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

    # Run forensic analysis on the raw headers (if available)
    analysis_dict: dict = {}
    if parsed.raw_headers:
        analysis = analyze_headers(parsed.raw_headers)
        analysis_dict = asdict(analysis)

        # Compute deterministic threat score from forensic flags
        threat_score = calculate_threat_score(analysis)
        analysis_dict["threat_score"] = asdict(threat_score)

    # Extract IOCs from the full parsed email (always)
    ioc_result = extract_iocs(parsed)
    analysis_dict["ioc_extraction"] = asdict(ioc_result)

    # Enrich IOCs with threat intelligence (always, NoOpProvider by default)
    ti_result = enrich_iocs(ioc_result)
    analysis_dict["threat_intelligence"] = asdict(ti_result)

    # Persist forensic analysis (including threat_score, IOCs, and
    # threat intelligence) to database
    db_forensic = ForensicAnalysisRecord(
        email_id=db_email.id,
        analysis=analysis_dict,
    )
    db.add(db_forensic)
    db.commit()
    db.refresh(db_forensic)

    forensics_result = ForensicAnalysisSchema.model_validate(analysis_dict)

    # Build response combining ORM attributes with forensic analysis
    response = EmailResponse.model_validate(db_email)
    response.forensics = forensics_result

    return response