import secrets
from sync_manager import get_sync_status, start_sync, finish_sync, SyncStatusResponse

from dataclasses import asdict

from typing import List, Optional

from fastapi import FastAPI, Request, Response, Depends, File, Form, HTTPException, UploadFile, BackgroundTasks, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db
from auth import create_access_token, get_current_user
from models import Email, EmailAccount, User, ForensicAnalysis as ForensicAnalysisRecord
from schemas import EmailResponse, ForensicAnalysisSchema, DashboardSummarySchema, ThreatSummaryResponse, IOCsPageResponse
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


_OAUTH_STATE_COOKIE = "oauth_state"
_OAUTH_STATE_MAX_AGE = 600

@app.get("/api/auth/gmail")
def gmail_auth_redirect(request: Request):
    """Redirect the user to Google's OAuth 2.0 authorization page."""
    try:
        config = get_oauth_config()
    except OAuthConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    state = secrets.token_urlsafe(32)
    url = build_authorization_url(config, state=state)
    
    response = RedirectResponse(url=url)
    
    is_secure = request.url.scheme == "https"
    
    response.set_cookie(
        key=_OAUTH_STATE_COOKIE,
        value=state,
        max_age=_OAUTH_STATE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=is_secure,
        path="/api/auth/gmail/callback"
    )
    return response


@app.get("/api/auth/gmail/callback")
def gmail_auth_callback(
    request: Request,
    response: Response,
    code: str = None,
    error: str = None,
    state: str = None,
    db: Session = Depends(get_db),
):
    """Handle Google's OAuth 2.0 callback."""

    # Helper to raise exception and clear cookie
    def raise_oauth_error(detail: str):
        response.delete_cookie(
            key=_OAUTH_STATE_COOKIE,
            path="/api/auth/gmail/callback",
            httponly=True,
            samesite="lax"
        )
        raise HTTPException(
            status_code=400,
            detail=detail,
            headers={"Set-Cookie": f"{_OAUTH_STATE_COOKIE}=; Max-Age=0; Path=/api/auth/gmail/callback; HttpOnly; SameSite=lax"}
        )

    stored_state = request.cookies.get(_OAUTH_STATE_COOKIE)
    
    response.delete_cookie(
        key=_OAUTH_STATE_COOKIE,
        path="/api/auth/gmail/callback",
        httponly=True,
        samesite="lax"
    )
    
    if not stored_state:
        raise_oauth_error("Missing or expired OAuth state cookie")
    
    if not state:
        raise_oauth_error("Missing OAuth state parameter")
        
    if not secrets.compare_digest(stored_state, state):
        raise_oauth_error("Invalid OAuth state parameter (CSRF protection)")

    if error:
        raise_oauth_error(f"OAuth authorization failed: {error}")

    if not code:
        raise_oauth_error("Missing authorization code")



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

    # Generate application JWT
    token = create_access_token(user.id)

    # Return success — NEVER expose Google OAuth tokens in the response
    return {
        "message": "Gmail account authorized successfully",
        "email_account_id": account.id,
        "email_address": account.email_address,
        "provider": account.provider,
        "token": token,
        "user_id": user.id,
    }

# ---------------------------------------------------------------------------
# Dashboard and Read-Only Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/emails", response_model=List[EmailResponse])
def list_emails(
    limit: int = 50,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Return a list of persisted emails, newest first."""
    query = db.query(Email).join(EmailAccount).filter(EmailAccount.user_id == current_user.id)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            Email.subject.ilike(search_term) | Email.sender.ilike(search_term)
        )
    emails = query.order_by(Email.received_at.desc()).limit(limit).all()
    responses = []
    for email in emails:
        resp = EmailResponse.model_validate(email)
        fa = db.query(ForensicAnalysisRecord).filter_by(email_id=email.id).first()
        if fa and fa.analysis:
            resp.forensics = ForensicAnalysisSchema.model_validate(fa.analysis)
        responses.append(resp)
    return responses





@app.get("/api/emails/{email_id}", response_model=EmailResponse)
def get_email(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a specific email and its forensic analysis."""
    email = (
        db.query(Email)
        .join(EmailAccount)
        .filter(Email.id == email_id, EmailAccount.user_id == current_user.id)
        .first()
    )
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
        
    resp = EmailResponse.model_validate(email)
    fa = db.query(ForensicAnalysisRecord).filter_by(email_id=email.id).first()
    if fa and fa.analysis:
        resp.forensics = ForensicAnalysisSchema.model_validate(fa.analysis)
        
    return resp

@app.get("/api/emails/{email_id}/report", response_model=EmailResponse)
def get_email_report(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a full forensic report for a specific email."""
    email = (
        db.query(Email)
        .join(EmailAccount)
        .filter(Email.id == email_id, EmailAccount.user_id == current_user.id)
        .first()
    )
    
    if not email:
        raise HTTPException(status_code=404, detail="Email report not found")
        
    resp = EmailResponse.model_validate(email)
    fa = db.query(ForensicAnalysisRecord).filter_by(email_id=email.id).first()
    if fa and fa.analysis:
        resp.forensics = ForensicAnalysisSchema.model_validate(fa.analysis)
        
    return resp


@app.post("/api/emails/{email_id}/retry-ai", response_model=EmailResponse)
def retry_ai_analysis(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retry AI analysis for an email, preserving deterministic forensics."""
    from ai_analysis import build_ai_evidence, get_ai_provider, AIAnalysisResult
    
    email = (
        db.query(Email)
        .join(EmailAccount)
        .filter(Email.id == email_id, EmailAccount.user_id == current_user.id)
        .first()
    )
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
        
    fa = db.query(ForensicAnalysisRecord).filter_by(email_id=email.id).first()
    if not fa or not fa.analysis:
        raise HTTPException(status_code=404, detail="Forensic analysis not found for this email")

    analysis_dict = dict(fa.analysis)
    
    email_metadata = {
        "subject": email.subject,
        "sender": email.sender,
        "recipient": email.recipient,
        "message_id": email.message_id,
    }
    
    evidence = build_ai_evidence(analysis_dict, email_metadata=email_metadata)
    
    try:
        ai_provider = get_ai_provider()
        ai_result = ai_provider.analyze(evidence)
    except Exception as exc:
        ai_result = AIAnalysisResult(
            classification="unknown",
            provider="error",
            error=f"AI provider raised an unexpected exception: {exc}",
        )
        
    analysis_dict["ai_analysis"] = {
        "classification": ai_result.classification,
        "confidence": ai_result.confidence,
        "summary": ai_result.summary,
        "explanation": ai_result.explanation,
        "recommended_actions": ai_result.recommended_actions,
        "provider": ai_result.provider,
        "error": ai_result.error,
        "error_category": getattr(ai_result, "error_category", None),
    }
    
    # SQLAlchemy requires re-assignment for JSON mutation tracking
    fa.analysis = analysis_dict
    db.commit()
    db.refresh(fa)
    
    resp = EmailResponse.model_validate(email)
    resp.forensics = ForensicAnalysisSchema.model_validate(fa.analysis)
    return resp

@app.get("/api/threats", response_model=List[ThreatSummaryResponse])
def list_threats(
    risk_level: Optional[str] = None,
    classification: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return a list of analyzed emails identified as potential threats."""
    query = (
        db.query(Email, ForensicAnalysisRecord)
        .join(EmailAccount)
        .join(ForensicAnalysisRecord, Email.id == ForensicAnalysisRecord.email_id)
        .filter(EmailAccount.user_id == current_user.id)
    )

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Email.sender.ilike(search_term)) | 
            (Email.subject.ilike(search_term))
        )

    results = query.order_by(Email.received_at.desc()).all()
    
    threats = []
    for email, fa in results:
        if not fa or not fa.analysis:
            continue
            
        analysis = fa.analysis
        
        t_score = analysis.get("threat_score", {})
        score = t_score.get("score", 0)
        risk = t_score.get("risk_level", "low").lower()
        
        ai = analysis.get("ai_analysis") or {}
        cls_type = ai.get("classification", "unknown").lower()
        conf = ai.get("confidence", 0.0)
        
        flags = analysis.get("flags", [])
        
        iocs = []
        if analysis.get("ioc_extraction"):
            iocs = analysis.get("ioc_extraction").get("iocs", [])
            
        # Default filtering logic: must be considered a threat by score or AI
        # unless explicit filters override
        is_threat = (score > 0 or risk in ["medium", "high", "critical"] or cls_type in ["suspicious", "phishing", "malicious", "malware"])
        
        if risk_level and risk != risk_level.lower():
            continue
            
        if classification and cls_type != classification.lower():
            continue
            
        if not risk_level and not classification and not search and not is_threat:
            # If no filters provided, only show actual threats
            continue
            
        threats.append({
            "id": email.id,
            "subject": email.subject,
            "sender": email.sender,
            "received_at": email.received_at,
            "threat_score": score,
            "risk_level": risk,
            "classification": cls_type,
            "confidence": conf,
            "flag_count": len(flags),
            "ioc_count": len(iocs)
        })
        
    return threats


@app.get("/api/iocs", response_model=IOCsPageResponse)
def list_iocs(
    ioc_type: Optional[str] = None,
    verdict: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return aggregated IOCs from the authenticated user's emails."""
    query = (
        db.query(Email, ForensicAnalysisRecord)
        .join(EmailAccount)
        .join(ForensicAnalysisRecord, Email.id == ForensicAnalysisRecord.email_id)
        .filter(EmailAccount.user_id == current_user.id)
    )

    results = query.all()
    
    iocs_map = {}
    
    for email, fa in results:
        if not fa or not fa.analysis:
            continue
            
        analysis = fa.analysis
        
        # Extract IOCs
        extracted = analysis.get("ioc_extraction", {}).get("iocs", [])
        if not extracted:
            continue
            
        # Get Threat Intel to merge
        ti_enrichments = analysis.get("threat_intelligence", {}).get("enrichments", [])
        ti_map = { e.get("ioc_value"): e for e in ti_enrichments }
        
        # Get Geolocation to merge
        geo_results = analysis.get("geolocation", {}).get("results", [])
        geo_map = { g.get("ip"): g for g in geo_results }
        
        for ioc in extracted:
            val = ioc.get("value")
            typ = ioc.get("ioc_type")
            if not val or not typ:
                continue
                
            if val not in iocs_map:
                iocs_map[val] = {
                    "ioc_type": typ,
                    "value": val,
                    "occurrence_count": 0,
                    "emails": set(),
                    "latest_email_id": email.id,
                    "first_seen": email.received_at,
                    "last_seen": email.received_at,
                    "verdict": "unknown",
                    "confidence": None,
                    "country": None,
                    "asn": None,
                    "organization": None
                }
            
            agg = iocs_map[val]
            agg["occurrence_count"] += 1
            
            # Update emails set and last/first seen
            agg["emails"].add(email.id)
            
            if email.received_at:
                if not agg["last_seen"] or email.received_at > agg["last_seen"]:
                    agg["last_seen"] = email.received_at
                    agg["latest_email_id"] = email.id
                if not agg["first_seen"] or email.received_at < agg["first_seen"]:
                    agg["first_seen"] = email.received_at
                    
            # Merge Threat Intel
            if val in ti_map:
                ti = ti_map[val]
                agg["verdict"] = ti.get("verdict", agg["verdict"])
                if ti.get("confidence") is not None:
                    agg["confidence"] = ti.get("confidence")
                if ti.get("country"):
                    agg["country"] = ti.get("country")
                if ti.get("asn"):
                    agg["asn"] = ti.get("asn")
                if ti.get("organization"):
                    agg["organization"] = ti.get("organization")
                    
            # Merge Geolocation if not already set by TI
            if val in geo_map:
                geo = geo_map[val]
                if not agg["country"] and geo.get("country"):
                    agg["country"] = geo.get("country")
                if not agg["asn"] and geo.get("asn"):
                    agg["asn"] = geo.get("asn")
                if not agg["organization"] and geo.get("organization"):
                    agg["organization"] = geo.get("organization")

    # Finalize list and apply filters
    final_iocs = []
    stats = {
        "total": 0,
        "ip": 0,
        "domain": 0,
        "url": 0,
        "email": 0
    }
    
    for val, agg in iocs_map.items():
        agg["associated_email_count"] = len(agg["emails"])
        
        # Stats are computed BEFORE filtering so the dashboard shows the overall universe
        stats["total"] += 1
        t = agg["ioc_type"].lower()
        if t in stats:
            stats[t] += 1
        
        # Apply filters
        if ioc_type and agg["ioc_type"].lower() != ioc_type.lower():
            continue
            
        if verdict and agg["verdict"].lower() != verdict.lower():
            continue
            
        if search and search.lower() not in val.lower():
            continue
            
        final_iocs.append(agg)
        
    # Sort by last_seen descending
    final_iocs.sort(key=lambda x: x["last_seen"] if x["last_seen"] else datetime.min, reverse=True)
    
    return {
        "iocs": final_iocs,
        "stats": stats
    }

@app.get("/api/dashboard/summary", response_model=DashboardSummarySchema)
def get_dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Return aggregated statistics and recent data for the dashboard."""
    # We load all forensic records for calculating accurate stats (in production we'd use optimized queries)
    # But since this is SQLite and a small demo, this is fine. Or we can query JSON fields using SQLAlchemy if supported.
    # For now, let's just do it in python memory for safety since JSON querying in SQLite is sometimes tricky.
    
    # Get total emails
    total_emails = db.query(Email).join(EmailAccount).filter(EmailAccount.user_id == current_user.id).count()
    
    threats_detected = 0
    high_risk = 0
    critical = 0
    
    threat_dist = {}
    ioc_summ = {}
    
    all_fa = db.query(ForensicAnalysisRecord).join(Email).join(EmailAccount).filter(EmailAccount.user_id == current_user.id).all()
    for fa in all_fa:
        if not fa.analysis:
            continue
            
        analysis = fa.analysis
        
        # Check if email is a threat based on any engine
        is_threat = False
        
        # 1. Threat score / Risk level (deterministic)
        threat_score_info = analysis.get("threat_score")
        if threat_score_info:
            risk = threat_score_info.get("risk_level", "low").lower()
            if risk in ["medium", "high", "critical"]:
                is_threat = True
            
            # High and Critical cards only use deterministic risk
            if risk == "high":
                high_risk += 1
            elif risk == "critical":
                critical += 1
                
        # 2. Threat distribution (AI classifications)
        ai_info = analysis.get("ai_analysis")
        if ai_info:
            cls = ai_info.get("classification", "unknown").lower()
            threat_dist[cls] = threat_dist.get(cls, 0) + 1
            if cls in ["suspicious", "malicious"]:
                is_threat = True
            
        # 3. IOC summary and Threat Intel
        ioc_info = analysis.get("ioc_extraction")
        if ioc_info:
            iocs = ioc_info.get("iocs", [])
            for ioc in iocs:
                ioc_type = ioc.get("ioc_type", "unknown")
                ioc_summ[ioc_type] = ioc_summ.get(ioc_type, 0) + 1
                
        ti_info = analysis.get("threat_intelligence")
        if ti_info:
            enrichments = ti_info.get("enrichments", [])
            for enrich in enrichments:
                verdict = enrich.get("verdict", "unknown").lower()
                if verdict in ["suspicious", "malicious"]:
                    is_threat = True
                    # Only need one malicious indicator to flag the email
                    break
                    
        if is_threat:
            threats_detected += 1
                
    # Get recent investigations
    recent_emails = db.query(Email).join(EmailAccount).filter(EmailAccount.user_id == current_user.id).order_by(Email.received_at.desc()).limit(5).all()
    recent_responses = []
    for email in recent_emails:
        resp = EmailResponse.model_validate(email)
        fa = db.query(ForensicAnalysisRecord).filter_by(email_id=email.id).first()
        if fa and fa.analysis:
            resp.forensics = ForensicAnalysisSchema.model_validate(fa.analysis)
        recent_responses.append(resp)
        
    return {
        "total_emails": total_emails,
        "threats_detected": threats_detected,
        "high_risk": high_risk,
        "critical": critical,
        "recent_investigations": recent_responses,
        "threat_distribution": threat_dist,
        "ioc_summary": ioc_summ
    }



# ---------------------------------------------------------------------------
# Global Search Endpoint
# ---------------------------------------------------------------------------
from sqlalchemy import or_, and_, cast, String

@app.get("/api/search")
def global_search(q: str = Query("", min_length=1), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Authenticated scope: we only query for this user's email accounts
    user_account_ids = [acc.id for acc in db.query(EmailAccount.id).filter(EmailAccount.user_id == current_user.id).all()]
    if not user_account_ids:
        return {"query": q, "emails": [], "iocs": [], "threats": []}

    search_term = f"%{q}%"
    
    # 1. Search Emails
    # Matching subject, sender, recipient
    emails = db.query(Email).filter(
        Email.email_account_id.in_(user_account_ids),
        or_(
            Email.subject.ilike(search_term),
            Email.sender.ilike(search_term),
            Email.recipient.ilike(search_term)
        )
    ).order_by(Email.received_at.desc()).limit(5).all()
    
    email_results = []
    for e in emails:
        fa = db.query(ForensicAnalysisRecord).filter(ForensicAnalysisRecord.email_id == e.id).first()
        risk = "low"
        is_threat = False
        if fa and fa.analysis:
            risk = fa.analysis.get("threat_score", {}).get("risk_level", "low")
            is_threat = fa.analysis.get("ai_analysis", {}).get("classification", "unknown").lower() in ["suspicious", "malicious", "phishing"]
        email_results.append({
            "id": e.id,
            "subject": e.subject,
            "sender": e.sender,
            "received_at": e.received_at,
            "risk_level": risk,
            "is_threat": is_threat
        })
        
    # 2. Search IOCs & Threats
    # We will search the ForensicAnalysisRecord JSON manually since it's SQLite and we can't do complex JSON queries easily.
    # Alternatively, since it's SQLite, we can just cast analysis to string and ilike, then extract matches.
    # We will do a substring search on the JSON string representation
    fa_records = db.query(ForensicAnalysisRecord).join(Email).filter(
        Email.email_account_id.in_(user_account_ids)
    ).all()
    
    ioc_results = []
    threat_results = []
    
    q_lower = q.lower()
    
    for fa in fa_records:
        if not fa.analysis:
            continue
            
        # Match IOCs
        iocs = fa.analysis.get("ioc_extraction", {}).get("iocs", [])
        for ioc in iocs:
            val = str(ioc.get("value", ""))
            if q_lower in val.lower():
                ioc_results.append({
                    "email_id": fa.email_id,
                    "value": val,
                    "type": ioc.get("ioc_type", "unknown"),
                    "associated_subject": fa.email.subject
                })
                
        # Match Threats
        ai_class = fa.analysis.get("ai_analysis", {}).get("classification", "")
        risk = fa.analysis.get("threat_score", {}).get("risk_level", "low")
        if q_lower in ai_class.lower() or q_lower in risk.lower() or q_lower in (fa.email.subject or "").lower() or q_lower in (fa.email.sender or "").lower():
            if ai_class.lower() in ["suspicious", "malicious", "phishing", "malware", "spam"]:
                threat_results.append({
                    "email_id": fa.email_id,
                    "classification": ai_class,
                    "risk_level": risk,
                    "sender": fa.email.sender,
                    "subject": fa.email.subject
                })
                
    # Deduplicate and limit
    # Deduplicate IOCs by value
    seen_iocs = set()
    unique_iocs = []
    for r in ioc_results:
        if r["value"] not in seen_iocs:
            seen_iocs.add(r["value"])
            unique_iocs.append(r)
            if len(unique_iocs) >= 5: break
            
    # Deduplicate threats by email_id
    seen_threat_emails = set()
    unique_threats = []
    for r in threat_results:
        if r["email_id"] not in seen_threat_emails:
            seen_threat_emails.add(r["email_id"])
            unique_threats.append(r)
            if len(unique_threats) >= 5: break

    return {
        "query": q,
        "emails": email_results,
        "iocs": unique_iocs,
        "threats": unique_threats
    }


# ---------------------------------------------------------------------------
# Email Upload Endpoint
# ---------------------------------------------------------------------------

@app.post("/api/emails/upload", response_model=EmailResponse)
def upload_email(
    file: UploadFile=File(...),
    email_account_id: Optional[int]=Form(
        None,
        description=(
            "DEV-ONLY: The EmailAccount ID to associate this email with. "
            "In production this will be derived from the authenticated user. "
            "For development testing, create an EmailAccount row first and "
            "supply its ID here. If omitted, a fallback development account will be used."
        ),
    ),
    db: Session=Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Upload and parse a single .eml file.

    Accepts a multipart/form-data request with:
    - **file**: the .eml file (required)
    - **email_account_id**: the EmailAccount to associate with (optional, dev-only)

    Returns the parsed and stored email record with forensic analysis.
    """
    if email_account_id is None:
        # Development fallback safely scoped to the authenticated user
        dev_account = db.query(EmailAccount).filter_by(
            user_id=current_user.id, provider="manual_upload"
        ).first()
        if not dev_account:
            dev_account = EmailAccount(
                user_id=current_user.id,
                provider="manual_upload",
                email_address=f"upload_{current_user.id}@mailforensics.local"
            )
            db.add(dev_account)
            db.commit()
            db.refresh(dev_account)
        email_account_id = dev_account.id
    else:
        # Verify ownership
        account = db.query(EmailAccount).filter_by(id=email_account_id).first()
        if not account or account.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="EmailAccount not found")

    # Validate filename
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file: please upload a .eml file.",
        )

    # Read raw bytes
    raw_bytes = file.file.read()
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

    # Use a secure file hash for manual upload deduplication
    import hashlib
    upload_id = f"upload_{hashlib.sha256(raw_bytes).hexdigest()}"

    existing = db.query(Email).filter_by(
        email_account_id=email_account_id,
        message_id=upload_id
    ).first()

    has_analysis = False
    if existing:
        from models import ForensicAnalysis
        db_forensic = db.query(ForensicAnalysis).filter_by(email_id=existing.id).first()
        if db_forensic:
            has_analysis = True
            analysis_dict = db_forensic.analysis
        db_email = existing
    else:
        # Store in database
        db_email = Email(
            email_account_id=email_account_id,
            message_id=upload_id,
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

    if not has_analysis:
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

from gmail_client import sync_gmail_messages, GmailAPIError, GmailAuthError  # noqa: E402


def run_sync_job(account_id: int, access_token: str, limit: int):
    from database import SessionLocal
    from gmail_client import sync_gmail_messages
    from gmail_oauth import refresh_access_token, get_oauth_config, TokenExchangeError
    from models import EmailAccount
    db = SessionLocal()
    try:
        try:
            result = sync_gmail_messages(
                account_id=account_id,
                access_token=access_token,
                db_session=db,
                limit=limit,
            )
        except GmailAuthError:
            # Token might be expired, attempt to refresh once
            account = db.query(EmailAccount).filter_by(id=account_id).first()
            if not account or not account.refresh_token:
                raise Exception("Gmail API authentication failed (401) and no refresh token is available. Please re-authenticate.")
            
            config = get_oauth_config()
            new_access, new_refresh = refresh_access_token(config, account.refresh_token)
            
            account.access_token = new_access
            if new_refresh:
                account.refresh_token = new_refresh
            db.commit()
            
            # Retry sync once
            result = sync_gmail_messages(
                account_id=account_id,
                access_token=new_access,
                db_session=db,
                limit=limit,
            )

        if result.errors:
            finish_sync(account_id, status="completed", errors=result.errors)
        else:
            finish_sync(account_id, status="completed")
    except Exception as exc:
        finish_sync(account_id, status="failed", errors=[str(exc)])
    finally:
        db.close()


@app.post("/api/gmail/{email_account_id}/messages")
def gmail_fetch_messages(
    email_account_id: int,
    background_tasks: BackgroundTasks,
    limit: int = 15,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger asynchronous Gmail message synchronization."""
    account = db.query(EmailAccount).filter_by(id=email_account_id).first()
    if not account or account.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="EmailAccount not found")

    if account.provider != "gmail":
        raise HTTPException(status_code=400, detail="Not a Gmail account")

    if not account.access_token:
        raise HTTPException(status_code=400, detail="No access token")

    if not start_sync(account.id):
        raise HTTPException(status_code=409, detail="A sync is already in progress for this account")

    background_tasks.add_task(run_sync_job, account.id, account.access_token, limit)

    return {"message": "Sync started", "email_account_id": account.id}

@app.get("/api/gmail/{email_account_id}/sync-status", response_model=SyncStatusResponse)
def get_gmail_sync_status(
    email_account_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    account = db.query(EmailAccount).filter_by(id=email_account_id).first()
    if not account or account.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="EmailAccount not found")
    
    return get_sync_status(account.id)


from pydantic import BaseModel
from datetime import datetime

class NotificationResponse(BaseModel):
    id: str
    type: str
    title: str
    message: str
    email_id: Optional[int] = None
    created_at: datetime
    is_read: bool = False

@app.get("/api/notifications", response_model=List[NotificationResponse])
def get_notifications(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    notifications = []
    
    recent_records = (
        db.query(ForensicAnalysisRecord, Email)
        .join(Email, ForensicAnalysisRecord.email_id == Email.id)
        .join(EmailAccount, Email.email_account_id == EmailAccount.id)
        .filter(EmailAccount.user_id == current_user.id)
        .order_by(Email.received_at.desc())
        .limit(limit)
        .all()
    )
    
    for fa, email in recent_records:
        analysis = fa.analysis or {}
        
        # Threat notifications
        threat = analysis.get("threat_score") or {}
        risk_level = str(threat.get("risk_level", "")).lower()
        if risk_level in ("critical", "high"):
            notifications.append(NotificationResponse(
                id=f"threat_{email.id}",
                type="threat",
                title=f"{risk_level.title()} Threat Detected",
                message=f"Risk detected in: {email.subject or 'No Subject'}",
                email_id=email.id,
                created_at=email.received_at or email.created_at,
            ))
            
        # AI failures
        ai = analysis.get("ai_analysis") or {}
        if ai.get("provider") == "error":
            notifications.append(NotificationResponse(
                id=f"ai_err_{email.id}",
                type="ai_error",
                title="AI Analysis Failed",
                message=f"Failed to analyze: {email.subject or 'No Subject'}",
                email_id=email.id,
                created_at=email.received_at or email.created_at,
            ))
            
    notifications.sort(key=lambda x: x.created_at, reverse=True)
    return notifications[:limit]

@app.get("/api/settings/info")
def get_settings_info(current_user: User = Depends(get_current_user)):
    from ai_analysis import get_ai_provider
    provider = get_ai_provider()
    return {
        "ai_provider": provider.name,
        "ai_model": getattr(provider, "_model", "Unknown")
    }
