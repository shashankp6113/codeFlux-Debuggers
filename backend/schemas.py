"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Forensic analysis response schemas
# ---------------------------------------------------------------------------

class ReceivedHopSchema(BaseModel):
    """A single Received header parsed into structured fields."""

    hop_number: int
    source_host: Optional[str] = None
    destination_host: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    timestamp: Optional[str] = None
    raw: str = ""


class AuthenticationHeadersSchema(BaseModel):
    """Authentication-related headers extracted verbatim."""

    authentication_results: Optional[str] = None
    received_spf: Optional[str] = None
    dkim_signature: Optional[str] = None
    arc_authentication_results: Optional[str] = None
    arc_seal: Optional[str] = None
    arc_message_signature: Optional[str] = None

    # Structured verdicts parsed from raw headers
    spf_verdict: Optional[str] = None
    dkim_verdict: Optional[str] = None
    dmarc_verdict: Optional[str] = None
    received_spf_verdict: Optional[str] = None


class IdentityHeadersSchema(BaseModel):
    """Identity-related headers extracted verbatim."""

    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    from_header: Optional[str] = None
    to_header: Optional[str] = None
    message_id: Optional[str] = None


class ForensicFlagSchema(BaseModel):
    """A single forensic observation or inconsistency."""

    rule_id: str
    severity: str
    description: str
    evidence: str


class RuleContributionSchema(BaseModel):
    """A single rule's contribution to the threat score."""

    rule_id: str
    category: str
    severity: str
    points: int


class ThreatScoreSchema(BaseModel):
    """Deterministic threat score computed from forensic flags."""

    score: int
    risk_level: str
    category_scores: dict = {}
    rule_contributions: List[RuleContributionSchema] = []


class IOCSchema(BaseModel):
    """A single Indicator of Compromise extracted from an email."""

    ioc_type: str
    value: str
    source: str
    context: str


class IOCExtractionResultSchema(BaseModel):
    """Complete IOC extraction result for one email."""

    iocs: List[IOCSchema] = []
    stats: dict = {}


class ForensicAnalysisSchema(BaseModel):
    """Complete forensic analysis result for one email."""

    received_hops: List[ReceivedHopSchema] = []
    authentication: AuthenticationHeadersSchema = AuthenticationHeadersSchema()
    identity: IdentityHeadersSchema = IdentityHeadersSchema()
    flags: List[ForensicFlagSchema] = []
    threat_score: Optional[ThreatScoreSchema] = None
    ioc_extraction: Optional[IOCExtractionResultSchema] = None


# ---------------------------------------------------------------------------
# Email upload response schema
# ---------------------------------------------------------------------------

class EmailResponse(BaseModel):
    """Response schema returned after a successful .eml upload."""

    id: int
    email_account_id: int
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender: str
    recipient: str
    cc: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    received_at: Optional[datetime] = None
    created_at: datetime
    forensics: Optional[ForensicAnalysisSchema] = None

    model_config = {"from_attributes": True}
