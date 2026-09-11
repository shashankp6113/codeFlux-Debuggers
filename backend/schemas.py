"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, model_validator


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



class AuthResultEntrySchema(BaseModel):
    """One parsed Authentication-Results header with its authserv-id."""

    authserv_id: str = ""
    raw: str = ""
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None


class DKIMSignatureEntrySchema(BaseModel):
    """One parsed DKIM-Signature header with extracted tag values."""

    raw: str = ""
    domain: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    signed_headers: Optional[List[str]] = None


class AuthenticationHeadersSchema(BaseModel):
    """Authentication-related headers extracted verbatim.

    Multi-header fields (``all_*``) preserve every occurrence in
    original header order.  The singular fields
    (``authentication_results``, ``received_spf``, ``dkim_signature``)
    are populated from the first list item for backward compatibility.
    """

    # All occurrences in header order
    all_authentication_results: List[str] = []
    all_received_spf: List[str] = []
    all_dkim_signatures: List[str] = []

    # Backward-compatible singular fields (first item or None)
    authentication_results: Optional[str] = None
    received_spf: Optional[str] = None
    dkim_signature: Optional[str] = None

    # ARC headers (still singular)
    arc_authentication_results: Optional[str] = None
    arc_seal: Optional[str] = None
    arc_message_signature: Optional[str] = None

    # Structured verdicts (first Authentication-Results header)
    spf_verdict: Optional[str] = None
    dkim_verdict: Optional[str] = None
    dmarc_verdict: Optional[str] = None
    received_spf_verdict: Optional[str] = None

    # All verdicts across all headers
    all_spf_verdicts: List[str] = []
    all_dkim_verdicts: List[str] = []
    all_dmarc_verdicts: List[str] = []
    all_received_spf_verdicts: List[str] = []

    # Per-header structured entries with authserv-id
    auth_results_entries: List[AuthResultEntrySchema] = []

    # Per-header structured DKIM-Signature entries
    dkim_signature_entries: List[DKIMSignatureEntrySchema] = []

    @model_validator(mode="before")
    @classmethod
    def _populate_singular_fields(cls, data):
        """Auto-populate singular fields from list fields for backward compat.

        When data comes from ``dataclasses.asdict()`` the ``@property``
        fields on the dataclass are not included, so the singular fields
        would be ``None``.  This validator fills them from the lists.
        """
        if isinstance(data, dict):
            ar = data.get("all_authentication_results") or []
            if ar and data.get("authentication_results") is None:
                data["authentication_results"] = ar[0]
            rs = data.get("all_received_spf") or []
            if rs and data.get("received_spf") is None:
                data["received_spf"] = rs[0]
            dk = data.get("all_dkim_signatures") or []
            if dk and data.get("dkim_signature") is None:
                data["dkim_signature"] = dk[0]
        return data


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


class EnrichmentResultSchema(BaseModel):
    """Threat-intelligence enrichment for a single IOC."""

    ioc_type: str
    ioc_value: str
    verdict: str = "not_enriched"
    confidence: Optional[float] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    provider: str = ""
    raw_data: Optional[dict] = None
    error: Optional[str] = None


class ThreatIntelResultSchema(BaseModel):
    """Aggregated threat-intelligence enrichment results."""

    enrichments: List[EnrichmentResultSchema] = []
    stats: dict = {}
    provider: str = ""


class GeolocationResultSchema(BaseModel):
    """Geolocation and network metadata for a single IP address."""

    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    provider: str = ""
    error: Optional[str] = None


class GeolocationBatchResultSchema(BaseModel):
    """Aggregated geolocation results for an IOC extraction batch."""

    results: List[GeolocationResultSchema] = []
    stats: dict = {}
    provider: str = ""


class ForensicAnalysisSchema(BaseModel):
    """Complete forensic analysis result for one email."""

    received_hops: List[ReceivedHopSchema] = []
    authentication: AuthenticationHeadersSchema = AuthenticationHeadersSchema()
    identity: IdentityHeadersSchema = IdentityHeadersSchema()
    flags: List[ForensicFlagSchema] = []
    threat_score: Optional[ThreatScoreSchema] = None
    ioc_extraction: Optional[IOCExtractionResultSchema] = None
    threat_intelligence: Optional[ThreatIntelResultSchema] = None
    geolocation: Optional[GeolocationBatchResultSchema] = None


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
