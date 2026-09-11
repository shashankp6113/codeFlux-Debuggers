"""Unified email analysis orchestration for MailForensics AI.

Provides a single ``run_email_analysis`` function that executes the
full deterministic analysis pipeline on a parsed email:

1. Header forensics (when raw headers exist)
2. Threat scoring (when header forensics ran)
3. IOC extraction (always)
4. Threat-intelligence enrichment (always)
5. IP geolocation (always)
6. ForensicAnalysis persistence (always)

Both the ``.eml`` upload endpoint and Gmail synchronisation call this
function so the pipeline logic is never duplicated.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from email_parser import ParsedEmail
from forensics import analyze_headers
from scoring import calculate_threat_score
from ioc_extractor import extract_iocs
from threat_intel import enrich_iocs, get_provider
from geolocation import geolocate_ips, get_geolocation_provider
from models import ForensicAnalysis as ForensicAnalysisRecord


def run_email_analysis(
    parsed: ParsedEmail,
    db_email,
    db,
) -> dict:
    """Run the full analysis pipeline on a parsed email and persist the result.

    Args:
        parsed:   The ``ParsedEmail`` produced by ``parse_eml``.
        db_email: The persisted ``Email`` ORM object (must have ``id``).
        db:       An active SQLAlchemy session.

    Returns:
        The analysis dict that was persisted as ``ForensicAnalysis.analysis``.
    """
    analysis_dict: dict = {}

    # 1. Header forensics (when raw headers exist)
    if parsed.raw_headers:
        analysis = analyze_headers(parsed.raw_headers)
        analysis_dict = asdict(analysis)

        # 2. Threat scoring
        threat_score = calculate_threat_score(analysis)
        analysis_dict["threat_score"] = asdict(threat_score)

    # 3. IOC extraction (always)
    ioc_result = extract_iocs(parsed)
    analysis_dict["ioc_extraction"] = asdict(ioc_result)

    # 4. Threat-intelligence enrichment (always)
    ti_provider = get_provider()
    ti_result = enrich_iocs(ioc_result, provider=ti_provider)
    analysis_dict["threat_intelligence"] = asdict(ti_result)

    # 5. IP geolocation (always)
    geo_provider = get_geolocation_provider()
    geo_result = geolocate_ips(ioc_result, provider=geo_provider)
    analysis_dict["geolocation"] = asdict(geo_result)

    # 6. Persist ForensicAnalysis
    db_forensic = ForensicAnalysisRecord(
        email_id=db_email.id,
        analysis=analysis_dict,
    )
    db.add(db_forensic)
    db.commit()
    db.refresh(db_forensic)

    return analysis_dict
