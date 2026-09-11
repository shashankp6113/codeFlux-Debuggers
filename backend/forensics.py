"""Deterministic email-header forensic analyzer.

Parses raw email headers and produces structured forensic data including
Received-hop tracing, authentication header extraction, identity header
extraction, and basic inconsistency detection.

This module is intentionally deterministic and explainable — no LLM or
external API calls are made.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ReceivedHop:
    """A single Received header parsed into structured fields."""

    hop_number: int
    source_host: Optional[str] = None
    destination_host: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    timestamp: Optional[str] = None
    raw: str = ""


# Controlled set of valid authentication verdict values.
# Using a tuple constant so it can be checked at runtime and referenced
# by typing.Literal in type hints.
VALID_VERDICTS = (
    "pass", "fail", "softfail", "neutral",
    "none", "temperror", "permerror",
)

AuthVerdict = str  # One of VALID_VERDICTS or None; see _normalise_verdict()


def _normalise_verdict(raw: str) -> Optional[str]:
    """Normalise a raw verdict string to a canonical value.

    Returns one of VALID_VERDICTS if recognised, otherwise None.
    """
    cleaned = raw.strip().lower()
    if cleaned in VALID_VERDICTS:
        return cleaned
    return None


@dataclass
class AuthenticationHeaders:
    """Authentication-related headers — raw values plus structured verdicts."""

    # Raw header values (preserved verbatim, unchanged from before)
    authentication_results: Optional[str] = None
    received_spf: Optional[str] = None
    dkim_signature: Optional[str] = None
    arc_authentication_results: Optional[str] = None
    arc_seal: Optional[str] = None
    arc_message_signature: Optional[str] = None

    # Structured verdicts parsed from the raw headers above
    spf_verdict: Optional[str] = None      # from Authentication-Results
    dkim_verdict: Optional[str] = None     # from Authentication-Results
    dmarc_verdict: Optional[str] = None    # from Authentication-Results
    received_spf_verdict: Optional[str] = None  # from Received-SPF header


@dataclass
class IdentityHeaders:
    """Identity-related headers extracted verbatim."""

    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    from_header: Optional[str] = None
    to_header: Optional[str] = None
    message_id: Optional[str] = None


@dataclass
class ForensicFlag:
    """A single forensic observation or inconsistency."""

    rule_id: str
    severity: str  # "info", "warning", "suspicious"
    description: str
    evidence: str


@dataclass
class ForensicAnalysis:
    """Complete forensic analysis result for one email."""

    received_hops: List[ReceivedHop] = field(default_factory=list)
    authentication: AuthenticationHeaders = field(
        default_factory=AuthenticationHeaders
    )
    identity: IdentityHeaders = field(default_factory=IdentityHeaders)
    flags: List[ForensicFlag] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Match "from <host>" in a Received header
_RE_FROM_HOST = re.compile(r"\bfrom\s+([\w.\-]+)", re.IGNORECASE)

# Match "by <host>" in a Received header
_RE_BY_HOST = re.compile(r"\bby\s+([\w.\-]+)", re.IGNORECASE)

# Match an IPv4 address inside brackets or parentheses
_RE_IPV4 = re.compile(
    r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"
)

# Match an IPv6 address inside brackets (e.g. [IPv6:2001:db8::1])
_RE_IPV6 = re.compile(
    r"\[IPv6:([\da-fA-F:]+)\]", re.IGNORECASE
)

# Match the timestamp portion after the semicolon in a Received header
_RE_TIMESTAMP = re.compile(r";\s*(.+)$")

# Extract the domain from an email address (bare or angle-bracketed)
_RE_EMAIL_DOMAIN = re.compile(r"@([\w.\-]+)>?\s*$")


# ---------------------------------------------------------------------------
# IP address classification
# ---------------------------------------------------------------------------

# RFC 5737 documentation ranges (not truly private/internal)
_DOC_V4_NETWORKS = [
    ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),     # TEST-NET-3
]

# RFC 3849 IPv6 documentation prefix
_DOC_V6_NETWORKS = [
    ipaddress.IPv6Network("2001:db8::/32"),
]


def classify_ip(addr_str: str) -> str:
    """Classify an IP address string into a human-readable category.

    Returns one of:
        "private"       – RFC 1918 (IPv4) or Unique Local (IPv6 fc00::/7)
        "loopback"      – 127.0.0.0/8 or ::1
        "link_local"    – 169.254.0.0/16 or fe80::/10
        "documentation" – RFC 5737 (IPv4) or RFC 3849 (IPv6)
        "reserved"      – other IANA reserved ranges
        "public"        – globally routable
        "invalid"       – unparseable string
    """
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        return "invalid"

    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"

    # Check documentation ranges before generic private/reserved
    if isinstance(addr, ipaddress.IPv4Address):
        for net in _DOC_V4_NETWORKS:
            if addr in net:
                return "documentation"
    elif isinstance(addr, ipaddress.IPv6Address):
        for net in _DOC_V6_NETWORKS:
            if addr in net:
                return "documentation"

    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"

    return "public"


def _is_internal_ip(addr_str: str) -> bool:
    """Return True only for genuinely private/internal or local addresses.

    This deliberately excludes documentation/test ranges (RFC 5737, RFC 3849)
    and other IANA reserved blocks that are not indicative of internal mail
    relay infrastructure.
    """
    return classify_ip(addr_str) in ("private", "loopback", "link_local")


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------

def _parse_header_block(raw_headers: str) -> List[tuple]:
    """Parse raw headers into a list of (name, value) tuples.

    Handles continuation lines (lines starting with whitespace).
    """
    headers: List[tuple] = []
    current_name: Optional[str] = None
    current_value_lines: List[str] = []

    for line in raw_headers.splitlines():
        if line and line[0] in (" ", "\t"):
            # Continuation of previous header
            current_value_lines.append(line.strip())
        else:
            # Save previous header if any
            if current_name is not None:
                headers.append(
                    (current_name, " ".join(current_value_lines))
                )
            # Parse new header
            if ":" in line:
                name, _, value = line.partition(":")
                current_name = name.strip()
                current_value_lines = [value.strip()]
            else:
                current_name = None
                current_value_lines = []

    # Don't forget the last header
    if current_name is not None:
        headers.append((current_name, " ".join(current_value_lines)))

    return headers


def _extract_domain(value: str) -> Optional[str]:
    """Extract the domain portion from a header value containing an email."""
    m = _RE_EMAIL_DOMAIN.search(value)
    return m.group(1).lower() if m else None


def _parse_received_hop(raw: str, hop_number: int) -> ReceivedHop:
    """Parse a single Received header value into a ReceivedHop."""
    hop = ReceivedHop(hop_number=hop_number, raw=raw)

    m = _RE_FROM_HOST.search(raw)
    if m:
        hop.source_host = m.group(1)

    m = _RE_BY_HOST.search(raw)
    if m:
        hop.destination_host = m.group(1)

    m = _RE_IPV4.search(raw)
    if m:
        hop.ipv4 = m.group(1)

    m = _RE_IPV6.search(raw)
    if m:
        hop.ipv6 = m.group(1)

    m = _RE_TIMESTAMP.search(raw)
    if m:
        hop.timestamp = m.group(1).strip()

    return hop


# ---------------------------------------------------------------------------
# Inconsistency detection rules
# ---------------------------------------------------------------------------

def _detect_inconsistencies(
    identity: IdentityHeaders,
    authentication: AuthenticationHeaders,
    hops: List[ReceivedHop],
) -> List[ForensicFlag]:
    """Run deterministic detection rules and return forensic flags."""
    flags: List[ForensicFlag] = []

    from_domain = _extract_domain(identity.from_header or "")

    # RULE 1: Reply-To domain differs from From domain
    if identity.reply_to and from_domain:
        reply_domain = _extract_domain(identity.reply_to)
        if reply_domain and reply_domain != from_domain:
            flags.append(ForensicFlag(
                rule_id="REPLY_TO_DOMAIN_MISMATCH",
                severity="warning",
                description=(
                    "The Reply-To domain differs from the From domain. "
                    "This is sometimes legitimate (e.g. mailing lists) but "
                    "is also a common phishing technique."
                ),
                evidence=(
                    f"From domain: {from_domain}, "
                    f"Reply-To domain: {reply_domain}"
                ),
            ))

    # RULE 2: Return-Path domain differs from From domain
    if identity.return_path and from_domain:
        return_domain = _extract_domain(identity.return_path)
        if return_domain and return_domain != from_domain:
            flags.append(ForensicFlag(
                rule_id="RETURN_PATH_DOMAIN_MISMATCH",
                severity="warning",
                description=(
                    "The Return-Path domain differs from the From domain. "
                    "This may indicate the email was sent through a "
                    "third-party service or could be a spoofing indicator."
                ),
                evidence=(
                    f"From domain: {from_domain}, "
                    f"Return-Path domain: {return_domain}"
                ),
            ))

    # RULE 3: Missing authentication information
    has_auth = any([
        authentication.authentication_results,
        authentication.received_spf,
        authentication.dkim_signature,
    ])
    if not has_auth:
        flags.append(ForensicFlag(
            rule_id="MISSING_AUTH_HEADERS",
            severity="info",
            description=(
                "No SPF, DKIM, or Authentication-Results headers found. "
                "The email's authenticity cannot be verified via standard "
                "email authentication mechanisms."
            ),
            evidence="None of Authentication-Results, Received-SPF, or DKIM-Signature headers present.",
        ))

    # RULE 4: Private/reserved IP in Received headers
    for hop in hops:
        for ip_str in [hop.ipv4, hop.ipv6]:
            if ip_str and _is_internal_ip(ip_str):
                flags.append(ForensicFlag(
                    rule_id="PRIVATE_IP_IN_RECEIVED",
                    severity="info",
                    description=(
                        f"Hop {hop.hop_number} contains a private/reserved "
                        f"IP address. This is normal for internal mail "
                        f"relays but unusual for external senders."
                    ),
                    evidence=f"Hop {hop.hop_number}: IP {ip_str}",
                ))

    # RULE 5: Received header with no parseable source host
    for hop in hops:
        if not hop.source_host and not hop.ipv4 and not hop.ipv6:
            flags.append(ForensicFlag(
                rule_id="MALFORMED_RECEIVED_HEADER",
                severity="warning",
                description=(
                    f"Hop {hop.hop_number} has no identifiable source "
                    f"hostname or IP address. The Received header may be "
                    f"malformed or intentionally obfuscated."
                ),
                evidence=f"Hop {hop.hop_number} raw: {hop.raw[:120]}",
            ))

    return flags


# ---------------------------------------------------------------------------
# Authentication verdict parsing
# ---------------------------------------------------------------------------

# Regex to extract method=verdict pairs from Authentication-Results.
# Matches patterns like "spf=pass", "dkim=fail", "dmarc=none" etc.
# The verdict portion may be followed by a space, parenthesis, semicolon, or EOL.
_RE_AUTH_RESULT_VERDICT = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(\S+)", re.IGNORECASE
)

# Regex to extract the verdict from a Received-SPF header value.
# The verdict is the first token, e.g. "pass (details...)" or "fail"
_RE_RECEIVED_SPF_VERDICT = re.compile(
    r"^\s*(\S+)", re.IGNORECASE
)


def _parse_authentication_results(header_value: str) -> dict:
    """Parse an Authentication-Results header into method→verdict dict.

    Args:
        header_value: The raw value of the Authentication-Results header.

    Returns:
        A dict like {"spf": "pass", "dkim": "fail", "dmarc": "pass"}.
        Only includes methods whose verdicts are valid/recognised.
    """
    verdicts = {}
    for match in _RE_AUTH_RESULT_VERDICT.finditer(header_value):
        method = match.group(1).lower()
        raw_verdict = match.group(2).split("(")[0].rstrip(";,)")
        normalised = _normalise_verdict(raw_verdict)
        if normalised is not None and method not in verdicts:
            verdicts[method] = normalised
    return verdicts


def _parse_received_spf_verdict(header_value: str) -> Optional[str]:
    """Parse the verdict from a Received-SPF header value.

    Args:
        header_value: The raw value of the Received-SPF header.

    Returns:
        A normalised verdict string, or None if unparseable.
    """
    m = _RE_RECEIVED_SPF_VERDICT.match(header_value)
    if m:
        return _normalise_verdict(m.group(1))
    return None


def _populate_verdicts(auth: AuthenticationHeaders) -> None:
    """Parse structured verdicts from raw authentication headers.

    Mutates the auth dataclass in place, setting the verdict fields.
    """
    # Parse Authentication-Results
    if auth.authentication_results:
        verdicts = _parse_authentication_results(auth.authentication_results)
        auth.spf_verdict = verdicts.get("spf")
        auth.dkim_verdict = verdicts.get("dkim")
        auth.dmarc_verdict = verdicts.get("dmarc")

    # Parse Received-SPF
    if auth.received_spf:
        auth.received_spf_verdict = _parse_received_spf_verdict(
            auth.received_spf
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_headers(raw_headers: str) -> ForensicAnalysis:
    """Perform deterministic forensic analysis on raw email headers.

    Args:
        raw_headers: The complete raw header block of an email as a string.

    Returns:
        A ForensicAnalysis dataclass containing parsed hops, extracted
        authentication and identity headers, and any forensic flags.
    """
    parsed = _parse_header_block(raw_headers)

    # --- Received hops (ordered top-to-bottom as they appear) ---
    received_values = [v for n, v in parsed if n.lower() == "received"]
    hops = [
        _parse_received_hop(val, hop_number=i + 1)
        for i, val in enumerate(received_values)
    ]

    # --- Authentication headers ---
    auth = AuthenticationHeaders()
    for name, value in parsed:
        lower = name.lower()
        if lower == "authentication-results" and auth.authentication_results is None:
            auth.authentication_results = value
        elif lower == "received-spf" and auth.received_spf is None:
            auth.received_spf = value
        elif lower == "dkim-signature" and auth.dkim_signature is None:
            auth.dkim_signature = value
        elif lower == "arc-authentication-results" and auth.arc_authentication_results is None:
            auth.arc_authentication_results = value
        elif lower == "arc-seal" and auth.arc_seal is None:
            auth.arc_seal = value
        elif lower == "arc-message-signature" and auth.arc_message_signature is None:
            auth.arc_message_signature = value

    # --- Identity headers ---
    identity = IdentityHeaders()
    for name, value in parsed:
        lower = name.lower()
        if lower == "return-path" and identity.return_path is None:
            identity.return_path = value
        elif lower == "reply-to" and identity.reply_to is None:
            identity.reply_to = value
        elif lower == "from" and identity.from_header is None:
            identity.from_header = value
        elif lower == "to" and identity.to_header is None:
            identity.to_header = value
        elif lower == "message-id" and identity.message_id is None:
            identity.message_id = value

    # --- Structured authentication verdicts ---
    _populate_verdicts(auth)

    # --- Detection rules ---
    flags = _detect_inconsistencies(identity, auth, hops)

    return ForensicAnalysis(
        received_hops=hops,
        authentication=auth,
        identity=identity,
        flags=flags,
    )
