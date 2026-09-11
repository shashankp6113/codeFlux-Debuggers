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
class AuthResultEntry:
    """One parsed Authentication-Results header with its authserv-id.

    Per RFC 7601 the header format is::

        Authentication-Results: <authserv-id>; <method>=<result> ...

    The ``authserv_id`` identifies the service that evaluated the message.
    It is **not** inherently trusted — any MTA in the delivery chain can
    inject an ``Authentication-Results`` header with an arbitrary
    ``authserv-id``.
    """

    authserv_id: str = ""
    raw: str = ""
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None


@dataclass
class DKIMSignatureEntry:
    """One parsed DKIM-Signature header with extracted tag values.

    Per RFC 6376 a DKIM-Signature header contains semicolon-separated
    ``tag=value`` pairs.  This dataclass extracts the forensically
    relevant tags while preserving the raw header for evidence.

    Duplicate-tag behaviour
    ~~~~~~~~~~~~~~~~~~~~~~~
    RFC 6376 §3.2 states that duplicate tags are not permitted, but
    malformed signatures do exist in the wild.  This parser keeps the
    **first** occurrence of each tag and silently ignores later duplicates.
    """

    raw: str = ""
    domain: Optional[str] = None          # d= signing domain
    selector: Optional[str] = None        # s= selector
    algorithm: Optional[str] = None       # a= algorithm (e.g. rsa-sha256)
    signed_headers: Optional[List[str]] = None  # h= list of header names


@dataclass
class AuthenticationHeaders:
    """Authentication-related headers — raw values plus structured verdicts.

    Multi-header support
    ~~~~~~~~~~~~~~~~~~~~
    Real-world emails commonly contain multiple ``Authentication-Results``,
    ``Received-SPF``, and ``DKIM-Signature`` headers (one per receiving MTA
    or signing domain).  All occurrences are preserved in order in the
    ``all_*`` list fields.

    For backward compatibility the singular property names
    (``authentication_results``, ``received_spf``, ``dkim_signature``)
    return the **first** item from the corresponding list (or ``None``).
    """

    # --- Raw header values (ALL occurrences, in header order) ---
    all_authentication_results: List[str] = field(default_factory=list)
    all_received_spf: List[str] = field(default_factory=list)
    all_dkim_signatures: List[str] = field(default_factory=list)

    # ARC headers — still singular (multi-instance ARC is a future task)
    arc_authentication_results: Optional[str] = None
    arc_seal: Optional[str] = None
    arc_message_signature: Optional[str] = None

    # --- Structured verdicts (first Authentication-Results header) ---
    spf_verdict: Optional[str] = None
    dkim_verdict: Optional[str] = None
    dmarc_verdict: Optional[str] = None

    # --- Structured verdict from first Received-SPF header ---
    received_spf_verdict: Optional[str] = None

    # --- All verdicts across all Authentication-Results headers ---
    all_spf_verdicts: List[str] = field(default_factory=list)
    all_dkim_verdicts: List[str] = field(default_factory=list)
    all_dmarc_verdicts: List[str] = field(default_factory=list)

    # --- All verdicts across all Received-SPF headers ---
    all_received_spf_verdicts: List[str] = field(default_factory=list)

    # --- Per-header structured Authentication-Results entries ---
    auth_results_entries: List[AuthResultEntry] = field(default_factory=list)

    # --- Per-header structured DKIM-Signature entries ---
    dkim_signature_entries: List[DKIMSignatureEntry] = field(default_factory=list)

    # --- Backward-compatible properties ---

    @property
    def authentication_results(self) -> Optional[str]:
        """First Authentication-Results header, or None."""
        return self.all_authentication_results[0] if self.all_authentication_results else None

    @property
    def received_spf(self) -> Optional[str]:
        """First Received-SPF header, or None."""
        return self.all_received_spf[0] if self.all_received_spf else None

    @property
    def dkim_signature(self) -> Optional[str]:
        """First DKIM-Signature header, or None."""
        return self.all_dkim_signatures[0] if self.all_dkim_signatures else None



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
        authentication.all_authentication_results,
        authentication.all_received_spf,
        authentication.all_dkim_signatures,
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

    # RULE 6: SPF failure reported in authentication headers
    all_spf = set(authentication.all_spf_verdicts)
    all_spf.update(authentication.all_received_spf_verdicts)
    if "fail" in all_spf:
        flags.append(ForensicFlag(
            rule_id="SPF_FAIL",
            severity="warning",
            description=(
                "An authentication header reported an SPF failure. "
                "This indicates the sending IP address was not authorized "
                "by the sender's domain SPF policy, as reported by the "
                "evaluating mail server."
            ),
            evidence=(
                f"SPF verdicts (Authentication-Results): "
                f"{authentication.all_spf_verdicts}, "
                f"SPF verdicts (Received-SPF): "
                f"{authentication.all_received_spf_verdicts}"
            ),
        ))

    # RULE 7: DKIM failure reported in authentication headers
    if "fail" in authentication.all_dkim_verdicts:
        flags.append(ForensicFlag(
            rule_id="DKIM_FAIL",
            severity="warning",
            description=(
                "An authentication header reported a DKIM failure. "
                "This indicates the DKIM signature did not verify, "
                "suggesting possible message modification in transit, "
                "as reported by the evaluating mail server."
            ),
            evidence=(
                f"DKIM verdicts: {authentication.all_dkim_verdicts}"
            ),
        ))

    # RULE 8: DMARC failure reported in authentication headers
    if "fail" in authentication.all_dmarc_verdicts:
        flags.append(ForensicFlag(
            rule_id="DMARC_FAIL",
            severity="warning",
            description=(
                "An authentication header reported a DMARC failure. "
                "This indicates the message did not align with the "
                "domain's DMARC policy, as reported by the evaluating "
                "mail server."
            ),
            evidence=(
                f"DMARC verdicts: {authentication.all_dmarc_verdicts}"
            ),
        ))

    # RULE 9: SPF softfail reported in authentication headers
    if "softfail" in all_spf:
        flags.append(ForensicFlag(
            rule_id="SPF_SOFTFAIL",
            severity="info",
            description=(
                "An authentication header reported an SPF softfail. "
                "This typically indicates the sender's domain is "
                "transitioning its SPF policy and the sending IP was "
                "not fully authorized, as reported by the evaluating "
                "mail server."
            ),
            evidence=(
                f"SPF verdicts (Authentication-Results): "
                f"{authentication.all_spf_verdicts}, "
                f"SPF verdicts (Received-SPF): "
                f"{authentication.all_received_spf_verdicts}"
            ),
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


def _extract_authserv_id(header_value: str) -> str:
    """Extract the authserv-id from an Authentication-Results header value.

    Per RFC 7601 §2.2 the header format is::

        Authentication-Results: authserv-id; method=result ...

    The authserv-id is the text before the first semicolon.  It is
    typically a hostname (e.g. ``mx.example.com``), optionally followed
    by a version number.

    Returns the extracted authserv-id stripped of whitespace, or an empty
    string if none can be determined.
    """
    # Split on the first semicolon; everything before it is the authserv-id.
    semi_pos = header_value.find(";")
    if semi_pos == -1:
        # No semicolon → the entire value may be a malformed header or just
        # an authserv-id with no results.  Return it stripped.
        return header_value.strip()
    return header_value[:semi_pos].strip()


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


def _parse_dkim_tags(header_value: str) -> dict:
    """Parse DKIM-Signature tag=value pairs into a dict.

    Per RFC 6376 §3.2 the header value is a semicolon-separated list of
    ``tag=value`` pairs.  Tag names are case-sensitive and typically
    lowercase.  Whitespace around ``=`` and around values is stripped.

    Duplicate tags: RFC 6376 disallows duplicate tags, but malformed
    signatures exist.  The **first** occurrence wins; later duplicates
    are silently ignored.

    Returns:
        A dict mapping lowercase tag names to stripped values.
    """
    tags: dict = {}
    # Split on semicolons; handle missing trailing semicolon
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        eq_pos = part.find("=")
        if eq_pos == -1:
            continue
        tag_name = part[:eq_pos].strip()
        tag_value = part[eq_pos + 1:].strip()
        # First occurrence wins (duplicate-tag rule)
        if tag_name and tag_name not in tags:
            tags[tag_name] = tag_value
    return tags


def _build_dkim_entry(header_value: str) -> DKIMSignatureEntry:
    """Build a DKIMSignatureEntry from a raw DKIM-Signature header value."""
    tags = _parse_dkim_tags(header_value)

    # Parse h= into a list of header names
    signed_headers = None
    h_value = tags.get("h")
    if h_value is not None:
        signed_headers = [
            name.strip() for name in h_value.split(":")
            if name.strip()
        ]

    return DKIMSignatureEntry(
        raw=header_value,
        domain=tags.get("d"),
        selector=tags.get("s"),
        algorithm=tags.get("a"),
        signed_headers=signed_headers,
    )


def _populate_verdicts(auth: AuthenticationHeaders) -> None:
    """Parse structured verdicts from raw authentication headers.

    Mutates the auth dataclass in place, setting the singular verdict
    fields (from the first header), the ``all_*`` verdict lists (from
    every header), and the ``auth_results_entries`` list that ties each
    ``Authentication-Results`` header to its ``authserv-id``.
    """
    # Parse all Authentication-Results headers
    for i, header_value in enumerate(auth.all_authentication_results):
        verdicts = _parse_authentication_results(header_value)
        authserv_id = _extract_authserv_id(header_value)

        # Build a structured entry for this header
        entry = AuthResultEntry(
            authserv_id=authserv_id,
            raw=header_value,
            spf=verdicts.get("spf"),
            dkim=verdicts.get("dkim"),
            dmarc=verdicts.get("dmarc"),
        )
        auth.auth_results_entries.append(entry)

        # Collect per-method verdicts into all_* lists
        if "spf" in verdicts:
            auth.all_spf_verdicts.append(verdicts["spf"])
        if "dkim" in verdicts:
            auth.all_dkim_verdicts.append(verdicts["dkim"])
        if "dmarc" in verdicts:
            auth.all_dmarc_verdicts.append(verdicts["dmarc"])
        # First header sets the singular verdict fields
        if i == 0:
            auth.spf_verdict = verdicts.get("spf")
            auth.dkim_verdict = verdicts.get("dkim")
            auth.dmarc_verdict = verdicts.get("dmarc")

    # Parse all Received-SPF headers
    for i, header_value in enumerate(auth.all_received_spf):
        verdict = _parse_received_spf_verdict(header_value)
        if verdict is not None:
            auth.all_received_spf_verdicts.append(verdict)
        # First header sets the singular verdict field
        if i == 0:
            auth.received_spf_verdict = verdict

    # Parse all DKIM-Signature headers into structured entries
    for header_value in auth.all_dkim_signatures:
        auth.dkim_signature_entries.append(_build_dkim_entry(header_value))


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
        if lower == "authentication-results":
            auth.all_authentication_results.append(value)
        elif lower == "received-spf":
            auth.all_received_spf.append(value)
        elif lower == "dkim-signature":
            auth.all_dkim_signatures.append(value)
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
