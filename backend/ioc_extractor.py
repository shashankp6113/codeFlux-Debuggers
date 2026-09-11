"""Deterministic IOC (Indicator of Compromise) extraction for MailForensics AI.

Scans parsed email fields — headers, body text, body HTML — and extracts
observable indicators: IPv4/IPv6 addresses, domains, URLs, and email
addresses.  Each IOC carries its type, value, source field, and a short
context snippet for investigator review.

This module is intentionally deterministic and self-contained.  No DNS
lookups, threat-intelligence services, geolocation, LLM, or database
access is performed.  IOCs are extracted and deduplicated — they are
**not** classified as malicious.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from email_parser import ParsedEmail


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    """A single Indicator of Compromise extracted from an email.

    Attributes:
        ioc_type:  One of ``"ipv4"``, ``"ipv6"``, ``"domain"``, ``"url"``,
                   ``"email"``.
        value:     The original indicator value (minimally normalised).
        source:    The email field it was found in (e.g. ``"from"``,
                   ``"body_text"``, ``"received_header"``).
        context:   A short surrounding-text snippet for investigation.
    """

    ioc_type: str
    value: str
    source: str
    context: str


@dataclass
class IOCExtractionResult:
    """Complete IOC extraction result for one email.

    Attributes:
        iocs:   Deduplicated list of extracted IOCs.
        stats:  Per-type count of extracted IOCs.
    """

    iocs: List[IOC] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# IPv4: four dotted octets, optionally followed by :port.
# Negative lookbehind avoids matching inside longer dotted sequences and
# the pattern validates octet ranges programmatically after matching.
_RE_IPV4 = re.compile(
    r"(?<![.\w])"                           # not preceded by dot or word char
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::\d{1,5})?"                        # optional :port
    r"(?![\w])"                             # not followed by word char
    r"(?!\.\d)"                             # not followed by .digit (more octets)
)

# IPv6 — matches bracketed [IPv6:...] notation (common in email headers)
# as well as bare full/abbreviated addresses.
_RE_IPV6_BRACKETED = re.compile(
    r"\[IPv6:([0-9a-fA-F:]+)\]", re.IGNORECASE
)
_RE_IPV6_BARE = re.compile(
    r"(?<![:\w])"
    r"((?:[0-9a-fA-F]{1,4}:){5,7}[0-9a-fA-F]{1,4}"   # 6-8 groups (full)
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}::"                   # trailing ::
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"  # leading ::
    r"|::)"                                              # just ::
    r"(?![:\w])"
)

# URLs — http(s), capturing path/query/fragment.
# The first alternative handles IPv6 bracketed authorities like
# https://[2001:db8::1]:443/path which contain ] that the general
# pattern would treat as a terminator.
_RE_URL = re.compile(
    r"(https?://\[[0-9a-fA-F:]+\](?::\d+)?[^\s<>\"'`,;)\]]*"
    r"|https?://[^\s<>\"'`,;)\]]+)", re.IGNORECASE
)

# Email addresses — deliberately conservative to avoid false positives.
_RE_EMAIL = re.compile(
    r"(?<![.\w@])"
    r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
    r"(?![.\w@])"
)

# Domain — standalone FQDN-like token with at least one dot.
# Negative look-arounds prevent matching inside URLs or emails.
_RE_DOMAIN = re.compile(
    r"(?<![/@.\w])"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,})"
    r"(?![/@\w])"                           # not followed by / @ or word char
    r"(?!\.[a-zA-Z0-9])"                    # not followed by .label (more subdomains)
)


# ---------------------------------------------------------------------------
# Known TLDs subset for domain validation (prevents false positives)
# ---------------------------------------------------------------------------

# A compact set of common TLDs.  We don't need an exhaustive list — the
# goal is to reject obvious non-domains like "v1.2" or "file.txt" while
# accepting real domains encountered in email forensics.
_VALID_TLDS: Set[str] = {
    # Generic
    "com", "org", "net", "edu", "gov", "mil", "int",
    "info", "biz", "name", "pro", "aero", "museum", "coop",
    # Common new gTLDs
    "io", "co", "app", "dev", "xyz", "online", "site", "tech",
    "cloud", "store", "shop", "blog", "email", "help",
    # Country codes (common ones)
    "us", "uk", "ca", "au", "de", "fr", "jp", "cn", "ru", "br",
    "in", "it", "es", "nl", "se", "no", "fi", "dk", "ch", "at",
    "be", "pl", "cz", "ie", "pt", "nz", "za", "mx", "ar", "cl",
    "kr", "sg", "hk", "tw", "th", "my", "ph", "id", "vn",
    # Test TLD (used in our fixtures)
    "test", "example", "local", "localhost", "invalid",
}

# File extensions and version-like TLDs to reject.
_FALSE_TLDS: Set[str] = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "sh", "py", "js",
    "ts", "rb", "go", "rs", "css", "html", "htm", "xml", "json",
    "yaml", "yml", "toml", "ini", "cfg", "conf", "log", "txt",
    "csv", "tsv", "md", "rst", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "zip", "tar", "gz", "bz2", "xz", "rar", "7z",
    "png", "jpg", "jpeg", "gif", "svg", "bmp", "ico", "webp",
    "mp3", "mp4", "avi", "mkv", "mov", "wav", "flac",
    "woff", "woff2", "ttf", "eot", "otf",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
}


# ---------------------------------------------------------------------------
# False-positive filters
# ---------------------------------------------------------------------------

def _is_valid_ipv4(addr: str) -> bool:
    """Return True if *addr* is a syntactically valid IPv4 address."""
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            val = int(p)
        except ValueError:
            return False
        if val < 0 or val > 255:
            return False
        # Reject leading zeros (e.g. "01.02.03.04") which are usually
        # version strings, not IPs.
        if p != str(val):
            return False
    return True


def _looks_like_version(text: str, match_start: int, match_end: int) -> bool:
    """Heuristic: is the matched text likely a version number?

    Checks whether the match is preceded by a version-indicator such as
    ``v``, ``version``, ``ver``, or ``V``.
    """
    prefix = text[max(0, match_start - 10):match_start].lower()
    if re.search(r"(?:version|ver|v)\s*$", prefix):
        return True
    return False


def _looks_like_date(text: str, match_start: int, match_end: int) -> bool:
    """Heuristic: does the matched IPv4-like pattern look like a date?

    Patterns like "2025.07.11.0" or "12.31.2025.0" are not IPs.
    """
    candidate = text[match_start:match_end]
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    # If first octet looks like a year (1900-2099), suspicious
    if 1900 <= nums[0] <= 2099 and 1 <= nums[1] <= 12 and 1 <= nums[2] <= 31:
        return True
    return False


def _is_valid_domain(candidate: str) -> bool:
    """Return True if *candidate* looks like a plausible domain name."""
    # Must have at least one dot
    if "." not in candidate:
        return False

    tld = candidate.rsplit(".", 1)[-1].lower()

    # Reject file extensions / version-like suffixes
    if tld in _FALSE_TLDS:
        return False

    # Must have a known TLD
    if tld not in _VALID_TLDS:
        return False

    # Each label must not be purely numeric (e.g. "192.168.1" after
    # stripping TLD should still have a non-numeric label)
    labels = candidate.split(".")
    non_tld_labels = labels[:-1]
    if all(label.isdigit() for label in non_tld_labels):
        return False

    return True


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

_CONTEXT_RADIUS = 60  # characters on each side of the IOC value


def _build_context(text: str, start: int, end: int) -> str:
    """Extract a short surrounding-text snippet around the IOC."""
    ctx_start = max(0, start - _CONTEXT_RADIUS)
    ctx_end = min(len(text), end + _CONTEXT_RADIUS)
    snippet = text[ctx_start:ctx_end].replace("\n", " ").replace("\r", " ")
    snippet = " ".join(snippet.split())  # collapse whitespace
    if ctx_start > 0:
        snippet = "..." + snippet
    if ctx_end < len(text):
        snippet = snippet + "..."
    return snippet


# ---------------------------------------------------------------------------
# Per-source extraction
# ---------------------------------------------------------------------------

def _extract_from_text(
    text: str,
    source: str,
    seen: Dict[Tuple[str, str, str], None],
    iocs: List[IOC],
) -> None:
    """Extract all IOC types from a text block and append to *iocs*.

    *seen* is an ordered dict keyed by ``(ioc_type, normalised_value, source)``
    used for deduplication.  We use dict (not set) to preserve insertion order.
    """
    if not text:
        return

    # --- URLs first (so we can track their spans for domain/IP suppression) ---
    url_spans: List[Tuple[int, int]] = []
    for m in _RE_URL.finditer(text):
        raw_url = m.group(1).rstrip(".")  # strip trailing dots
        key = ("url", raw_url.lower(), source)
        if key not in seen:
            seen[key] = None
            iocs.append(IOC(
                ioc_type="url",
                value=raw_url,
                source=source,
                context=_build_context(text, m.start(), m.end()),
            ))
        url_spans.append((m.start(1), m.end(1)))

        # Extract IP from URL authority (host portion only).
        # This ensures IPs used as hostnames produce separate IOCs,
        # while IPs that merely appear in URL paths/queries do not.
        try:
            parsed_url = urlparse(raw_url)
            hostname = parsed_url.hostname
        except Exception:
            continue
        if not hostname:
            continue
        if _is_valid_ipv4(hostname):
            ip_key = ("ipv4", hostname, source)
            if ip_key not in seen:
                seen[ip_key] = None
                iocs.append(IOC(
                    ioc_type="ipv4",
                    value=hostname,
                    source=source,
                    context=_build_context(text, m.start(), m.end()),
                ))
        elif ":" in hostname:
            # urlparse strips brackets from IPv6 authorities
            ip_key = ("ipv6", hostname.lower(), source)
            if ip_key not in seen:
                seen[ip_key] = None
                iocs.append(IOC(
                    ioc_type="ipv6",
                    value=hostname,
                    source=source,
                    context=_build_context(text, m.start(), m.end()),
                ))

    # --- Email addresses ---
    email_spans: List[Tuple[int, int]] = []
    for m in _RE_EMAIL.finditer(text):
        addr = m.group(1)
        key = ("email", addr.lower(), source)
        if key not in seen:
            seen[key] = None
            iocs.append(IOC(
                ioc_type="email",
                value=addr,
                source=source,
                context=_build_context(text, m.start(), m.end()),
            ))
        email_spans.append((m.start(1), m.end(1)))

    def _inside_url_or_email(start: int, end: int) -> bool:
        for us, ue in url_spans:
            if start >= us and end <= ue:
                return True
        for es, ee in email_spans:
            if start >= es and end <= ee:
                return True
        return False

    # --- IPv4 (suppress those inside URLs/emails — authority IPs already
    #     extracted above via urlparse) ---
    for m in _RE_IPV4.finditer(text):
        addr = m.group(1)
        if not _is_valid_ipv4(addr):
            continue
        if _looks_like_version(text, m.start(), m.end()):
            continue
        if _looks_like_date(text, m.start(), m.end()):
            continue
        if _inside_url_or_email(m.start(1), m.end(1)):
            continue
        key = ("ipv4", addr, source)
        if key not in seen:
            seen[key] = None
            iocs.append(IOC(
                ioc_type="ipv4",
                value=addr,
                source=source,
                context=_build_context(text, m.start(), m.end()),
            ))

    # --- IPv6 (bracketed) — suppress those inside URLs/emails ---
    for m in _RE_IPV6_BRACKETED.finditer(text):
        addr = m.group(1)
        if _inside_url_or_email(m.start(), m.end()):
            continue
        key = ("ipv6", addr.lower(), source)
        if key not in seen:
            seen[key] = None
            iocs.append(IOC(
                ioc_type="ipv6",
                value=addr,
                source=source,
                context=_build_context(text, m.start(), m.end()),
            ))

    # --- IPv6 (bare) — suppress those inside URLs/emails ---
    for m in _RE_IPV6_BARE.finditer(text):
        addr = m.group(1)
        # Must have at least two colons to be a plausible IPv6
        if addr.count(":") < 2:
            continue
        if _inside_url_or_email(m.start(1), m.end(1)):
            continue
        key = ("ipv6", addr.lower(), source)
        if key not in seen:
            seen[key] = None
            iocs.append(IOC(
                ioc_type="ipv6",
                value=addr,
                source=source,
                context=_build_context(text, m.start(), m.end()),
            ))

    # --- Domains (suppress those already captured inside URLs/emails) ---
    for m in _RE_DOMAIN.finditer(text):
        candidate = m.group(1)
        if not _is_valid_domain(candidate):
            continue
        if _inside_url_or_email(m.start(1), m.end(1)):
            continue
        key = ("domain", candidate.lower(), source)
        if key not in seen:
            seen[key] = None
            iocs.append(IOC(
                ioc_type="domain",
                value=candidate,
                source=source,
                context=_build_context(text, m.start(), m.end()),
            ))


# ---------------------------------------------------------------------------
# Header-field source mapping
# ---------------------------------------------------------------------------

_HEADER_SOURCE_MAP = {
    "from": "from",
    "to": "to",
    "cc": "cc",
    "subject": "subject",
    "message-id": "message_id",
    "reply-to": "reply_to",
    "return-path": "return_path",
}

_AUTH_HEADER_NAMES = {
    "authentication-results",
    "received-spf",
    "dkim-signature",
    "arc-authentication-results",
    "arc-seal",
    "arc-message-signature",
}


def _parse_header_lines(raw_headers: str) -> List[Tuple[str, str]]:
    """Parse raw headers into (name, value) tuples, handling continuations."""
    headers: List[Tuple[str, str]] = []
    current_name: Optional[str] = None
    current_lines: List[str] = []

    for line in raw_headers.splitlines():
        if line and line[0] in (" ", "\t"):
            current_lines.append(line.strip())
        else:
            if current_name is not None:
                headers.append((current_name, " ".join(current_lines)))
            if ":" in line:
                name, _, value = line.partition(":")
                current_name = name.strip()
                current_lines = [value.strip()]
            else:
                current_name = None
                current_lines = []

    if current_name is not None:
        headers.append((current_name, " ".join(current_lines)))

    return headers


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_iocs(parsed_email: ParsedEmail) -> IOCExtractionResult:
    """Extract IOCs from a parsed email.

    Scans header fields, plain-text body, and HTML body for observable
    indicators.  Results are deduplicated per (type, normalised_value,
    source).

    Args:
        parsed_email: A ``ParsedEmail`` dataclass from ``email_parser.py``.

    Returns:
        An ``IOCExtractionResult`` containing deduplicated IOCs and stats.
    """
    iocs: List[IOC] = []
    seen: Dict[Tuple[str, str, str], None] = {}

    # --- Structured header fields ---
    _field_sources = [
        (parsed_email.sender, "from"),
        (parsed_email.recipient, "to"),
        (parsed_email.cc, "cc"),
        (parsed_email.subject, "subject"),
    ]
    for value, source in _field_sources:
        if value:
            _extract_from_text(value, source, seen, iocs)

    # --- Raw headers (Received, authentication, and other headers) ---
    if parsed_email.raw_headers:
        parsed_headers = _parse_header_lines(parsed_email.raw_headers)
        for name, value in parsed_headers:
            lower_name = name.lower()
            if lower_name == "received":
                _extract_from_text(value, "received_header", seen, iocs)
            elif lower_name in _AUTH_HEADER_NAMES:
                _extract_from_text(value, "authentication_header", seen, iocs)
            elif lower_name in _HEADER_SOURCE_MAP:
                # Already handled above via structured fields; skip to
                # avoid double-extraction.
                continue
            else:
                _extract_from_text(value, "raw_headers", seen, iocs)

    # --- Body text ---
    if parsed_email.body_text:
        _extract_from_text(parsed_email.body_text, "body_text", seen, iocs)

    # --- Body HTML ---
    if parsed_email.body_html:
        _extract_from_text(parsed_email.body_html, "body_html", seen, iocs)

    # --- Build stats ---
    stats: Dict[str, int] = {}
    for ioc in iocs:
        stats[ioc.ioc_type] = stats.get(ioc.ioc_type, 0) + 1

    return IOCExtractionResult(iocs=iocs, stats=stats)
