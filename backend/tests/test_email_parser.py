"""Tests for the email parsing module and upload endpoint."""

import pytest
from email_parser import parse_eml, ParsedEmail


# ---------------------------------------------------------------------------
# Sample .eml content fixtures
# ---------------------------------------------------------------------------

VALID_SIMPLE_EML = b"""\
Message-ID: <test-001@example.com>
From: alice@example.com
To: bob@example.com
Subject: Test Email
Date: Thu, 10 Jul 2025 14:30:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Bob, this is a test email.
"""

VALID_MULTIPART_EML = b"""\
Message-ID: <test-002@example.com>
From: alice@example.com
To: bob@example.com
Cc: carol@example.com
Subject: Multipart Test
Date: Fri, 11 Jul 2025 09:00:00 -0500
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Plain text body here.
--boundary123
Content-Type: text/html; charset="utf-8"

<html><body><p>HTML body here.</p></body></html>
--boundary123--
"""

MISSING_FROM_EML = b"""\
To: bob@example.com
Subject: No sender
Date: Thu, 10 Jul 2025 14:30:00 +0000
Content-Type: text/plain

Body text.
"""

MISSING_TO_EML = b"""\
From: alice@example.com
Subject: No recipient
Date: Thu, 10 Jul 2025 14:30:00 +0000
Content-Type: text/plain

Body text.
"""

MINIMAL_EML = b"""\
From: sender@example.com
To: receiver@example.com

Minimal body.
"""


# ---------------------------------------------------------------------------
# Unit tests for parse_eml()
# ---------------------------------------------------------------------------

class TestParseEmlSimple:
    """Tests for a simple single-part .eml."""

    def test_extracts_message_id(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert result.message_id == "<test-001@example.com>"

    def test_extracts_subject(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert result.subject == "Test Email"

    def test_extracts_sender(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert result.sender == "alice@example.com"

    def test_extracts_recipient(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert result.recipient == "bob@example.com"

    def test_extracts_plain_body(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert "Hello Bob" in result.body_text

    def test_html_body_is_none(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert result.body_html is None

    def test_cc_is_none(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert result.cc is None

    def test_received_at_parsed(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert result.received_at is not None
        assert result.received_at.year == 2025
        assert result.received_at.month == 7
        assert result.received_at.day == 10

    def test_raw_headers_present(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert "Message-ID" in result.raw_headers
        assert "From:" in result.raw_headers

    def test_returns_parsed_email_type(self):
        result = parse_eml(VALID_SIMPLE_EML)
        assert isinstance(result, ParsedEmail)


class TestParseEmlMultipart:
    """Tests for a multipart .eml."""

    def test_extracts_plain_text(self):
        result = parse_eml(VALID_MULTIPART_EML)
        assert "Plain text body" in result.body_text

    def test_extracts_html(self):
        result = parse_eml(VALID_MULTIPART_EML)
        assert "<html>" in result.body_html

    def test_extracts_cc(self):
        result = parse_eml(VALID_MULTIPART_EML)
        assert result.cc == "carol@example.com"

    def test_received_at_timezone_normalised(self):
        result = parse_eml(VALID_MULTIPART_EML)
        assert result.received_at is not None
        # Original is -0500, should be normalised to UTC (14:00 UTC)
        assert result.received_at.hour == 14


class TestParseEmlErrors:
    """Tests for malformed .eml files."""

    def test_missing_from_raises(self):
        with pytest.raises(ValueError, match="From"):
            parse_eml(MISSING_FROM_EML)

    def test_missing_to_raises(self):
        with pytest.raises(ValueError, match="To"):
            parse_eml(MISSING_TO_EML)

    def test_empty_bytes_raises(self):
        with pytest.raises(ValueError):
            parse_eml(b"")

    def test_garbage_bytes_raises(self):
        with pytest.raises(ValueError):
            parse_eml(b"\x00\x01\x02\x03\x04\x05")


class TestParseEmlMinimal:
    """Tests for a minimal valid .eml (no Message-ID, no Date, no Subject)."""

    def test_minimal_parses(self):
        result = parse_eml(MINIMAL_EML)
        assert result.sender == "sender@example.com"
        assert result.recipient == "receiver@example.com"

    def test_minimal_message_id_none(self):
        result = parse_eml(MINIMAL_EML)
        assert result.message_id is None

    def test_minimal_subject_none(self):
        result = parse_eml(MINIMAL_EML)
        assert result.subject is None

    def test_minimal_received_at_none(self):
        result = parse_eml(MINIMAL_EML)
        assert result.received_at is None
