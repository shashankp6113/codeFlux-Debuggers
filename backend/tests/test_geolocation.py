"""Comprehensive tests for the IP geolocation layer."""

import pytest

from geolocation import (
    GeolocationResult,
    IPGeolocationProvider,
    NoOpGeolocationProvider,
    get_geolocation_provider,
    is_public_ip,
    _non_public_reason,
)


# ---------------------------------------------------------------------------
# Tests: is_public_ip validation
# ---------------------------------------------------------------------------

class TestIsPublicIP:
    """IP validation using the ipaddress module."""

    # --- Valid public IPv4 ---

    def test_public_ipv4(self):
        assert is_public_ip("8.8.8.8") is True

    def test_public_ipv4_alt(self):
        assert is_public_ip("1.1.1.1") is True

    # --- Valid public IPv6 ---

    def test_public_ipv6(self):
        assert is_public_ip("2607:f8b0:4004:800::200e") is True

    def test_public_ipv6_short(self):
        assert is_public_ip("2001:4860:4860::8888") is True

    # --- Invalid strings ---

    def test_invalid_string(self):
        assert is_public_ip("not-an-ip") is False

    def test_empty_string(self):
        assert is_public_ip("") is False

    def test_none_value(self):
        assert is_public_ip(None) is False

    def test_domain_not_ip(self):
        assert is_public_ip("example.com") is False

    # --- Private IPv4 (RFC 1918) ---

    def test_private_10(self):
        assert is_public_ip("10.0.0.1") is False

    def test_private_172(self):
        assert is_public_ip("172.16.0.1") is False

    def test_private_192(self):
        assert is_public_ip("192.168.1.1") is False

    # --- Private IPv6 ---

    def test_private_ipv6_ula(self):
        """Unique local address (fc00::/7)."""
        assert is_public_ip("fd12:3456:789a::1") is False

    # --- Loopback ---

    def test_loopback_ipv4(self):
        assert is_public_ip("127.0.0.1") is False

    def test_loopback_ipv6(self):
        assert is_public_ip("::1") is False

    # --- Link-local ---

    def test_link_local_ipv4(self):
        assert is_public_ip("169.254.1.1") is False

    def test_link_local_ipv6(self):
        assert is_public_ip("fe80::1") is False

    # --- Multicast ---

    def test_multicast_ipv4(self):
        assert is_public_ip("224.0.0.1") is False

    def test_multicast_ipv6(self):
        assert is_public_ip("ff02::1") is False

    # --- Reserved / unspecified ---

    def test_unspecified_ipv4(self):
        assert is_public_ip("0.0.0.0") is False

    def test_unspecified_ipv6(self):
        assert is_public_ip("::") is False

    def test_reserved_ipv4(self):
        """Documentation range 192.0.2.0/24 is reserved."""
        assert is_public_ip("192.0.2.1") is False

    def test_reserved_ipv6(self):
        """Documentation range 2001:db8::/32 is reserved."""
        assert is_public_ip("2001:db8::1") is False


# ---------------------------------------------------------------------------
# Tests: _non_public_reason messages
# ---------------------------------------------------------------------------

class TestNonPublicReason:
    """Human-readable reason strings for non-public addresses."""

    def test_public_returns_none(self):
        assert _non_public_reason("8.8.8.8") is None

    def test_invalid_returns_reason(self):
        reason = _non_public_reason("not-an-ip")
        assert reason is not None
        assert "not a valid" in reason.lower()

    def test_private_returns_reason(self):
        reason = _non_public_reason("10.0.0.1")
        assert reason is not None
        assert "private" in reason.lower()

    def test_loopback_returns_reason(self):
        reason = _non_public_reason("127.0.0.1")
        assert reason is not None
        assert "loopback" in reason.lower()

    def test_link_local_returns_reason(self):
        reason = _non_public_reason("169.254.1.1")
        assert reason is not None
        assert "link-local" in reason.lower()

    def test_multicast_returns_reason(self):
        reason = _non_public_reason("224.0.0.1")
        assert reason is not None
        assert "multicast" in reason.lower()

    def test_unspecified_returns_reason(self):
        reason = _non_public_reason("0.0.0.0")
        assert reason is not None

    def test_reserved_returns_reason(self):
        reason = _non_public_reason("192.0.2.1")
        assert reason is not None


# ---------------------------------------------------------------------------
# Tests: NoOpGeolocationProvider
# ---------------------------------------------------------------------------

class TestNoOpProviderBasics:
    """NoOpGeolocationProvider name, supports, and basic behavior."""

    def test_name(self):
        p = NoOpGeolocationProvider()
        assert p.name == "noop"

    def test_supports_valid_ipv4(self):
        p = NoOpGeolocationProvider()
        assert p.supports("8.8.8.8") is True

    def test_supports_valid_ipv6(self):
        p = NoOpGeolocationProvider()
        assert p.supports("2607:f8b0:4004:800::200e") is True

    def test_supports_private_ipv4(self):
        """supports() validates syntax, not public-ness."""
        p = NoOpGeolocationProvider()
        assert p.supports("10.0.0.1") is True

    def test_does_not_support_invalid(self):
        p = NoOpGeolocationProvider()
        assert p.supports("not-an-ip") is False

    def test_does_not_support_empty(self):
        p = NoOpGeolocationProvider()
        assert p.supports("") is False


class TestNoOpPublicIP:
    """NoOp results for valid public IP addresses."""

    def test_public_ipv4_no_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert result.error is None

    def test_public_ipv4_ip_preserved(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert result.ip == "8.8.8.8"

    def test_public_ipv4_provider(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert result.provider == "noop"

    def test_public_ipv4_no_country(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert result.country is None
        assert result.country_code is None

    def test_public_ipv4_no_city(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert result.city is None
        assert result.region is None

    def test_public_ipv4_no_coordinates(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert result.latitude is None
        assert result.longitude is None

    def test_public_ipv4_no_asn(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert result.asn is None
        assert result.organization is None

    def test_public_ipv6_no_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("2607:f8b0:4004:800::200e")
        assert result.error is None
        assert result.provider == "noop"

    def test_returns_geolocation_result(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("8.8.8.8")
        assert isinstance(result, GeolocationResult)


class TestNoOpNonPublicIP:
    """NoOp results for non-public IP addresses — error with reason."""

    def test_private_ipv4_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("10.0.0.1")
        assert result.error is not None
        assert "private" in result.error.lower()

    def test_private_ipv4_ip_preserved(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("10.0.0.1")
        assert result.ip == "10.0.0.1"

    def test_private_ipv4_provider(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("10.0.0.1")
        assert result.provider == "noop"

    def test_loopback_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("127.0.0.1")
        assert result.error is not None
        assert "loopback" in result.error.lower()

    def test_loopback_ipv6_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("::1")
        assert result.error is not None
        assert "loopback" in result.error.lower()

    def test_link_local_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("169.254.1.1")
        assert result.error is not None
        assert "link-local" in result.error.lower()

    def test_multicast_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("224.0.0.1")
        assert result.error is not None
        assert "multicast" in result.error.lower()

    def test_unspecified_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("0.0.0.0")
        assert result.error is not None

    def test_reserved_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("192.0.2.1")
        assert result.error is not None

    def test_invalid_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("not-an-ip")
        assert result.error is not None
        assert "not a valid" in result.error.lower()

    def test_private_ipv6_has_error(self):
        p = NoOpGeolocationProvider()
        result = p.geolocate("fd12:3456:789a::1")
        assert result.error is not None


# ---------------------------------------------------------------------------
# Tests: Provider factory
# ---------------------------------------------------------------------------

class TestGetGeolocationProvider:
    """get_geolocation_provider() factory."""

    def test_returns_noop(self):
        p = get_geolocation_provider()
        assert isinstance(p, NoOpGeolocationProvider)

    def test_returns_provider_interface(self):
        p = get_geolocation_provider()
        assert isinstance(p, IPGeolocationProvider)

    def test_name_is_noop(self):
        p = get_geolocation_provider()
        assert p.name == "noop"

    def test_is_callable_multiple_times(self):
        """Factory can be called repeatedly without error."""
        p1 = get_geolocation_provider()
        p2 = get_geolocation_provider()
        assert p1.name == p2.name


# ---------------------------------------------------------------------------
# Tests: No network requests
# ---------------------------------------------------------------------------

class TestNoNetworkRequests:
    """Verify that the NoOp provider makes no network calls."""

    def test_geolocate_does_not_import_httpx(self, monkeypatch):
        """If httpx were imported and used, this would fail."""
        import sys
        # Remove httpx from sys.modules to detect fresh imports
        original = sys.modules.pop("httpx", None)
        try:
            p = NoOpGeolocationProvider()
            p.geolocate("8.8.8.8")
            # httpx should NOT have been imported
            assert "httpx" not in sys.modules or sys.modules["httpx"] is original
        finally:
            if original is not None:
                sys.modules["httpx"] = original

    def test_geolocate_does_not_import_requests(self, monkeypatch):
        import sys
        original = sys.modules.pop("requests", None)
        try:
            p = NoOpGeolocationProvider()
            p.geolocate("8.8.8.8")
            assert "requests" not in sys.modules or sys.modules["requests"] is original
        finally:
            if original is not None:
                sys.modules["requests"] = original


# ---------------------------------------------------------------------------
# Tests: GeolocationResult dataclass
# ---------------------------------------------------------------------------

class TestGeolocationResultDataclass:
    """GeolocationResult field defaults and structure."""

    def test_minimal_construction(self):
        r = GeolocationResult(ip="1.2.3.4")
        assert r.ip == "1.2.3.4"
        assert r.country is None
        assert r.error is None
        assert r.provider == ""

    def test_full_construction(self):
        r = GeolocationResult(
            ip="8.8.8.8",
            country="United States",
            country_code="US",
            city="Mountain View",
            region="California",
            latitude=37.386,
            longitude=-122.084,
            asn="AS15169",
            organization="Google LLC",
            provider="test",
            error=None,
        )
        assert r.country == "United States"
        assert r.latitude == 37.386
        assert r.asn == "AS15169"

    def test_error_construction(self):
        r = GeolocationResult(ip="10.0.0.1", provider="test", error="private")
        assert r.error == "private"
        assert r.country is None
