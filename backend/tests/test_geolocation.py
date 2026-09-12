"""Comprehensive tests for the IP geolocation layer."""

import json
import pytest

from geolocation import (
    GeolocationResult,
    IPGeolocationProvider,
    NoOpGeolocationProvider,
    IPWhoProvider,
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

    def test_returns_ipwho_by_default(self, monkeypatch):
        monkeypatch.delenv("GEOLOCATION_PROVIDER", raising=False)
        p = get_geolocation_provider()
        assert isinstance(p, IPWhoProvider)
        assert p.name == "ipwho"

    def test_returns_noop_when_configured(self, monkeypatch):
        monkeypatch.setenv("GEOLOCATION_PROVIDER", "noop")
        p = get_geolocation_provider()
        assert isinstance(p, NoOpGeolocationProvider)
        assert p.name == "noop"

    def test_returns_provider_interface(self, monkeypatch):
        monkeypatch.delenv("GEOLOCATION_PROVIDER", raising=False)
        p = get_geolocation_provider()
        assert isinstance(p, IPGeolocationProvider)

    def test_is_callable_multiple_times(self, monkeypatch):
        """Factory can be called repeatedly without error."""
        monkeypatch.delenv("GEOLOCATION_PROVIDER", raising=False)
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


# ---------------------------------------------------------------------------
# Tests: geolocate_ips service function
# ---------------------------------------------------------------------------

from geolocation import geolocate_ips, GeolocationBatchResult
from ioc_extractor import IOC, IOCExtractionResult


def _ioc(ioc_type, value):
    return IOC(ioc_type=ioc_type, value=value, source="body_text", context="test")


def _ioc_result(iocs):
    stats = {}
    for i in iocs:
        stats[i.ioc_type] = stats.get(i.ioc_type, 0) + 1
    return IOCExtractionResult(iocs=iocs, stats=stats)


class TestGeolocateIpsService:
    """geolocate_ips() service function behavior."""

    def test_returns_batch_result(self):
        result = geolocate_ips(_ioc_result([_ioc("ipv4", "8.8.8.8")]))
        assert isinstance(result, GeolocationBatchResult)

    def test_provider_name(self):
        result = geolocate_ips(_ioc_result([_ioc("ipv4", "8.8.8.8")]))
        assert result.provider == "noop"

    def test_ipv4_geolocated(self):
        result = geolocate_ips(_ioc_result([_ioc("ipv4", "8.8.8.8")]))
        assert len(result.results) == 1
        assert result.results[0].ip == "8.8.8.8"

    def test_ipv6_geolocated(self):
        result = geolocate_ips(_ioc_result([
            _ioc("ipv6", "2607:f8b0:4004:800::200e"),
        ]))
        assert len(result.results) == 1

    def test_domain_skipped(self):
        result = geolocate_ips(_ioc_result([_ioc("domain", "evil.test")]))
        assert len(result.results) == 0

    def test_email_skipped(self):
        result = geolocate_ips(_ioc_result([_ioc("email", "bad@evil.test")]))
        assert len(result.results) == 0

    def test_url_skipped(self):
        result = geolocate_ips(_ioc_result([
            _ioc("url", "http://evil.test/payload"),
        ]))
        assert len(result.results) == 0

    def test_mixed_only_ips(self):
        result = geolocate_ips(_ioc_result([
            _ioc("ipv4", "8.8.8.8"),
            _ioc("domain", "evil.test"),
            _ioc("email", "bad@evil.test"),
            _ioc("url", "http://evil.test"),
            _ioc("ipv6", "2001:4860:4860::8888"),
        ]))
        assert len(result.results) == 2
        ips = {r.ip for r in result.results}
        assert "8.8.8.8" in ips
        assert "2001:4860:4860::8888" in ips

    def test_deduplication(self):
        result = geolocate_ips(_ioc_result([
            _ioc("ipv4", "8.8.8.8"),
            _ioc("ipv4", "8.8.8.8"),
            _ioc("ipv4", "8.8.8.8"),
        ]))
        assert len(result.results) == 1

    def test_empty_iocs(self):
        result = geolocate_ips(_ioc_result([]))
        assert len(result.results) == 0
        assert result.stats == {}

    def test_private_ip_has_error(self):
        result = geolocate_ips(_ioc_result([_ioc("ipv4", "10.0.0.1")]))
        assert len(result.results) == 1
        assert result.results[0].error is not None

    def test_private_ip_stats(self):
        result = geolocate_ips(_ioc_result([_ioc("ipv4", "10.0.0.1")]))
        assert result.stats.get("error", 0) == 1

    def test_public_ip_stats(self):
        result = geolocate_ips(_ioc_result([_ioc("ipv4", "8.8.8.8")]))
        assert result.stats.get("ok", 0) == 1

    def test_provider_exception_caught(self):
        """Provider exception → error result, no crash."""

        class _CrashProvider(IPGeolocationProvider):
            @property
            def name(self):
                return "crash"
            def geolocate(self, ip):
                raise RuntimeError("boom")

        result = geolocate_ips(
            _ioc_result([_ioc("ipv4", "8.8.8.8")]),
            provider=_CrashProvider(),
        )
        assert len(result.results) == 1
        assert result.results[0].error is not None
        assert "boom" in result.results[0].error

    def test_default_provider_is_noop(self):
        """No explicit provider → NoOp."""
        result = geolocate_ips(_ioc_result([_ioc("ipv4", "8.8.8.8")]))
        assert result.provider == "noop"


# ===========================================================================
# IPWho provider tests
# ===========================================================================

class _FakeHTTPResponse:
    """Minimal httpx.Response stand-in."""

    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text or json.dumps(json_data or {})

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


def _ipwho_success(
    ip="8.8.8.8",
    country="United States",
    country_code="US",
    city="Mountain View",
    region="California",
    latitude=37.386,
    longitude=-122.0838,
    asn=15169,
    org="Google LLC",
    isp="Google LLC",
):
    """Build a mock IPWho success response."""
    return {
        "success": True,
        "ip": ip,
        "type": "IPv4",
        "country": country,
        "country_code": country_code,
        "city": city,
        "region": region,
        "latitude": latitude,
        "longitude": longitude,
        "connection": {
            "asn": asn,
            "org": org,
            "isp": isp,
        },
        # Extra fields that should NOT appear in our result
        "continent": "North America",
        "continent_code": "NA",
        "timezone": {"id": "America/Los_Angeles"},
        "flag": {"emoji": "🇺🇸"},
    }


# ---------------------------------------------------------------------------
# Tests: IPWho successful responses
# ---------------------------------------------------------------------------

class TestIPWhoSuccessIPv4:
    """Successful IPv4 geolocation."""

    def test_basic_fields(self, monkeypatch):
        resp = _FakeHTTPResponse(200, _ipwho_success())
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        p = IPWhoProvider()
        r = p.geolocate("8.8.8.8")
        assert r.ip == "8.8.8.8"
        assert r.country == "United States"
        assert r.country_code == "US"
        assert r.city == "Mountain View"
        assert r.region == "California"
        assert r.provider == "ipwho"
        assert r.error is None

    def test_coordinates(self, monkeypatch):
        resp = _FakeHTTPResponse(200, _ipwho_success())
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.latitude == pytest.approx(37.386)
        assert r.longitude == pytest.approx(-122.0838)

    def test_asn_and_org(self, monkeypatch):
        resp = _FakeHTTPResponse(200, _ipwho_success())
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.asn == "15169"
        assert r.organization == "Google LLC"

    def test_no_full_upstream_response(self, monkeypatch):
        """GeolocationResult should NOT contain the full upstream response."""
        resp = _FakeHTTPResponse(200, _ipwho_success())
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        # The result is a dataclass, not a dict with raw response
        assert not hasattr(r, "raw_data")
        # Ensure extra fields like "continent", "flag" are not present
        result_str = str(r)
        assert "continent" not in result_str
        assert "flag" not in result_str


class TestIPWhoSuccessIPv6:
    """Successful IPv6 geolocation."""

    def test_ipv6_basic(self, monkeypatch):
        resp = _FakeHTTPResponse(200, _ipwho_success(
            ip="2001:4860:4860::8888",
            country="United States",
            country_code="US",
            city="Mountain View",
            region="California",
        ))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("2001:4860:4860::8888")
        assert r.ip == "2001:4860:4860::8888"
        assert r.country == "United States"
        assert r.error is None


# ---------------------------------------------------------------------------
# Tests: IPWho error handling
# ---------------------------------------------------------------------------

class TestIPWhoAPIFailures:
    """HTTP and API-level failures."""

    def test_http_429(self, monkeypatch):
        resp = _FakeHTTPResponse(429)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is not None
        assert "429" in r.error
        assert r.provider == "ipwho"

    def test_http_500(self, monkeypatch):
        resp = _FakeHTTPResponse(500)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is not None
        assert "500" in r.error

    def test_timeout(self, monkeypatch):
        import httpx
        def _raise(*a, **kw):
            raise httpx.ReadTimeout("timed out")
        monkeypatch.setattr("httpx.get", _raise)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is not None
        assert "timed out" in r.error.lower() or "lookup failed" in r.error.lower()

    def test_connection_error(self, monkeypatch):
        def _raise(*a, **kw):
            raise ConnectionError("DNS failure")
        monkeypatch.setattr("httpx.get", _raise)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is not None
        assert r.provider == "ipwho"

    def test_malformed_json(self, monkeypatch):
        resp = _FakeHTTPResponse(200, json_data=None, text="not json")
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is not None
        assert "JSON" in r.error or "lookup failed" in r.error

    def test_success_false(self, monkeypatch):
        """IPWho returns success:false for invalid lookups."""
        resp = _FakeHTTPResponse(200, {
            "success": False,
            "message": "Invalid IP address",
        })
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is not None
        assert "Invalid IP" in r.error


# ---------------------------------------------------------------------------
# Tests: IPWho missing/null fields
# ---------------------------------------------------------------------------

class TestIPWhoMissingFields:
    """Missing or null fields should not crash."""

    def test_missing_connection(self, monkeypatch):
        data = _ipwho_success()
        del data["connection"]
        resp = _FakeHTTPResponse(200, data)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is None
        assert r.asn is None
        assert r.organization is None
        assert r.country == "United States"

    def test_null_fields(self, monkeypatch):
        data = _ipwho_success()
        data["city"] = None
        data["region"] = None
        data["connection"]["asn"] = None
        data["connection"]["org"] = None
        data["connection"]["isp"] = None
        resp = _FakeHTTPResponse(200, data)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is None
        assert r.city is None
        assert r.region is None
        assert r.asn is None
        assert r.organization is None

    def test_empty_string_fields(self, monkeypatch):
        data = _ipwho_success()
        data["country"] = ""
        data["country_code"] = ""
        resp = _FakeHTTPResponse(200, data)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        r = IPWhoProvider().geolocate("8.8.8.8")
        assert r.error is None
        # Empty strings should become None
        assert r.country is None
        assert r.country_code is None


# ---------------------------------------------------------------------------
# Tests: IPWho non-public IP handling
# ---------------------------------------------------------------------------

class TestIPWhoNonPublicIPs:
    """Non-public IPs handled locally without network call."""

    def test_private_ip(self, monkeypatch):
        # Should NOT call httpx at all
        def _should_not_call(*a, **kw):
            raise AssertionError("httpx should not be called for private IP")
        monkeypatch.setattr("httpx.get", _should_not_call)
        r = IPWhoProvider().geolocate("192.168.1.1")
        assert r.error is not None
        assert "private" in r.error.lower()
        assert r.provider == "ipwho"

    def test_loopback(self, monkeypatch):
        def _should_not_call(*a, **kw):
            raise AssertionError("should not call")
        monkeypatch.setattr("httpx.get", _should_not_call)
        r = IPWhoProvider().geolocate("127.0.0.1")
        assert r.error is not None
        assert "loopback" in r.error.lower()

    def test_link_local(self, monkeypatch):
        def _should_not_call(*a, **kw):
            raise AssertionError("should not call")
        monkeypatch.setattr("httpx.get", _should_not_call)
        r = IPWhoProvider().geolocate("169.254.1.1")
        assert r.error is not None
        assert "link-local" in r.error.lower()

    def test_multicast(self, monkeypatch):
        def _should_not_call(*a, **kw):
            raise AssertionError("should not call")
        monkeypatch.setattr("httpx.get", _should_not_call)
        r = IPWhoProvider().geolocate("224.0.0.1")
        assert r.error is not None
        assert "multicast" in r.error.lower()

    def test_invalid_ip(self, monkeypatch):
        def _should_not_call(*a, **kw):
            raise AssertionError("should not call")
        monkeypatch.setattr("httpx.get", _should_not_call)
        r = IPWhoProvider().geolocate("not-an-ip")
        assert r.error is not None
        assert "not a valid" in r.error.lower()


# ---------------------------------------------------------------------------
# Tests: IPWho provider interface
# ---------------------------------------------------------------------------

class TestIPWhoProviderInterface:
    """IPWhoProvider conforms to IPGeolocationProvider."""

    def test_is_provider_instance(self):
        assert isinstance(IPWhoProvider(), IPGeolocationProvider)

    def test_name(self):
        assert IPWhoProvider().name == "ipwho"

    def test_supports_ipv4(self):
        assert IPWhoProvider().supports("8.8.8.8")

    def test_supports_ipv6(self):
        assert IPWhoProvider().supports("2001:4860:4860::8888")

def test_geolocate_ips_limit():
    from geolocation import geolocate_ips, IPGeolocationProvider, GeolocationResult
    from ioc_extractor import IOCExtractionResult, IOC
    
    class FakeGeoProvider(IPGeolocationProvider):
        @property
        def name(self): return "fakegeo"
        def geolocate(self, ip):
            return GeolocationResult(ip=ip, provider="fakegeo")
            
    iocs = [IOC("ipv4", f"2.2.2.{i}", "body", "ctx") for i in range(20)]
    result = geolocate_ips(IOCExtractionResult(iocs), FakeGeoProvider())
    
    assert len(result.results) == 20
    ok = [r for r in result.results if r.error is None]
    skipped = [r for r in result.results if r.error == "Skipped due to MAX_GEOLOCATION_IPS limit"]
    
    assert len(ok) == 15
    assert len(skipped) == 5
