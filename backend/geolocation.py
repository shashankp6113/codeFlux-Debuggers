"""Provider-agnostic IP geolocation layer for MailForensics AI.

Defines a clean architecture for resolving geographic and network
metadata for IP addresses.  This module contains:

- A ``GeolocationResult`` dataclass for per-IP results.
- An abstract ``IPGeolocationProvider`` interface that future provider
  implementations (e.g. MaxMind, ip-api) can subclass.
- A deterministic ``NoOpGeolocationProvider`` for dev/testing.
- An ``IPWhoProvider`` backed by the free ipwho.is API.
- A ``get_geolocation_provider()`` factory for provider selection.
- A helper ``is_public_ip()`` that validates and filters non-public
  addresses using Python's standard-library ``ipaddress`` module.
"""

from __future__ import annotations

import abc
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class GeolocationResult:
    """Geolocation and network metadata for a single IP address.

    Attributes:
        ip:            The IP address that was looked up.
        country:       Country name (e.g. ``"United States"``).
                       ``None`` when unavailable.
        country_code:  ISO 3166-1 alpha-2 code (e.g. ``"US"``).
                       ``None`` when unavailable.
        city:          City name. ``None`` when unavailable.
        region:        Region / state / province name.
                       ``None`` when unavailable.
        latitude:      Geographic latitude. ``None`` when unavailable.
        longitude:     Geographic longitude. ``None`` when unavailable.
        asn:           Autonomous System Number (e.g. ``"AS15169"``).
                       ``None`` when unavailable.
        organization:  Owning organisation (e.g. ``"Google LLC"``).
                       ``None`` when unavailable.
        provider:      Name of the provider that produced this result.
        error:         Human-readable error message if the lookup failed.
                       ``None`` on success.
    """

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


# ---------------------------------------------------------------------------
# IP validation helpers
# ---------------------------------------------------------------------------

def is_public_ip(ip_str: str) -> bool:
    """Return whether *ip_str* is a valid, publicly geolocatable IP address.

    Returns ``False`` for:

    - Syntactically invalid strings
    - Private / RFC 1918 addresses (``10.x``, ``172.16-31.x``, ``192.168.x``)
    - Loopback (``127.x``, ``::1``)
    - Link-local (``169.254.x``, ``fe80::``)
    - Multicast (``224.x``–``239.x``, ``ff00::``)
    - Reserved / unspecified (``0.0.0.0``, ``::``, etc.)

    Uses Python's standard-library ``ipaddress`` module — **no regex**.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False

    # Explicit checks needed because Python 3.9's is_global returns
    # True for multicast addresses.
    if addr.is_multicast or addr.is_private or addr.is_loopback:
        return False
    if addr.is_link_local or addr.is_reserved or addr.is_unspecified:
        return False

    return True


def _non_public_reason(ip_str: str) -> Optional[str]:
    """Return a human-readable reason why *ip_str* is not publicly geolocatable.

    Returns ``None`` if the address **is** public and valid.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return f"'{ip_str}' is not a valid IP address"

    if addr.is_loopback:
        return f"{ip_str} is a loopback address"
    if addr.is_link_local:
        return f"{ip_str} is a link-local address"
    if addr.is_multicast:
        return f"{ip_str} is a multicast address"
    if addr.is_private:
        return f"{ip_str} is a private address"
    if addr.is_reserved:
        return f"{ip_str} is a reserved address"
    if addr.is_unspecified:
        return f"{ip_str} is an unspecified address"
    if not addr.is_global:
        return f"{ip_str} is not a globally routable address"

    return None


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------

class IPGeolocationProvider(abc.ABC):
    """Abstract base class for IP geolocation providers.

    Subclass this to integrate a new provider.  At minimum you must
    implement :pyattr:`name` and :pymeth:`geolocate`.

    Example::

        class MaxMindProvider(IPGeolocationProvider):
            @property
            def name(self) -> str:
                return "maxmind"

            def geolocate(self, ip: str) -> GeolocationResult:
                # … look up IP …
                return GeolocationResult(
                    ip=ip,
                    country="United States",
                    country_code="US",
                    provider=self.name,
                )
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique human-readable provider name (e.g. ``"maxmind"``)."""
        ...

    @abc.abstractmethod
    def geolocate(self, ip: str) -> GeolocationResult:
        """Look up geolocation for a single IP address.

        Must **not** raise exceptions — return a ``GeolocationResult``
        with a populated ``error`` field instead.

        The implementation should call :func:`is_public_ip` (or
        equivalent validation) and return an appropriate error for
        non-public addresses rather than attempting a lookup.

        Args:
            ip: An IPv4 or IPv6 address string.

        Returns:
            A ``GeolocationResult`` for this IP.
        """
        ...

    def supports(self, ip: str) -> bool:
        """Return whether this provider can geolocate *ip*.

        The default implementation accepts valid IPv4 and IPv6
        addresses (using ``ipaddress.ip_address``).  Override to
        restrict.
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False


# ---------------------------------------------------------------------------
# No-op / mock provider
# ---------------------------------------------------------------------------

class NoOpGeolocationProvider(IPGeolocationProvider):
    """Deterministic provider that makes **no** network requests.

    Returns a ``GeolocationResult`` with no location claims for public
    IPs, and an appropriate error for non-public or invalid IPs.
    Useful for development and testing.
    """

    @property
    def name(self) -> str:
        return "noop"

    def geolocate(self, ip: str) -> GeolocationResult:
        # Validate the address
        reason = _non_public_reason(ip)
        if reason is not None:
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error=reason,
            )

        # Valid public IP — return empty geolocation (no claims)
        return GeolocationResult(
            ip=ip,
            provider=self.name,
        )


# ---------------------------------------------------------------------------
# IPWho provider — free, no API key required
# ---------------------------------------------------------------------------

class IPWhoProvider(IPGeolocationProvider):
    """Geolocation provider backed by the free ipwho.is API.

    Supports IPv4 and IPv6.  No API key required.
    Non-public IPs are handled locally without making a network request.

    Only the fields supported by ``GeolocationResult`` are extracted
    from the upstream response — the full API response is never stored.
    """

    _BASE_URL = "https://ipwho.is"
    _TIMEOUT = 10  # seconds

    @property
    def name(self) -> str:
        return "ipwho"

    def geolocate(self, ip: str) -> GeolocationResult:
        # Handle non-public IPs locally — no network call needed
        reason = _non_public_reason(ip)
        if reason is not None:
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error=reason,
            )

        try:
            return self._do_lookup(ip)
        except Exception as exc:
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error=f"IPWho lookup failed: {exc}",
            )

    def _do_lookup(self, ip: str) -> GeolocationResult:
        import httpx

        url = f"{self._BASE_URL}/{ip}"
        resp = httpx.get(url, timeout=self._TIMEOUT)

        if resp.status_code == 429:
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error="IPWho rate limit exceeded (HTTP 429)",
            )

        if resp.status_code != 200:
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error=f"IPWho API error (HTTP {resp.status_code})",
            )

        try:
            data = resp.json()
        except Exception:
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error="IPWho returned invalid JSON",
            )

        if not isinstance(data, dict):
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error="IPWho returned unexpected response format",
            )

        # IPWho returns success: false for invalid/non-routable IPs
        if not data.get("success", False):
            msg = data.get("message", "Unknown error")
            return GeolocationResult(
                ip=ip,
                provider=self.name,
                error=f"IPWho: {msg}",
            )

        # Extract only the fields our GeolocationResult supports
        asn_val = None
        connection = data.get("connection")
        if isinstance(connection, dict):
            raw_asn = connection.get("asn")
            if raw_asn is not None:
                asn_val = str(raw_asn) if not str(raw_asn).startswith("AS") else str(raw_asn)
            organization = connection.get("org") or connection.get("isp")
        else:
            organization = None

        return GeolocationResult(
            ip=ip,
            country=data.get("country") or None,
            country_code=data.get("country_code") or None,
            city=data.get("city") or None,
            region=data.get("region") or None,
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            asn=asn_val,
            organization=organization or None,
            provider=self.name,
        )


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

def get_geolocation_provider() -> IPGeolocationProvider:
    """Return the best available geolocation provider.

    Returns :class:`IPWhoProvider` by default.  Set the
    ``GEOLOCATION_PROVIDER`` environment variable to ``"noop"``
    to force :class:`NoOpGeolocationProvider` for testing.
    """
    import os
    choice = os.environ.get("GEOLOCATION_PROVIDER", "").strip().lower()
    if choice == "noop":
        return NoOpGeolocationProvider()
    return IPWhoProvider()


# ---------------------------------------------------------------------------
# Geolocation service
# ---------------------------------------------------------------------------

_IP_IOC_TYPES = frozenset({"ipv4", "ipv6"})


@dataclass
class GeolocationBatchResult:
    """Aggregated geolocation results for an IOC extraction batch.

    Attributes:
        results:   One ``GeolocationResult`` per unique IP IOC.
        stats:     Counts keyed by outcome (e.g. ``{"ok": 2, "error": 1}``).
        provider:  Name of the provider used for this batch.
    """

    results: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    provider: str = ""


def geolocate_ips(
    ioc_result,
    provider: Optional[IPGeolocationProvider] = None,
) -> GeolocationBatchResult:
    """Geolocate IP IOCs extracted from an email.

    Iterates over the IOCs in *ioc_result*, selecting only ``ipv4``
    and ``ipv6`` types, deduplicates by normalised value, and calls
    *provider* for each unique IP.

    If *provider* is ``None`` the :class:`NoOpGeolocationProvider` is
    used.

    Provider exceptions are caught and recorded in the
    ``GeolocationResult.error`` field — they never crash the pipeline.

    Args:
        ioc_result: An ``IOCExtractionResult`` from the IOC extractor.
        provider:   An ``IPGeolocationProvider`` implementation.

    Returns:
        A ``GeolocationBatchResult`` with per-IP results and stats.
    """
    if provider is None:
        provider = NoOpGeolocationProvider()

    MAX_GEOLOCATION_IPS = 15
    results = []
    seen: dict = {}

    for ioc in ioc_result.iocs:
        if ioc.ioc_type not in _IP_IOC_TYPES:
            continue

        key = ioc.value.lower()
        if key in seen:
            continue
        
        if len(seen) >= MAX_GEOLOCATION_IPS:
            results.append(GeolocationResult(
                ip=ioc.value,
                provider=provider.name,
                error="Skipped due to MAX_GEOLOCATION_IPS limit",
            ))
            continue
            
        seen[key] = None

        try:
            result = provider.geolocate(ioc.value)
        except Exception as exc:
            result = GeolocationResult(
                ip=ioc.value,
                provider=provider.name,
                error=f"Geolocation error: {exc}",
            )

        results.append(result)

    # Build stats
    stats: dict = {}
    for r in results:
        key = "error" if r.error else "ok"
        stats[key] = stats.get(key, 0) + 1

    return GeolocationBatchResult(
        results=results,
        stats=stats,
        provider=provider.name,
    )
