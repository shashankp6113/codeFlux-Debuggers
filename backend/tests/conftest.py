"""Shared pytest configuration for backend tests.

Sets environment defaults that must be present before any test module
imports application code.
"""

import os

# Use NoOp geolocation provider during tests to avoid real network
# calls to ipwho.is.  Individual tests that need to verify the real
# provider can override this via monkeypatch.
os.environ.setdefault("GEOLOCATION_PROVIDER", "noop")
