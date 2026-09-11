
import os
os.environ["VIRUSTOTAL_API_KEY"] = ""
"""Shared pytest configuration for backend tests.

Sets environment defaults that must be present before any test module
imports application code.
"""

import os

# Use NoOp geolocation provider during tests to avoid real network
# calls to ipwho.is.  Individual tests that need to verify the real
# provider can override this via monkeypatch.
import os
os.environ.setdefault("GEOLOCATION_PROVIDER", "noop")


import pytest
import httpx

@pytest.fixture(autouse=True)
def _prevent_live_gemini_calls(monkeypatch):
    """Ensure no test makes a real network call to the Gemini API."""
    original_post = httpx.post
    
    def _safe_post(url, *args, **kwargs):
        if "generativelanguage.googleapis.com" in str(url):
            raise RuntimeError("Tests must not call the live Gemini API!")
        return original_post(url, *args, **kwargs)
        
    monkeypatch.setattr("httpx.post", _safe_post)
    
    # Also override getting the AI provider to NoOp by default unless explicitly tested
    # Some tests set GEMINI_API_KEY to test the provider factory, which is fine,
    # because if they try to use it, the httpx.post mock above will catch it.
