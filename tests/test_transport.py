"""Tests for configurable endpoint transport security."""

import pytest

from aap.transport import InsecureTransportError, require_secure_url


@pytest.mark.parametrize(
    "url",
    [
        "https://relay.example",
        "http://localhost:8000",
        "http://api.localhost:8000/path",
        "http://127.0.0.1",
        "http://127.12.34.56",
        "http://[::1]:8000",
    ],
)
def test_accepts_https_and_loopback_http(url):
    assert require_secure_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://relay.example",
        "ftp://relay.example",
        "relay.example",
        "https://user:password@relay.example",
        "https://relay.example/path#fragment",
        "",
    ],
)
def test_rejects_insecure_or_malformed_urls(url):
    with pytest.raises(InsecureTransportError):
        require_secure_url(url)
