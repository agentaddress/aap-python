"""Transport security policy for configurable AAP network endpoints."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


class InsecureTransportError(ValueError):
    """Raised when a network endpoint does not meet AAP transport policy."""


def require_secure_url(url: str, *, field_name: str = "URL") -> str:
    """Require HTTPS, except for HTTP endpoints on the local loopback host."""
    if not isinstance(url, str) or not url:
        raise InsecureTransportError(f"{field_name} must be a non-empty absolute URL")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as e:
        raise InsecureTransportError(f"{field_name} is malformed: {e}") from e

    if not parsed.scheme or not parsed.netloc or hostname is None:
        raise InsecureTransportError(f"{field_name} must be an absolute URL")
    if parsed.username is not None or parsed.password is not None:
        raise InsecureTransportError(f"{field_name} must not contain credentials")
    if parsed.fragment:
        raise InsecureTransportError(f"{field_name} must not contain a fragment")

    if parsed.scheme.lower() == "https":
        return url
    if parsed.scheme.lower() == "http" and _is_loopback_host(hostname):
        return url

    raise InsecureTransportError(
        f"{field_name} must use HTTPS; HTTP is allowed only for loopback development"
    )


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False
