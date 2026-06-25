"""Tests for the trusted-verifiers list parser."""

import pytest

from aap.trusted_verifiers import VerifierTrustListEntry, parse_trusted_verifiers

_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_parse_minimal_list():
    data = {
        "publisher": "agentaddress.org",
        "version": "2026-05-22",
        "verifiers": [
            {
                "domain": "verify.example",
                "supported_identities": ["phone", "email"],
                "discovery_endpoint": "https://verify.example/aap/discover",
                "verification_endpoint": "https://verify.example/aap/verify",
                "pubkey_endpoint": "https://verify.example/.well-known/aap-verifier-key",
                "public_key": _PUBLIC_KEY,
                "policy_url": "https://verify.example/policy",
                "trust_score": "established",
            }
        ],
    }
    entries = parse_trusted_verifiers(data)
    assert len(entries) == 1
    e = entries[0]
    assert isinstance(e, VerifierTrustListEntry)
    assert e.domain == "verify.example"
    assert "phone" in e.supported_identities
    assert e.discovery_endpoint.startswith("https://")


def test_parse_rejects_non_https_endpoints():
    data = {
        "publisher": "x",
        "version": "2026-05-22",
        "verifiers": [
            {
                "domain": "v.example.com",
                "supported_identities": ["phone"],
                "discovery_endpoint": "http://insecure.example/aap/discover",
                "verification_endpoint": "https://v.example.com/aap/verify",
                "pubkey_endpoint": "https://v.example.com/.well-known/aap-verifier-key",
                "public_key": _PUBLIC_KEY,
            }
        ],
    }
    with pytest.raises(ValueError, match="endpoint.*https"):
        parse_trusted_verifiers(data)


def test_parse_empty_list():
    data = {"publisher": "x", "version": "v", "verifiers": []}
    entries = parse_trusted_verifiers(data)
    assert entries == []


def test_parse_supports_identity_filter():
    data = {
        "publisher": "x",
        "version": "v",
        "verifiers": [
            {"domain": "v1", "supported_identities": ["phone"],
             "discovery_endpoint": "https://v1/aap/discover",
             "verification_endpoint": "https://v1/aap/verify",
             "pubkey_endpoint": "https://v1/.well-known/aap-verifier-key",
             "public_key": _PUBLIC_KEY},
            {"domain": "v2", "supported_identities": ["email"],
             "discovery_endpoint": "https://v2/aap/discover",
             "verification_endpoint": "https://v2/aap/verify",
             "pubkey_endpoint": "https://v2/.well-known/aap-verifier-key",
             "public_key": _PUBLIC_KEY},
        ],
    }
    entries = parse_trusted_verifiers(data)
    phone_verifiers = [e for e in entries if "phone" in e.supported_identities]
    assert len(phone_verifiers) == 1
    assert phone_verifiers[0].domain == "v1"
