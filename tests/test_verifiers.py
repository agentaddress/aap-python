"""Tests for the trust-list + verifier-key management module."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest
import respx

from aap.envelope import Envelope
from aap.keys import encode_b64url, generate_keypair
from aap.transport import InsecureTransportError
from aap.verifiers import (
    DEFAULT_TRUSTED_VERIFIERS_URL,
    TRUSTED_VERIFIERS_ISSUER,
    TRUSTED_VERIFIERS_PAYLOAD_TYPE,
    TrustListCache,
    VerifierPubkeyCache,
    trusted_verifiers_supporting,
)
from aap.trusted_verifiers import VerifierTrustListEntry


_DEFAULT_TRUST_LIST_URL = (
    "https://api.agentaddress.org/.well-known/aap-trusted-verifiers"
)
_ROOT_SEED, _ROOT_PUBLIC = generate_keypair()
_, _VERIFIER_PUBLIC = generate_keypair()
_VERIFIER_PUBLIC_B64 = encode_b64url(_VERIFIER_PUBLIC)

_DEFAULT_LIST_BODY = {
    "publisher": "agentaddress.org",
    "version": "2026-05-22",
    "verifiers": [
        {
            "domain": "verify.aap.org",
            "supported_identities": ["phone", "email"],
            "discovery_endpoint": "https://verify.aap.org/aap/discover",
            "verification_endpoint": "https://verify.aap.org/aap/verify",
            "pubkey_endpoint": "https://verify.aap.org/.well-known/aap-verifier-key",
            "public_key": _VERIFIER_PUBLIC_B64,
            "policy_url": "https://verify.aap.org/policy",
            "trust_score": "established",
        }
    ],
}


def _make_cache(tmp_path: Path, **kwargs) -> TrustListCache:
    """Construct a TrustListCache with sensible test defaults."""
    url = kwargs.pop("url", _DEFAULT_TRUST_LIST_URL)
    return TrustListCache(
        cache_path=tmp_path / "trust.json",
        overrides_path=tmp_path / "overrides.json",
        trust_list_public_key=kwargs.pop("trust_list_public_key", _ROOT_PUBLIC),
        url=url,
        **kwargs,
    )


def _write_overrides(tmp_path: Path, payload: dict) -> None:
    (tmp_path / "overrides.json").write_text(json.dumps(payload))


def _trust_list_envelope_json(
    body: dict = _DEFAULT_LIST_BODY,
    *,
    seed: bytes = _ROOT_SEED,
    issuer: str = TRUSTED_VERIFIERS_ISSUER,
) -> str:
    return Envelope(
        type="aap.envelope/v1",
        payload_type=TRUSTED_VERIFIERS_PAYLOAD_TYPE,
        payload=body,
        iss=issuer,
        iat="2026-06-15T12:00:00Z",
    ).sign(seed).to_json()


# ---------------------------------------------------------------------------
# DEFAULT_TRUSTED_VERIFIERS_URL constant
# ---------------------------------------------------------------------------


def test_default_url_constant():
    assert DEFAULT_TRUSTED_VERIFIERS_URL == _DEFAULT_TRUST_LIST_URL


def test_rejects_remote_http_trust_list_url(tmp_path):
    with pytest.raises(InsecureTransportError, match="must use HTTPS"):
        _make_cache(tmp_path, url="http://directory.example/trust-list")


@respx.mock
@pytest.mark.asyncio
async def test_allows_loopback_http_trust_list_url(tmp_path):
    url = "http://localhost:8080/trust-list"
    route = respx.get(url).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json())
    )
    cache = _make_cache(tmp_path, url=url)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    assert route.call_count == 1
    assert [entry.domain for entry in entries] == ["verify.aap.org"]


@pytest.mark.asyncio
async def test_rejects_remote_http_trust_list_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "AAP_TRUSTED_VERIFIERS_URL",
        "http://directory.example/trust-list",
    )
    cache = TrustListCache(
        cache_path=tmp_path / "trust.json",
        overrides_path=tmp_path / "overrides.json",
        trust_list_public_key=_ROOT_PUBLIC,
    )
    try:
        with pytest.raises(InsecureTransportError, match="must use HTTPS"):
            await cache.get()
    finally:
        await cache.aclose()


# ---------------------------------------------------------------------------
# TrustListCache — fetch and disk cache
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_parse_and_cache(tmp_path):
    """First call hits the network and writes the cache file."""
    route = respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    assert route.call_count == 1
    assert [e.domain for e in entries] == ["verify.aap.org"]
    cache_path = tmp_path / "trust.json"
    assert cache_path.exists()
    data = json.loads(cache_path.read_text())
    envelope = Envelope.from_json(data["envelope_json"])
    assert envelope.payload["verifiers"][0]["domain"] == "verify.aap.org"
    assert "fetched_at" in data


@respx.mock
@pytest.mark.asyncio
async def test_rejects_unsigned_trust_list_response(tmp_path):
    """Published trust lists must be signed by the configured trust root."""
    route = respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, json=_DEFAULT_LIST_BODY),
    )
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    assert route.call_count == 1
    assert entries == []
    assert not (tmp_path / "trust.json").exists()


@respx.mock
@pytest.mark.asyncio
async def test_rejects_wrongly_signed_trust_list_response(tmp_path):
    """A valid envelope signed by the wrong key is not accepted or cached."""
    wrong_seed, _wrong_public = generate_keypair()
    route = respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(
            200,
            text=_trust_list_envelope_json(seed=wrong_seed),
        ),
    )
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    assert route.call_count == 1
    assert entries == []
    assert not (tmp_path / "trust.json").exists()


@respx.mock
@pytest.mark.asyncio
async def test_uses_cached_body_within_ttl(tmp_path):
    """Second call within TTL doesn't re-fetch."""
    route = respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    cache = _make_cache(tmp_path)
    try:
        await cache.get()
        await cache.get()
    finally:
        await cache.aclose()
    assert route.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_refetches_when_cache_is_stale(tmp_path):
    """Past TTL, the cache file is ignored and the URL is re-hit."""
    stale_body = dict(_DEFAULT_LIST_BODY)
    cache_path = tmp_path / "trust.json"
    cache_path.write_text(
        json.dumps({
            "fetched_at": time.time() - 60 * 60 * 48,
            "envelope_json": _trust_list_envelope_json(stale_body),
        })
    )
    route = respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    cache = _make_cache(tmp_path)
    try:
        await cache.get()
    finally:
        await cache.aclose()
    assert route.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_disk_cache_used_when_fresh(tmp_path):
    """If the disk cache is fresh, the URL is not hit at all."""
    cache_path = tmp_path / "trust.json"
    cache_path.write_text(
        json.dumps({
            "fetched_at": time.time(),
            "envelope_json": _trust_list_envelope_json(_DEFAULT_LIST_BODY),
        })
    )
    route = respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    assert route.call_count == 0
    assert [e.domain for e in entries] == ["verify.aap.org"]


@respx.mock
@pytest.mark.asyncio
async def test_falls_back_to_stale_cache_on_network_error(tmp_path):
    """Network failure falls back to stale on-disk cache rather than empty."""
    stale_body = dict(_DEFAULT_LIST_BODY)
    cache_path = tmp_path / "trust.json"
    cache_path.write_text(
        json.dumps({
            "fetched_at": time.time() - 60 * 60 * 48,
            "envelope_json": _trust_list_envelope_json(stale_body),
        })
    )
    respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        side_effect=httpx.ConnectError("network down"),
    )
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    assert [e.domain for e in entries] == ["verify.aap.org"]


# ---------------------------------------------------------------------------
# TrustListCache — overrides
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_local_override_adds_verifier(tmp_path):
    """Local overrides can add a new verifier alongside the published list."""
    respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    _write_overrides(
        tmp_path,
        {
            "add": [
                {
                    "domain": "extra.example",
                    "supported_identities": ["phone"],
                    "discovery_endpoint": "https://extra.example/aap/discover",
                    "verification_endpoint": "https://extra.example/aap/verify",
                    "pubkey_endpoint": "https://extra.example/.well-known/aap-verifier-key",
                    "public_key": encode_b64url(generate_keypair()[1]),
                }
            ],
        },
    )
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    domains = [e.domain for e in entries]
    assert "verify.aap.org" in domains
    assert "extra.example" in domains


@respx.mock
@pytest.mark.asyncio
async def test_local_override_removes_verifier(tmp_path):
    """Overrides take precedence: remove wins even if domain is in the published list."""
    respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    _write_overrides(tmp_path, {"remove": ["verify.aap.org"]})
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    assert all(e.domain != "verify.aap.org" for e in entries)


@respx.mock
@pytest.mark.asyncio
async def test_local_override_add_replaces_existing_domain(tmp_path):
    """An add-override for an existing domain replaces it (not duplicates)."""
    respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    replacement = {
        "domain": "verify.aap.org",
        "supported_identities": ["email"],  # changed
        "discovery_endpoint": "https://verify.aap.org/aap/discover",
        "verification_endpoint": "https://verify.aap.org/aap/verify",
        "pubkey_endpoint": "https://verify.aap.org/.well-known/aap-verifier-key",
        "public_key": encode_b64url(generate_keypair()[1]),
    }
    _write_overrides(tmp_path, {"add": [replacement]})
    cache = _make_cache(tmp_path)
    try:
        entries = await cache.get()
    finally:
        await cache.aclose()
    matching = [e for e in entries if e.domain == "verify.aap.org"]
    assert len(matching) == 1
    assert matching[0].supported_identities == ["email"]


# ---------------------------------------------------------------------------
# trusted_verifiers_supporting — pure function
# ---------------------------------------------------------------------------


def test_trusted_verifiers_supporting_filters_by_identity_type():
    """Pure filter over a list — no I/O."""
    entry_phone_email = VerifierTrustListEntry(
        domain="verify.aap.org",
        supported_identities=["phone", "email"],
        discovery_endpoint="https://verify.aap.org/aap/discover",
        verification_endpoint="https://verify.aap.org/aap/verify",
        pubkey_endpoint="https://verify.aap.org/.well-known/aap-verifier-key",
        public_key=encode_b64url(generate_keypair()[1]),
    )
    entry_phone_only = VerifierTrustListEntry(
        domain="phone-only.example",
        supported_identities=["phone"],
        discovery_endpoint="https://phone-only.example/aap/discover",
        verification_endpoint="https://phone-only.example/aap/verify",
        pubkey_endpoint="https://phone-only.example/.well-known/aap-verifier-key",
        public_key=encode_b64url(generate_keypair()[1]),
    )
    entries = [entry_phone_email, entry_phone_only]

    phone_results = trusted_verifiers_supporting(entries, "phone")
    assert len(phone_results) == 2

    email_results = trusted_verifiers_supporting(entries, "email")
    assert len(email_results) == 1
    assert email_results[0].domain == "verify.aap.org"

    gov_results = trusted_verifiers_supporting(entries, "government-id")
    assert gov_results == []


# ---------------------------------------------------------------------------
# VerifierPubkeyCache
# ---------------------------------------------------------------------------


def _make_trust_list() -> list[VerifierTrustListEntry]:
    from aap.trusted_verifiers import parse_trusted_verifiers
    return parse_trusted_verifiers(_DEFAULT_LIST_BODY)


@respx.mock
@pytest.mark.asyncio
async def test_fetch_verifier_pubkey_returns_signed_list_key_and_caches(tmp_path):
    """Verifier pubkey lookup uses the signed trust-list key and caches it."""
    route = respx.get("https://verify.aap.org/.well-known/aap-verifier-key").mock(
        return_value=httpx.Response(500),
    )
    trust_list = _make_trust_list()
    cache = VerifierPubkeyCache(cache_dir=tmp_path)
    try:
        first = await cache.get("verify.aap.org", trust_list)
        second = await cache.get("verify.aap.org", trust_list)
    finally:
        await cache.aclose()
    assert first == second
    assert first == _VERIFIER_PUBLIC
    assert route.call_count == 0


@respx.mock
@pytest.mark.asyncio
async def test_fetch_verifier_pubkey_returns_none_for_untrusted_domain(tmp_path):
    """Domain not in trust list returns None without hitting the network."""
    trust_list = _make_trust_list()
    cache = VerifierPubkeyCache(cache_dir=tmp_path)
    try:
        result = await cache.get("untrusted.example", trust_list)
    finally:
        await cache.aclose()
    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_fetch_verifier_pubkey_ignores_pubkey_endpoint_http_error(tmp_path):
    """The mutable pubkey endpoint is not consulted once the signed list has a key."""
    route = respx.get("https://verify.aap.org/.well-known/aap-verifier-key").mock(
        return_value=httpx.Response(404),
    )
    trust_list = _make_trust_list()
    cache = VerifierPubkeyCache(cache_dir=tmp_path)
    try:
        result = await cache.get("verify.aap.org", trust_list)
    finally:
        await cache.aclose()
    assert result == _VERIFIER_PUBLIC
    assert route.call_count == 0


@respx.mock
@pytest.mark.asyncio
async def test_fetch_verifier_pubkey_returns_none_for_wrong_key_length(tmp_path):
    """Pubkey that doesn't decode to 32 bytes is rejected."""
    # 16 zero bytes = 22 b64url chars (padded: 24)
    short_b64 = "AAAAAAAAAAAAAAAAAAAAAA"  # 16 zero bytes
    trust_list = [
        VerifierTrustListEntry(
            domain="verify.aap.org",
            supported_identities=["phone"],
            discovery_endpoint="https://verify.aap.org/aap/discover",
            verification_endpoint="https://verify.aap.org/aap/verify",
            pubkey_endpoint="https://verify.aap.org/.well-known/aap-verifier-key",
            public_key=short_b64,
        )
    ]
    cache = VerifierPubkeyCache(cache_dir=tmp_path)
    try:
        result = await cache.get("verify.aap.org", trust_list)
    finally:
        await cache.aclose()
    assert result is None


# ---------------------------------------------------------------------------
# Each TrustListCache instance is isolated (path-injected, no singletons)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_two_cache_instances_are_independent(tmp_path):
    """Two TrustListCache instances with different paths don't share state."""
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    dir_b = tmp_path / "b"
    dir_b.mkdir()

    respx.get(_DEFAULT_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    cache_a = TrustListCache(
        cache_path=dir_a / "trust.json",
        overrides_path=dir_a / "overrides.json",
        trust_list_public_key=_ROOT_PUBLIC,
        url=_DEFAULT_TRUST_LIST_URL,
    )
    cache_b = TrustListCache(
        cache_path=dir_b / "trust.json",
        overrides_path=dir_b / "overrides.json",
        trust_list_public_key=_ROOT_PUBLIC,
        url=_DEFAULT_TRUST_LIST_URL,
    )
    try:
        entries_a = await cache_a.get()
        entries_b = await cache_b.get()
    finally:
        await cache_a.aclose()
        await cache_b.aclose()
    # Both return the same data; each wrote its own cache file.
    assert [e.domain for e in entries_a] == [e.domain for e in entries_b]
    assert (dir_a / "trust.json").exists()
    assert (dir_b / "trust.json").exists()
