"""Tests for aap.discovery — protocol helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx

from aap.discovery import (
    build_introduction_response_envelope,
    extract_searcher_identities,
    query_discovery,
)
from aap.envelope import Envelope
from aap.keys import encode_b64url, generate_keypair
from aap.payloads import DiscoveryQueryResponse, VerificationAttestation
from aap.trusted_verifiers import VerifierTrustListEntry
from aap.verifiers import (
    TRUSTED_VERIFIERS_ISSUER,
    TRUSTED_VERIFIERS_PAYLOAD_TYPE,
    TrustListCache,
    verifier_relay_address,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DISCOVERY_ENDPOINT = "https://verify.example.com/aap/discover"
_TRUST_ROOT_SEED, _TRUST_ROOT_PUBLIC = generate_keypair()
_TRUST_LIST_VERIFIER_SEED, _TRUST_LIST_VERIFIER_PUBLIC = generate_keypair()

_TRUST_LIST_BODY = {
    "publisher": "agentaddress.org",
    "version": "2026-06-01",
    "verifiers": [
        {
            "domain": "verify.example.com",
            "supported_identities": ["phone", "email"],
            "discovery_endpoint": _DISCOVERY_ENDPOINT,
            "verification_endpoint": "https://verify.example.com/aap/verify",
            "pubkey_endpoint": "https://verify.example.com/.well-known/aap-verifier-key",
            "public_key": encode_b64url(_TRUST_LIST_VERIFIER_PUBLIC),
            "policy_url": "https://verify.example.com/policy",
            "trust_score": "established",
        }
    ],
}

_TRUST_LIST_URL = "https://api.agentaddress.org/.well-known/aap-trusted-verifiers"


def _make_trust_list_cache(tmp_path: Path) -> TrustListCache:
    return TrustListCache(
        cache_path=tmp_path / "trust.json",
        overrides_path=tmp_path / "overrides.json",
        trust_list_public_key=_TRUST_ROOT_PUBLIC,
        url=_TRUST_LIST_URL,
    )


def _make_seed_and_address() -> tuple[bytes, str]:
    seed, _pub = generate_keypair()
    return seed, "alice^example.com"


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _trust_entry(domain: str = "verify.example.com") -> VerifierTrustListEntry:
    return VerifierTrustListEntry(
        domain=domain,
        supported_identities=["phone", "email"],
        discovery_endpoint=f"https://{domain}/aap/discover",
        verification_endpoint=f"https://{domain}/aap/verify",
        pubkey_endpoint=f"https://{domain}/.well-known/aap-verifier-key",
        public_key=encode_b64url(generate_keypair()[1]),
    )


def _trust_list_envelope_json() -> str:
    return Envelope(
        type="aap.envelope/v1",
        payload_type=TRUSTED_VERIFIERS_PAYLOAD_TYPE,
        payload=_TRUST_LIST_BODY,
        iss=TRUSTED_VERIFIERS_ISSUER,
        iat=_rfc3339(datetime.now(timezone.utc)),
    ).sign(_TRUST_ROOT_SEED).to_json()


def _make_attestation_envelope_json(
    subject_address: str,
    identity_type: str,
    identity_value: str,
    verifier_seed: bytes,
    *,
    verifier_domain: str = "verify.example.com",
    expires_at: datetime | None = None,
) -> str:
    """Build a minimal VerificationAttestation envelope JSON for test use."""
    now = datetime.now(timezone.utc)
    att = VerificationAttestation(
        subject_address=subject_address,
        identity={"type": identity_type, "value": identity_value},
        challenge_method="sms-otp",
        verified_at=_rfc3339(now),
        expires_at=_rfc3339(expires_at or (now + timedelta(days=365))),
        verifier=verifier_domain,
        nonce="test-nonce",
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=VerificationAttestation.PAYLOAD_TYPE,
        payload=att.to_dict(),
        iss=verifier_domain,
        iat=_rfc3339(now),
    ).sign(verifier_seed)
    return env.to_json()


def _make_discovery_response_envelope_json(
    *,
    query_nonce: str,
    result: str | None,
    verifier_seed: bytes,
    verifier_domain: str = "verify.example.com",
    iat: datetime | None = None,
    expires_at: datetime | None = None,
) -> str:
    now = iat or datetime.now(timezone.utc)
    payload = DiscoveryQueryResponse(
        query_nonce=query_nonce,
        result=result,
        expires_at=_rfc3339(expires_at) if expires_at is not None else None,
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=DiscoveryQueryResponse.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=verifier_relay_address(verifier_domain),
        iat=_rfc3339(now),
    ).sign(verifier_seed)
    return env.to_json()


def _make_discovery_response_handler(
    *,
    verifier_seed: bytes,
    result: str | None,
    verifier_domain: str = "verify.example.com",
    query_nonce: str | None = None,
    iat: datetime | None = None,
    expires_at: datetime | None = None,
):
    def handler(request: httpx.Request) -> httpx.Response:
        request_env = Envelope.from_json(request.content.decode("utf-8"))
        response_nonce = query_nonce or request_env.payload["nonce"]
        return httpx.Response(
            200,
            text=_make_discovery_response_envelope_json(
                query_nonce=response_nonce,
                result=result,
                verifier_seed=verifier_seed,
                verifier_domain=verifier_domain,
                iat=iat,
                expires_at=expires_at,
            ),
        )

    return handler


# ---------------------------------------------------------------------------
# query_discovery — happy path
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_returns_address_on_success(tmp_path: Path) -> None:
    """Successful discovery returns the resolved AAP address."""
    verifier_seed, verifier_public = generate_keypair()
    trust_route = respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    discover_route = respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=_make_discovery_response_handler(
            verifier_seed=verifier_seed,
            result="bob^example.com",
        ),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result == "bob^example.com"
    assert trust_route.call_count == 1
    assert discover_route.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_sends_timeout_param(tmp_path: Path) -> None:
    """The ``?timeout=`` query param is forwarded to the verifier."""
    verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    discover_route = respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=_make_discovery_response_handler(
            verifier_seed=verifier_seed,
            result="bob^example.com",
        ),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            timeout_seconds=120,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    request = discover_route.calls[0].request
    assert b"timeout=120" in request.url.query


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_null_result_returns_none(tmp_path: Path) -> None:
    """Verifier returns null result → None."""
    verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=_make_discovery_response_handler(
            verifier_seed=verifier_seed,
            result=None,
        ),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


# ---------------------------------------------------------------------------
# query_discovery — HTTP error handling
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_http_error_returns_none(tmp_path: Path) -> None:
    """Non-200 from verifier → None (continues to next verifier, then None)."""
    _verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        return_value=httpx.Response(503, text="Service Unavailable"),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_network_error_returns_none(tmp_path: Path) -> None:
    """Connection error to verifier → None."""
    _verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=httpx.ConnectError("Connection refused"),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_no_verifier_supports_type(tmp_path: Path) -> None:
    """When no verifier supports the identity_type, returns None immediately."""
    _verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    # identity_type "ssn" is not in the trust list
    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="ssn",
            identifier_value="123-45-6789",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_rejects_plain_json_response(tmp_path: Path) -> None:
    """Verifier response must be a signed discovery-query-response envelope."""
    _verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        return_value=httpx.Response(200, json={"result": "bob^example.com"}),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_rejects_mismatched_nonce(tmp_path: Path) -> None:
    verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=_make_discovery_response_handler(
            verifier_seed=verifier_seed,
            result="bob^example.com",
            query_nonce="wrong-nonce",
        ),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_rejects_bad_signature(tmp_path: Path) -> None:
    verifier_seed, _verifier_public = generate_keypair()
    _wrong_seed, wrong_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=_make_discovery_response_handler(
            verifier_seed=verifier_seed,
            result="bob^example.com",
        ),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: wrong_public,
        )
    finally:
        await cache.aclose()

    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_rejects_wrong_issuer(tmp_path: Path) -> None:
    verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=_make_discovery_response_handler(
            verifier_seed=verifier_seed,
            verifier_domain="other.example.com",
            result="bob^example.com",
        ),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


@respx.mock
@pytest.mark.asyncio
async def test_query_discovery_rejects_stale_response(tmp_path: Path) -> None:
    verifier_seed, verifier_public = generate_keypair()
    respx.get(_TRUST_LIST_URL).mock(
        return_value=httpx.Response(200, text=_trust_list_envelope_json()),
    )
    respx.post(_DISCOVERY_ENDPOINT).mock(
        side_effect=_make_discovery_response_handler(
            verifier_seed=verifier_seed,
            result="bob^example.com",
            iat=datetime.now(timezone.utc) - timedelta(days=31),
        ),
    )

    seed, self_address = _make_seed_and_address()
    cache = _make_trust_list_cache(tmp_path)
    try:
        result = await query_discovery(
            self_address=self_address,
            self_seed=seed,
            identity_type="phone",
            identifier_value="+15555550100",
            searcher_label=None,
            trust_list_cache=cache,
            verifier_public_key_resolver=lambda _entry: verifier_public,
        )
    finally:
        await cache.aclose()

    assert result is None


# ---------------------------------------------------------------------------
# extract_searcher_identities
# ---------------------------------------------------------------------------


def test_extract_searcher_identities_happy_path() -> None:
    """Returns type+value dict for attestations matching the subject."""
    verifier_seed, verifier_public = generate_keypair()
    subject = "alice^example.com"
    att_json = _make_attestation_envelope_json(subject, "phone", "+15555550100", verifier_seed)

    result = extract_searcher_identities(
        searcher_attestations=[att_json],
        expected_subject_address=subject,
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={"verify.example.com": verifier_public},
    )
    assert result == [{"type": "phone", "value": "+15555550100"}]


def test_extract_searcher_identities_wrong_subject_filtered() -> None:
    """Attestations for a different subject address are skipped."""
    verifier_seed, verifier_public = generate_keypair()
    att_json = _make_attestation_envelope_json(
        "other^example.com", "email", "other@example.com", verifier_seed
    )

    result = extract_searcher_identities(
        searcher_attestations=[att_json],
        expected_subject_address="alice^example.com",
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={"verify.example.com": verifier_public},
    )
    assert result == []


def test_extract_searcher_identities_multiple_attestations() -> None:
    """Multiple matching attestations all returned."""
    verifier_seed, verifier_public = generate_keypair()
    subject = "alice^example.com"
    phone_att = _make_attestation_envelope_json(subject, "phone", "+15555550100", verifier_seed)
    email_att = _make_attestation_envelope_json(subject, "email", "alice@example.com", verifier_seed)

    result = extract_searcher_identities(
        searcher_attestations=[phone_att, email_att],
        expected_subject_address=subject,
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={"verify.example.com": verifier_public},
    )
    assert len(result) == 2
    types = {r["type"] for r in result}
    assert types == {"phone", "email"}


def test_extract_searcher_identities_malformed_json_skipped() -> None:
    """Malformed envelope JSON is silently skipped."""
    result = extract_searcher_identities(
        searcher_attestations=["not-valid-json", "{}"],
        expected_subject_address="alice^example.com",
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={},
    )
    assert result == []


def test_extract_searcher_identities_empty_list() -> None:
    """Empty attestation list returns empty result."""
    result = extract_searcher_identities(
        searcher_attestations=[],
        expected_subject_address="alice^example.com",
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={},
    )
    assert result == []


def test_extract_searcher_identities_rejects_bad_signature() -> None:
    verifier_seed, _ = generate_keypair()
    _, wrong_public = generate_keypair()
    subject = "alice^example.com"
    att_json = _make_attestation_envelope_json(subject, "phone", "+15555550100", verifier_seed)

    result = extract_searcher_identities(
        searcher_attestations=[att_json],
        expected_subject_address=subject,
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={"verify.example.com": wrong_public},
    )
    assert result == []


def test_extract_searcher_identities_rejects_untrusted_verifier() -> None:
    verifier_seed, verifier_public = generate_keypair()
    subject = "alice^example.com"
    att_json = _make_attestation_envelope_json(
        subject,
        "phone",
        "+15555550100",
        verifier_seed,
        verifier_domain="untrusted.example",
    )

    result = extract_searcher_identities(
        searcher_attestations=[att_json],
        expected_subject_address=subject,
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={"untrusted.example": verifier_public},
    )
    assert result == []


def test_extract_searcher_identities_rejects_expired_attestation() -> None:
    verifier_seed, verifier_public = generate_keypair()
    subject = "alice^example.com"
    att_json = _make_attestation_envelope_json(
        subject,
        "phone",
        "+15555550100",
        verifier_seed,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    result = extract_searcher_identities(
        searcher_attestations=[att_json],
        expected_subject_address=subject,
        trusted_verifiers=[_trust_entry()],
        verifier_public_keys={"verify.example.com": verifier_public},
    )
    assert result == []


# ---------------------------------------------------------------------------
# build_introduction_response_envelope
# ---------------------------------------------------------------------------


def test_build_introduction_response_envelope_approved() -> None:
    """Approved response envelope has correct payload fields."""
    seed, address = _make_seed_and_address()
    env = build_introduction_response_envelope(
        responder_seed=seed,
        responder_address=address,
        verifier_nonce="nonce-abc",
        approved=True,
    )
    assert env.iss == address
    assert env.payload_type == "aap.discovery-introduction-response/v1"
    assert env.payload["verifier_nonce"] == "nonce-abc"
    assert env.payload["approved"] is True


def test_build_introduction_response_envelope_denied() -> None:
    """Denied response envelope has approved=False."""
    seed, address = _make_seed_and_address()
    env = build_introduction_response_envelope(
        responder_seed=seed,
        responder_address=address,
        verifier_nonce="nonce-xyz",
        approved=False,
    )
    assert env.payload["approved"] is False


def test_build_introduction_response_envelope_with_capability_token() -> None:
    """capability_token is passed through to the envelope."""
    seed, address = _make_seed_and_address()
    env = build_introduction_response_envelope(
        responder_seed=seed,
        responder_address=address,
        verifier_nonce="nonce-cap",
        approved=True,
        verifier_capability_token="tok-abc",
    )
    assert env.capability_token == "tok-abc"
