"""Tests for the local attestation store."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aap.envelope import Envelope
from aap.keys import generate_keypair
from aap.payloads import VerificationAttestation

from aap.stores.attestations import AttestationStore


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_attestation_envelope(
    *,
    subject_address: str = "chris^relay.example",
    identity_type: str = "phone",
    identity_value: str = "+14155551111",
    verifier_domain: str = "verify.aap.org",
    verified_at: datetime | None = None,
    expires_at: datetime | None = None,
    nonce: str = "test-nonce-1",
) -> tuple[str, bytes]:
    """Build a signed VerificationAttestation envelope for tests."""
    seed, pub = generate_keypair()
    verified_at = verified_at or _now()
    expires_at = expires_at or (verified_at + timedelta(days=365))
    payload = VerificationAttestation(
        subject_address=subject_address,
        identity={"type": identity_type, "value": identity_value},
        challenge_method="sms-otp",
        verified_at=_rfc3339(verified_at),
        expires_at=_rfc3339(expires_at),
        verifier=verifier_domain,
        nonce=nonce,
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=VerificationAttestation.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=verifier_domain,
        iat=_rfc3339(verified_at),
    ).sign(seed)
    return env.to_json(), pub


def _record_attestation(store: AttestationStore, **kwargs):
    envelope_json, public_key = _build_attestation_envelope(**kwargs)
    return store.record(envelope_json, verifier_public_key=public_key)


def test_record_and_round_trip(tmp_path):
    store = AttestationStore.load(tmp_path)
    env_json, public_key = _build_attestation_envelope()
    store.record(env_json, verifier_public_key=public_key)

    reloaded = AttestationStore.load(tmp_path)
    held = reloaded.held_for("phone")
    assert len(held) == 1
    assert held[0].identifier_value == "+14155551111"
    assert held[0].verifier == "verify.aap.org"
    assert held[0].attestation_envelope_json == env_json


def test_held_for_filters_by_identity_type(tmp_path):
    store = AttestationStore.load(tmp_path)
    _record_attestation(store, identity_type="phone")
    _record_attestation(
        store,
        identity_type="email",
        identity_value="chris@example.com",
        nonce="e1",
    )
    assert len(store.held_for("phone")) == 1
    assert len(store.held_for("email")) == 1
    assert store.held_for("government-id") == []


def test_matching_returns_attestation_satisfying_constraints(tmp_path):
    store = AttestationStore.load(tmp_path)
    _record_attestation(store)

    match = store.matching(
        identity_type="phone",
        verifiers_oneof=["verify.aap.org", "twilio.com"],
        max_age_days=365,
    )
    assert match is not None
    assert match.identifier_value == "+14155551111"


def test_matching_rejects_when_verifier_not_in_list(tmp_path):
    store = AttestationStore.load(tmp_path)
    _record_attestation(store)

    match = store.matching(
        identity_type="phone",
        verifiers_oneof=["different.example"],
        max_age_days=365,
    )
    assert match is None


def test_matching_rejects_expired_attestation(tmp_path):
    store = AttestationStore.load(tmp_path)
    past = _now() - timedelta(days=400)
    expired_exp = _now() - timedelta(days=1)
    _record_attestation(store, verified_at=past, expires_at=expired_exp)
    match = store.matching(
        identity_type="phone", verifiers_oneof=["verify.aap.org"], max_age_days=365
    )
    assert match is None


def test_matching_rejects_attestation_older_than_max_age(tmp_path):
    store = AttestationStore.load(tmp_path)
    old = _now() - timedelta(days=400)
    future_exp = _now() + timedelta(days=200)
    _record_attestation(store, verified_at=old, expires_at=future_exp)
    match = store.matching(
        identity_type="phone",
        verifiers_oneof=["verify.aap.org"],
        max_age_days=90,
    )
    assert match is None


def test_remove_expired_drops_expired_only(tmp_path):
    store = AttestationStore.load(tmp_path)
    past = _now() - timedelta(days=400)
    expired_exp = _now() - timedelta(days=1)
    _record_attestation(
        store,
        verified_at=past,
        expires_at=expired_exp,
        nonce="exp-1",
    )
    _record_attestation(store, nonce="active-1")
    removed = store.remove_expired()
    assert removed == 1
    held = store.held_for("phone")
    assert len(held) == 1
    assert held[0].verified_at != _rfc3339(past)


def test_record_rejects_envelope_with_wrong_payload_type(tmp_path):
    """Refuses to store a non-attestation envelope (defensive)."""
    seed, pub = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hi"},
        iss="verify.aap.org",
        iat="2026-05-22T00:00:00Z",
    ).sign(seed)
    store = AttestationStore.load(tmp_path)
    with pytest.raises(ValueError):
        store.record(env.to_json(), verifier_public_key=pub)


def test_record_rejects_bad_verifier_signature(tmp_path):
    store = AttestationStore.load(tmp_path)
    env_json, _ = _build_attestation_envelope()
    _, wrong_public_key = generate_keypair()

    with pytest.raises(ValueError, match="signature did not verify"):
        store.record(env_json, verifier_public_key=wrong_public_key)


def test_record_rejects_issuer_verifier_mismatch(tmp_path):
    store = AttestationStore.load(tmp_path)
    seed, public_key = generate_keypair()
    payload = VerificationAttestation(
        subject_address="chris^relay.example",
        identity={"type": "phone", "value": "+14155551111"},
        challenge_method="sms-otp",
        verified_at=_rfc3339(_now()),
        expires_at=_rfc3339(_now() + timedelta(days=365)),
        verifier="verify.aap.org",
        nonce="issuer-mismatch",
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=VerificationAttestation.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss="evil.example",
        iat=_rfc3339(_now()),
    ).sign(seed)

    with pytest.raises(ValueError, match="does not match"):
        store.record(env.to_json(), verifier_public_key=public_key)


def test_record_rejects_duplicate_verifier_nonce(tmp_path):
    store = AttestationStore.load(tmp_path)
    env_json, public_key = _build_attestation_envelope(nonce="same-nonce")
    store.record(env_json, verifier_public_key=public_key)

    second_json, second_public_key = _build_attestation_envelope(nonce="same-nonce")
    with pytest.raises(ValueError, match="replay"):
        store.record(second_json, verifier_public_key=second_public_key)


def test_load_returns_empty_when_file_missing(tmp_path):
    store = AttestationStore.load(tmp_path)
    assert store.held_for("phone") == []
    assert store.held_for("email") == []
