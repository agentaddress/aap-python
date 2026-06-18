"""Tests for RFC 9180 encrypted AAP envelopes."""

import dataclasses

import pytest

from aap.encryption import (
    ENCRYPTED_ENVELOPE_TYPE,
    HPKE_ALGORITHM,
    EncryptedEnvelope,
    EncryptionError,
    decrypt_envelope,
    derive_encryption_keypair,
    encrypt_envelope,
    generate_encryption_keypair,
)
from aap.envelope import Envelope
from aap.keys import decode_b64url, encode_b64url, generate_keypair


def _signed_envelope() -> tuple[Envelope, bytes]:
    seed, public = generate_keypair()
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "relay must not see this"},
        iss="alice^example.com",
        iat="2026-06-15T12:00:00Z",
    ).sign(seed)
    return envelope, public


def test_hpke_round_trip_preserves_signed_inner_envelope():
    envelope, signing_public = _signed_envelope()
    recipient_private, recipient_public = generate_encryption_keypair()

    encrypted = encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public,
        recipient_address="bob^example.net",
    )

    assert encrypted.type == ENCRYPTED_ENVELOPE_TYPE
    assert encrypted.alg == HPKE_ALGORITHM
    assert "relay must not see this" not in encrypted.to_json()

    decrypted = decrypt_envelope(
        encrypted,
        recipient_private_key=recipient_private,
        recipient_address="bob^example.net",
    )
    assert decrypted == envelope
    assert decrypted.verify(signing_public) is True


def test_encryption_uses_fresh_ephemeral_key_per_message():
    envelope, _ = _signed_envelope()
    _, recipient_public = generate_encryption_keypair()

    first = encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public,
        recipient_address="bob^example.net",
    )
    second = encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public,
        recipient_address="bob^example.net",
    )

    assert first.enc != second.enc
    assert first.ciphertext != second.ciphertext


def test_tampered_ciphertext_is_rejected():
    envelope, _ = _signed_envelope()
    recipient_private, recipient_public = generate_encryption_keypair()
    encrypted = encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public,
        recipient_address="bob^example.net",
    )
    ciphertext = bytearray(decode_b64url(encrypted.ciphertext))
    ciphertext[-1] ^= 0x01
    tampered = dataclasses.replace(
        encrypted,
        ciphertext=encode_b64url(bytes(ciphertext)),
    )

    with pytest.raises(EncryptionError, match="decryption failed"):
        decrypt_envelope(
            tampered,
            recipient_private_key=recipient_private,
            recipient_address="bob^example.net",
        )


def test_recipient_address_is_authenticated():
    envelope, _ = _signed_envelope()
    recipient_private, recipient_public = generate_encryption_keypair()
    encrypted = encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public,
        recipient_address="bob^example.net",
    )

    with pytest.raises(EncryptionError, match="decryption failed"):
        decrypt_envelope(
            encrypted,
            recipient_private_key=recipient_private,
            recipient_address="mallory^example.net",
        )


def test_wrong_recipient_key_is_rejected_before_decryption():
    envelope, _ = _signed_envelope()
    _, recipient_public = generate_encryption_keypair()
    wrong_private, _ = generate_encryption_keypair()
    encrypted = encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public,
        recipient_address="bob^example.net",
    )

    with pytest.raises(EncryptionError, match="not addressed"):
        decrypt_envelope(
            encrypted,
            recipient_private_key=wrong_private,
            recipient_address="bob^example.net",
        )


def test_unsigned_envelope_is_not_encrypted():
    unsigned = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hello"},
        iss="alice^example.com",
        iat="2026-06-15T12:00:00Z",
    )
    _, recipient_public = generate_encryption_keypair()

    with pytest.raises(EncryptionError, match="unsigned"):
        encrypt_envelope(
            unsigned,
            recipient_public_key=recipient_public,
            recipient_address="bob^example.net",
        )


def test_deterministic_derivation_is_domain_stable():
    first = derive_encryption_keypair(bytes(range(32)))
    second = derive_encryption_keypair(bytes(range(32)))
    other = derive_encryption_keypair(bytes(reversed(range(32))))

    assert first == second
    assert first != other


def test_encrypted_envelope_round_trips_json():
    envelope, _ = _signed_envelope()
    _, recipient_public = generate_encryption_keypair()
    encrypted = encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public,
        recipient_address="bob^example.net",
    )

    assert EncryptedEnvelope.from_json(encrypted.to_json()) == encrypted
