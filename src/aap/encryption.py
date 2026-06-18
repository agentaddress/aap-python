"""End-to-end encryption for signed AAP envelopes.

The relay-visible object is an ``aap.encrypted-envelope/v1`` containing an
RFC 9180 HPKE ciphertext. The plaintext is the existing signed
``aap.envelope/v1`` JSON, so sender authentication remains the responsibility
of normal Ed25519 envelope verification after decryption.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from Crypto.Protocol import HPKE
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aap.envelope import Envelope, EnvelopeError
from aap.jcs import canonicalize
from aap.keys import decode_b64url, encode_b64url

ENCRYPTED_ENVELOPE_TYPE = "aap.encrypted-envelope/v1"
HPKE_ALGORITHM = "HPKE-BASE-X25519-HKDF-SHA256-CHACHA20POLY1305"
_HPKE_INFO = b"aap.encrypted-envelope/v1"


class EncryptionError(ValueError):
    """Raised when encrypted-envelope construction or decryption fails."""


@dataclass(frozen=True)
class EncryptedEnvelope:
    """Relay-safe encrypted representation of one signed AAP envelope."""

    type: str
    alg: str
    kid: str
    enc: str
    ciphertext: str

    def to_dict(self) -> dict[str, str]:
        return {
            "alg": self.alg,
            "ciphertext": self.ciphertext,
            "enc": self.enc,
            "kid": self.kid,
            "type": self.type,
        }

    def to_json(self) -> str:
        return canonicalize(self.to_dict()).decode("utf-8")

    @classmethod
    def from_json(cls, value: str) -> "EncryptedEnvelope":
        try:
            data = json.loads(value)
        except json.JSONDecodeError as e:
            raise EncryptionError(f"invalid encrypted-envelope JSON: {e}") from e
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EncryptedEnvelope":
        if not isinstance(data, dict):
            raise EncryptionError("encrypted envelope must be a JSON object")
        allowed = {"type", "alg", "kid", "enc", "ciphertext"}
        unknown = set(data) - allowed
        if unknown:
            raise EncryptionError(f"unknown encrypted-envelope field(s): {sorted(unknown)!r}")
        for field in allowed:
            if not isinstance(data.get(field), str) or not data[field]:
                raise EncryptionError(f"encrypted envelope missing string field {field!r}")
        if data["type"] != ENCRYPTED_ENVELOPE_TYPE:
            raise EncryptionError(f"unsupported encrypted-envelope type: {data['type']!r}")
        if data["alg"] != HPKE_ALGORITHM:
            raise EncryptionError(f"unsupported encryption algorithm: {data['alg']!r}")
        return cls(
            type=data["type"],
            alg=data["alg"],
            kid=data["kid"],
            enc=data["enc"],
            ciphertext=data["ciphertext"],
        )


def generate_encryption_keypair() -> tuple[bytes, bytes]:
    """Generate a raw 32-byte X25519 private/public keypair."""
    private = X25519PrivateKey.generate()
    return _serialize_keypair(private)


def derive_encryption_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive a domain-separated X25519 keypair from a 32-byte master seed."""
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
    private_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"aap/x25519-private-key/v1",
    ).derive(seed)
    return _serialize_keypair(X25519PrivateKey.from_private_bytes(private_bytes))


def encryption_public_from_private(private_key: bytes) -> bytes:
    """Derive the raw X25519 public key for a raw private key."""
    if len(private_key) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(private_key)}")
    return _serialize_keypair(X25519PrivateKey.from_private_bytes(private_key))[1]


def encryption_key_id(public_key: bytes) -> str:
    """Return a compact stable identifier for an X25519 public key."""
    _validate_public_key(public_key)
    return encode_b64url(hashlib.sha256(public_key).digest()[:16])


def encrypt_envelope(
    envelope: Envelope,
    *,
    recipient_public_key: bytes,
    recipient_address: str,
) -> EncryptedEnvelope:
    """Encrypt a signed AAP envelope for one recipient."""
    if envelope.sig is None:
        raise EncryptionError("refusing to encrypt an unsigned AAP envelope")
    recipient_key = _hpke_public_key(recipient_public_key)
    kid = encryption_key_id(recipient_public_key)
    aad = _associated_data(recipient_address=recipient_address, kid=kid)
    try:
        encryptor = HPKE.new(
            receiver_key=recipient_key,
            aead_id=HPKE.AEAD.CHACHA20_POLY1305,
            info=_HPKE_INFO,
        )
        ciphertext = encryptor.seal(envelope.to_json().encode("utf-8"), auth_data=aad)
    except (TypeError, ValueError) as e:
        raise EncryptionError("HPKE encryption failed") from e
    return EncryptedEnvelope(
        type=ENCRYPTED_ENVELOPE_TYPE,
        alg=HPKE_ALGORITHM,
        kid=kid,
        enc=encode_b64url(encryptor.enc),
        ciphertext=encode_b64url(ciphertext),
    )


def decrypt_envelope(
    encrypted: EncryptedEnvelope,
    *,
    recipient_private_key: bytes,
    recipient_address: str,
) -> Envelope:
    """Decrypt an encrypted envelope and parse its signed inner envelope."""
    recipient_public_key = encryption_public_from_private(recipient_private_key)
    expected_kid = encryption_key_id(recipient_public_key)
    if encrypted.kid != expected_kid:
        raise EncryptionError("encrypted envelope is not addressed to this encryption key")
    aad = _associated_data(recipient_address=recipient_address, kid=encrypted.kid)
    try:
        decryptor = HPKE.new(
            receiver_key=_hpke_private_key(recipient_private_key),
            aead_id=HPKE.AEAD.CHACHA20_POLY1305,
            enc=decode_b64url(encrypted.enc),
            info=_HPKE_INFO,
        )
        plaintext = decryptor.unseal(
            decode_b64url(encrypted.ciphertext),
            auth_data=aad,
        )
        return Envelope.from_json(plaintext.decode("utf-8"))
    except (TypeError, ValueError, UnicodeDecodeError, EnvelopeError) as e:
        raise EncryptionError("HPKE decryption failed") from e


def _serialize_keypair(private: X25519PrivateKey) -> tuple[bytes, bytes]:
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def _validate_public_key(public_key: bytes) -> None:
    if len(public_key) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes, got {len(public_key)}")
    X25519PublicKey.from_public_bytes(public_key)


def _hpke_public_key(public_key: bytes) -> ECC.EccKey:
    _validate_public_key(public_key)
    return ECC.construct(
        curve="Curve25519",
        point_x=int.from_bytes(public_key, "little"),
    )


def _hpke_private_key(private_key: bytes) -> ECC.EccKey:
    if len(private_key) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(private_key)}")
    return ECC.construct(curve="Curve25519", seed=private_key)


def _associated_data(*, recipient_address: str, kid: str) -> bytes:
    return canonicalize(
        {
            "alg": HPKE_ALGORITHM,
            "kid": kid,
            "to": recipient_address,
            "type": ENCRYPTED_ENVELOPE_TYPE,
        }
    )
