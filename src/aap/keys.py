"""Ed25519 keypair generation, signing, verification, and base64url codec."""

import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def seed_to_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive (seed, public_key) from a 32-byte Ed25519 seed."""
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return seed, pub


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        (private_seed_32_bytes, public_key_32_bytes)
    """
    return seed_to_keypair(os.urandom(32))


def sign(private_seed: bytes, message: bytes) -> bytes:
    """Sign a message with an Ed25519 private seed.

    Returns:
        64-byte signature.
    """
    if len(private_seed) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    private = Ed25519PrivateKey.from_private_bytes(private_seed)
    return private.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Returns True iff the signature is valid.
    """
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    if len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def encode_b64url(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_b64url(s: str) -> bytes:
    """Decode base64url without padding. Rejects padded input."""
    if "=" in s:
        raise ValueError("base64url must not contain padding ('=')")
    # Re-pad for the stdlib decoder.
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)
