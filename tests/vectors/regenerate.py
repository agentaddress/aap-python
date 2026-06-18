"""Regenerate `tests/vectors/envelopes.json`.

Builds each conformance envelope programmatically, signs with the
fixed test seed, and writes the canonical/signed forms back.

Run from the repo root::

    python tests/vectors/regenerate.py

The fixed seed is documented inside the resulting JSON so the
fixtures are fully reproducible from this script alone. Hostnames
use the RFC 2606 ``.example`` TLD to keep test data hermetic.

See ``tests/vectors/README.md`` for context.
"""

from __future__ import annotations

import json
from pathlib import Path

from aap.envelope import Envelope
from aap.keys import encode_b64url, sign
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


VECTORS_PATH = Path(__file__).parent / "envelopes.json"

# Fixed test seed — must remain stable so the vectors are reproducible.
PRIVATE_SEED_HEX = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"


def _derive_public(seed: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _build_vector(name: str, env: Envelope, seed: bytes) -> dict:
    canonical = env.canonical_bytes()
    signature = sign(seed, canonical)
    signed_env = env.sign(seed)
    return {
        "name": name,
        "private_seed_hex": PRIVATE_SEED_HEX,
        "public_key_b64url": encode_b64url(_derive_public(seed)),
        "envelope_unsigned": env.to_dict(),
        "canonical_bytes_hex": canonical.hex(),
        "signature_b64url": encode_b64url(signature),
        "envelope_signed_json": signed_env.to_json(),
    }


def main() -> None:
    seed = bytes.fromhex(PRIVATE_SEED_HEX)
    public_key_b64url = encode_b64url(_derive_public(seed))

    agent_card_unsigned = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.agent-card/v1",
        payload={
            "address": "chris^chrisevans.id",
            "did": "did:web:chrisevans.id#agent",
            "public_key": public_key_b64url,
            "endpoints": [
                {"type": "didcomm", "uri": "https://relay.example"},
            ],
        },
        iss="did:web:chrisevans.id#agent",
        iat="2026-05-19T12:00:00Z",
    )

    relationship_token_unsigned = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.relationship-token/v1",
        payload={
            "parties": [
                "chris^chrisevans.id",
                "james^bob.example",
            ],
            "purpose": "social-scheduling",
            "scopes": ["calendar.read", "messages.write"],
            "iat": "2026-05-19T12:00:00Z",
            "exp": "2026-08-19T12:00:00Z",
            "nonce": "nonce-abc-123",
        },
        iss="did:web:chrisevans.id#agent",
        iat="2026-05-19T12:00:00Z",
    )

    vectors = {
        "vectors": [
            _build_vector("agent-card-basic", agent_card_unsigned, seed),
            _build_vector(
                "relationship-token-two-party",
                relationship_token_unsigned,
                seed,
            ),
        ],
    }

    VECTORS_PATH.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"Wrote {VECTORS_PATH} with {len(vectors['vectors'])} vector(s).")


if __name__ == "__main__":
    main()
