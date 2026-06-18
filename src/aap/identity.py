"""Ed25519 identity lifecycle.

Source-of-truth order:
1. AAP_PRIVATE_SEED_B64 env override (do not persist).
2. The identity file at ``identity_path`` (load if exists).
3. Generate a fresh keypair and persist.

The env-override branch is checked before any disk I/O so callers
using ``AAP_PRIVATE_SEED_B64`` get the documented no-persist
contract.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from aap.encryption import (
    derive_encryption_keypair,
    encryption_public_from_private,
    generate_encryption_keypair,
)
from aap.keys import decode_b64url, encode_b64url, generate_keypair
from aap.storage import write_json_private
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IdentityFile:
    """The Ed25519 identity used to sign AAP envelopes."""

    private_seed: bytes      # 32-byte Ed25519 seed
    public_key: bytes        # 32-byte Ed25519 public key
    address: str             # full AAP address
    encryption_private_key: bytes = b""  # 32-byte X25519 private key
    encryption_public_key: bytes = b""   # 32-byte X25519 public key

    def __post_init__(self) -> None:
        if self.encryption_private_key:
            public = encryption_public_from_private(self.encryption_private_key)
            if self.encryption_public_key and self.encryption_public_key != public:
                raise ValueError("encryption public key does not match private key")
            object.__setattr__(self, "encryption_public_key", public)
        elif self.encryption_public_key:
            raise ValueError("encryption private key is required when public key is set")
        else:
            private, public = derive_encryption_keypair(self.private_seed)
            object.__setattr__(self, "encryption_private_key", private)
            object.__setattr__(self, "encryption_public_key", public)


def _derive_public_key(seed: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_or_generate(
    identity_path: Path,
    env_seed_b64: str | None,
    address: str,
    env_encryption_private_b64: str | None = None,
) -> IdentityFile:
    """Resolve the agent's identity by env/file/generate order."""
    # 1. Env override
    if env_seed_b64:
        seed = decode_b64url(env_seed_b64)
        if len(seed) != 32:
            raise ValueError(f"AAP_PRIVATE_SEED_B64 must decode to 32 bytes, got {len(seed)}")
        public = _derive_public_key(seed)
        if env_encryption_private_b64:
            encryption_private = decode_b64url(env_encryption_private_b64)
            encryption_public = encryption_public_from_private(encryption_private)
        else:
            encryption_private, encryption_public = derive_encryption_keypair(seed)
        return IdentityFile(
            private_seed=seed,
            public_key=public,
            encryption_private_key=encryption_private,
            encryption_public_key=encryption_public,
            address=address,
        )

    # 2. Existing file
    if identity_path.exists():
        data = json.loads(identity_path.read_text())
        seed = decode_b64url(data["private_seed_b64"])
        public = decode_b64url(data["public_key_b64"])
        needs_write = False
        encryption_private_b64 = data.get("encryption_private_key_b64")
        if encryption_private_b64:
            encryption_private = decode_b64url(encryption_private_b64)
            encryption_public = encryption_public_from_private(encryption_private)
            canonical_public_b64 = encode_b64url(encryption_public)
            if data.get("encryption_public_key_b64") != canonical_public_b64:
                data["encryption_public_key_b64"] = canonical_public_b64
                needs_write = True
        else:
            encryption_private, encryption_public = generate_encryption_keypair()
            data["encryption_private_key_b64"] = encode_b64url(encryption_private)
            data["encryption_public_key_b64"] = encode_b64url(encryption_public)
            needs_write = True
        stored_address = data.get("address", "")
        if stored_address != address:
            data["address"] = address
            logger.info(
                "Address in %s rewritten from %r to %r (seed preserved)",
                identity_path, stored_address, address,
            )
            needs_write = True
        if needs_write:
            _atomic_write(identity_path, data)
        return IdentityFile(
            private_seed=seed,
            public_key=public,
            encryption_private_key=encryption_private,
            encryption_public_key=encryption_public,
            address=address,
        )

    # 3. Generate fresh
    seed, public = generate_keypair()
    encryption_private, encryption_public = generate_encryption_keypair()
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(identity_path, {
        "private_seed_b64": encode_b64url(seed),
        "public_key_b64": encode_b64url(public),
        "encryption_private_key_b64": encode_b64url(encryption_private),
        "encryption_public_key_b64": encode_b64url(encryption_public),
        "address": address,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    logger.warning(
        "Generated new AAP identity at %s - back this file up. "
        "Address: %s  Public key: %s",
        identity_path, address, encode_b64url(public),
    )
    return IdentityFile(
        private_seed=seed,
        public_key=public,
        encryption_private_key=encryption_private,
        encryption_public_key=encryption_public,
        address=address,
    )


def _atomic_write(path: Path, data: dict) -> None:
    """Write JSON to `path` atomically with mode 0600."""
    write_json_private(path, data)
