"""Parser for the /.well-known/aap-trusted-verifiers list.

The standards-body domain publishes this document declaring which
verifiers it considers trusted. Recipient hosts fetch the document,
cache it (24h TTL recommended), and consult it whenever a verification
or discovery flow needs to decide whether to trust an attestation /
issue a discovery query.

This module only parses the JSON. Fetching, caching, and policy
decisions live in host implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aap.keys import decode_b64url


@dataclass(frozen=True)
class VerifierTrustListEntry:
    domain: str
    supported_identities: list[str]   # ["phone", "email", ...]
    discovery_endpoint: str           # https://...
    verification_endpoint: str        # https://...
    pubkey_endpoint: str              # https://...
    public_key: str                   # base64url Ed25519 public key
    policy_url: str | None = None
    trust_score: str | None = None     # informational (e.g., "established")


def parse_trusted_verifiers(data: dict[str, Any]) -> list[VerifierTrustListEntry]:
    """Parse the JSON body of /.well-known/aap-trusted-verifiers.

    Raises ``ValueError`` for malformed entries (non-HTTPS endpoints,
    missing required fields, etc.).
    """
    verifiers = data.get("verifiers") or []
    if not isinstance(verifiers, list):
        raise ValueError("verifiers must be a list")

    entries: list[VerifierTrustListEntry] = []
    for v in verifiers:
        if not isinstance(v, dict):
            raise ValueError("each verifier entry must be a dict")
        for required in (
            "domain", "supported_identities",
            "discovery_endpoint", "verification_endpoint", "pubkey_endpoint",
            "public_key",
        ):
            if required not in v:
                raise ValueError(f"verifier entry missing required field {required!r}")
        for ep_field in ("discovery_endpoint", "verification_endpoint", "pubkey_endpoint"):
            url = v[ep_field]
            if not (isinstance(url, str) and url.startswith("https://")):
                raise ValueError(
                    f"verifier {v.get('domain')!r}: {ep_field} must be an https:// endpoint, got {url!r}"
                )
        identities = v["supported_identities"]
        if not isinstance(identities, list) or not all(isinstance(i, str) for i in identities):
            raise ValueError(
                f"verifier {v['domain']!r}: supported_identities must be list of strings"
            )
        public_key = v["public_key"]
        if not isinstance(public_key, str):
            raise ValueError(f"verifier {v['domain']!r}: public_key must be a string")
        try:
            decoded_public_key = decode_b64url(public_key)
        except Exception as e:
            raise ValueError(
                f"verifier {v['domain']!r}: public_key must be base64url"
            ) from e
        if len(decoded_public_key) != 32:
            raise ValueError(
                f"verifier {v['domain']!r}: public_key must decode to 32 bytes"
            )
        entries.append(VerifierTrustListEntry(
            domain=v["domain"],
            supported_identities=list(identities),
            discovery_endpoint=v["discovery_endpoint"],
            verification_endpoint=v["verification_endpoint"],
            pubkey_endpoint=v["pubkey_endpoint"],
            public_key=public_key,
            policy_url=v.get("policy_url"),
            trust_score=v.get("trust_score"),
        ))
    return entries
