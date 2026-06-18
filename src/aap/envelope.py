"""AAP signed envelope.

Wire shape:
    {
        "iat": "...",
        "iss": "did:...",
        "payload": {...},
        "payload_type": "aap.<thing>/vN",
        "sig": "base64url-ed25519",
        "type": "aap.envelope/v1",
        "v": 1
    }

The signature is computed over the JCS canonical form of every field
*except* "sig". This file is the only place that knows the wire format.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Optional

from aap.jcs import canonicalize
from aap.keys import decode_b64url, encode_b64url, sign as _sign, verify as _verify

ENVELOPE_VERSION = 1
ENVELOPE_TYPE = "aap.envelope/v1"


class EnvelopeError(ValueError):
    """Raised for any envelope construction, parsing, or verification error."""


@dataclass(frozen=True)
class Envelope:
    """A signed AAP envelope.

    v0.1.x note on temporal validation:
        This library does NOT validate `iat` (issued-at) timestamps,
        does NOT enforce expiry, and does NOT detect replay. Envelopes
        carry the timestamp but verification is purely cryptographic.
        Callers responsible for temporal policy (clock skew windows,
        replay caches, expiry enforcement) must implement it themselves.
    """

    type: str
    payload_type: str
    payload: dict[str, Any]
    iss: str
    iat: str
    sig: str | None = None
    capability_token: Optional[str] = None
    conversation_id: Optional[str] = None
    conversation_members: Optional[list[str]] = None
    verification_attestations: Optional[list[str]] = None

    def _signing_dict(self) -> dict[str, Any]:
        """Dict used for canonical signing bytes (excludes 'sig').

        If ``capability_token``, ``conversation_id``,
        ``conversation_members``, or ``verification_attestations`` are
        set, they are included in the signed form so that detaching,
        swapping, or modifying any of those fields invalidates the
        signature. Fields are omitted when None (or empty list) so
        backward-compatibility with envelopes that never set them is
        preserved (canonical bytes are byte-identical to previous versions).
        """
        out: dict[str, Any] = {
            "iat": self.iat,
            "iss": self.iss,
            "payload": self.payload,
            "payload_type": self.payload_type,
            "type": self.type,
            "v": ENVELOPE_VERSION,
        }
        if self.capability_token is not None:
            out["capability_token"] = self.capability_token
        if self.conversation_id is not None:
            out["conversation_id"] = self.conversation_id
        if self.conversation_members is not None:
            out["conversation_members"] = list(self.conversation_members)
        if self.verification_attestations:
            out["verification_attestations"] = list(self.verification_attestations)
        return out

    def canonical_bytes(self) -> bytes:
        return canonicalize(self._signing_dict())

    def sign(self, private_seed: bytes) -> "Envelope":
        signature = _sign(private_seed, self.canonical_bytes())
        return replace(self, sig=encode_b64url(signature))

    def verify(self, public_key: bytes) -> bool:
        if self.sig is None:
            raise EnvelopeError("envelope is not signed")
        try:
            signature = decode_b64url(self.sig)
        except ValueError:
            return False
        return _verify(public_key, self.canonical_bytes(), signature)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to wire dict form (canonical key order via JCS round-trip)."""
        return json.loads(self.to_json())

    def to_json(self) -> str:
        d = self._signing_dict()
        if self.sig is not None:
            d["sig"] = self.sig
        # Emit in JCS-canonical order so wire form is stable.
        return canonicalize(d).decode("utf-8")

    @classmethod
    def from_json(cls, s: str) -> "Envelope":
        try:
            d = json.loads(s)
        except json.JSONDecodeError as e:
            raise EnvelopeError(f"invalid JSON: {e}") from e
        return cls.from_dict(d)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Envelope":
        allowed_fields = {
            "type", "payload_type", "payload", "iss", "iat", "v", "sig",
            "capability_token", "conversation_id", "conversation_members",
            "verification_attestations",
        }
        unknown = set(d) - allowed_fields
        if unknown:
            raise EnvelopeError(f"unknown field(s): {sorted(unknown)!r}")
        for required in ("type", "payload_type", "payload", "iss", "iat", "v"):
            if required not in d:
                raise EnvelopeError(f"missing field: {required!r}")
        if d["v"] != ENVELOPE_VERSION:
            raise EnvelopeError(
                f"unsupported envelope version: {d['v']!r} (expected {ENVELOPE_VERSION})"
            )
        if d["type"] != ENVELOPE_TYPE:
            raise EnvelopeError(
                f"unsupported envelope type: {d['type']!r} (expected {ENVELOPE_TYPE!r})"
            )
        conv_members = d.get("conversation_members")
        if conv_members is not None:
            # Import locally to avoid a circular import at module load.
            from aap.payloads import _validate_members_list
            _validate_members_list(conv_members, field_name="conversation_members")
            conv_members = list(conv_members)
        ver_atts = d.get("verification_attestations")
        if ver_atts is not None:
            if not isinstance(ver_atts, list) or not all(
                isinstance(a, str) for a in ver_atts
            ):
                raise EnvelopeError(
                    "verification_attestations must be a list of strings"
                )
            ver_atts = list(ver_atts)
        return cls(
            type=d["type"],
            payload_type=d["payload_type"],
            payload=d["payload"],
            iss=d["iss"],
            iat=d["iat"],
            sig=d.get("sig"),
            capability_token=d.get("capability_token"),
            conversation_id=d.get("conversation_id"),
            conversation_members=conv_members,
            verification_attestations=ver_atts,
        )
