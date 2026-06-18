"""Local store of held VerificationAttestation envelopes.

When the agent verifies a phone or email with a trusted verifier, the
returned signed attestation envelope is persisted here. Later, when the
agent sends a ``capability_request`` to a recipient whose catalog
declares ``verification_required``, the relevant attestation is fetched
from this store and attached to the outgoing envelope.

Storage is a flat JSON file at ``<base_dir>/aap-attestations.json``:

    {
        "attestations": [
            {
                "identity_type": "phone",
                "identifier_value": "+14155551111",
                "verifier": "verify.aap.org",
                "verified_at": "...",
                "expires_at": "...",
                "attestation_envelope_json": "..."
            },
            ...
        ]
    }

The ``attestation_envelope_json`` is the raw signed envelope JSON — the
exact bytes the verifier returned. It's what gets attached to outgoing
envelopes so the recipient can verify the signature against the
verifier's pubkey.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from aap.envelope import Envelope
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.payloads import VerificationAttestation
from aap.storage import write_json_private

logger = logging.getLogger(__name__)


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class StoredAttestation:
    """One row in the attestation store."""

    identity_type: str          # "phone" | "email"
    identifier_value: str       # "+14154442222"
    verifier: str               # "verify.aap.org"
    verified_at: str            # RFC 3339
    expires_at: str             # RFC 3339
    attestation_envelope_json: str

    @classmethod
    def from_envelope_json(
        cls,
        envelope_json: str,
        *,
        verifier_public_key: bytes,
    ) -> "StoredAttestation":
        env = Envelope.from_json(envelope_json)
        if env.payload_type != VerificationAttestation.PAYLOAD_TYPE:
            raise ValueError(
                f"expected payload_type {VerificationAttestation.PAYLOAD_TYPE!r}, "
                f"got {env.payload_type!r}"
            )
        att = VerificationAttestation.from_dict(env.payload)
        if env.iss != att.verifier:
            raise ValueError(
                f"attestation envelope issuer {env.iss!r} does not match "
                f"payload verifier {att.verifier!r}"
            )
        try:
            verify_envelope(env, verifier_public_key, max_age_seconds=None)
        except EnvelopePolicyError as e:
            raise ValueError(f"attestation envelope failed verification: {e}") from e
        identifier_value = att.identity.get("value")
        if not identifier_value:
            raise ValueError(
                "attestation identity.value missing — cannot store a presence-only "
                "attestation as a held credential"
            )
        return cls(
            identity_type=att.identity["type"],
            identifier_value=identifier_value,
            verifier=att.verifier,
            verified_at=att.verified_at,
            expires_at=att.expires_at,
            attestation_envelope_json=envelope_json,
        )

    def is_expired(self, *, now: Optional[datetime] = None) -> bool:
        now = now or _now_utc()
        try:
            return _parse_iso(self.expires_at) <= now
        except ValueError:
            return True

    def age_days(self, *, now: Optional[datetime] = None) -> float:
        now = now or _now_utc()
        try:
            return (now - _parse_iso(self.verified_at)).total_seconds() / 86400.0
        except ValueError:
            return float("inf")


@dataclass
class AttestationStore:
    """Persistent collection of held attestations."""

    rows: list[StoredAttestation]

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-attestations.json"
        self.rows: list[StoredAttestation] = []

    @classmethod
    def load(cls, base_dir: Path) -> "AttestationStore":
        store = cls(base_dir=base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("Failed to read %s; starting empty", store._path)
            return store
        raw_rows = data.get("attestations") or []
        rows: list[StoredAttestation] = []
        for r in raw_rows:
            try:
                rows.append(StoredAttestation(**r))
            except TypeError:
                logger.warning("Skipping malformed attestation row: %r", r)
        store.rows = rows
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {"attestations": [asdict(r) for r in self.rows]},
        )

    def record(
        self,
        envelope_json: str,
        *,
        verifier_public_key: bytes,
    ) -> StoredAttestation:
        """Parse and persist a signed VerificationAttestation envelope.

        Raises ``ValueError`` if the envelope's ``payload_type`` is not
        ``aap.verification-attestation/v1``, the payload is malformed, the
        verifier signature is invalid, or the verifier nonce was already stored.
        """
        row = StoredAttestation.from_envelope_json(
            envelope_json,
            verifier_public_key=verifier_public_key,
        )
        if any(
            _stored_nonce(existing.attestation_envelope_json) == _stored_nonce(envelope_json)
            and existing.verifier == row.verifier
            for existing in self.rows
        ):
            raise ValueError("attestation replay detected: verifier nonce already stored")
        self.rows.append(row)
        self._save()
        return row

    def held_for(self, identity_type: str) -> list[StoredAttestation]:
        return [r for r in self.rows if r.identity_type == identity_type]

    def matching(
        self,
        *,
        identity_type: str,
        verifiers_oneof: Iterable[str],
        max_age_days: int,
        now: Optional[datetime] = None,
    ) -> Optional[StoredAttestation]:
        """Find one attestation that satisfies the supplied constraints.

        The constraints mirror the ``verification_required`` block on a
        capability-catalog entry: identity type, allowed verifier set,
        max age (now - verified_at). Expired attestations are always
        rejected. Returns the first match (insertion order) or None.
        """
        now = now or _now_utc()
        allowed = set(verifiers_oneof)
        for row in self.rows:
            if row.identity_type != identity_type:
                continue
            if row.verifier not in allowed:
                continue
            if row.is_expired(now=now):
                continue
            if row.age_days(now=now) > max_age_days:
                continue
            return row
        return None

    def remove_expired(self, *, now: Optional[datetime] = None) -> int:
        """Drop expired attestations. Returns the number removed."""
        now = now or _now_utc()
        before = len(self.rows)
        self.rows = [r for r in self.rows if not r.is_expired(now=now)]
        removed = before - len(self.rows)
        if removed:
            self._save()
        return removed


def _stored_nonce(envelope_json: str) -> str | None:
    try:
        env = Envelope.from_json(envelope_json)
        att = VerificationAttestation.from_dict(env.payload)
    except Exception:
        return None
    return att.nonce
