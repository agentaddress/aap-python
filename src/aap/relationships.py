"""Personal-agent relationship records — friend / admin / team.

Replaces the per-action RelationshipToken store. Personal↔personal traffic
is governed by relationship TYPE rather than per-action capability tokens:

  * ``friend`` — bilateral; allows chat. No tool calls across AAP.
  * ``admin`` — same human owns both agents; allows tool calls.
  * ``team(resource)`` — bilateral, scoped to a shared resource label
    (e.g. a repo). Both sides must agree on the label; access is not
    verified at the protocol level (manual setup only).

A relationship is established by a 2-message handshake: one side sends
``aap.relationship-proposal/v1``, the other replies with
``aap.relationship-accept/v1``. Both signed envelopes are persisted on
both sides as cryptographic proof that the relationship exists.

Storage: a single JSON file at ``<base_dir>/aap-relationships.json``.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aap.envelope import Envelope, EnvelopeError
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.keys import decode_b64url
from aap.payloads import (
    AgentCard,
    RelationshipAccept,
    RelationshipDecline,
    RelationshipProposal,
    RelationshipRevoke,
)
from aap.storage import write_json_private

logger = logging.getLogger(__name__)


VALID_RELATIONSHIP_TYPES = frozenset({"friend", "admin", "team"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class RelationshipRecord:
    """One bilateral relationship between this agent and a peer.

    Both ``proposal_envelope_json`` and ``accept_envelope_json`` are stored
    regardless of which side proposed — together they form the
    cryptographic proof that both parties consented.
    """

    relationship_type: str           # "friend" | "admin" | "team"
    peer_address: str
    established_at: str              # RFC 3339
    proposal_envelope_json: str
    accept_envelope_json: str
    resource: Optional[str] = None   # team only

    def matches(self, *, relationship_type: str, resource: Optional[str] = None) -> bool:
        if self.relationship_type != relationship_type:
            return False
        if relationship_type == "team":
            return self.resource == resource
        return True


@dataclass(frozen=True)
class RelationshipRevocationRecord:
    """Signed proof that either party ended a relationship."""

    relationship_type: str
    peer_address: str
    revoked_at: str
    revoker_address: str
    revoke_envelope_json: str
    resource: Optional[str] = None


@dataclass
class RelationshipStore:
    rows: list[RelationshipRecord] = field(default_factory=list)
    revocations: list[RelationshipRevocationRecord] = field(default_factory=list)

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-relationships.json"
        self.rows: list[RelationshipRecord] = []
        self.revocations: list[RelationshipRevocationRecord] = []

    @classmethod
    def load(cls, base_dir: Path) -> "RelationshipStore":
        store = cls(base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("failed to load %s; starting empty", store._path)
            return store
        rows: list[RelationshipRecord] = []
        for r in data.get("relationships") or []:
            try:
                rows.append(RelationshipRecord(**r))
            except TypeError:
                logger.warning("skipping malformed relationship row: %r", r)
        store.rows = rows
        revocations: list[RelationshipRevocationRecord] = []
        for r in data.get("revocations") or []:
            try:
                revocations.append(RelationshipRevocationRecord(**r))
            except TypeError:
                logger.warning("skipping malformed relationship revocation row: %r", r)
        store.revocations = revocations
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {
                "relationships": [asdict(r) for r in self.rows],
                "revocations": [asdict(r) for r in self.revocations],
            },
        )

    # -- queries -----------------------------------------------------------

    def find(
        self,
        peer_address: str,
        *,
        relationship_type: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> Optional[RelationshipRecord]:
        for r in self.rows:
            if r.peer_address != peer_address:
                continue
            if relationship_type is not None and r.relationship_type != relationship_type:
                continue
            if relationship_type == "team" and r.resource != resource:
                continue
            return r
        return None

    def has_friend(self, peer_address: str) -> bool:
        return self.find(peer_address, relationship_type="friend") is not None

    def has_admin(self, peer_address: str) -> bool:
        return self.find(peer_address, relationship_type="admin") is not None

    def has_team(self, peer_address: str, resource: str) -> bool:
        return (
            self.find(peer_address, relationship_type="team", resource=resource) is not None
        )

    def any_relationship_with(self, peer_address: str) -> Optional[RelationshipRecord]:
        for r in self.rows:
            if r.peer_address == peer_address:
                return r
        return None

    def all_for_peer(self, peer_address: str) -> list[RelationshipRecord]:
        return [r for r in self.rows if r.peer_address == peer_address]

    def list_all(self) -> list[RelationshipRecord]:
        return list(self.rows)

    def list_revocations(self) -> list[RelationshipRevocationRecord]:
        return list(self.revocations)

    # -- mutators ----------------------------------------------------------

    def add(self, record: RelationshipRecord) -> None:
        raise ValueError(
            "relationship records must be created with establish() so the "
            "signed proposal and accept envelopes can be verified"
        )

    def establish(
        self,
        *,
        self_address: str,
        peer_address: str,
        proposal_envelope_json: str,
        accept_envelope_json: str,
        proposer_public_key: bytes,
        accepter_public_key: bytes,
    ) -> RelationshipRecord:
        """Verify a relationship handshake, persist it, and return the row.

        The proposal and accept envelopes are the proof of consent.  Storage is
        therefore intentionally a construction API: callers provide the signed
        wire artifacts plus the authenticated public keys resolved from each
        participant's AgentCard/DID path, and the store derives the durable row.
        """
        proposal_env = _parse_envelope(
            proposal_envelope_json, expected_payload_type=RelationshipProposal.PAYLOAD_TYPE
        )
        accept_env = _parse_envelope(
            accept_envelope_json, expected_payload_type=RelationshipAccept.PAYLOAD_TYPE
        )
        _verify_policy(proposal_env, proposer_public_key, label="proposal")
        _verify_policy(accept_env, accepter_public_key, label="accept")

        try:
            proposal = RelationshipProposal.from_dict(proposal_env.payload)
            accept = RelationshipAccept.from_dict(accept_env.payload)
        except ValueError as e:
            raise ValueError(f"invalid relationship handshake payload: {e}") from e

        if accept.proposal_nonce != proposal.nonce:
            raise ValueError("relationship accept does not reference proposal nonce")

        issuers = {proposal_env.iss, accept_env.iss}
        expected_issuers = {self_address, peer_address}
        if issuers != expected_issuers:
            raise ValueError(
                "relationship handshake issuers must be exactly self_address "
                "and peer_address"
            )
        if self_address == peer_address:
            raise ValueError("self_address and peer_address must differ")
        if proposal_env.iss == accept_env.iss:
            raise ValueError("relationship proposal and accept must have different issuers")

        proposer_card = _parse_agent_card(
            proposal.proposer_card_envelope,
            expected_public_key=proposer_public_key,
            label="proposer card",
        )
        if proposer_card.address != proposal_env.iss:
            raise ValueError("proposer AgentCard address does not match proposal issuer")

        accepter_card = _parse_agent_card(
            accept.accepter_card_envelope,
            expected_public_key=accepter_public_key,
            label="accepter card",
        )
        if accepter_card.address != accept_env.iss:
            raise ValueError("accepter AgentCard address does not match accept issuer")

        if self._has_seen_proposal_nonce(proposal.nonce):
            raise ValueError("relationship proposal nonce replay detected")

        record = RelationshipRecord(
            relationship_type=proposal.relationship_type,
            peer_address=peer_address,
            established_at=accept_env.iat,
            proposal_envelope_json=proposal_envelope_json,
            accept_envelope_json=accept_envelope_json,
            resource=proposal.resource,
        )
        self._add_verified(record)
        return record

    def _add_verified(self, record: RelationshipRecord) -> None:
        if record.relationship_type not in VALID_RELATIONSHIP_TYPES:
            raise ValueError(
                f"invalid relationship_type {record.relationship_type!r}"
            )
        if record.relationship_type == "team" and not record.resource:
            raise ValueError("team relationship requires a non-empty resource label")
        # Replace any existing record with the same (peer, type, resource) key.
        self.rows = [
            r for r in self.rows
            if not (
                r.peer_address == record.peer_address
                and r.relationship_type == record.relationship_type
                and r.resource == record.resource
            )
        ]
        self.rows.append(record)
        self._save()

    def _has_seen_proposal_nonce(self, nonce: str) -> bool:
        for record in self.rows:
            try:
                env = _parse_envelope(
                    record.proposal_envelope_json,
                    expected_payload_type=RelationshipProposal.PAYLOAD_TYPE,
                )
                proposal = RelationshipProposal.from_dict(env.payload)
            except ValueError:
                continue
            if proposal.nonce == nonce:
                return True
        return False

    def revoke(
        self,
        *,
        self_address: str,
        peer_address: str,
        revoke_envelope_json: str,
        revoker_public_key: bytes,
    ) -> bool:
        """Verify and persist a signed revocation, then delete the active row."""
        if not isinstance(revoker_public_key, bytes):
            raise ValueError("revoker_public_key must be bytes")
        if self_address == peer_address:
            raise ValueError("self_address and peer_address must differ")

        revoke_env = _parse_envelope(
            revoke_envelope_json, expected_payload_type=RelationshipRevoke.PAYLOAD_TYPE
        )
        _verify_policy(revoke_env, revoker_public_key, label="revoke")
        if revoke_env.iss not in {self_address, peer_address}:
            raise ValueError("relationship revoke issuer must be self_address or peer_address")

        try:
            revoke = RelationshipRevoke.from_dict(revoke_env.payload)
        except ValueError as e:
            raise ValueError(f"invalid relationship revoke payload: {e}") from e

        if self._has_seen_revocation_nonce(revoke.nonce):
            raise ValueError("relationship revoke nonce replay detected")

        revocation = RelationshipRevocationRecord(
            relationship_type=revoke.relationship_type,
            peer_address=peer_address,
            revoked_at=revoke_env.iat,
            revoker_address=revoke_env.iss,
            revoke_envelope_json=revoke_envelope_json,
            resource=revoke.resource,
        )
        self.revocations.append(revocation)

        relationship_type = revoke.relationship_type
        resource = revoke.resource
        before = len(self.rows)
        self.rows = [
            r for r in self.rows
            if not (
                r.peer_address == peer_address
                and r.relationship_type == relationship_type
                and r.resource == resource
            )
        ]
        if len(self.rows) < before:
            self._save()
            return True
        self._save()
        return False

    def _has_seen_revocation_nonce(self, nonce: str) -> bool:
        for record in self.revocations:
            try:
                env = _parse_envelope(
                    record.revoke_envelope_json,
                    expected_payload_type=RelationshipRevoke.PAYLOAD_TYPE,
                )
                revoke = RelationshipRevoke.from_dict(env.payload)
            except ValueError:
                continue
            if revoke.nonce == nonce:
                return True
        return False


# ---------------------------------------------------------------------------
# Envelope builders
# ---------------------------------------------------------------------------


def _parse_envelope(envelope_json: str, *, expected_payload_type: str) -> Envelope:
    try:
        env = Envelope.from_json(envelope_json)
    except (EnvelopeError, ValueError) as e:
        raise ValueError(f"invalid envelope JSON: {e}") from e
    if env.payload_type != expected_payload_type:
        raise ValueError(
            f"expected payload_type {expected_payload_type!r}, got {env.payload_type!r}"
        )
    return env


def _verify_policy(envelope: Envelope, public_key: bytes, *, label: str) -> None:
    try:
        verify_envelope(envelope, public_key)
    except EnvelopePolicyError as e:
        raise ValueError(f"{label} envelope failed verification: {e}") from e


def _parse_agent_card(
    envelope_json: str,
    *,
    expected_public_key: bytes,
    label: str,
) -> AgentCard:
    env = _parse_envelope(envelope_json, expected_payload_type=AgentCard.PAYLOAD_TYPE)
    try:
        card = AgentCard.from_dict(env.payload)
        card_public_key = decode_b64url(card.public_key)
    except ValueError as e:
        raise ValueError(f"invalid {label}: {e}") from e
    if card_public_key != expected_public_key:
        raise ValueError(f"{label} public_key does not match relationship signer")
    _verify_policy(env, card_public_key, label=label)
    return card


def build_relationship_proposal_envelope(
    *,
    seed: bytes,
    sender_address: str,
    relationship_type: str,
    proposer_card_envelope_json: str,
    identity_attestations: Optional[list[str]] = None,
    resource: Optional[str] = None,
    nonce: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    """Build a signed ``aap.relationship-proposal/v1`` envelope.

    ``proposer_card_envelope_json`` is the signed AgentCard envelope
    representing the proposer (the recipient verifies signature, reads
    public_key, etc.). ``identity_attestations`` is a list of signed
    VerificationAttestation envelope JSONs the proposer chooses to share.
    """
    if relationship_type not in VALID_RELATIONSHIP_TYPES:
        raise ValueError(f"invalid relationship_type {relationship_type!r}")
    if relationship_type == "team" and not resource:
        raise ValueError("team proposal requires a non-empty resource label")
    proposal = RelationshipProposal(
        relationship_type=relationship_type,
        proposer_card_envelope=proposer_card_envelope_json,
        nonce=nonce or secrets.token_urlsafe(12),
        identity_attestations=list(identity_attestations or []),
        resource=resource,
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=RelationshipProposal.PAYLOAD_TYPE,
        payload=proposal.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
    ).sign(seed)


def build_relationship_accept_envelope(
    *,
    seed: bytes,
    sender_address: str,
    proposal_nonce: str,
    accepter_card_envelope_json: str,
    identity_attestations: Optional[list[str]] = None,
    iat: Optional[str] = None,
) -> Envelope:
    accept = RelationshipAccept(
        proposal_nonce=proposal_nonce,
        accepter_card_envelope=accepter_card_envelope_json,
        identity_attestations=list(identity_attestations or []),
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=RelationshipAccept.PAYLOAD_TYPE,
        payload=accept.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
    ).sign(seed)


def build_relationship_decline_envelope(
    *,
    seed: bytes,
    sender_address: str,
    proposal_nonce: str,
    reason: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    decline = RelationshipDecline(proposal_nonce=proposal_nonce, reason=reason)
    return Envelope(
        type="aap.envelope/v1",
        payload_type=RelationshipDecline.PAYLOAD_TYPE,
        payload=decline.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
    ).sign(seed)


def build_relationship_revoke_envelope(
    *,
    seed: bytes,
    sender_address: str,
    relationship_type: str,
    nonce: Optional[str] = None,
    resource: Optional[str] = None,
    reason: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    if relationship_type not in VALID_RELATIONSHIP_TYPES:
        raise ValueError(f"invalid relationship_type {relationship_type!r}")
    if relationship_type == "team" and not resource:
        raise ValueError("team revoke requires a non-empty resource label")
    revoke = RelationshipRevoke(
        relationship_type=relationship_type,
        nonce=nonce or secrets.token_urlsafe(12),
        resource=resource,
        reason=reason,
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=RelationshipRevoke.PAYLOAD_TYPE,
        payload=revoke.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
    ).sign(seed)
