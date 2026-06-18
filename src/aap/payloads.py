"""Structured payload types carried inside AAP envelopes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar


def _require_field(d: dict[str, Any], name: str) -> Any:
    if name not in d:
        raise ValueError(f"missing field: {name!r}")
    return d[name]


def _validate_members_list(members: Any, *, field_name: str = "members") -> None:
    """Validate a group-conversation membership list.

    Shared by ``Envelope.from_dict`` (for ``conversation_members``),
    ``GroupInvitation.from_dict``, and ``GroupMembershipUpdate.from_dict``
    so the 10-member cap and shape rules are enforced consistently.
    """
    if not isinstance(members, list):
        raise ValueError(f"{field_name} must be a list of addresses")
    if len(members) < 2:
        raise ValueError(
            f"{field_name} must contain at least 2 addresses, got {len(members)}"
        )
    if len(members) > 10:
        raise ValueError(
            f"{field_name} exceeds the 10-member cap (got {len(members)}); "
            f"at most 10 allowed"
        )
    if not all(isinstance(a, str) and a for a in members):
        raise ValueError(f"{field_name} entries must be non-empty strings")
    if len(set(members)) != len(members):
        raise ValueError(f"{field_name} entries must be unique")


def _validate_endpoint(ep: Any) -> dict[str, str]:
    if not isinstance(ep, dict):
        raise ValueError(f"endpoint must be a dict, got {type(ep).__name__}")
    if "type" not in ep:
        raise ValueError("endpoint missing 'type'")
    if "uri" not in ep:
        raise ValueError("endpoint missing 'uri'")
    for key, value in ep.items():
        if not isinstance(value, str):
            raise ValueError(
                f"endpoint values must be strings, got {type(value).__name__} for {key!r}"
            )
    return dict(ep)


@dataclass(frozen=True)
class VerifiedIdentity:
    """A claim about an identity the agent's owner has verified.

    Embedded in an ``AgentCard`` to surface real-world identifiers
    (phone numbers, email addresses) that the agent's host has
    challenged-and-verified. Recipients can use these for identity
    binding (matching against the user's local contacts), but should
    treat the claim's trust as bounded by trust in the agent's domain
    (since the AgentCard is served from there).
    """
    type: str               # "phone" | "email" | future-extensible
    value: str | None        # E.164 for phones, RFC 5322 for emails; None = presence-only
    verified_at: str         # RFC 3339 timestamp
    verified_by: str         # "self" or "<verifier-domain>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "verified_at": self.verified_at,
            "verified_by": self.verified_by,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifiedIdentity":
        return cls(
            type=_require_field(d, "type"),
            value=d.get("value"),
            verified_at=_require_field(d, "verified_at"),
            verified_by=_require_field(d, "verified_by"),
        )


_AGENT_KIND_VALUES = frozenset({"personal", "business"})


@dataclass(frozen=True)
class AgentCard:
    PAYLOAD_TYPE: ClassVar[str] = "aap.agent-card/v1"

    address: str
    did: str
    public_key: str          # base64url-encoded Ed25519 public key
    endpoints: list[dict[str, str]]
    verified_identities: list[VerifiedIdentity] = field(default_factory=list)
    kind: str = "personal"   # "personal" | "business" — determines which protocol path peers take
    encryption_key: str | None = None  # base64url-encoded X25519 public key

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "address": self.address,
            "did": self.did,
            "public_key": self.public_key,
            "endpoints": list(self.endpoints),
            "kind": self.kind,
        }
        if self.verified_identities:
            out["verified_identities"] = [v.to_dict() for v in self.verified_identities]
        if self.encryption_key is not None:
            out["encryption_key"] = self.encryption_key
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentCard":
        verified = d.get("verified_identities") or []
        encryption_key = d.get("encryption_key")
        if encryption_key is not None and not isinstance(encryption_key, str):
            raise ValueError("encryption_key must be a base64url string when present")
        # Backward compat: pre-v0.6 cards omitted "kind"; treat as personal
        # (the more restrictive default — business agents must opt in explicitly).
        kind = d.get("kind", "personal")
        if kind not in _AGENT_KIND_VALUES:
            raise ValueError(
                f"kind must be one of {sorted(_AGENT_KIND_VALUES)}, got {kind!r}"
            )
        return cls(
            address=_require_field(d, "address"),
            did=_require_field(d, "did"),
            public_key=_require_field(d, "public_key"),
            endpoints=[_validate_endpoint(ep) for ep in _require_field(d, "endpoints")],
            encryption_key=encryption_key,
            verified_identities=[VerifiedIdentity.from_dict(v) for v in verified],
            kind=kind,
        )


@dataclass(frozen=True)
class GroupInvitation:
    PAYLOAD_TYPE: ClassVar[str] = "aap.group-invitation/v1"

    conversation_id: str
    purpose: str
    members: list[str]
    convener: str
    nonce: str
    name: str = ""
    goal: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "conversation_id": self.conversation_id,
            "purpose": self.purpose,
            "members": list(self.members),
            "convener": self.convener,
            "nonce": self.nonce,
        }
        if self.name:
            d["name"] = self.name
        if self.goal:
            d["goal"] = self.goal
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GroupInvitation":
        members_raw = _require_field(d, "members")
        _validate_members_list(members_raw)
        members = list(members_raw)
        convener = _require_field(d, "convener")
        if convener not in members:
            raise ValueError(f"convener {convener!r} must be in members list")
        return cls(
            conversation_id=_require_field(d, "conversation_id"),
            purpose=_require_field(d, "purpose"),
            members=members,
            convener=convener,
            nonce=_require_field(d, "nonce"),
            name=d.get("name", ""),
            goal=d.get("goal", ""),
        )


@dataclass(frozen=True)
class GroupMembershipUpdate:
    PAYLOAD_TYPE: ClassVar[str] = "aap.group-membership-update/v1"

    conversation_id: str
    members: list[str]
    convener: str
    added: list[str]
    removed: list[str]
    convener_changed_from: str | None
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "members": list(self.members),
            "convener": self.convener,
            "added": list(self.added),
            "removed": list(self.removed),
            "convener_changed_from": self.convener_changed_from,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GroupMembershipUpdate":
        members_raw = _require_field(d, "members")
        _validate_members_list(members_raw)
        members = list(members_raw)
        convener = _require_field(d, "convener")
        if convener not in members:
            raise ValueError(f"convener {convener!r} must be in members list")
        return cls(
            conversation_id=_require_field(d, "conversation_id"),
            members=members,
            convener=convener,
            added=list(d.get("added") or []),
            removed=list(d.get("removed") or []),
            convener_changed_from=d.get("convener_changed_from"),
            nonce=_require_field(d, "nonce"),
        )


@dataclass(frozen=True)
class GroupComplete:
    """Sent by the convener to signal the group goal has been achieved.

    All members should treat this as a terminal event for the conversation —
    no further coordination is expected. The ``outcome`` field carries a
    human-readable summary of what was accomplished.
    """
    PAYLOAD_TYPE: ClassVar[str] = "aap.group-complete/v1"

    conversation_id: str
    outcome: str
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "outcome": self.outcome,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GroupComplete":
        return cls(
            conversation_id=_require_field(d, "conversation_id"),
            outcome=_require_field(d, "outcome"),
            nonce=_require_field(d, "nonce"),
        )


@dataclass(frozen=True)
class VerificationAttestation:
    PAYLOAD_TYPE: ClassVar[str] = "aap.verification-attestation/v1"

    subject_address: str
    identity: dict[str, str]    # {"type": "phone" | "email", "value": "..."}
    challenge_method: str       # "sms-otp", "email-link", etc.
    verified_at: str
    expires_at: str
    verifier: str               # domain of the verifier; must equal envelope.iss
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_address": self.subject_address,
            "identity": dict(self.identity),
            "challenge_method": self.challenge_method,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "verifier": self.verifier,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerificationAttestation":
        identity = _require_field(d, "identity")
        if not isinstance(identity, dict):
            raise ValueError("identity must be a dict")
        if "type" not in identity or "value" not in identity:
            raise ValueError("identity missing required 'type' or 'value'")
        return cls(
            subject_address=_require_field(d, "subject_address"),
            identity={"type": identity["type"], "value": identity["value"]},
            challenge_method=_require_field(d, "challenge_method"),
            verified_at=_require_field(d, "verified_at"),
            expires_at=_require_field(d, "expires_at"),
            verifier=_require_field(d, "verifier"),
            nonce=_require_field(d, "nonce"),
        )


@dataclass(frozen=True)
class VerifyStartResponse:
    PAYLOAD_TYPE: ClassVar[str] = "aap.verify-start-response/v1"

    request_nonce: str
    otp_id: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_nonce": self.request_nonce,
            "otp_id": self.otp_id,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyStartResponse":
        return cls(
            request_nonce=_require_field(d, "request_nonce"),
            otp_id=_require_field(d, "otp_id"),
            expires_at=_require_field(d, "expires_at"),
        )


@dataclass(frozen=True)
class VerifyConfirmResponse:
    PAYLOAD_TYPE: ClassVar[str] = "aap.verify-confirm-response/v1"

    request_nonce: str
    otp_id: str
    attestation_envelope: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_nonce": self.request_nonce,
            "otp_id": self.otp_id,
            "attestation_envelope": self.attestation_envelope,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyConfirmResponse":
        return cls(
            request_nonce=_require_field(d, "request_nonce"),
            otp_id=_require_field(d, "otp_id"),
            attestation_envelope=_require_field(d, "attestation_envelope"),
        )


@dataclass(frozen=True)
class DiscoveryIntroductionRequest:
    PAYLOAD_TYPE: ClassVar[str] = "aap.discovery-introduction-request/v1"

    searcher: str
    verifier_nonce: str
    expires_at: str
    searcher_label_for_recipient: str | None = None
    searcher_attestations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "searcher": self.searcher,
            "verifier_nonce": self.verifier_nonce,
            "expires_at": self.expires_at,
        }
        if self.searcher_label_for_recipient is not None:
            out["searcher_label_for_recipient"] = self.searcher_label_for_recipient
        if self.searcher_attestations:
            out["searcher_attestations"] = list(self.searcher_attestations)
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DiscoveryIntroductionRequest":
        return cls(
            searcher=_require_field(d, "searcher"),
            verifier_nonce=_require_field(d, "verifier_nonce"),
            expires_at=_require_field(d, "expires_at"),
            searcher_label_for_recipient=d.get("searcher_label_for_recipient"),
            searcher_attestations=list(d.get("searcher_attestations") or []),
        )


@dataclass(frozen=True)
class DiscoveryIntroductionResponse:
    PAYLOAD_TYPE: ClassVar[str] = "aap.discovery-introduction-response/v1"

    verifier_nonce: str
    approved: bool

    def to_dict(self) -> dict[str, Any]:
        return {"verifier_nonce": self.verifier_nonce, "approved": self.approved}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DiscoveryIntroductionResponse":
        return cls(
            verifier_nonce=_require_field(d, "verifier_nonce"),
            approved=bool(_require_field(d, "approved")),
        )


@dataclass(frozen=True)
class DiscoveryQueryResponse:
    PAYLOAD_TYPE: ClassVar[str] = "aap.discovery-query-response/v1"

    query_nonce: str
    result: str | None
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "query_nonce": self.query_nonce,
            "result": self.result,
        }
        if self.expires_at is not None:
            out["expires_at"] = self.expires_at
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DiscoveryQueryResponse":
        result = d.get("result")
        if result is not None and not isinstance(result, str):
            raise ValueError("result must be a string or null")
        expires_at = d.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, str):
            raise ValueError("expires_at must be a string")
        return cls(
            query_nonce=_require_field(d, "query_nonce"),
            result=result,
            expires_at=expires_at,
        )


@dataclass(frozen=True)
class GroupLeave:
    PAYLOAD_TYPE: ClassVar[str] = "aap.group-leave/v1"

    conversation_id: str
    nonce: str
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "conversation_id": self.conversation_id,
            "nonce": self.nonce,
        }
        if self.reason is not None:
            out["reason"] = self.reason
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GroupLeave":
        return cls(
            conversation_id=_require_field(d, "conversation_id"),
            nonce=_require_field(d, "nonce"),
            reason=d.get("reason"),
        )


# ---------------------------------------------------------------------------
# v0.6 — services + relationships
#
# Replaces the capability/scope/token machinery. Two protocol paths:
#   * personal ↔ business : ServiceRequest / ServiceResponse against a catalog
#   * personal ↔ personal : RelationshipProposal / Accept / Decline / Revoke
# Plus one residual token type for business-initiated recurring outreach:
#   * ServiceFollowupGrant (customer → business)
#   * ServiceFollowup     (business → customer, gated by the grant)
# ---------------------------------------------------------------------------


_RELATIONSHIP_TYPE_VALUES = frozenset({"friend", "admin", "team"})


class ServiceResponseStatus(str, Enum):
    CONFIRMED = "confirmed"
    DENIED = "denied"
    PENDING = "pending"


@dataclass(frozen=True)
class ServiceRequest:
    """A request to invoke one entry in the recipient's published service catalog.

    The payload data fields are validated against the catalog's input_schema by
    the receiver. Verification attestations (signed VerificationAttestation
    envelopes) ride on Envelope.verification_attestations — not in this payload.
    """
    PAYLOAD_TYPE: ClassVar[str] = "aap.service-request/v1"

    service_id: str
    payload: dict[str, Any]
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "payload": dict(self.payload),
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ServiceRequest":
        payload = _require_field(d, "payload")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        return cls(
            service_id=_require_field(d, "service_id"),
            payload=dict(payload),
            nonce=_require_field(d, "nonce"),
        )


@dataclass(frozen=True)
class ServiceResponse:
    """Reply to a ServiceRequest.

    status="confirmed" — payload carries the success result (e.g. confirmation id).
    status="denied"    — denial_reason is set; payload may carry hints.
    status="pending"   — async; sender will see follow-up envelopes later.
    """
    PAYLOAD_TYPE: ClassVar[str] = "aap.service-response/v1"

    service_id: str
    request_nonce: str
    status: ServiceResponseStatus
    nonce: str
    payload: dict[str, Any] = field(default_factory=dict)
    denial_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "nonce": self.nonce,
            "service_id": self.service_id,
            "request_nonce": self.request_nonce,
            "status": self.status.value,
            "payload": dict(self.payload),
        }
        if self.denial_reason is not None:
            out["denial_reason"] = self.denial_reason
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ServiceResponse":
        status_str = _require_field(d, "status")
        try:
            status = ServiceResponseStatus(status_str)
        except ValueError:
            raise ValueError(f"unknown service-response status: {status_str!r}")
        payload = d.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        return cls(
            service_id=_require_field(d, "service_id"),
            request_nonce=_require_field(d, "request_nonce"),
            status=status,
            nonce=_require_field(d, "nonce"),
            payload=dict(payload),
            denial_reason=d.get("denial_reason"),
        )


@dataclass(frozen=True)
class RelationshipProposal:
    """Personal-agent handshake initiator. The proposer asks to establish a
    typed relationship (friend / admin / team) with the recipient.

    proposer_card_envelope is a signed AgentCard envelope (JSON string) — lets
    the recipient verify the proposer's identity material. identity_attestations
    are signed VerificationAttestation envelope JSONs the proposer chooses to
    share (phone/email) so the recipient can match against their contacts.

    For type="team", resource is a free-form shared-resource label. Both sides
    must agree on the label; the protocol does not verify access.
    """
    PAYLOAD_TYPE: ClassVar[str] = "aap.relationship-proposal/v1"

    relationship_type: str               # "friend" | "admin" | "team"
    proposer_card_envelope: str          # signed AgentCard envelope (JSON)
    nonce: str
    identity_attestations: list[str] = field(default_factory=list)
    resource: str | None = None          # required when type=="team"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "relationship_type": self.relationship_type,
            "proposer_card_envelope": self.proposer_card_envelope,
            "nonce": self.nonce,
        }
        if self.identity_attestations:
            out["identity_attestations"] = list(self.identity_attestations)
        if self.resource is not None:
            out["resource"] = self.resource
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RelationshipProposal":
        rt = _require_field(d, "relationship_type")
        if rt not in _RELATIONSHIP_TYPE_VALUES:
            raise ValueError(
                f"relationship_type must be one of {sorted(_RELATIONSHIP_TYPE_VALUES)}, got {rt!r}"
            )
        resource = d.get("resource")
        if rt == "team" and not resource:
            raise ValueError("relationship_type='team' requires a 'resource' label")
        return cls(
            relationship_type=rt,
            proposer_card_envelope=_require_field(d, "proposer_card_envelope"),
            nonce=_require_field(d, "nonce"),
            identity_attestations=list(d.get("identity_attestations") or []),
            resource=resource,
        )


@dataclass(frozen=True)
class RelationshipAccept:
    """Acceptance of a RelationshipProposal. References the proposal's nonce
    and mirrors the proposer's identity material from the accepter's side."""
    PAYLOAD_TYPE: ClassVar[str] = "aap.relationship-accept/v1"

    proposal_nonce: str
    accepter_card_envelope: str
    identity_attestations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "proposal_nonce": self.proposal_nonce,
            "accepter_card_envelope": self.accepter_card_envelope,
        }
        if self.identity_attestations:
            out["identity_attestations"] = list(self.identity_attestations)
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RelationshipAccept":
        return cls(
            proposal_nonce=_require_field(d, "proposal_nonce"),
            accepter_card_envelope=_require_field(d, "accepter_card_envelope"),
            identity_attestations=list(d.get("identity_attestations") or []),
        )


@dataclass(frozen=True)
class RelationshipDecline:
    PAYLOAD_TYPE: ClassVar[str] = "aap.relationship-decline/v1"

    proposal_nonce: str
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"proposal_nonce": self.proposal_nonce}
        if self.reason is not None:
            out["reason"] = self.reason
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RelationshipDecline":
        return cls(
            proposal_nonce=_require_field(d, "proposal_nonce"),
            reason=d.get("reason"),
        )


@dataclass(frozen=True)
class RelationshipRevoke:
    """Either side may send this to end a relationship. The receiver deletes
    its local record; future messages from the revoker fall back to the
    stranger gate."""
    PAYLOAD_TYPE: ClassVar[str] = "aap.relationship-revoke/v1"

    relationship_type: str               # "friend" | "admin" | "team"
    nonce: str
    resource: str | None = None          # for team relationships
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "relationship_type": self.relationship_type,
            "nonce": self.nonce,
        }
        if self.resource is not None:
            out["resource"] = self.resource
        if self.reason is not None:
            out["reason"] = self.reason
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RelationshipRevoke":
        rt = _require_field(d, "relationship_type")
        if rt not in _RELATIONSHIP_TYPE_VALUES:
            raise ValueError(
                f"relationship_type must be one of {sorted(_RELATIONSHIP_TYPE_VALUES)}, got {rt!r}"
            )
        resource = d.get("resource")
        if rt == "team" and not resource:
            raise ValueError("relationship_type='team' requires a 'resource' label")
        return cls(
            relationship_type=rt,
            nonce=_require_field(d, "nonce"),
            resource=resource,
            reason=d.get("reason"),
        )


@dataclass(frozen=True)
class ServiceFollowupGrant:
    """Customer → business: standing authorization to break the silence and
    send ONE follow-up proposal per cadence window. The customer's adapter
    stores this locally and references it when validating inbound
    ServiceFollowup envelopes from the business.
    """
    PAYLOAD_TYPE: ClassVar[str] = "aap.service-followup-grant/v1"

    service_id: str
    cadence_iso: str                  # ISO 8601 duration, e.g. "P6M"
    outreach_window_before: str       # how early before due, e.g. "P1M"
    valid_until: str                  # absolute RFC 3339 ts
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "cadence_iso": self.cadence_iso,
            "outreach_window_before": self.outreach_window_before,
            "valid_until": self.valid_until,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ServiceFollowupGrant":
        return cls(
            service_id=_require_field(d, "service_id"),
            cadence_iso=_require_field(d, "cadence_iso"),
            outreach_window_before=_require_field(d, "outreach_window_before"),
            valid_until=_require_field(d, "valid_until"),
            nonce=_require_field(d, "nonce"),
        )


@dataclass(frozen=True)
class ServiceFollowup:
    """Business → customer: a proposal to schedule the next iteration of a
    recurring service. Not a tool call — the customer's user must confirm
    before any booking happens. The receiver validates grant_nonce against
    its locally-stored ServiceFollowupGrant and checks cadence/window.
    """
    PAYLOAD_TYPE: ClassVar[str] = "aap.service-followup/v1"

    service_id: str
    grant_nonce: str                  # references a stored ServiceFollowupGrant
    message: str
    nonce: str
    suggested_slots: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "service_id": self.service_id,
            "grant_nonce": self.grant_nonce,
            "message": self.message,
            "nonce": self.nonce,
        }
        if self.suggested_slots:
            out["suggested_slots"] = list(self.suggested_slots)
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ServiceFollowup":
        return cls(
            service_id=_require_field(d, "service_id"),
            grant_nonce=_require_field(d, "grant_nonce"),
            message=_require_field(d, "message"),
            nonce=_require_field(d, "nonce"),
            suggested_slots=list(d.get("suggested_slots") or []),
        )
