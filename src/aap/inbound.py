"""Strict inbound receive policy for AAP chat envelopes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from aap.encryption import EncryptedEnvelope, EncryptionError, decrypt_envelope
from aap.envelope import Envelope, EnvelopeError
from aap.envelope_policy import (
    DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
    EnvelopePolicyError,
    EnvelopeReplayCache,
    verify_envelope,
)
from aap.messages import UnsupportedPayloadType, unwrap_chat_envelope
from aap.relationships import RelationshipRecord, RelationshipStore


class InboundPolicyError(ValueError):
    """Raised when an inbound envelope fails receive policy."""


@dataclass(frozen=True)
class ValidatedEnvelope:
    """A signed envelope that has passed decryption, signature, and freshness."""

    envelope: Envelope
    sender_address: str


@dataclass(frozen=True)
class ValidatedChat:
    """A chat message that has passed decryption, signature, and auth checks."""

    envelope: Envelope
    sender_address: str
    text: str
    thread_id: str | None
    relationship: RelationshipRecord


def validate_inbound_chat(
    value: EncryptedEnvelope | Envelope | dict[str, Any] | str,
    *,
    recipient_private_key: bytes,
    recipient_address: str,
    sender_public_key: bytes,
    relationship_store: RelationshipStore,
    replay_cache: EnvelopeReplayCache | None = None,
    now: datetime | None = None,
    max_age_seconds: int | None = DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
    allowed_relationship_types: Iterable[str] = ("friend", "admin"),
    allow_plaintext: bool = False,
) -> ValidatedChat:
    """Validate one inbound chat message and return its trusted contents.

    The default receive path requires HPKE encryption. After decryption, the
    inner signed envelope is verified for sender signature, freshness, optional
    replay cache, chat payload shape, and active relationship authorization.
    """
    validated = validate_inbound_envelope(
        value,
        recipient_private_key=recipient_private_key,
        recipient_address=recipient_address,
        sender_public_key=sender_public_key,
        replay_cache=replay_cache,
        now=now,
        max_age_seconds=max_age_seconds,
        allow_plaintext=allow_plaintext,
    )
    envelope = validated.envelope

    try:
        text, thread_id = unwrap_chat_envelope(envelope)
    except (UnsupportedPayloadType, ValueError) as e:
        raise InboundPolicyError(f"inbound chat payload rejected: {e}") from e

    relationship = _authorized_relationship(
        relationship_store,
        sender_address=envelope.iss,
        allowed_relationship_types=allowed_relationship_types,
    )
    return ValidatedChat(
        envelope=envelope,
        sender_address=envelope.iss,
        text=text,
        thread_id=thread_id,
        relationship=relationship,
    )


def validate_inbound_envelope(
    value: EncryptedEnvelope | Envelope | dict[str, Any] | str,
    *,
    recipient_private_key: bytes,
    recipient_address: str,
    sender_public_key: bytes,
    replay_cache: EnvelopeReplayCache | None = None,
    now: datetime | None = None,
    max_age_seconds: int | None = DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
    allow_plaintext: bool = False,
) -> ValidatedEnvelope:
    """Decrypt or parse an inbound envelope, then verify signature/freshness.

    This is the protocol-level receive gate. Hosts that need to route multiple
    payload types should use this first, then apply payload-specific policy.
    """
    envelope = _decrypt_or_parse_inbound(
        value,
        recipient_private_key=recipient_private_key,
        recipient_address=recipient_address,
        allow_plaintext=allow_plaintext,
    )
    try:
        verify_envelope(
            envelope,
            sender_public_key,
            now=now,
            max_age_seconds=max_age_seconds,
            replay_cache=replay_cache,
        )
    except EnvelopePolicyError as e:
        raise InboundPolicyError(f"inbound envelope failed verification: {e}") from e
    return ValidatedEnvelope(envelope=envelope, sender_address=envelope.iss)


def _decrypt_or_parse_inbound(
    value: EncryptedEnvelope | Envelope | dict[str, Any] | str,
    *,
    recipient_private_key: bytes,
    recipient_address: str,
    allow_plaintext: bool,
) -> Envelope:
    if isinstance(value, Envelope):
        if not allow_plaintext:
            raise InboundPolicyError("plaintext inbound envelopes are not accepted")
        return value
    if isinstance(value, EncryptedEnvelope):
        return _decrypt(value, recipient_private_key, recipient_address)

    data: dict[str, Any]
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except json.JSONDecodeError as e:
            raise InboundPolicyError(f"inbound value is not valid JSON: {e}") from e
    elif isinstance(value, dict):
        data = value
    else:
        raise InboundPolicyError(f"unsupported inbound value type {type(value).__name__}")

    envelope_type = data.get("type")
    if envelope_type == "aap.encrypted-envelope/v1":
        try:
            encrypted = EncryptedEnvelope.from_dict(data)
        except EncryptionError as e:
            raise InboundPolicyError(f"malformed encrypted inbound envelope: {e}") from e
        return _decrypt(encrypted, recipient_private_key, recipient_address)
    if envelope_type == "aap.envelope/v1":
        if not allow_plaintext:
            raise InboundPolicyError("plaintext inbound envelopes are not accepted")
        try:
            return Envelope.from_dict(data)
        except EnvelopeError as e:
            raise InboundPolicyError(f"malformed plaintext inbound envelope: {e}") from e
    raise InboundPolicyError(f"unsupported inbound envelope type {envelope_type!r}")


def _decrypt(
    encrypted: EncryptedEnvelope,
    recipient_private_key: bytes,
    recipient_address: str,
) -> Envelope:
    try:
        return decrypt_envelope(
            encrypted,
            recipient_private_key=recipient_private_key,
            recipient_address=recipient_address,
        )
    except EncryptionError as e:
        raise InboundPolicyError(f"inbound envelope decryption failed: {e}") from e


def _authorized_relationship(
    relationship_store: RelationshipStore,
    *,
    sender_address: str,
    allowed_relationship_types: Iterable[str],
) -> RelationshipRecord:
    allowed = tuple(allowed_relationship_types)
    if not allowed:
        raise InboundPolicyError("at least one relationship type must be allowed")
    for relationship_type in allowed:
        record = relationship_store.find(
            sender_address,
            relationship_type=relationship_type,
        )
        if record is not None:
            return record
    raise InboundPolicyError(
        f"sender {sender_address!r} has no active allowed relationship"
    )
