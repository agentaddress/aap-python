"""Tests for strict inbound envelope receive policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aap.encryption import generate_encryption_keypair, encrypt_envelope
from aap.envelope import Envelope
from aap.envelope_policy import EnvelopeReplayCache
from aap.inbound import (
    InboundPolicyError,
    validate_inbound_chat,
    validate_inbound_envelope,
)
from aap.keys import encode_b64url, generate_keypair
from aap.messages import build_chat_envelope
from aap.payloads import AgentCard
from aap.relationships import (
    RelationshipStore,
    build_relationship_accept_envelope,
    build_relationship_proposal_envelope,
    build_relationship_revoke_envelope,
)


SELF_ADDRESS = "john^example.com"
PEER_ADDRESS = "mary^example.com"
NOW = datetime(2026, 6, 15, 12, 30, tzinfo=timezone.utc)


def _card_envelope_json(*, seed: bytes, public_key: bytes, address: str) -> str:
    card = AgentCard(
        address=address,
        did=f"did:web:{address.split('^', 1)[1]}#agent",
        public_key=encode_b64url(public_key),
        endpoints=[{"type": "relay", "uri": f"https://{address}/aap"}],
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss=address,
        iat="2026-06-15T12:00:00Z",
    ).sign(seed).to_json()


def _establish_friend(
    store: RelationshipStore,
    *,
    self_seed: bytes,
    self_public: bytes,
    peer_seed: bytes,
    peer_public: bytes,
) -> None:
    proposal = build_relationship_proposal_envelope(
        seed=peer_seed,
        sender_address=PEER_ADDRESS,
        relationship_type="friend",
        proposer_card_envelope_json=_card_envelope_json(
            seed=peer_seed,
            public_key=peer_public,
            address=PEER_ADDRESS,
        ),
        nonce="proposal-1",
        iat="2026-06-15T12:00:00Z",
    )
    accept = build_relationship_accept_envelope(
        seed=self_seed,
        sender_address=SELF_ADDRESS,
        proposal_nonce="proposal-1",
        accepter_card_envelope_json=_card_envelope_json(
            seed=self_seed,
            public_key=self_public,
            address=SELF_ADDRESS,
        ),
        iat="2026-06-15T12:05:00Z",
    )
    store.establish(
        self_address=SELF_ADDRESS,
        peer_address=PEER_ADDRESS,
        proposal_envelope_json=proposal.to_json(),
        accept_envelope_json=accept.to_json(),
        proposer_public_key=peer_public,
        accepter_public_key=self_public,
    )


def _encrypted_chat(*, sender_seed: bytes, recipient_public_key: bytes, iat: str):
    envelope = build_chat_envelope(
        seed=sender_seed,
        sender_address=PEER_ADDRESS,
        text="hello",
        thread_id="thread-1",
        iat=iat,
    )
    return encrypt_envelope(
        envelope,
        recipient_public_key=recipient_public_key,
        recipient_address=SELF_ADDRESS,
    )


def test_validate_inbound_envelope_decrypts_then_verifies():
    sender_seed, sender_public = generate_keypair()
    recipient_private, recipient_public = generate_encryption_keypair()
    encrypted = _encrypted_chat(
        sender_seed=sender_seed,
        recipient_public_key=recipient_public,
        iat="2026-06-15T12:10:00Z",
    )

    validated = validate_inbound_envelope(
        encrypted.to_json(),
        recipient_private_key=recipient_private,
        recipient_address=SELF_ADDRESS,
        sender_public_key=sender_public,
        now=NOW,
    )

    assert validated.sender_address == PEER_ADDRESS
    assert validated.envelope.payload["text"] == "hello"


def test_validate_inbound_envelope_rejects_plaintext_by_default():
    sender_seed, sender_public = generate_keypair()
    recipient_private, _ = generate_encryption_keypair()
    envelope = build_chat_envelope(
        seed=sender_seed,
        sender_address=PEER_ADDRESS,
        text="hello",
        iat="2026-06-15T12:10:00Z",
    )

    with pytest.raises(InboundPolicyError, match="plaintext"):
        validate_inbound_envelope(
            envelope.to_json(),
            recipient_private_key=recipient_private,
            recipient_address=SELF_ADDRESS,
            sender_public_key=sender_public,
            now=NOW,
        )


def test_validate_inbound_envelope_rejects_bad_signature():
    sender_seed, _ = generate_keypair()
    _, wrong_public = generate_keypair()
    recipient_private, recipient_public = generate_encryption_keypair()
    encrypted = _encrypted_chat(
        sender_seed=sender_seed,
        recipient_public_key=recipient_public,
        iat="2026-06-15T12:10:00Z",
    )

    with pytest.raises(InboundPolicyError, match="signature"):
        validate_inbound_envelope(
            encrypted.to_dict(),
            recipient_private_key=recipient_private,
            recipient_address=SELF_ADDRESS,
            sender_public_key=wrong_public,
            now=NOW,
        )


def test_validate_inbound_envelope_rejects_replay():
    sender_seed, sender_public = generate_keypair()
    recipient_private, recipient_public = generate_encryption_keypair()
    encrypted = _encrypted_chat(
        sender_seed=sender_seed,
        recipient_public_key=recipient_public,
        iat="2026-06-15T12:10:00Z",
    )
    cache = EnvelopeReplayCache()

    validate_inbound_envelope(
        encrypted,
        recipient_private_key=recipient_private,
        recipient_address=SELF_ADDRESS,
        sender_public_key=sender_public,
        replay_cache=cache,
        now=NOW,
    )
    with pytest.raises(InboundPolicyError, match="replay"):
        validate_inbound_envelope(
            encrypted,
            recipient_private_key=recipient_private,
            recipient_address=SELF_ADDRESS,
            sender_public_key=sender_public,
            replay_cache=cache,
            now=NOW,
        )


def test_validate_inbound_envelope_rejects_stale_message():
    sender_seed, sender_public = generate_keypair()
    recipient_private, recipient_public = generate_encryption_keypair()
    encrypted = _encrypted_chat(
        sender_seed=sender_seed,
        recipient_public_key=recipient_public,
        iat=(NOW - timedelta(days=31)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    with pytest.raises(InboundPolicyError, match="too old"):
        validate_inbound_envelope(
            encrypted,
            recipient_private_key=recipient_private,
            recipient_address=SELF_ADDRESS,
            sender_public_key=sender_public,
            now=NOW,
        )


def test_validate_inbound_chat_requires_active_relationship(tmp_path):
    sender_seed, sender_public = generate_keypair()
    recipient_private, recipient_public = generate_encryption_keypair()
    store = RelationshipStore.load(tmp_path)
    encrypted = _encrypted_chat(
        sender_seed=sender_seed,
        recipient_public_key=recipient_public,
        iat="2026-06-15T12:10:00Z",
    )

    with pytest.raises(InboundPolicyError, match="no active allowed relationship"):
        validate_inbound_chat(
            encrypted,
            recipient_private_key=recipient_private,
            recipient_address=SELF_ADDRESS,
            sender_public_key=sender_public,
            relationship_store=store,
            now=NOW,
        )


def test_validate_inbound_chat_returns_trusted_chat_for_friend(tmp_path):
    self_seed, self_public = generate_keypair()
    peer_seed, peer_public = generate_keypair()
    recipient_private, recipient_public = generate_encryption_keypair()
    store = RelationshipStore.load(tmp_path)
    _establish_friend(
        store,
        self_seed=self_seed,
        self_public=self_public,
        peer_seed=peer_seed,
        peer_public=peer_public,
    )
    encrypted = _encrypted_chat(
        sender_seed=peer_seed,
        recipient_public_key=recipient_public,
        iat="2026-06-15T12:10:00Z",
    )

    chat = validate_inbound_chat(
        encrypted,
        recipient_private_key=recipient_private,
        recipient_address=SELF_ADDRESS,
        sender_public_key=peer_public,
        relationship_store=store,
        now=NOW,
    )

    assert chat.sender_address == PEER_ADDRESS
    assert chat.text == "hello"
    assert chat.thread_id == "thread-1"
    assert chat.relationship.relationship_type == "friend"


def test_validate_inbound_chat_rejects_after_revocation(tmp_path):
    self_seed, self_public = generate_keypair()
    peer_seed, peer_public = generate_keypair()
    recipient_private, recipient_public = generate_encryption_keypair()
    store = RelationshipStore.load(tmp_path)
    _establish_friend(
        store,
        self_seed=self_seed,
        self_public=self_public,
        peer_seed=peer_seed,
        peer_public=peer_public,
    )
    revoke = build_relationship_revoke_envelope(
        seed=peer_seed,
        sender_address=PEER_ADDRESS,
        relationship_type="friend",
        nonce="revoke-1",
        iat="2026-06-15T12:08:00Z",
    )
    store.revoke(
        self_address=SELF_ADDRESS,
        peer_address=PEER_ADDRESS,
        revoke_envelope_json=revoke.to_json(),
        revoker_public_key=peer_public,
    )
    encrypted = _encrypted_chat(
        sender_seed=peer_seed,
        recipient_public_key=recipient_public,
        iat="2026-06-15T12:10:00Z",
    )

    with pytest.raises(InboundPolicyError, match="no active allowed relationship"):
        validate_inbound_chat(
            encrypted,
            recipient_private_key=recipient_private,
            recipient_address=SELF_ADDRESS,
            sender_public_key=peer_public,
            relationship_store=store,
            now=NOW,
        )
