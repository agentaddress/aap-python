"""Tests for the relationships module — record store + handshake envelope builders."""

from __future__ import annotations

import pytest

from aap.envelope import Envelope
from aap.keys import encode_b64url, generate_keypair
from aap.payloads import (
    AgentCard,
    RelationshipAccept,
    RelationshipDecline,
    RelationshipProposal,
    RelationshipRevoke,
)

from aap.relationships import (
    RelationshipStore,
    build_relationship_accept_envelope,
    build_relationship_decline_envelope,
    build_relationship_proposal_envelope,
    build_relationship_revoke_envelope,
)


def _agent_card_envelope_json(
    *,
    seed: bytes,
    public_key: bytes,
    address: str,
) -> str:
    card = AgentCard(
        address=address,
        did=f"did:web:{address.split('^', 1)[-1]}",
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


def _handshake(
    *,
    self_address: str = "john^example.com",
    peer_address: str = "mary^example.com",
    relationship_type: str = "friend",
    resource: str | None = None,
    proposal_nonce: str = "prop-1",
    accept_nonce: str | None = None,
    proposer_address: str | None = None,
    accepter_address: str | None = None,
    proposer_card_address: str | None = None,
    accepter_card_address: str | None = None,
) -> dict[str, object]:
    proposer_seed, proposer_public = generate_keypair()
    accepter_seed, accepter_public = generate_keypair()
    proposer_address = proposer_address or peer_address
    accepter_address = accepter_address or self_address
    proposer_card = _agent_card_envelope_json(
        seed=proposer_seed,
        public_key=proposer_public,
        address=proposer_card_address or proposer_address,
    )
    accepter_card = _agent_card_envelope_json(
        seed=accepter_seed,
        public_key=accepter_public,
        address=accepter_card_address or accepter_address,
    )
    proposal = build_relationship_proposal_envelope(
        seed=proposer_seed,
        sender_address=proposer_address,
        relationship_type=relationship_type,
        proposer_card_envelope_json=proposer_card,
        resource=resource,
        nonce=proposal_nonce,
        iat="2026-06-15T12:00:00Z",
    )
    accept = build_relationship_accept_envelope(
        seed=accepter_seed,
        sender_address=accepter_address,
        proposal_nonce=accept_nonce or proposal_nonce,
        accepter_card_envelope_json=accepter_card,
        iat="2026-06-15T12:05:00Z",
    )
    return {
        "self_address": self_address,
        "peer_address": peer_address,
        "proposal_envelope_json": proposal.to_json(),
        "accept_envelope_json": accept.to_json(),
        "proposer_public_key": proposer_public,
        "accepter_public_key": accepter_public,
    }


def _establish(store: RelationshipStore, **kwargs):
    return store.establish(**_handshake(**kwargs))


def _revoke_args(
    *,
    self_address: str = "john^example.com",
    peer_address: str = "mary^example.com",
    revoker_address: str | None = None,
    relationship_type: str = "friend",
    resource: str | None = None,
    nonce: str = "revoke-1",
) -> dict[str, object]:
    revoker_seed, revoker_public = generate_keypair()
    revoker_address = revoker_address or peer_address
    env = build_relationship_revoke_envelope(
        seed=revoker_seed,
        sender_address=revoker_address,
        relationship_type=relationship_type,
        resource=resource,
        nonce=nonce,
        iat="2026-06-15T12:10:00Z",
    )
    return {
        "self_address": self_address,
        "peer_address": peer_address,
        "revoke_envelope_json": env.to_json(),
        "revoker_public_key": revoker_public,
    }


# -- store CRUD -------------------------------------------------------------


def test_empty_store_when_no_file(tmp_path):
    store = RelationshipStore.load(tmp_path)
    assert store.list_all() == []


def test_establish_friend_persists(tmp_path):
    store = RelationshipStore.load(tmp_path)
    store.establish(**_handshake())
    reloaded = RelationshipStore.load(tmp_path)
    records = reloaded.list_all()
    assert len(records) == 1
    assert records[0].peer_address == "mary^example.com"
    assert records[0].relationship_type == "friend"


def test_has_friend_query(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store)
    assert store.has_friend("mary^example.com")
    assert not store.has_friend("bob^example.com")


def test_admin_and_team_distinguished_from_friend(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store)
    assert not store.has_admin("mary^example.com")
    assert not store.has_team("mary^example.com", "anything")


def test_team_requires_resource_match(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(
        store,
        self_address="lead^example.com",
        peer_address="dev^example.com",
        relationship_type="team",
        resource="github.com/acme/widgets",
    )
    assert store.has_team("dev^example.com", "github.com/acme/widgets")
    assert not store.has_team("dev^example.com", "github.com/other/repo")


def test_raw_add_is_rejected(tmp_path):
    store = RelationshipStore.load(tmp_path)
    with pytest.raises(ValueError, match="created with establish"):
        store.add(object())  # type: ignore[arg-type]


def test_revoke_requires_signed_envelope(tmp_path):
    store = RelationshipStore.load(tmp_path)
    with pytest.raises(TypeError):
        store.revoke("mary^example.com", "friend")


def test_verified_revoke_removes_record_and_persists_proof(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store)
    assert store.revoke(**_revoke_args())
    assert not store.has_friend("mary^example.com")

    reloaded = RelationshipStore.load(tmp_path)
    assert not reloaded.has_friend("mary^example.com")
    revocations = reloaded.list_revocations()
    assert len(revocations) == 1
    assert revocations[0].peer_address == "mary^example.com"
    assert revocations[0].revoker_address == "mary^example.com"


def test_revoke_team_requires_resource_match(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(
        store,
        self_address="lead^example.com",
        peer_address="dev^example.com",
        relationship_type="team",
        resource="github.com/acme/widgets",
    )
    assert not store.revoke(
        **_revoke_args(
            self_address="lead^example.com",
            peer_address="dev^example.com",
            revoker_address="dev^example.com",
            relationship_type="team",
            resource="github.com/other/repo",
            nonce="wrong-resource",
        )
    )
    assert store.revoke(
        **_revoke_args(
            self_address="lead^example.com",
            peer_address="dev^example.com",
            revoker_address="dev^example.com",
            relationship_type="team",
            resource="github.com/acme/widgets",
            nonce="right-resource",
        )
    )


def test_revoke_rejects_bad_signature(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store)
    args = _revoke_args()
    _, wrong_public = generate_keypair()
    args["revoker_public_key"] = wrong_public
    with pytest.raises(ValueError, match="revoke envelope failed verification"):
        store.revoke(**args)
    assert store.has_friend("mary^example.com")


def test_revoke_rejects_third_party_issuer(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store)
    args = _revoke_args(revoker_address="mallory^example.com")
    with pytest.raises(ValueError, match="issuer must be self_address or peer_address"):
        store.revoke(**args)
    assert store.has_friend("mary^example.com")


def test_revoke_rejects_duplicate_nonce(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store)
    assert store.revoke(**_revoke_args(nonce="duplicate-revoke"))
    args = _revoke_args(
        peer_address="alice^example.com",
        revoker_address="alice^example.com",
        nonce="duplicate-revoke",
    )
    with pytest.raises(ValueError, match="revoke nonce replay"):
        store.revoke(**args)


def test_add_replaces_existing_same_kind(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store, proposal_nonce="prop-1")
    # Establish another friend relationship for the same peer: replace, not duplicate.
    _establish(store, proposal_nonce="prop-2")
    records = [r for r in store.list_all() if r.peer_address == "mary^example.com"]
    assert len(records) == 1
    assert records[0].established_at == "2026-06-15T12:05:00Z"


def test_distinct_team_resources_coexist_for_same_peer(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(
        store,
        self_address="lead^example.com",
        peer_address="dev^example.com",
        relationship_type="team",
        resource="github.com/acme/widgets",
        proposal_nonce="widgets",
    )
    _establish(
        store,
        self_address="lead^example.com",
        peer_address="dev^example.com",
        relationship_type="team",
        resource="github.com/acme/gadgets",
        proposal_nonce="gadgets",
    )
    teams = [r for r in store.list_all() if r.relationship_type == "team"]
    assert len(teams) == 2


def test_establish_rejects_bad_proposal_signature(tmp_path):
    store = RelationshipStore.load(tmp_path)
    args = _handshake()
    _, wrong_public = generate_keypair()
    args["proposer_public_key"] = wrong_public
    with pytest.raises(ValueError, match="proposal envelope failed verification"):
        store.establish(**args)


def test_establish_rejects_accept_nonce_mismatch(tmp_path):
    store = RelationshipStore.load(tmp_path)
    args = _handshake(accept_nonce="different")
    with pytest.raises(ValueError, match="does not reference proposal nonce"):
        store.establish(**args)


def test_establish_rejects_issuer_not_self_or_peer(tmp_path):
    store = RelationshipStore.load(tmp_path)
    args = _handshake(proposer_address="mallory^example.com")
    with pytest.raises(ValueError, match="issuers must be exactly"):
        store.establish(**args)


def test_establish_rejects_embedded_card_address_mismatch(tmp_path):
    store = RelationshipStore.load(tmp_path)
    args = _handshake(proposer_card_address="mallory^example.com")
    with pytest.raises(ValueError, match="AgentCard address does not match"):
        store.establish(**args)


def test_establish_rejects_duplicate_proposal_nonce(tmp_path):
    store = RelationshipStore.load(tmp_path)
    _establish(store, proposal_nonce="duplicate")
    args = _handshake(
        peer_address="alice^example.com",
        proposal_nonce="duplicate",
    )
    with pytest.raises(ValueError, match="proposal nonce replay"):
        store.establish(**args)


# -- envelope builders ------------------------------------------------------


def test_proposal_envelope_signs_and_verifies():
    seed, pub = generate_keypair()
    env = build_relationship_proposal_envelope(
        seed=seed,
        sender_address="mary^example.com",
        relationship_type="friend",
        proposer_card_envelope_json='{"card": "mary-card"}',
    )
    assert env.payload_type == RelationshipProposal.PAYLOAD_TYPE
    assert env.payload["relationship_type"] == "friend"
    assert env.payload["nonce"]
    assert env.verify(pub)


def test_proposal_team_requires_resource():
    seed, _ = generate_keypair()
    with pytest.raises(ValueError, match="team proposal requires"):
        build_relationship_proposal_envelope(
            seed=seed,
            sender_address="x^example.com",
            relationship_type="team",
            proposer_card_envelope_json='{}',
        )


def test_proposal_invalid_type_rejected():
    seed, _ = generate_keypair()
    with pytest.raises(ValueError, match="invalid relationship_type"):
        build_relationship_proposal_envelope(
            seed=seed,
            sender_address="x^example.com",
            relationship_type="frenemies",
            proposer_card_envelope_json='{}',
        )


def test_accept_envelope_signs_and_verifies():
    seed, pub = generate_keypair()
    env = build_relationship_accept_envelope(
        seed=seed,
        sender_address="john^example.com",
        proposal_nonce="prop-1",
        accepter_card_envelope_json='{"card": "john-card"}',
    )
    assert env.payload_type == RelationshipAccept.PAYLOAD_TYPE
    assert env.payload["proposal_nonce"] == "prop-1"
    assert env.verify(pub)


def test_decline_envelope_signs_and_verifies():
    seed, pub = generate_keypair()
    env = build_relationship_decline_envelope(
        seed=seed,
        sender_address="john^example.com",
        proposal_nonce="prop-1",
        reason="don't know you",
    )
    assert env.payload_type == RelationshipDecline.PAYLOAD_TYPE
    assert env.payload["reason"] == "don't know you"
    assert env.verify(pub)


def test_revoke_envelope_signs_and_verifies():
    seed, pub = generate_keypair()
    env = build_relationship_revoke_envelope(
        seed=seed,
        sender_address="john^example.com",
        relationship_type="friend",
        nonce="revoke-1",
    )
    assert env.payload_type == RelationshipRevoke.PAYLOAD_TYPE
    assert env.payload["relationship_type"] == "friend"
    assert env.payload["nonce"] == "revoke-1"
    assert env.verify(pub)


def test_revoke_team_requires_resource():
    seed, _ = generate_keypair()
    with pytest.raises(ValueError, match="team revoke requires"):
        build_relationship_revoke_envelope(
            seed=seed,
            sender_address="x^example.com",
            relationship_type="team",
        )


def test_revoke_invalid_type_rejected():
    seed, _ = generate_keypair()
    with pytest.raises(ValueError, match="invalid relationship_type"):
        build_relationship_revoke_envelope(
            seed=seed,
            sender_address="x^example.com",
            relationship_type="frenemies",
        )
