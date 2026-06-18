import pytest

from aap.payloads import AgentCard, VerifiedIdentity


def test_agent_card_roundtrip():
    card = AgentCard(
        address="chris^chrisevans.id",
        did="did:web:chrisevans.id#agent",
        public_key="abcDEF123",
        endpoints=[{"type": "didcomm", "uri": "https://relay.example"}],
    )
    restored = AgentCard.from_dict(card.to_dict())
    assert restored == card


def test_agent_card_rejects_missing_field():
    with pytest.raises(ValueError, match="missing field"):
        AgentCard.from_dict({"address": "chris^chrisevans.id"})


def test_agent_card_payload_type_constant():
    assert AgentCard.PAYLOAD_TYPE == "aap.agent-card/v1"


def test_agent_card_encryption_key_round_trips():
    card = AgentCard(
        address="chris^chrisevans.id",
        did="did:web:chrisevans.id#agent",
        public_key="signing-key",
        encryption_key="encryption-key",
        endpoints=[],
    )

    assert AgentCard.from_dict(card.to_dict()) == card


def test_agent_card_rejects_non_string_encryption_key():
    with pytest.raises(ValueError, match="encryption_key"):
        AgentCard.from_dict({
            "address": "chris^chrisevans.id",
            "did": "did:web:chrisevans.id#agent",
            "public_key": "signing-key",
            "encryption_key": 42,
            "endpoints": [],
        })


def test_agent_card_rejects_non_dict_endpoint():
    with pytest.raises(ValueError, match="endpoint must be a dict"):
        AgentCard.from_dict({
            "address": "chris^chrisevans.id",
            "did": "did:web:chrisevans.id#agent",
            "public_key": "k",
            "endpoints": ["not-a-dict"],
        })


def test_agent_card_rejects_endpoint_missing_type():
    with pytest.raises(ValueError, match="endpoint missing 'type'"):
        AgentCard.from_dict({
            "address": "chris^chrisevans.id",
            "did": "did:web:chrisevans.id#agent",
            "public_key": "k",
            "endpoints": [{"uri": "https://example.com"}],
        })


def test_agent_card_rejects_endpoint_missing_uri():
    with pytest.raises(ValueError, match="endpoint missing 'uri'"):
        AgentCard.from_dict({
            "address": "chris^chrisevans.id",
            "did": "did:web:chrisevans.id#agent",
            "public_key": "k",
            "endpoints": [{"type": "didcomm"}],
        })


def test_agent_card_rejects_endpoint_non_string_value():
    with pytest.raises(ValueError, match="endpoint values must be strings"):
        AgentCard.from_dict({
            "address": "chris^chrisevans.id",
            "did": "did:web:chrisevans.id#agent",
            "public_key": "k",
            "endpoints": [{"type": "didcomm", "uri": 42}],
        })


def test_verified_identity_round_trips():
    vi = VerifiedIdentity(
        type="phone",
        value="+14154442222",
        verified_at="2026-01-15T12:00:00Z",
        verified_by="self",
    )
    d = vi.to_dict()
    assert d == {
        "type": "phone",
        "value": "+14154442222",
        "verified_at": "2026-01-15T12:00:00Z",
        "verified_by": "self",
    }
    round_tripped = VerifiedIdentity.from_dict(d)
    assert round_tripped == vi


def test_verified_identity_requires_type_and_verifier_fields():
    """value is optional (v0.5); type, verified_at, verified_by remain required."""
    with pytest.raises(ValueError, match="missing field"):
        VerifiedIdentity.from_dict({"value": "x"})


def test_verified_identity_value_can_be_null():
    """v0.5: value is nullable for presence-only indicators."""
    vi = VerifiedIdentity(
        type="phone",
        value=None,
        verified_at="2026-05-22T12:00:00Z",
        verified_by="verify.example",
    )
    d = vi.to_dict()
    assert d["value"] is None
    restored = VerifiedIdentity.from_dict(d)
    assert restored.value is None


def test_verified_identity_omits_value_when_absent_in_dict():
    """Parsing a dict without a `value` field defaults to None."""
    vi = VerifiedIdentity.from_dict({
        "type": "phone",
        "verified_at": "2026-05-22T12:00:00Z",
        "verified_by": "verify.example",
    })
    assert vi.value is None


def test_agent_card_with_verified_identities_round_trips():
    card = AgentCard(
        address="james-bot^james-bots.example",
        did="did:web:james-bots.example#agent",
        public_key="abc",
        endpoints=[{"type": "inbox", "uri": "https://james-bots.example/aap/inbox"}],
        verified_identities=[
            VerifiedIdentity("phone", "+14154442222", "2026-01-15T12:00:00Z", "self"),
            VerifiedIdentity("email", "james@example.com", "2026-01-15T12:00:00Z", "self"),
        ],
    )
    d = card.to_dict()
    assert len(d["verified_identities"]) == 2
    assert d["verified_identities"][0]["type"] == "phone"
    round_tripped = AgentCard.from_dict(d)
    assert round_tripped == card


def test_agent_card_omits_verified_identities_when_empty():
    """v0.1 AgentCards without verified_identities still serialize without that key."""
    card = AgentCard(
        address="foo^example.com",
        did="did:web:example.com#agent",
        public_key="abc",
        endpoints=[{"type": "inbox", "uri": "https://example.com/aap/inbox"}],
    )
    d = card.to_dict()
    assert "verified_identities" not in d


def test_agent_card_parses_without_verified_identities_field():
    """v0.1 AgentCards (no verified_identities key) must still parse."""
    card = AgentCard.from_dict({
        "address": "foo^example.com",
        "did": "did:web:example.com#agent",
        "public_key": "abc",
        "endpoints": [{"type": "inbox", "uri": "https://example.com/aap/inbox"}],
    })
    assert card.verified_identities == []
