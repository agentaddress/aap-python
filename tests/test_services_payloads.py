"""Tests for the v0.6 services + relationships payload types."""

import pytest

from aap.payloads import (
    AgentCard,
    RelationshipAccept,
    RelationshipDecline,
    RelationshipProposal,
    RelationshipRevoke,
    ServiceFollowup,
    ServiceFollowupGrant,
    ServiceRequest,
    ServiceResponse,
    ServiceResponseStatus,
)


# -- AgentCard.kind ---------------------------------------------------------

def test_agent_card_defaults_kind_to_personal_when_omitted():
    """Pre-v0.6 cards without 'kind' parse as personal — the safer default."""
    card = AgentCard.from_dict({
        "address": "foo^example.com",
        "did": "did:web:example.com#agent",
        "public_key": "abc",
        "endpoints": [{"type": "inbox", "uri": "https://example.com"}],
    })
    assert card.kind == "personal"


def test_agent_card_round_trips_business_kind():
    card = AgentCard(
        address="reception^frankies.example",
        did="did:web:frankies.example#agent",
        public_key="abc",
        endpoints=[{"type": "inbox", "uri": "https://frankies.example"}],
        kind="business",
    )
    d = card.to_dict()
    assert d["kind"] == "business"
    assert AgentCard.from_dict(d) == card


def test_agent_card_rejects_unknown_kind():
    with pytest.raises(ValueError, match="kind must be one of"):
        AgentCard.from_dict({
            "address": "foo^example.com",
            "did": "did:web:example.com#agent",
            "public_key": "abc",
            "endpoints": [{"type": "inbox", "uri": "https://example.com"}],
            "kind": "robot",
        })


def test_agent_card_kind_appears_in_serialized_form():
    """Even for the default 'personal', kind round-trips explicitly — consumers
    can rely on the field always being present in serialized cards."""
    card = AgentCard(
        address="foo^example.com",
        did="did:web:example.com#agent",
        public_key="abc",
        endpoints=[{"type": "inbox", "uri": "https://example.com"}],
    )
    assert card.to_dict()["kind"] == "personal"


# -- ServiceRequest / ServiceResponse ---------------------------------------

def test_service_request_round_trip():
    req = ServiceRequest(
        service_id="book-table",
        payload={"name": "John", "party_size": 4, "iso_datetime": "2026-05-31T19:00:00+10:00"},
        nonce="abc123",
    )
    restored = ServiceRequest.from_dict(req.to_dict())
    assert restored == req


def test_service_request_payload_type_constant():
    assert ServiceRequest.PAYLOAD_TYPE == "aap.service-request/v1"


def test_service_request_rejects_non_dict_payload():
    with pytest.raises(ValueError, match="payload must be a dict"):
        ServiceRequest.from_dict({
            "service_id": "book-table",
            "payload": "not a dict",
            "nonce": "x",
        })


def test_service_request_rejects_missing_field():
    with pytest.raises(ValueError, match="missing field"):
        ServiceRequest.from_dict({"service_id": "x", "nonce": "y"})


def test_service_response_round_trip_confirmed():
    resp = ServiceResponse(
        service_id="book-table",
        request_nonce="req-1",
        status=ServiceResponseStatus.CONFIRMED,
        nonce="resp-1",
        payload={"confirmation_id": "FR-9X42", "table": 12},
    )
    restored = ServiceResponse.from_dict(resp.to_dict())
    assert restored == resp


def test_service_response_round_trip_denied():
    resp = ServiceResponse(
        service_id="book-table",
        request_nonce="req-1",
        status=ServiceResponseStatus.DENIED,
        nonce="resp-1",
        denial_reason="no_availability",
        payload={"suggested_slots": ["2026-05-31T18:00", "2026-05-31T20:30"]},
    )
    restored = ServiceResponse.from_dict(resp.to_dict())
    assert restored == resp


def test_service_response_round_trip_pending():
    resp = ServiceResponse(
        service_id="book-table",
        request_nonce="req-1",
        status=ServiceResponseStatus.PENDING,
        nonce="resp-1",
    )
    restored = ServiceResponse.from_dict(resp.to_dict())
    assert restored.status == ServiceResponseStatus.PENDING


def test_service_response_rejects_unknown_status():
    with pytest.raises(ValueError, match="unknown service-response status"):
        ServiceResponse.from_dict({
            "service_id": "book-table",
            "request_nonce": "x",
            "nonce": "resp-1",
            "status": "maybe",
        })


def test_service_response_payload_defaults_to_empty_dict():
    resp = ServiceResponse(
        service_id="book-table",
        request_nonce="x",
        status=ServiceResponseStatus.CONFIRMED,
        nonce="resp-1",
    )
    assert resp.payload == {}


# -- RelationshipProposal ---------------------------------------------------

def test_relationship_proposal_round_trip_friend():
    prop = RelationshipProposal(
        relationship_type="friend",
        proposer_card_envelope='{"signed": "agent-card-envelope-json"}',
        nonce="n1",
        identity_attestations=['{"phone-attestation": "..."}'],
    )
    restored = RelationshipProposal.from_dict(prop.to_dict())
    assert restored == prop


def test_relationship_proposal_team_requires_resource():
    with pytest.raises(ValueError, match="team.*requires a 'resource'"):
        RelationshipProposal.from_dict({
            "relationship_type": "team",
            "proposer_card_envelope": "{}",
            "nonce": "n",
        })


def test_relationship_proposal_team_round_trips_with_resource():
    prop = RelationshipProposal(
        relationship_type="team",
        proposer_card_envelope='{"card": "..."}',
        nonce="n",
        resource="github.com/acme/widgets",
    )
    restored = RelationshipProposal.from_dict(prop.to_dict())
    assert restored == prop
    assert restored.resource == "github.com/acme/widgets"


def test_relationship_proposal_rejects_unknown_type():
    with pytest.raises(ValueError, match="relationship_type must be one of"):
        RelationshipProposal.from_dict({
            "relationship_type": "frenemies",
            "proposer_card_envelope": "{}",
            "nonce": "n",
        })


def test_relationship_proposal_payload_type_constant():
    assert RelationshipProposal.PAYLOAD_TYPE == "aap.relationship-proposal/v1"


def test_relationship_proposal_omits_empty_attestations_in_dict():
    prop = RelationshipProposal(
        relationship_type="friend",
        proposer_card_envelope="{}",
        nonce="n",
    )
    d = prop.to_dict()
    assert "identity_attestations" not in d
    assert "resource" not in d


# -- RelationshipAccept / Decline / Revoke ----------------------------------

def test_relationship_accept_round_trip():
    acc = RelationshipAccept(
        proposal_nonce="prop-1",
        accepter_card_envelope='{"card": "..."}',
        identity_attestations=['{"att": "..."}'],
    )
    restored = RelationshipAccept.from_dict(acc.to_dict())
    assert restored == acc


def test_relationship_decline_round_trip_with_reason():
    dec = RelationshipDecline(proposal_nonce="prop-1", reason="don't know you")
    restored = RelationshipDecline.from_dict(dec.to_dict())
    assert restored == dec


def test_relationship_decline_round_trip_without_reason():
    dec = RelationshipDecline(proposal_nonce="prop-1")
    d = dec.to_dict()
    assert "reason" not in d
    assert RelationshipDecline.from_dict(d) == dec


def test_relationship_revoke_round_trip_friend():
    rev = RelationshipRevoke(
        relationship_type="friend",
        nonce="revoke-1",
        reason="moved on",
    )
    restored = RelationshipRevoke.from_dict(rev.to_dict())
    assert restored == rev


def test_relationship_revoke_round_trip_team_with_resource():
    rev = RelationshipRevoke(
        relationship_type="team",
        nonce="revoke-1",
        resource="github.com/acme/widgets",
    )
    restored = RelationshipRevoke.from_dict(rev.to_dict())
    assert restored == rev


def test_relationship_revoke_team_requires_resource():
    with pytest.raises(ValueError, match="requires a 'resource'"):
        RelationshipRevoke.from_dict(
            {"relationship_type": "team", "nonce": "revoke-1"}
        )


def test_relationship_revoke_rejects_unknown_type():
    with pytest.raises(ValueError, match="relationship_type must be one of"):
        RelationshipRevoke.from_dict(
            {"relationship_type": "frenemies", "nonce": "revoke-1"}
        )


# -- ServiceFollowupGrant / ServiceFollowup ---------------------------------

def test_service_followup_grant_round_trip():
    grant = ServiceFollowupGrant(
        service_id="routine-cleaning",
        cadence_iso="P6M",
        outreach_window_before="P1M",
        valid_until="2027-05-26T00:00:00Z",
        nonce="grant-1",
    )
    restored = ServiceFollowupGrant.from_dict(grant.to_dict())
    assert restored == grant


def test_service_followup_grant_payload_type_constant():
    assert ServiceFollowupGrant.PAYLOAD_TYPE == "aap.service-followup-grant/v1"


def test_service_followup_round_trip():
    fu = ServiceFollowup(
        service_id="routine-cleaning",
        grant_nonce="grant-1",
        message="Time for your next cleaning!",
        nonce="fu-1",
        suggested_slots=["2026-11-10T09:00:00Z", "2026-11-12T14:30:00Z"],
    )
    restored = ServiceFollowup.from_dict(fu.to_dict())
    assert restored == fu


def test_service_followup_omits_empty_slots_in_dict():
    fu = ServiceFollowup(
        service_id="x",
        grant_nonce="g",
        message="m",
        nonce="n",
    )
    assert "suggested_slots" not in fu.to_dict()


def test_service_followup_payload_type_constant():
    assert ServiceFollowup.PAYLOAD_TYPE == "aap.service-followup/v1"
