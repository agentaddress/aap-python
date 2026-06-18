import json

import pytest

from aap.envelope import Envelope, EnvelopeError
from aap.keys import generate_keypair


def _example_envelope() -> Envelope:
    return Envelope(
        type="aap.envelope/v1",
        payload_type="aap.test/v1",
        payload={"hello": "world"},
        iss="did:web:example.com#agent",
        iat="2026-05-19T12:00:00Z",
    )


def test_construct_envelope_is_unsigned():
    env = _example_envelope()
    assert env.sig is None


def test_sign_populates_signature():
    private, _ = generate_keypair()
    env = _example_envelope().sign(private)
    assert env.sig is not None
    assert len(env.sig) > 0


def test_verify_valid_signature():
    private, public = generate_keypair()
    env = _example_envelope().sign(private)
    assert env.verify(public) is True


def test_verify_rejects_tampered_payload():
    private, public = generate_keypair()
    env = _example_envelope().sign(private)
    # Construct an envelope that claims to have this signature but
    # different payload.
    tampered = Envelope(
        type=env.type,
        payload_type=env.payload_type,
        payload={"hello": "tampered"},
        iss=env.iss,
        iat=env.iat,
        sig=env.sig,
    )
    assert tampered.verify(public) is False


def test_verify_rejects_wrong_key():
    private_a, _ = generate_keypair()
    _, public_b = generate_keypair()
    env = _example_envelope().sign(private_a)
    assert env.verify(public_b) is False


def test_verify_unsigned_envelope_raises():
    _, public = generate_keypair()
    env = _example_envelope()
    with pytest.raises(EnvelopeError, match="not signed"):
        env.verify(public)


def test_to_json_includes_sig():
    private, _ = generate_keypair()
    env = _example_envelope().sign(private)
    data = json.loads(env.to_json())
    assert data["sig"] == env.sig
    assert data["payload"] == {"hello": "world"}
    assert data["v"] == 1


def test_from_json_roundtrip():
    private, public = generate_keypair()
    env = _example_envelope().sign(private)
    restored = Envelope.from_json(env.to_json())
    assert restored == env
    assert restored.verify(public) is True


def test_from_json_rejects_missing_field():
    bad = '{"type":"aap.envelope/v1","v":1}'
    with pytest.raises(EnvelopeError, match="missing field"):
        Envelope.from_json(bad)


def test_from_json_rejects_unknown_version():
    bad = json.dumps({
        "v": 999,
        "type": "aap.envelope/v1",
        "payload_type": "aap.test/v1",
        "payload": {},
        "iss": "did:web:example.com#agent",
        "iat": "2026-05-19T12:00:00Z",
    })
    with pytest.raises(EnvelopeError, match="unsupported envelope version"):
        Envelope.from_json(bad)


def test_from_dict_rejects_unknown_field():
    bad = {
        "v": 1,
        "type": "aap.envelope/v1",
        "payload_type": "aap.test/v1",
        "payload": {},
        "iss": "did:web:example.com#agent",
        "iat": "2026-05-19T12:00:00Z",
        "smuggled": "extra",
    }
    with pytest.raises(EnvelopeError, match="unknown field"):
        Envelope.from_dict(bad)


def test_from_dict_rejects_wrong_type():
    bad = {
        "v": 1,
        "type": "not.aap.envelope/v1",
        "payload_type": "aap.test/v1",
        "payload": {},
        "iss": "did:web:example.com#agent",
        "iat": "2026-05-19T12:00:00Z",
    }
    with pytest.raises(EnvelopeError, match="unsupported envelope type"):
        Envelope.from_dict(bad)


def test_envelope_capability_token_field_round_trip():
    """Envelope.from_dict/to_dict must preserve an optional capability_token field."""
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hi"},
        iss="foo^example.com",
        iat="2026-05-22T12:00:00Z",
        capability_token='{"type":"aap.envelope/v1","payload_type":"aap.relationship-token/v1"}',
    )
    d = env.to_dict()
    assert d["capability_token"] == env.capability_token
    restored = Envelope.from_dict(d)
    assert restored.capability_token == env.capability_token


def test_envelope_without_capability_token_omits_field():
    """Backward compat: envelopes without a capability_token must not include
    the field in their serialized form."""
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.capability-request/v1",
        payload={},
        iss="foo^example.com",
        iat="2026-05-22T12:00:00Z",
    )
    d = env.to_dict()
    assert "capability_token" not in d


def test_envelope_parses_v01_form_without_capability_token():
    """v0.1 envelopes that don't have a capability_token field must still parse."""
    d = {
        "v": 1,
        "type": "aap.envelope/v1",
        "payload_type": "aap.message/v1",
        "payload": {"text": "hi"},
        "iss": "foo^example.com",
        "iat": "2026-05-22T12:00:00Z",
    }
    env = Envelope.from_dict(d)
    assert env.capability_token is None


def test_envelope_capability_token_covered_by_signature():
    """Tampering with capability_token must invalidate the signature."""
    private, public = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hi"},
        iss="did:web:example.com#agent",
        iat="2026-05-22T12:00:00Z",
        capability_token="original-token-blob",
    ).sign(private)
    assert env.verify(public) is True
    tampered = Envelope(
        type=env.type,
        payload_type=env.payload_type,
        payload=env.payload,
        iss=env.iss,
        iat=env.iat,
        sig=env.sig,
        capability_token="different-token-blob",
    )
    assert tampered.verify(public) is False


def test_envelope_signed_with_capability_token_round_trips_via_json():
    """Signed envelope with capability_token round-trips through JSON."""
    private, public = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hi"},
        iss="did:web:example.com#agent",
        iat="2026-05-22T12:00:00Z",
        capability_token="my-token-blob",
    ).sign(private)
    restored = Envelope.from_json(env.to_json())
    assert restored == env
    assert restored.capability_token == "my-token-blob"
    assert restored.verify(public) is True


def test_envelope_with_conversation_fields_round_trips():
    from aap.envelope import Envelope
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hi group"},
        iss="james^example.com",
        iat="2026-05-22T12:00:00Z",
        conversation_id="dinner-2026-05-23-abc123",
        conversation_members=[
            "chris^example.com",
            "james^example.com",
            "sarah^example.com",
            "mike^example.com",
        ],
    )
    d = env.to_dict()
    assert d["conversation_id"] == "dinner-2026-05-23-abc123"
    assert len(d["conversation_members"]) == 4
    restored = Envelope.from_dict(d)
    assert restored.conversation_id == env.conversation_id
    assert restored.conversation_members == env.conversation_members


def test_envelope_without_conversation_fields_omits_them():
    from aap.envelope import Envelope
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "1:1 message"},
        iss="foo^example.com",
        iat="2026-05-22T12:00:00Z",
    )
    d = env.to_dict()
    assert "conversation_id" not in d
    assert "conversation_members" not in d


def test_envelope_rejects_too_few_conversation_members():
    """A 1-member conversation makes no sense - minimum is 2."""
    from aap.envelope import Envelope
    import pytest
    with pytest.raises(ValueError, match="conversation_members.*at least 2"):
        Envelope.from_dict({
            "v": 1,
            "type": "aap.envelope/v1",
            "payload_type": "aap.message/v1",
            "payload": {"text": "x"},
            "iss": "foo^example.com",
            "iat": "2026-05-22T12:00:00Z",
            "conversation_id": "abc",
            "conversation_members": ["foo^example.com"],
        })


def test_envelope_rejects_too_many_conversation_members():
    """v0.4 caps groups at 10 members."""
    from aap.envelope import Envelope
    import pytest
    members = [f"m{i}^example.com" for i in range(11)]
    with pytest.raises(ValueError, match="conversation_members.*at most 10|cap"):
        Envelope.from_dict({
            "v": 1,
            "type": "aap.envelope/v1",
            "payload_type": "aap.message/v1",
            "payload": {"text": "x"},
            "iss": "m0^example.com",
            "iat": "2026-05-22T12:00:00Z",
            "conversation_id": "abc",
            "conversation_members": members,
        })


def test_envelope_conversation_fields_covered_by_signature():
    """Tampering with conversation_id or conversation_members must
    invalidate the envelope's signature (JCS canonicalization covers
    them)."""
    from aap.envelope import Envelope
    from aap.keys import generate_keypair
    seed, public = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "group msg"},
        iss="foo^example.com",
        iat="2026-05-22T12:00:00Z",
        conversation_id="abc",
        conversation_members=["foo^example.com", "bar^example.com"],
    ).sign(seed)
    # Untampered: verifies
    assert env.verify(public) is True
    # Tamper with conversation_id: verification fails
    import dataclasses
    tampered = dataclasses.replace(env, conversation_id="evil-conversation")
    assert tampered.verify(public) is False


def test_envelope_parses_v03_form_without_conversation_fields():
    """v0.3 envelopes (no conversation_id, no conversation_members) must
    still parse cleanly under v0.4."""
    from aap.envelope import Envelope
    d = {
        "v": 1,
        "type": "aap.envelope/v1",
        "payload_type": "aap.message/v1",
        "payload": {"text": "old style"},
        "iss": "foo^example.com",
        "iat": "2026-05-22T12:00:00Z",
    }
    env = Envelope.from_dict(d)
    assert env.conversation_id is None
    assert env.conversation_members is None


def test_envelope_verification_attestations_round_trips():
    from aap.envelope import Envelope
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.capability-request/v1",
        payload={},
        iss="foo^example.com",
        iat="2026-05-22T12:00:00Z",
        verification_attestations=[
            '{"type":"aap.envelope/v1","payload_type":"aap.verification-attestation/v1",...}',
        ],
    )
    d = env.to_dict()
    assert len(d["verification_attestations"]) == 1
    restored = Envelope.from_dict(d)
    assert restored.verification_attestations == env.verification_attestations


def test_envelope_omits_verification_attestations_when_empty():
    from aap.envelope import Envelope
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hi"},
        iss="foo^example.com",
        iat="2026-05-22T12:00:00Z",
    )
    d = env.to_dict()
    assert "verification_attestations" not in d


def test_envelope_verification_attestations_covered_by_signature():
    """Tampering with verification_attestations invalidates the envelope signature."""
    import dataclasses
    from aap.envelope import Envelope
    from aap.keys import generate_keypair
    seed, public = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.capability-request/v1",
        payload={},
        iss="foo^example.com",
        iat="2026-05-22T12:00:00Z",
        verification_attestations=['<token-A-json>'],
    ).sign(seed)
    assert env.verify(public) is True
    # Tamper: swap the attestation list
    tampered = dataclasses.replace(env, verification_attestations=['<token-B-json>'])
    assert tampered.verify(public) is False
