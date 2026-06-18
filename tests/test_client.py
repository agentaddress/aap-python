"""Tests for the AAP relay HTTP client."""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from aap.envelope import Envelope
from aap.encryption import EncryptedEnvelope, decrypt_envelope, generate_encryption_keypair
from aap.jcs import canonicalize
from aap.keys import (
    decode_b64url,
    encode_b64url,
    generate_keypair,
    verify as ed25519_verify,
)
from aap.payloads import AgentCard
from aap.transport import InsecureTransportError

from aap.client import AAPClient, AAPClientError


@pytest.fixture
def client_fixture():
    seed, public = generate_keypair()
    client = AAPClient(
        relay_url="https://relay.test",
        seed=seed,
        public_key=public,
        address="chris^relay.example",
        timeout_seconds=5,
    )
    return client, seed, public


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fresh_iat() -> str:
    return _rfc3339(datetime.now(timezone.utc))


def test_client_rejects_remote_http_relay():
    seed, public = generate_keypair()
    with pytest.raises(InsecureTransportError, match="must use HTTPS"):
        AAPClient(
            relay_url="http://relay.example",
            seed=seed,
            public_key=public,
            address="chris^relay.example",
        )


@pytest.mark.asyncio
async def test_client_allows_loopback_http_relay():
    seed, public = generate_keypair()
    client = AAPClient(
        relay_url="http://127.0.0.1:8000",
        seed=seed,
        public_key=public,
        address="chris^relay.example",
    )
    try:
        assert client.relay_url == "http://127.0.0.1:8000"
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_register_posts_signed_agent_card(client_fixture):
    client, _, public = client_fixture
    route = respx.post("https://relay.test/aap/agents/register").mock(
        return_value=httpx.Response(200, json={
            "address": "chris^relay.example",
            "first_seen": True,
        })
    )

    result = await client.register()

    assert route.called
    assert result == {"address": "chris^relay.example", "first_seen": True}

    sent = json.loads(route.calls.last.request.content.decode())
    env = Envelope.from_dict(sent)
    assert env.payload_type == AgentCard.PAYLOAD_TYPE
    assert env.iss == "chris^relay.example"
    assert env.verify(public) is True
    card = AgentCard.from_dict(env.payload)
    assert card.address == "chris^relay.example"
    assert card.public_key == encode_b64url(public)
    assert card.encryption_key == encode_b64url(client.encryption_public_key)


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_posts_routing_envelope(client_fixture):
    client, _, public = client_fixture
    recipient_private, recipient_public = generate_encryption_keypair()
    route = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 42, "queued_at": "2026-05-20T12:00:00Z"}),
    )

    envelope_id = await client.send_envelope(
        to="james^bob.example",
        text="Hi James",
        recipient_encryption_key=recipient_public,
    )
    assert envelope_id == 42

    sent = json.loads(route.calls.last.request.content.decode())
    assert sent["type"] == "aap.routing-envelope/v1"
    assert sent["v"] == 1
    assert sent["from"] == "chris^relay.example"
    assert sent["to"] == "james^bob.example"
    assert isinstance(sent["iat"], str)
    assert isinstance(sent["nonce"], str)
    signed_route = dict(sent)
    route_sig = signed_route.pop("sig")
    assert ed25519_verify(
        public,
        canonicalize(signed_route),
        decode_b64url(route_sig),
    ) is True
    assert sent["envelope"]["type"] == "aap.encrypted-envelope/v1"
    assert "Hi James" not in route.calls.last.request.content.decode()
    inner = decrypt_envelope(
        EncryptedEnvelope.from_dict(sent["envelope"]),
        recipient_private_key=recipient_private,
        recipient_address="james^bob.example",
    )
    assert inner.payload_type == "aap.message/v1"
    assert inner.payload["text"] == "Hi James"


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_includes_thread_id_when_provided(client_fixture):
    """When thread_id is passed, the routing envelope's inner payload contains it."""
    client, _, _ = client_fixture
    recipient_private, recipient_public = generate_encryption_keypair()
    route = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 100, "queued_at": "2026-05-21T12:00:00Z"}),
    )

    await client.send_envelope(
        to="james^bob.example",
        text="hi",
        thread_id="my-thread",
        recipient_encryption_key=recipient_public,
    )

    sent = json.loads(route.calls.last.request.content.decode())
    inner = decrypt_envelope(
        EncryptedEnvelope.from_dict(sent["envelope"]),
        recipient_private_key=recipient_private,
        recipient_address="james^bob.example",
    )
    assert inner.payload["text"] == "hi"
    assert inner.payload["thread_id"] == "my-thread"


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_omits_thread_id_when_absent(client_fixture):
    """When thread_id is not passed, the payload must not include the field."""
    client, _, _ = client_fixture
    recipient_private, recipient_public = generate_encryption_keypair()
    route = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 101, "queued_at": "2026-05-21T12:00:00Z"}),
    )

    await client.send_envelope(
        to="james^bob.example",
        text="hi",
        recipient_encryption_key=recipient_public,
    )

    sent = json.loads(route.calls.last.request.content.decode())
    inner = decrypt_envelope(
        EncryptedEnvelope.from_dict(sent["envelope"]),
        recipient_private_key=recipient_private,
        recipient_address="james^bob.example",
    )
    assert "thread_id" not in inner.payload


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_resolves_recipient_encryption_key(client_fixture):
    client, _, _ = client_fixture
    recipient_private, recipient_public = generate_encryption_keypair()
    peer_seed, peer_public = generate_keypair()
    card = AgentCard(
        address="james^bob.example",
        did="did:web:bob.example#agent",
        public_key=encode_b64url(peer_public),
        encryption_key=encode_b64url(recipient_public),
        endpoints=[],
    )
    card_envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss=card.address,
        iat=_fresh_iat(),
    ).sign(peer_seed)
    respx.post("https://bob.example/.well-known/aap-resolve").mock(
        return_value=httpx.Response(200, content=card_envelope.to_json())
    )
    inbox = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 102})
    )

    await client.send_envelope(to="james^bob.example", text="secret")

    sent = json.loads(inbox.calls.last.request.content.decode())
    inner = decrypt_envelope(
        EncryptedEnvelope.from_dict(sent["envelope"]),
        recipient_private_key=recipient_private,
        recipient_address="james^bob.example",
    )
    assert inner.payload["text"] == "secret"


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_raw_validates_and_encrypts(client_fixture):
    client, seed, _ = client_fixture
    recipient_private, recipient_public = generate_encryption_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.test/v1",
        payload={"ok": True},
        iss="chris^relay.example",
        iat=_fresh_iat(),
    ).sign(seed)
    inbox = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 500})
    )

    result = await client.send_envelope_raw(
        to="james^bob.example",
        envelope_json=env.to_json(),
        recipient_encryption_key=recipient_public,
    )

    assert result == 500
    sent = json.loads(inbox.calls.last.request.content.decode())
    inner = decrypt_envelope(
        EncryptedEnvelope.from_dict(sent["envelope"]),
        recipient_private_key=recipient_private,
        recipient_address="james^bob.example",
    )
    assert inner.payload == {"ok": True}


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_raw_rejects_unsigned_before_post(client_fixture):
    client, _, _ = client_fixture
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.test/v1",
        payload={"ok": True},
        iss="chris^relay.example",
        iat=_fresh_iat(),
    )
    inbox = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 500})
    )

    with pytest.raises(AAPClientError, match="could not be verified|not signed"):
        await client.send_envelope_raw(
            to="james^bob.example",
            envelope_json=env.to_json(),
            recipient_encryption_key=generate_encryption_keypair()[1],
        )
    assert not inbox.called


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_raw_rejects_wrong_issuer_before_post(client_fixture):
    client, seed, _ = client_fixture
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.test/v1",
        payload={"ok": True},
        iss="attacker^relay.example",
        iat=_fresh_iat(),
    ).sign(seed)
    inbox = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 500})
    )

    with pytest.raises(AAPClientError, match="issuer"):
        await client.send_envelope_raw(
            to="james^bob.example",
            envelope_json=env.to_json(),
            recipient_encryption_key=generate_encryption_keypair()[1],
        )
    assert not inbox.called


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_raw_rejects_bad_signature_before_post(client_fixture):
    client, _, _ = client_fixture
    other_seed, _ = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.test/v1",
        payload={"ok": True},
        iss="chris^relay.example",
        iat=_fresh_iat(),
    ).sign(other_seed)
    inbox = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 500})
    )

    with pytest.raises(AAPClientError, match="signature"):
        await client.send_envelope_raw(
            to="james^bob.example",
            envelope_json=env.to_json(),
            recipient_encryption_key=generate_encryption_keypair()[1],
        )
    assert not inbox.called


@respx.mock
@pytest.mark.asyncio
async def test_send_envelope_raw_rejects_stale_iat_before_post(client_fixture):
    client, seed, _ = client_fixture
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.test/v1",
        payload={"ok": True},
        iss="chris^relay.example",
        iat=_rfc3339(datetime.now(timezone.utc) - timedelta(days=31)),
    ).sign(seed)
    inbox = respx.post("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(202, json={"id": 500})
    )

    with pytest.raises(AAPClientError, match="freshness|too old"):
        await client.send_envelope_raw(
            to="james^bob.example",
            envelope_json=env.to_json(),
            recipient_encryption_key=generate_encryption_keypair()[1],
        )
    assert not inbox.called


@respx.mock
@pytest.mark.asyncio
async def test_poll_inbox_constructs_correct_aap_sig_header(client_fixture):
    client, seed, public = client_fixture
    route = respx.get("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(200, json={"envelopes": []})
    )

    await client.poll_inbox(wait=0)

    assert route.called
    request = route.calls.last.request
    auth = request.headers.get("Authorization")
    assert auth is not None and auth.startswith("AAP-Sig ")
    sig_b64 = auth.removeprefix("AAP-Sig ").strip()
    ts = request.headers["X-AAP-Sig-Ts"]
    nonce = request.headers["X-AAP-Sig-Nonce"]

    # Verify the signature against the client's public key
    canonical = canonicalize({
        "address": "chris^relay.example",
        "method": "GET",
        "nonce": nonce,
        "path": "/aap/inbox",
        "ts": ts,
    })
    assert ed25519_verify(public, canonical, decode_b64url(sig_b64))


@respx.mock
@pytest.mark.asyncio
async def test_poll_inbox_returns_envelopes(client_fixture):
    client, _, _ = client_fixture
    respx.get("https://relay.test/aap/inbox").mock(
        return_value=httpx.Response(200, json={
            "envelopes": [
                {"id": 1, "body": "{\"v\":1}", "sender": "james^bob.example"},
            ],
        }),
    )

    envelopes = await client.poll_inbox(wait=0)
    assert len(envelopes) == 1
    assert envelopes[0]["id"] == 1
    assert envelopes[0]["sender"] == "james^bob.example"


@respx.mock
@pytest.mark.asyncio
async def test_register_raises_on_409(client_fixture):
    client, _, _ = client_fixture
    respx.post("https://relay.test/aap/agents/register").mock(
        return_value=httpx.Response(409, json={"detail": "key change"})
    )
    from aap.client import KeyChangeRejected
    with pytest.raises(KeyChangeRejected):
        await client.register()


@respx.mock
@pytest.mark.asyncio
async def test_resolve_peer_returns_pubkey_on_success(client_fixture):
    """resolve_peer authenticates the AgentCard through its self-signature."""
    client, _, _ = client_fixture
    # Build a signed AgentCard envelope as if from the relay
    peer_seed, peer_public = generate_keypair()
    peer_address = "alice^example.dev"
    card = AgentCard(
        address=peer_address,
        did="did:web:example.dev#agent",
        public_key=encode_b64url(peer_public),
        endpoints=[],
    )
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss=card.address,
        iat=_fresh_iat(),
    ).sign(peer_seed)

    respx.post("https://example.dev/.well-known/aap-resolve").mock(
        return_value=httpx.Response(200, content=envelope.to_json()),
    )
    result = await client.resolve_peer(peer_address)
    assert result == peer_public


@respx.mock
@pytest.mark.asyncio
async def test_resolve_peer_raises_on_404(client_fixture):
    from aap.client import AAPClientError
    client, _, _ = client_fixture
    respx.post("https://example.dev/.well-known/aap-resolve").mock(
        return_value=httpx.Response(404, json={"detail": "not hosted here"}),
    )
    with pytest.raises(AAPClientError, match="not hosted at example.dev"):
        await client.resolve_peer("alice^example.dev")


@respx.mock
@pytest.mark.asyncio
async def test_resolve_peer_raises_on_mismatched_address(client_fixture):
    """If the resolved AgentCard's address doesn't match what we asked for, error out."""
    from aap.client import AAPClientError
    client, _, _ = client_fixture
    peer_seed, peer_public = generate_keypair()
    # Card claims to be 'bob' but we asked for 'alice'
    card = AgentCard(
        address="bob^example.dev",
        did="did:web:example.dev#agent",
        public_key=encode_b64url(peer_public),
        endpoints=[],
    )
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss=card.address,
        iat=_fresh_iat(),
    ).sign(peer_seed)
    respx.post("https://example.dev/.well-known/aap-resolve").mock(
        return_value=httpx.Response(200, content=envelope.to_json()),
    )
    with pytest.raises(AAPClientError, match="address.*!= requested"):
        await client.resolve_peer("alice^example.dev")


@respx.mock
@pytest.mark.asyncio
async def test_resolve_agent_card_rejects_substituted_signature(client_fixture):
    from aap.client import AAPClientError

    client, _, _ = client_fixture
    legitimate_seed, legitimate_public = generate_keypair()
    attacker_seed, _ = generate_keypair()
    card = AgentCard(
        address="alice^example.dev",
        did="did:web:example.dev#agent",
        public_key=encode_b64url(legitimate_public),
        endpoints=[],
    )
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss=card.address,
        iat=_fresh_iat(),
    ).sign(attacker_seed)
    respx.post("https://example.dev/.well-known/aap-resolve").mock(
        return_value=httpx.Response(200, content=envelope.to_json())
    )
    with pytest.raises(AAPClientError, match="signature did not verify"):
        await client.resolve_agent_card(card.address)


@respx.mock
@pytest.mark.asyncio
async def test_resolve_agent_card_rejects_issuer_substitution(client_fixture):
    from aap.client import AAPClientError

    client, _, _ = client_fixture
    seed, public = generate_keypair()
    card = AgentCard(
        address="alice^example.dev",
        did="did:web:example.dev#agent",
        public_key=encode_b64url(public),
        endpoints=[],
    )
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss="mallory^example.dev",
        iat=_fresh_iat(),
    ).sign(seed)
    respx.post("https://example.dev/.well-known/aap-resolve").mock(
        return_value=httpx.Response(200, content=envelope.to_json())
    )

    with pytest.raises(AAPClientError, match="issuer.*does not match"):
        await client.resolve_agent_card(card.address)


@respx.mock
@pytest.mark.asyncio
async def test_resolve_agent_card_rejects_did_from_other_domain(client_fixture):
    from aap.client import AAPClientError

    client, _, _ = client_fixture
    seed, public = generate_keypair()
    card = AgentCard(
        address="alice^example.dev",
        did="did:web:evil.example#agent",
        public_key=encode_b64url(public),
        endpoints=[],
    )
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss=card.address,
        iat=_fresh_iat(),
    ).sign(seed)
    respx.post("https://example.dev/.well-known/aap-resolve").mock(
        return_value=httpx.Response(200, content=envelope.to_json())
    )

    with pytest.raises(AAPClientError, match="does not belong"):
        await client.resolve_agent_card(card.address)


@respx.mock
@pytest.mark.asyncio
async def test_resolve_agent_card_rejects_pinned_address_key_rotation(client_fixture):
    from aap.client import AgentCardKeyChanged

    client, _, _ = client_fixture
    first_seed, first_public = generate_keypair()
    second_seed, second_public = generate_keypair()
    address = "alice^example.dev"
    did = "did:web:example.dev#agent"
    resolve_route = respx.post("https://example.dev/.well-known/aap-resolve")

    def card_envelope(seed: bytes, public_key: bytes) -> str:
        card = AgentCard(
            address=address,
            did=did,
            public_key=encode_b64url(public_key),
            endpoints=[],
        )
        return Envelope(
            type="aap.envelope/v1",
            payload_type=AgentCard.PAYLOAD_TYPE,
            payload=card.to_dict(),
            iss=address,
            iat=_fresh_iat(),
        ).sign(seed).to_json()

    resolve_route.mock(
        return_value=httpx.Response(200, content=card_envelope(first_seed, first_public))
    )
    await client.resolve_agent_card(address)

    resolve_route.mock(
        return_value=httpx.Response(200, content=card_envelope(second_seed, second_public))
    )

    with pytest.raises(AgentCardKeyChanged, match="changed"):
        await client.resolve_agent_card(address)


@respx.mock
@pytest.mark.asyncio
async def test_resolve_agent_card_rejects_stale_envelope(client_fixture):
    from aap.client import AAPClientError

    client, _, _ = client_fixture
    seed, public = generate_keypair()
    card = AgentCard(
        address="alice^example.dev",
        did="did:web:example.dev#agent",
        public_key=encode_b64url(public),
        endpoints=[],
    )
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss=card.address,
        iat=_rfc3339(datetime.now(timezone.utc) - timedelta(days=31)),
    ).sign(seed)
    respx.post("https://example.dev/.well-known/aap-resolve").mock(
        return_value=httpx.Response(200, content=envelope.to_json())
    )
    with pytest.raises(AAPClientError, match="too old"):
        await client.resolve_agent_card(card.address)
