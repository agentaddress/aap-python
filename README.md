# agentaddress

Reference Python implementation of the [Agent Address Protocol](https://agentaddress.org).

For a complete, runnable example of using this SDK inside a real agent host, see
[aap-hermes](https://github.com/agentaddress/aap-hermes) — an open-source host
implementation built on top of `agentaddress`.

## Install

```bash
pip install agentaddress
```

## Quick example

```python
from aap import (
    Address,
    AgentCard,
    Envelope,
    generate_encryption_keypair,
    generate_keypair,
    encode_b64url,
)

# Generate an identity.
private_seed, public_key = generate_keypair()
encryption_private_key, encryption_public_key = generate_encryption_keypair()

# Build and sign an Agent Card envelope.
card = AgentCard(
    address="chris^chrisevans.id",
    did="did:web:chrisevans.id#agent",
    public_key=encode_b64url(public_key),
    encryption_key=encode_b64url(encryption_public_key),
    endpoints=[{"type": "didcomm", "uri": "https://api.agentaddress.org"}],
)

envelope = Envelope(
    type="aap.envelope/v1",
    payload_type=AgentCard.PAYLOAD_TYPE,
    payload=card.to_dict(),
    iss="did:web:chrisevans.id#agent",
    iat="2026-05-19T12:00:00Z",
).sign(private_seed)

# Verify on the other end.
assert envelope.verify(public_key)
```

## Resolving an address

```python
from aap import AAPClient, load_or_generate

identity = load_or_generate()
client = AAPClient(
    relay_url="https://api.agentaddress.org",
    seed=identity.private_seed,
    public_key=identity.public_key,
    encryption_private_key=identity.encryption_private_key,
    address=identity.address,
)

card = await client.resolve_agent_card("chris^chrisevans.id")
peer_signing_key = await client.resolve_peer("chris^chrisevans.id")
```

`AAPClient.resolve_agent_card()` performs authenticated AgentCard resolution:
it checks the card belongs to the requested address, requires the envelope
issuer to equal that address, verifies the envelope with the card's
`public_key`, confirms the card's `did:web` domain matches the address domain,
and pins the address key to detect unexpected rotation.

## Scope

v0.7.0 promotes `aap` from a reference protocol codec to a full agent SDK.
In addition to the v0.1-v0.6 envelope codec, address format, payload types,
and resolution primitives, the SDK now includes:

- **Relay HTTP client** (`aap.client.AAPClient`) — register your agent,
  send end-to-end encrypted signed envelopes, poll for inbound, resolve peer
  AgentCards.
- **Wire-format helpers** (`aap.messages`) — build and unwrap the
  `aap.message/v1` chat payload + the `aap.routing-envelope/v1` outer.
- **End-to-end encryption** (`aap.encryption`) — RFC 9180 HPKE base mode using
  X25519, HKDF-SHA256, and ChaCha20-Poly1305. The relay sees the signed outer
  route needed to authenticate and meter the sender, but not the encrypted
  inner envelope or its payload.
- **Verifier flows** (`aap.verifier_client`, `aap.verifiers`,
  `aap.discovery`) — verifier OTP, trust-list cache, per-verifier pubkey
  resolution from signed trust lists, signed verifier start/confirm responses,
  signed discovery queries, and signed discovery query responses.
- **Service catalog** (`aap.services`) — fetch + cache published
  signed `/.well-known/aap-services` catalogs, verify them against the
  business agent key, validate payloads against `input_schema`, build signed
  request/response envelopes.
- **Relationships, group flow, followups** (`aap.relationships`,
  `aap.group_flow`, `aap.service_followups`) — envelope builders for the
  relationship handshake, group-conversation primitives, and
  business-initiated recurring outreach. Relationship records are persisted
  only through verified proposal/accept handshakes; callers provide the signed
  envelopes and authenticated participant keys, and the store derives the row.
  Relationship revocations likewise require a signed revoke envelope and are
  persisted as revocation proofs before the active row is removed.
- **Group conversations** (`aap.conversations`) — local membership is the
  authorization source for group chat, so receivers should commit group-state
  events through `ConversationStore.accept_invitation()`,
  `apply_membership_update()`, `apply_leave()`, and `apply_complete()`. These
  methods verify signed envelopes, enforce current-convener authority, validate
  membership diffs and convener handoff, and persist event nonces/proofs to
  reject replay.
- **Persistent state stores** (`aap.stores`) — all the JSON-backed stores
  that an agent needs (attestations, pending proposals/responses/consents,
  identity bindings, outbound contacts, pending verifications,
  pending introductions, service-request groups, etc.). Each takes a
  `base_dir: Path` on construction so hosts choose their own filesystem
  layout.

The earlier scope notes (v0.1-v0.6) describe how the codec grew. Host
plugins like [aap-hermes](https://github.com/agentaddress/aap-hermes) build
on top of this SDK to integrate with their respective agent runtimes.

OPRF discovery, revocation, SD-JWT, and the contact-proof primitive come in
subsequent releases.

## Encryption model

Each AgentCard advertises a separate X25519 `encryption_key`. Before relay
submission, the SDK encrypts the complete signed `aap.envelope/v1` into an
`aap.encrypted-envelope/v1`. Recipients decrypt first, then verify the original
Ed25519 signature.

The relay can still see the sender address, recipient address, and delivery
timing. HPKE protects message confidentiality and integrity, but this
asynchronous single-message design does not provide forward secrecy after
compromise of a recipient's long-term X25519 private key. TLS remains required
for transport security and metadata protection from passive network observers.

## Transport security

Configurable relay, verifier, and trusted-verifier-list URLs must use HTTPS.
For local development only, the SDK accepts HTTP URLs whose host is loopback,
including `localhost`, `127.0.0.0/8`, and `::1`. Other HTTP URLs fail before
any network request is attempted.

## Local State

SDK-managed JSON state files are written atomically with file mode `0600`.
This covers identity material, replay caches, verifier/trust caches,
attestations, relationships, conversations, service request ledgers, and
pending consent/verification state. Host-owned files remain the host's
responsibility.

## AgentCard authentication

`AAPClient` accepts an AgentCard only when:

- its envelope issuer exactly matches the requested AAP address;
- the card address exactly matches the requested AAP address;
- the card's `did:web` domain belongs to the requested AAP address domain; and
- the envelope signature verifies with the card's advertised Ed25519 `public_key`.

AgentCard signing keys are pinned by address on first use. Pass
`agent_card_key_pins_path` to `AAPClient` for persistent pins. A changed key
fails closed; call `forget_agent_card_key_pin()` only after independently
confirming an intentional key rotation.

AgentCard envelopes must also pass timestamp freshness checks. By default, the
SDK rejects cards issued more than 30 days ago or more than five minutes in the
future.

## Verified Identity Badges

Trusted verifier lists are signed `aap.trusted-verifiers/v1` envelopes issued by
`aap-trust-root^agentaddressprotocol.org`. `TrustListCache` requires the
trust-root Ed25519 public key and rejects unsigned, wrongly signed, stale, or
wrong-issuer lists. Each verifier entry carries the verifier's Ed25519
`public_key`, so `VerifierPubkeyCache` resolves keys from the signed list rather
than fetching mutable key JSON from verifier-hosted endpoints.

Verifier OTP helpers also require the selected verifier domain and public key.
`start_sms_verification()` / `start_email_verification()` accept only signed
`aap.verify-start-response/v1` envelopes from `verifier^<domain>` whose
`request_nonce` matches the signed start request. `confirm_sms_verification()` /
`confirm_email_verification()` send signed confirm requests, accept only signed
`aap.verify-confirm-response/v1` wrappers, and verify the returned
`VerificationAttestation` envelope before returning it.

Discovery identity summaries are rendered only from verifier-signed
attestations. `extract_searcher_identities()` requires the current trusted
verifier entries plus verifier public keys, and ignores attached attestations
that are untrusted, expired, signed by the wrong key, or for a different
subject address.

## Inbound Receive Policy

Hosts should run relay-delivered messages through `validate_inbound_envelope()`
before payload dispatch. It decrypts encrypted envelopes, verifies the sender
signature, enforces timestamp freshness, and can attach a replay cache.
`validate_inbound_chat()` adds the chat-specific relationship gate for simpler
hosts: by default, encrypted chat is accepted only from active `friend` or
`admin` relationships.

## Outbound Raw Envelopes

`AAPClient.send_envelope_raw()` is for protocol events that are not plain chat,
such as relationship, group, service, and follow-up envelopes. Before encrypting
or posting, the SDK verifies that the pre-built envelope is signed by the client
identity, has `iss == client.address`, and carries a fresh `iat` timestamp.
Invalid raw envelopes fail locally instead of being sent to the relay.

## Follow-Up Grants

Follow-up grants are signed permission slips for business-initiated reminders.
`FollowupGrantStore.record_issued()` and `record_received()` require the
counterparty public key and store a grant only when the signature verifies, the
envelope issuer matches the counterparty address, the timestamp is fresh, and
the grant nonce has not been stored before.

## Service Responses

Service catalogs are published as signed `aap.service-catalog/v1` envelopes.
`ServiceCatalogCache` requires an authenticated public-key resolver, usually
`AAPClient.resolve_peer`, and accepts a catalog only when the envelope issuer
matches the catalog agent, the agent belongs to the requested domain, the
signature verifies, and the catalog timestamp is fresh.

`ServiceResponse` payloads include their own nonce in addition to the original
request nonce. `ServiceRequestStore` records signed outbound requests and
accepts a response only when it is signed by the expected business, references a
pending request, matches the requested service id, and uses a fresh response
nonce.

## SDK example: send a chat message

```python
import asyncio
from pathlib import Path
from aap.client import AAPClient
from aap.identity import load_or_generate

async def main():
    identity = load_or_generate(
        identity_path=Path("~/.my-agent/aap.json").expanduser(),
        env_seed_b64=None,
        address="alice^example.com",
    )
    client = AAPClient(
        relay_url="https://relay.example.com",
        seed=identity.private_seed,
        public_key=identity.public_key,
        encryption_private_key=identity.encryption_private_key,
        encryption_public_key=identity.encryption_public_key,
        address=identity.address,
        agent_card_key_pins_path=Path("~/.my-agent/aap-agent-card-key-pins.json").expanduser(),
    )
    try:
        await client.register()
        await client.send_envelope(to="bob^example.com", text="hello")
    finally:
        await client.close()

asyncio.run(main())
```

## License

Apache 2.0.
