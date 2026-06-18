"""Standalone demo of aap-python v0.1.

Run from the repo root with venv active:
    python demo.py
"""

from aap import (
    Address,
    AgentCard,
    Envelope,
    generate_encryption_keypair,
    generate_keypair,
    encode_b64url,
)


def main() -> None:
    # 1. Chris generates an identity.
    private_seed, public_key = generate_keypair()
    _, encryption_public_key = generate_encryption_keypair()
    print("=== Chris generates an Ed25519 identity ===")
    print(f"Public key (b64url): {encode_b64url(public_key)}\n")

    # 2. Chris builds his Agent Card — the discoverable record of his agent.
    card = AgentCard(
        address="chris^chrisevans.id",
        did="did:web:chrisevans.id#agent",
        public_key=encode_b64url(public_key),
        encryption_key=encode_b64url(encryption_public_key),
        endpoints=[{"type": "didcomm", "uri": "https://api.agentaddress.org"}],
    )

    # 3. Wrap the card in a signed envelope. This is what a server at
    #    chrisevans.id/.well-known/aap-resolve would return.
    envelope = Envelope(
        type="aap.envelope/v1",
        payload_type=AgentCard.PAYLOAD_TYPE,
        payload=card.to_dict(),
        iss="did:web:chrisevans.id#agent",
        iat="2026-05-19T12:00:00Z",
    ).sign(private_seed)

    print("=== Wire format (would be served at .well-known/aap-resolve) ===")
    print(envelope.to_json())
    print()

    # 4. James's agent receives the envelope and verifies the signature
    #    using Chris's public key (which James got out-of-band).
    print("=== Verification ===")
    print(f"Verifies with Chris's key:        {envelope.verify(public_key)}")

    _, mallorys_key = generate_keypair()
    print(f"Rejects Mallory's wrong key:      {envelope.verify(mallorys_key)}")

    # 5. Tamper detection — try to swap the address after signing.
    tampered_payload = card.to_dict()
    tampered_payload["address"] = "mallory^evil.example"
    tampered = Envelope(
        type=envelope.type,
        payload_type=envelope.payload_type,
        payload=tampered_payload,
        iss=envelope.iss,
        iat=envelope.iat,
        sig=envelope.sig,  # keep the original signature
    )
    print(f"Detects payload tampering:        {not tampered.verify(public_key)}")

    # 6. Address parsing.
    print("\n=== Address parsing ===")
    addr = Address.parse("chris^chrisevans.id")
    print(f"Parsed: localpart={addr.localpart}, domain={addr.domain}")
    print(f"Round-trip: {addr}")


if __name__ == "__main__":
    main()
