"""Wire format for chat messages between AAP agents.

We use `aap.message/v1` with payload `{"text": str}`. This is a convention
we're establishing now; once aap-spec grows up, this constant will move there.
"""

from __future__ import annotations

from typing import Union

from aap.encryption import EncryptedEnvelope
from aap.envelope import Envelope
from aap.jcs import canonicalize
from aap.keys import encode_b64url, sign as ed25519_sign

CHAT_PAYLOAD_TYPE = "aap.message/v1"
ROUTING_ENVELOPE_TYPE = "aap.routing-envelope/v1"
ROUTING_ENVELOPE_VERSION = 1


class UnsupportedPayloadType(ValueError):
    """The envelope's payload_type is not one we handle."""


def build_chat_envelope(
    *,
    seed: bytes,
    sender_address: str,
    text: str,
    iat: str,
    thread_id: str | None = None,
    capability_token: str | None = None,
    conversation_id: str | None = None,
    conversation_members: list[str] | None = None,
) -> Envelope:
    """Build and sign an aap.message/v1 envelope.

    thread_id, when set, identifies a conversation thread within the
    sender <-> recipient channel. Receivers route by thread_id when present;
    absent = the default thread per peer.

    capability_token, when set, embeds a signed RelationshipToken envelope
    (the one the recipient previously issued to us) as the chat envelope's
    ``capability_token`` field. v0.7.0 makes this mandatory for chat
    envelopes — recipients reject envelopes without a valid token.
    The token MUST be set before ``.sign()`` so JCS canonicalization
    includes it in the signed bytes.

    conversation_id + conversation_members (v0.8.0), when set, mark this
    envelope as part of a group conversation. Both fields MUST be set
    before ``.sign()`` for the same JCS reason.
    """
    payload: dict = {"text": text}
    if thread_id is not None:
        payload["thread_id"] = thread_id

    return Envelope(
        type="aap.envelope/v1",
        payload_type=CHAT_PAYLOAD_TYPE,
        payload=payload,
        iss=sender_address,
        iat=iat,
        capability_token=capability_token,
        conversation_id=conversation_id,
        conversation_members=conversation_members,
    ).sign(seed)


def wrap_routing_envelope(
    to: str,
    inner: Union[Envelope, EncryptedEnvelope],
    *,
    sender_address: str | None = None,
    seed: bytes | None = None,
    iat: str | None = None,
    nonce: str | None = None,
) -> str:
    """Wrap a signed or encrypted envelope for POST /aap/inbox.

    Modern encrypted delivery signs the relay-visible routing wrapper so a
    relay can authenticate and meter the sender without decrypting the inner
    envelope. The routing signature follows the AAP envelope convention:
    Ed25519 over JCS canonical bytes of every routing field except ``sig``.

    When no signing inputs are supplied this emits the historical unsigned
    wrapper, which remains useful for local plaintext tests and older relays.
    """
    signing_requested = any(
        value is not None for value in (sender_address, seed, iat, nonce)
    )
    if signing_requested and None in (sender_address, seed, iat, nonce):
        raise ValueError(
            "signed routing envelopes require sender_address, seed, iat, and nonce"
        )

    if signing_requested:
        route = _routing_signing_dict(
            to=to,
            inner=inner,
            sender_address=sender_address,
            iat=iat,
            nonce=nonce,
        )
        route["sig"] = encode_b64url(ed25519_sign(seed, canonicalize(route)))
    else:
        route = {
            "type": ROUTING_ENVELOPE_TYPE,
            "to": to,
            "envelope": inner.to_dict(),
        }
    return canonicalize(route).decode("utf-8")


def _routing_signing_dict(
    *,
    to: str,
    inner: Union[Envelope, EncryptedEnvelope],
    sender_address: str,
    iat: str,
    nonce: str,
) -> dict:
    return {
        "envelope": inner.to_dict(),
        "from": sender_address,
        "iat": iat,
        "nonce": nonce,
        "to": to,
        "type": ROUTING_ENVELOPE_TYPE,
        "v": ROUTING_ENVELOPE_VERSION,
    }


def unwrap_chat_envelope(envelope: Envelope) -> tuple[str, str | None]:
    """Extract (text, thread_id) from an aap.message/v1 envelope.

    Raises:
        UnsupportedPayloadType: payload_type isn't aap.message/v1.
        ValueError: payload doesn't contain a string `text` field, or
            thread_id is present but not a string.
    """
    if envelope.payload_type != CHAT_PAYLOAD_TYPE:
        raise UnsupportedPayloadType(
            f"unsupported payload_type {envelope.payload_type!r} "
            f"(expected {CHAT_PAYLOAD_TYPE!r})"
        )
    text = envelope.payload.get("text")
    if not isinstance(text, str):
        raise ValueError("chat envelope missing 'text' string field in payload")

    thread_id = envelope.payload.get("thread_id")
    if thread_id is not None and not isinstance(thread_id, str):
        raise ValueError("chat envelope 'thread_id' must be a string when present")

    return text, thread_id
