"""Async HTTP client for AAP-compatible relay endpoints."""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from aap.encryption import (
    EncryptedEnvelope,
    EncryptionError,
    decrypt_envelope,
    derive_encryption_keypair,
    encrypt_envelope,
    encryption_public_from_private,
)
from aap.envelope import Envelope, EnvelopeError
from aap.envelope_policy import (
    DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
    EnvelopePolicyError,
    EnvelopeReplayCache,
    validate_envelope_iat,
)
from aap.inbound import (
    ValidatedChat,
    ValidatedEnvelope,
    validate_inbound_chat,
    validate_inbound_envelope,
)
from aap.did_web import (
    KeyPinChanged,
    KeyPins,
    did_web_domain,
)
from aap.jcs import canonicalize
from aap.keys import decode_b64url, encode_b64url, sign as ed25519_sign
from aap.payloads import AgentCard
from aap.address import Address
from aap.relationships import RelationshipStore
from aap.transport import require_secure_url

from aap.messages import build_chat_envelope, wrap_routing_envelope


class AAPClientError(Exception):
    """Base exception for AAP relay HTTP failures."""


class KeyChangeRejected(AAPClientError):
    """Relay rejected our registration with 409 (TOFU key conflict)."""


class AgentCardKeyChanged(AAPClientError):
    """A pinned AgentCard signing key changed unexpectedly."""


class AAPClient:
    """Async HTTP client wrapping AAP-compatible relay endpoints."""

    def __init__(
        self,
        relay_url: str,
        seed: bytes,
        public_key: bytes,
        address: str,
        timeout_seconds: int = 35,
        encryption_private_key: bytes | None = None,
        encryption_public_key: bytes | None = None,
        agent_card_key_pins_path: Path | None = None,
        agent_card_max_age_seconds: int = DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
    ) -> None:
        self.relay_url = require_secure_url(
            relay_url, field_name="relay_url"
        ).rstrip("/")
        self.seed = seed
        self.public_key = public_key
        self.address = address
        self.timeout_seconds = timeout_seconds
        if encryption_private_key is None:
            encryption_private_key, derived_public = derive_encryption_keypair(seed)
        else:
            derived_public = encryption_public_from_private(encryption_private_key)
        if encryption_public_key is not None and encryption_public_key != derived_public:
            raise ValueError("encryption public key does not match encryption private key")
        self.encryption_private_key = encryption_private_key
        self.encryption_public_key = derived_public
        self._agent_card_key_pins = KeyPins(agent_card_key_pins_path)
        self._agent_card_max_age_seconds = agent_card_max_age_seconds
        self._http = httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False)

    async def close(self) -> None:
        await self._http.aclose()

    async def register(self) -> dict[str, Any]:
        """POST a signed AgentCard envelope. Returns the relay's response body."""
        card = AgentCard(
            address=self.address,
            did=f"did:web:{Address.parse(self.address).domain}#agent",
            public_key=encode_b64url(self.public_key),
            endpoints=[{"type": "didcomm", "uri": self.relay_url}],
            encryption_key=encode_b64url(self.encryption_public_key),
        )
        envelope = Envelope(
            type="aap.envelope/v1",
            payload_type=AgentCard.PAYLOAD_TYPE,
            payload=card.to_dict(),
            iss=self.address,
            iat=_now_iso(),
        ).sign(self.seed)

        response = await self._http.post(
            f"{self.relay_url}/aap/agents/register",
            content=envelope.to_json(),
            headers={"Content-Type": "application/json"},
        )
        if response.status_code == 409:
            raise KeyChangeRejected(response.json().get("detail", "key change rejected"))
        if response.status_code != 200:
            raise AAPClientError(
                f"register failed: HTTP {response.status_code}: {response.text}"
            )
        return response.json()

    async def send_envelope(
        self,
        to: str,
        text: str,
        thread_id: str | None = None,
        capability_token: str | None = None,
        conversation_id: str | None = None,
        conversation_members: list[str] | None = None,
        recipient_encryption_key: bytes | None = None,
    ) -> int:
        """Encrypt and send a chat message. Returns the relay-assigned envelope id.

        ``capability_token`` (when supplied) is the signed RelationshipToken
        envelope JSON the recipient previously issued to us. Receivers
        reject chat envelopes without one (v0.7.0 token enforcement).

        ``conversation_id`` + ``conversation_members`` (v0.8.0) mark the
        envelope as part of a group conversation. When omitted, the envelope
        is a 1:1 chat (existing behavior).
        """
        inner = build_chat_envelope(
            seed=self.seed,
            sender_address=self.address,
            text=text,
            iat=_now_iso(),
            thread_id=thread_id,
            capability_token=capability_token,
            conversation_id=conversation_id,
            conversation_members=conversation_members,
        )
        recipient_key = recipient_encryption_key or await self.resolve_encryption_key(to)
        encrypted = encrypt_envelope(
            inner,
            recipient_public_key=recipient_key,
            recipient_address=to,
        )
        routing_body = wrap_routing_envelope(
            to=to,
            inner=encrypted,
            sender_address=self.address,
            seed=self.seed,
            iat=_now_iso(),
            nonce=secrets.token_urlsafe(24),
        )

        response = await self._http.post(
            f"{self.relay_url}/aap/inbox",
            content=routing_body,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code != 202:
            raise AAPClientError(
                f"send failed: HTTP {response.status_code}: {response.text}"
            )
        return int(response.json()["id"])

    async def send_envelope_raw(
        self,
        to: str,
        envelope_json: str,
        *,
        recipient_encryption_key: bytes | None = None,
    ) -> int:
        """Encrypt and post a pre-built signed envelope to the relay's inbox.

        Used by the capability flow (and any other code path that builds
        an envelope outside ``send_envelope``, which only handles chat
        envelopes). The envelope must be signed by this client identity and
        carry a fresh ``iat`` timestamp.
        """
        envelope = self._validate_outbound_raw_envelope(envelope_json)
        recipient_key = recipient_encryption_key or await self.resolve_encryption_key(to)
        encrypted = encrypt_envelope(
            envelope,
            recipient_public_key=recipient_key,
            recipient_address=to,
        )
        routing_body = wrap_routing_envelope(
            to=to,
            inner=encrypted,
            sender_address=self.address,
            seed=self.seed,
            iat=_now_iso(),
            nonce=secrets.token_urlsafe(24),
        )
        response = await self._http.post(
            f"{self.relay_url}/aap/inbox",
            content=routing_body,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code != 202:
            raise AAPClientError(
                f"send_envelope_raw failed: HTTP {response.status_code}: {response.text}"
            )
        return int(response.json()["id"])

    def _validate_outbound_raw_envelope(self, envelope_json: str) -> Envelope:
        try:
            envelope = Envelope.from_json(envelope_json)
        except EnvelopeError as e:
            raise AAPClientError(f"send_envelope_raw: malformed envelope: {e}") from e
        if envelope.iss != self.address:
            raise AAPClientError(
                f"send_envelope_raw: envelope issuer {envelope.iss!r} "
                f"does not match client address {self.address!r}"
            )
        try:
            if not envelope.verify(self.public_key):
                raise AAPClientError(
                    "send_envelope_raw: envelope signature did not verify "
                    "against client public key"
                )
            validate_envelope_iat(envelope)
        except EnvelopeError as e:
            raise AAPClientError(
                f"send_envelope_raw: envelope could not be verified: {e}"
            ) from e
        except EnvelopePolicyError as e:
            raise AAPClientError(
                f"send_envelope_raw: envelope freshness check failed: {e}"
            ) from e
        return envelope

    def decrypt_inbound(self, value: dict[str, Any] | str) -> Envelope:
        """Decrypt one relay-delivered ``aap.encrypted-envelope/v1`` object."""
        try:
            encrypted = (
                EncryptedEnvelope.from_json(value)
                if isinstance(value, str)
                else EncryptedEnvelope.from_dict(value)
            )
            return decrypt_envelope(
                encrypted,
                recipient_private_key=self.encryption_private_key,
                recipient_address=self.address,
            )
        except EncryptionError as e:
            raise AAPClientError(f"failed to decrypt inbound envelope: {e}") from e

    def validate_inbound_chat(
        self,
        value: EncryptedEnvelope | Envelope | dict[str, Any] | str,
        *,
        sender_public_key: bytes,
        relationship_store: RelationshipStore,
        replay_cache: EnvelopeReplayCache | None = None,
        now: datetime | None = None,
        max_age_seconds: int | None = DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
        allowed_relationship_types: tuple[str, ...] = ("friend", "admin"),
        allow_plaintext: bool = False,
    ) -> ValidatedChat:
        """Strictly validate one inbound encrypted chat message."""
        return validate_inbound_chat(
            value,
            recipient_private_key=self.encryption_private_key,
            recipient_address=self.address,
            sender_public_key=sender_public_key,
            relationship_store=relationship_store,
            replay_cache=replay_cache,
            now=now,
            max_age_seconds=max_age_seconds,
            allowed_relationship_types=allowed_relationship_types,
            allow_plaintext=allow_plaintext,
        )

    def validate_inbound_envelope(
        self,
        value: EncryptedEnvelope | Envelope | dict[str, Any] | str,
        *,
        sender_public_key: bytes,
        replay_cache: EnvelopeReplayCache | None = None,
        now: datetime | None = None,
        max_age_seconds: int | None = DEFAULT_ENVELOPE_MAX_AGE_SECONDS,
        allow_plaintext: bool = False,
    ) -> ValidatedEnvelope:
        """Strictly validate one inbound encrypted envelope before dispatch."""
        return validate_inbound_envelope(
            value,
            recipient_private_key=self.encryption_private_key,
            recipient_address=self.address,
            sender_public_key=sender_public_key,
            replay_cache=replay_cache,
            now=now,
            max_age_seconds=max_age_seconds,
            allow_plaintext=allow_plaintext,
        )

    async def resolve_agent_card(self, address: str) -> AgentCard:
        """Resolve and return the peer's full AgentCard (not just the
        public key). Used by the trust layer to read
        ``verified_identities`` and other future card fields.
        """
        try:
            parsed = Address.parse(address)
        except ValueError as e:
            raise AAPClientError(f"resolve_agent_card: malformed address {address!r}") from e
        localpart, domain = parsed.localpart, parsed.domain

        resolve_url = f"https://{domain}/.well-known/aap-resolve"
        try:
            response = await self._http.post(
                resolve_url,
                json={"localpart": localpart},
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError as e:
            raise AAPClientError(f"resolve_agent_card: HTTP error contacting {domain}: {e}") from e

        if response.status_code == 404:
            raise AAPClientError(f"resolve_agent_card: peer {address!r} not hosted at {domain}")
        if response.status_code != 200:
            raise AAPClientError(
                f"resolve_agent_card: HTTP {response.status_code} from {domain}: {response.text}"
            )

        try:
            envelope = Envelope.from_json(response.content.decode("utf-8"))
        except (EnvelopeError, UnicodeDecodeError) as e:
            raise AAPClientError(f"resolve_agent_card: malformed envelope: {e}") from e

        if envelope.payload_type != AgentCard.PAYLOAD_TYPE:
            raise AAPClientError(
                f"resolve_agent_card: expected {AgentCard.PAYLOAD_TYPE}, got {envelope.payload_type!r}"
            )

        try:
            card = AgentCard.from_dict(envelope.payload)
        except (ValueError, TypeError) as e:
            raise AAPClientError(f"resolve_agent_card: malformed AgentCard: {e}") from e
        if card.address != address:
            raise AAPClientError(
                f"resolve_agent_card: resolved card address {card.address!r} "
                f"!= requested {address!r}"
            )
        if envelope.iss != card.address:
            raise AAPClientError(
                f"resolve_agent_card: envelope issuer {envelope.iss!r} "
                f"does not match card address {card.address!r}"
            )
        try:
            if did_web_domain(card.did) != domain:
                raise AAPClientError(
                    f"resolve_agent_card: card DID {card.did!r} "
                    f"does not belong to {domain!r}"
                )
            verification_key = decode_b64url(card.public_key)
            if not envelope.verify(verification_key):
                raise AAPClientError(
                    "resolve_agent_card: envelope signature did not verify "
                    "against the AgentCard public_key"
                )
            validate_envelope_iat(
                envelope,
                max_age_seconds=self._agent_card_max_age_seconds,
            )
            self._agent_card_key_pins.check_or_pin(card.address, verification_key)
        except KeyPinChanged as e:
            raise AgentCardKeyChanged(str(e)) from e
        except (EnvelopeError, EnvelopePolicyError, ValueError) as e:
            raise AAPClientError(f"resolve_agent_card: verification failed: {e}") from e
        return card

    def forget_agent_card_key_pin(self, address: str) -> bool:
        """Forget a pinned AgentCard key after independently verifying rotation."""
        return self._agent_card_key_pins.forget(address)

    async def resolve_encryption_key(self, address: str) -> bytes:
        """Resolve the peer's advertised X25519 HPKE public key."""
        card = await self.resolve_agent_card(address)
        if not card.encryption_key:
            raise AAPClientError(
                f"peer {address!r} does not advertise an encryption key"
            )
        try:
            public_key = decode_b64url(card.encryption_key)
        except ValueError as e:
            raise AAPClientError(
                f"peer {address!r} has a malformed encryption key"
            ) from e
        if len(public_key) != 32:
            raise AAPClientError(
                f"peer {address!r} encryption key must be 32 bytes"
            )
        return public_key

    async def resolve_peer(self, address: str) -> bytes:
        """Resolve an authenticated peer Ed25519 signing key."""
        card = await self.resolve_agent_card(address)
        try:
            return decode_b64url(card.public_key)
        except ValueError as e:
            raise AAPClientError(f"resolve_peer: malformed public_key field: {e}") from e

    async def poll_inbox(self, wait: int = 30) -> list[dict[str, Any]]:
        """Long-poll for inbound envelopes. Returns the relay's envelopes list."""
        path = "/aap/inbox"
        # AAP-Sig timestamps are Unix epoch seconds (as a string), per the
        # relay's parse rule. Earlier drafts used ISO-8601; the relay tightened
        # this for replay-window enforcement.
        ts = str(int(time.time()))
        nonce = secrets.token_urlsafe(12)
        canonical = canonicalize({
            "address": self.address,
            "method": "GET",
            "nonce": nonce,
            "path": path,
            "ts": ts,
        })
        sig_b64 = encode_b64url(ed25519_sign(self.seed, canonical))

        response = await self._http.get(
            f"{self.relay_url}{path}",
            params={"address": self.address, "wait": wait},
            headers={
                "Authorization": f"AAP-Sig {sig_b64}",
                "X-AAP-Sig-Ts": ts,
                "X-AAP-Sig-Nonce": nonce,
            },
        )
        if response.status_code != 200:
            raise AAPClientError(
                f"poll failed: HTTP {response.status_code}: {response.text}"
            )
        return response.json().get("envelopes", [])


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
