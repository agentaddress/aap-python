"""Discovery flow: outbound query helpers and introduction-response builder.

This module contains the protocol-level pieces of the AAP discovery flow:

1. :func:`query_discovery` — POSTs a signed envelope to a trusted verifier's
   ``discovery_endpoint``. The verifier mediates a consent prompt on the
   target's side, then resolves the request with the target's AAP address
   (or null).

   IMPORTANT: the hashed-identifier construction is server-side. The
   client sends the plaintext identifier under TLS in the request payload
   (``identifier.type`` + ``identifier.value``). The verifier holds the
   pepper and computes the hash internally; the client cannot.

2. :func:`extract_searcher_identities` — parse attestation envelopes
   attached to an inbound introduction request.

3. :func:`build_introduction_response_envelope` — build the signed
   ``aap.discovery-introduction-response/v1`` envelope.

The host-UI renderer (``render_introduction_prompt``) and the
persistent-store (``PendingIntroductions``) are intentionally kept out
of this module — the renderer stays in the host adapter (host text)
and the store lives in ``aap.stores.pending_introductions``.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from inspect import isawaitable
from typing import Awaitable, Callable, Mapping, Optional

import httpx

from aap.envelope import Envelope, EnvelopeError
from aap.envelope_policy import parse_rfc3339, verify_envelope
from aap.payloads import (
    DiscoveryIntroductionResponse,
    DiscoveryQueryResponse,
    VerificationAttestation,
)
from aap.trusted_verifiers import VerifierTrustListEntry
from aap.verifiers import (
    TrustListCache,
    trusted_verifiers_supporting,
    verifier_relay_address,
)

logger = logging.getLogger(__name__)


# Convention: the discovery query payload type sent inside the signed
# envelope POSTed to the verifier's /aap/discover endpoint. The verifier
# parses this, looks up the hashed identifier internally, and either
# resolves immediately (null result) or kicks off the introduction flow.
DISCOVERY_QUERY_PAYLOAD_TYPE = "aap.discovery-query/v1"

VerifierPublicKeyResolver = Callable[
    [VerifierTrustListEntry], bytes | None | Awaitable[bytes | None]
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Outbound query ───────────────────────────────────────────────────────


async def query_discovery(
    *,
    self_address: str,
    self_seed: bytes,
    identity_type: str,
    identifier_value: str,
    searcher_label: Optional[str],
    trust_list_cache: TrustListCache,
    verifier_public_key_resolver: VerifierPublicKeyResolver,
    searcher_attestations: Optional[list[str]] = None,
    timeout_seconds: int = 300,
    client: Optional[httpx.AsyncClient] = None,
) -> Optional[str]:
    """Query trusted verifiers for an AAP address matching the identifier.

    Returns the target's address (after they approve the introduction)
    or ``None`` (no match / declined / verifier unreachable). Sequential
    fan-out: queries verifiers that support ``identity_type`` in trust
    list order; first success wins.

    Parameters
    ----------
    self_address:
        The caller's AAP address (used as ``iss`` in the signed envelope).
    self_seed:
        Ed25519 seed bytes for signing the outbound envelope.
    identity_type:
        The identity type to search (e.g. ``"phone"``, ``"email"``).
    identifier_value:
        The plaintext identifier value (sent under TLS to the verifier).
    searcher_label:
        Optional label the searcher has stored for the target (shown in
        the consent prompt on the target's side).
    trust_list_cache:
        Resolved trust-list cache instance. ``await trust_list_cache.get()``
        is called to obtain the current entry list before filtering.
    verifier_public_key_resolver:
        Callable that returns the Ed25519 public key for the selected verifier.
        Discovery responses are accepted only when signed by that verifier's
        relay address and bound to this request's nonce.
    searcher_attestations:
        Optional list of attestation envelope JSON strings to attach.
    timeout_seconds:
        How long (seconds) to ask the verifier to wait for the target's
        consent response. Defaults to 300 s (5 minutes).
    client:
        Optional shared ``httpx.AsyncClient``. If omitted, a temporary one
        is created and closed before returning.
    """
    entries = await trust_list_cache.get()
    candidates = trusted_verifiers_supporting(entries, identity_type)
    if not candidates:
        logger.warning(
            "No trusted verifier supports identity_type=%r for discovery", identity_type
        )
        return None

    own_client = client is None
    http = client or httpx.AsyncClient(timeout=timeout_seconds + 5)
    try:
        for verifier in candidates:
            # Discovery query payload shape: flat ``identity_type`` +
            # ``identifier_value`` fields, not a nested ``identifier``
            # dict. Searcher address comes from the envelope's ``iss``
            # (verifier reads env.iss, not payload).
            # TODO(F4): this shape is currently the reference verifier's
            # contract, not a formal AAP spec. Promote it to normative
            # schemas and conformance tests before treating it as stable.
            query_nonce = secrets.token_urlsafe(12)
            payload = {
                "identity_type": identity_type,
                "identifier_value": identifier_value,
                "searcher_label_for_recipient": searcher_label,
                "searcher_attestations": list(searcher_attestations or []),
                "nonce": query_nonce,
            }
            env = Envelope(
                type="aap.envelope/v1",
                payload_type=DISCOVERY_QUERY_PAYLOAD_TYPE,
                payload=payload,
                iss=self_address,
                iat=_now_iso(),
            ).sign(self_seed)
            body = env.to_json()
            try:
                # Tell the verifier how long we want it to wait for the
                # target's introduction-response. Without ``?timeout=``, the
                # reference verifier defaults to 30s — too short for a
                # human to read the consent prompt and approve.
                resp = await http.post(
                    verifier.discovery_endpoint,
                    params={"timeout": str(timeout_seconds)},
                    content=body,
                    headers={"Content-Type": "application/json"},
                )
            except Exception as e:
                logger.warning(
                    "Discovery query to %s failed: %s",
                    verifier.discovery_endpoint, e,
                )
                continue
            if resp.status_code != 200:
                logger.warning(
                    "Discovery query to %s returned HTTP %s",
                    verifier.discovery_endpoint, resp.status_code,
                )
                continue
            result = await _verified_query_result(
                response_body=resp.text,
                verifier=verifier,
                query_nonce=query_nonce,
                verifier_public_key_resolver=verifier_public_key_resolver,
            )
            if isinstance(result, str) and result:
                return result
            # null / empty: try the next verifier.
        return None
    finally:
        if own_client:
            await http.aclose()


async def _resolve_verifier_public_key(
    resolver: VerifierPublicKeyResolver,
    verifier: VerifierTrustListEntry,
) -> bytes | None:
    value = resolver(verifier)
    if isawaitable(value):
        value = await value
    return value if isinstance(value, bytes) else None


async def _verified_query_result(
    *,
    response_body: str,
    verifier: VerifierTrustListEntry,
    query_nonce: str,
    verifier_public_key_resolver: VerifierPublicKeyResolver,
) -> str | None:
    try:
        env = Envelope.from_json(response_body)
        if env.payload_type != DiscoveryQueryResponse.PAYLOAD_TYPE:
            logger.warning(
                "Discovery query to %s returned wrong payload_type=%r",
                verifier.discovery_endpoint,
                env.payload_type,
            )
            return None
        expected_issuer = verifier_relay_address(verifier.domain)
        if env.iss != expected_issuer:
            logger.warning(
                "Discovery query to %s returned issuer %r, expected %r",
                verifier.discovery_endpoint,
                env.iss,
                expected_issuer,
            )
            return None
        public_key = await _resolve_verifier_public_key(
            verifier_public_key_resolver,
            verifier,
        )
        if public_key is None:
            logger.warning(
                "No public key available for discovery verifier %s", verifier.domain
            )
            return None
        verify_envelope(env, public_key)
        payload = DiscoveryQueryResponse.from_dict(env.payload)
        if payload.query_nonce != query_nonce:
            logger.warning(
                "Discovery query to %s returned mismatched nonce",
                verifier.discovery_endpoint,
            )
            return None
        if payload.expires_at is not None:
            expires_at = parse_rfc3339(payload.expires_at)
            if expires_at <= datetime.now(timezone.utc):
                logger.warning(
                    "Discovery query to %s returned expired response",
                    verifier.discovery_endpoint,
                )
                return None
        return payload.result
    except (EnvelopeError, ValueError, TypeError) as e:
        logger.warning(
            "Discovery query to %s returned invalid signed response: %s",
            verifier.discovery_endpoint,
            e,
        )
        return None


# ─── Inbound helpers ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class _SearcherIdentitySummary:
    """One verified identity carried in the searcher's attestation(s)."""

    type: str
    value: str


def extract_searcher_identities(
    *,
    searcher_attestations: list[str],
    expected_subject_address: str,
    trusted_verifiers: list[VerifierTrustListEntry],
    verifier_public_keys: Mapping[str, bytes],
    now: datetime | None = None,
) -> list[dict[str, str]]:
    """Return verified ``{type, value}`` identity badges for a searcher.

    An attestation contributes a badge only when it is issued by a trusted
    verifier, verifies against that verifier's public key, names the expected
    searcher as its subject, and has not expired.
    """
    now = now or datetime.now(timezone.utc)
    trusted_by_domain = {entry.domain: entry for entry in trusted_verifiers}
    out: list[dict[str, str]] = []
    for env_json in searcher_attestations:
        try:
            env = Envelope.from_json(env_json)
            if env.payload_type != VerificationAttestation.PAYLOAD_TYPE:
                continue
            att = VerificationAttestation.from_dict(env.payload)
            if env.iss != att.verifier:
                continue
            verifier = trusted_by_domain.get(att.verifier)
            if verifier is None:
                continue
            if att.identity["type"] not in verifier.supported_identities:
                continue
            public_key = verifier_public_keys.get(att.verifier)
            if public_key is None:
                continue
            verify_envelope(
                env,
                public_key,
                now=now,
                max_age_seconds=None,
            )
            if parse_rfc3339(att.expires_at) <= now:
                continue
        except Exception:
            continue
        if att.subject_address != expected_subject_address:
            continue
        value = att.identity.get("value")
        type_ = att.identity.get("type")
        if not (isinstance(type_, str) and isinstance(value, str)):
            continue
        out.append({"type": type_, "value": value})
    return out


def build_introduction_response_envelope(
    *,
    responder_seed: bytes,
    responder_address: str,
    verifier_nonce: str,
    approved: bool,
    verifier_capability_token: Optional[str] = None,
) -> Envelope:
    """Build a signed ``aap.discovery-introduction-response/v1`` envelope.

    ``verifier_capability_token`` (if supplied) is the relationship-token
    envelope JSON that the verifier previously granted us (so the verifier
    can authenticate the response). v1 ships without this — we sign with
    the responder's key and the verifier resolves by ``iss`` + envelope
    signature alone.
    """
    payload = DiscoveryIntroductionResponse(
        verifier_nonce=verifier_nonce, approved=approved
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=DiscoveryIntroductionResponse.PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=responder_address,
        iat=_now_iso(),
        capability_token=verifier_capability_token,
    )
    return env.sign(responder_seed)
