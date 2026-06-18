"""Async HTTPS helper for talking to a verifier's verification endpoints.

A verifier exposes:

- ``POST <verification_endpoint>/sms/start``  — body ``{phone, subject_address}`` signed by the agent
- ``POST <verification_endpoint>/sms/confirm`` — body ``{otp_id, otp}`` signed by the agent
- ``POST <verification_endpoint>/email/start`` — body ``{email, subject_address}`` signed
- ``POST <verification_endpoint>/email/confirm`` — body ``{otp_id, token}`` signed

The verifier responds with signed ``aap.verify-start-response/v1`` and
``aap.verify-confirm-response/v1`` envelopes. Confirm responses carry the
signed verification-attestation envelope.

We sign the request body with an ``aap.envelope/v1`` whose payload carries
the request fields. The verifier resolves the signing key by looking up the
caller's AgentCard from its ``iss`` address.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx

from aap.envelope import Envelope, EnvelopeError
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.payloads import (
    VerificationAttestation,
    VerifyConfirmResponse,
    VerifyStartResponse,
)
from aap.transport import InsecureTransportError, require_secure_url
from aap.verifiers import verifier_relay_address

logger = logging.getLogger(__name__)


# Payload types the verifier service expects on /aap/verify/<channel>/start.
# The verifier rejects anything else with HTTP 400 "unexpected payload_type".
# TODO(F4): these shapes are currently the reference verifier's contract,
# not a formal AAP spec. Promote them to normative schemas and conformance
# tests before treating them as stable protocol surface.
_VERIFY_SMS_START_PAYLOAD = "aap.verify-sms-start/v1"
_VERIFY_EMAIL_START_PAYLOAD = "aap.verify-email-start/v1"
_VERIFY_SMS_CONFIRM_PAYLOAD = "aap.verify-sms-confirm/v1"
_VERIFY_EMAIL_CONFIRM_PAYLOAD = "aap.verify-email-confirm/v1"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VerifierClientError(RuntimeError):
    """Surfaces a verifier HTTP failure to the caller."""


@dataclass(frozen=True)
class VerifyStartResult:
    otp_id: str
    expires_at: str


def _endpoint_url(verification_endpoint: str, suffix: str) -> str:
    try:
        endpoint = require_secure_url(
            verification_endpoint,
            field_name="verification_endpoint",
        )
    except InsecureTransportError as e:
        raise VerifierClientError(str(e)) from e
    return endpoint.rstrip("/") + suffix


def _sign_request(
    *,
    seed: bytes,
    subject_address: str,
    payload_type: str,
    payload: dict,
) -> str:
    """Wrap ``payload`` in a signed envelope and serialize."""
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=payload_type,
        payload=payload,
        iss=subject_address,
        iat=_now_iso(),
    ).sign(seed)
    return env.to_json()


async def start_sms_verification(
    *,
    seed: bytes,
    subject_address: str,
    phone: str,
    verification_endpoint: str,
    verifier_domain: str,
    verifier_public_key: bytes,
    client: Optional[httpx.AsyncClient] = None,
) -> VerifyStartResult:
    """Initiate an SMS-OTP verification.

    Returns the ``otp_id`` (used to confirm) and the expiry hint. Raises
    ``VerifierClientError`` on transport or 4xx/5xx response.
    """
    url = _endpoint_url(verification_endpoint, "/sms/start")
    request_nonce = secrets.token_urlsafe(12)
    payload = {
        "phone": phone,
        "subject_address": subject_address,
        "nonce": request_nonce,
    }
    body = _sign_request(
        seed=seed,
        subject_address=subject_address,
        payload_type=_VERIFY_SMS_START_PAYLOAD,
        payload=payload,
    )
    return await _post_start(
        url=url,
        body=body,
        request_nonce=request_nonce,
        verifier_domain=verifier_domain,
        verifier_public_key=verifier_public_key,
        client=client,
    )


async def confirm_sms_verification(
    *,
    seed: bytes,
    subject_address: str,
    otp_id: str,
    otp: str,
    verification_endpoint: str,
    verifier_domain: str,
    verifier_public_key: bytes,
    client: Optional[httpx.AsyncClient] = None,
) -> str:
    """Confirm an SMS OTP. Returns the signed attestation envelope JSON.

    The verifier response and the returned attestation are both verified
    against ``verifier_public_key`` before the attestation JSON is returned.
    """
    url = _endpoint_url(verification_endpoint, "/sms/confirm")
    request_nonce = secrets.token_urlsafe(12)
    body = _sign_request(
        seed=seed,
        subject_address=subject_address,
        payload_type=_VERIFY_SMS_CONFIRM_PAYLOAD,
        payload={"otp_id": otp_id, "otp": otp, "nonce": request_nonce},
    )
    return await _post_confirm(
        url=url,
        body=body,
        request_nonce=request_nonce,
        otp_id=otp_id,
        subject_address=subject_address,
        verifier_domain=verifier_domain,
        verifier_public_key=verifier_public_key,
        client=client,
    )


async def start_email_verification(
    *,
    seed: bytes,
    subject_address: str,
    email: str,
    verification_endpoint: str,
    verifier_domain: str,
    verifier_public_key: bytes,
    client: Optional[httpx.AsyncClient] = None,
) -> VerifyStartResult:
    url = _endpoint_url(verification_endpoint, "/email/start")
    request_nonce = secrets.token_urlsafe(12)
    payload = {
        "email": email,
        "subject_address": subject_address,
        "nonce": request_nonce,
    }
    body = _sign_request(
        seed=seed,
        subject_address=subject_address,
        payload_type=_VERIFY_EMAIL_START_PAYLOAD,
        payload=payload,
    )
    return await _post_start(
        url=url,
        body=body,
        request_nonce=request_nonce,
        verifier_domain=verifier_domain,
        verifier_public_key=verifier_public_key,
        client=client,
    )


async def confirm_email_verification(
    *,
    seed: bytes,
    subject_address: str,
    otp_id: str,
    token: str,
    verification_endpoint: str,
    verifier_domain: str,
    verifier_public_key: bytes,
    client: Optional[httpx.AsyncClient] = None,
) -> str:
    """Confirm an email-link token. Same raw-JSON shape as SMS confirm."""
    url = _endpoint_url(verification_endpoint, "/email/confirm")
    request_nonce = secrets.token_urlsafe(12)
    body = _sign_request(
        seed=seed,
        subject_address=subject_address,
        payload_type=_VERIFY_EMAIL_CONFIRM_PAYLOAD,
        payload={"otp_id": otp_id, "token": token, "nonce": request_nonce},
    )
    return await _post_confirm(
        url=url,
        body=body,
        request_nonce=request_nonce,
        otp_id=otp_id,
        subject_address=subject_address,
        verifier_domain=verifier_domain,
        verifier_public_key=verifier_public_key,
        client=client,
    )


async def _post_start(
    *,
    url: str,
    body: str,
    request_nonce: str,
    verifier_domain: str,
    verifier_public_key: bytes,
    client: Optional[httpx.AsyncClient],
) -> VerifyStartResult:
    resp = await _post(url=url, body=body, client=client)
    try:
        env = _verified_verifier_response(
            resp.text,
            expected_payload_type=VerifyStartResponse.PAYLOAD_TYPE,
            verifier_domain=verifier_domain,
            verifier_public_key=verifier_public_key,
        )
        payload = VerifyStartResponse.from_dict(env.payload)
    except Exception as e:
        raise VerifierClientError(f"invalid verifier start response: {e}") from e
    if payload.request_nonce != request_nonce:
        raise VerifierClientError("verifier start response nonce mismatch")
    if not payload.otp_id:
        raise VerifierClientError("verifier response missing 'otp_id'")
    if not payload.expires_at:
        raise VerifierClientError("verifier response missing 'expires_at'")
    return VerifyStartResult(otp_id=payload.otp_id, expires_at=payload.expires_at)


async def _post_confirm(
    *,
    url: str,
    body: str,
    request_nonce: str,
    otp_id: str,
    subject_address: str,
    verifier_domain: str,
    verifier_public_key: bytes,
    client: Optional[httpx.AsyncClient],
) -> str:
    resp = await _post(url=url, body=body, client=client)
    try:
        env = _verified_verifier_response(
            resp.text,
            expected_payload_type=VerifyConfirmResponse.PAYLOAD_TYPE,
            verifier_domain=verifier_domain,
            verifier_public_key=verifier_public_key,
        )
        payload = VerifyConfirmResponse.from_dict(env.payload)
    except Exception as e:
        raise VerifierClientError(f"invalid verifier confirm response: {e}") from e
    if payload.request_nonce != request_nonce:
        raise VerifierClientError("verifier confirm response nonce mismatch")
    if payload.otp_id != otp_id:
        raise VerifierClientError("verifier confirm response otp_id mismatch")
    if not payload.attestation_envelope:
        raise VerifierClientError(
            "verifier response missing 'attestation_envelope' envelope"
        )
    _verify_attestation(
        payload.attestation_envelope,
        subject_address=subject_address,
        verifier_domain=verifier_domain,
        verifier_public_key=verifier_public_key,
    )
    return payload.attestation_envelope


def _verified_verifier_response(
    envelope_json: str,
    *,
    expected_payload_type: str,
    verifier_domain: str,
    verifier_public_key: bytes,
) -> Envelope:
    env = Envelope.from_json(envelope_json)
    if env.payload_type != expected_payload_type:
        raise VerifierClientError("unexpected verifier response payload_type")
    expected_issuer = verifier_relay_address(verifier_domain)
    if env.iss != expected_issuer:
        raise VerifierClientError("unexpected verifier response issuer")
    verify_envelope(env, verifier_public_key)
    return env


def _verify_attestation(
    attestation_envelope_json: str,
    *,
    subject_address: str,
    verifier_domain: str,
    verifier_public_key: bytes,
) -> None:
    try:
        env = Envelope.from_json(attestation_envelope_json)
        if env.payload_type != VerificationAttestation.PAYLOAD_TYPE:
            raise VerifierClientError("unexpected attestation payload_type")
        verify_envelope(env, verifier_public_key)
        attestation = VerificationAttestation.from_dict(env.payload)
    except (EnvelopeError, EnvelopePolicyError, ValueError) as e:
        raise VerifierClientError(f"invalid attestation envelope: {e}") from e
    if env.iss != verifier_domain or attestation.verifier != verifier_domain:
        raise VerifierClientError("attestation verifier mismatch")
    if attestation.subject_address != subject_address:
        raise VerifierClientError("attestation subject mismatch")


async def _post(
    *, url: str, body: str, client: Optional[httpx.AsyncClient]
) -> httpx.Response:
    owns = client is None
    http = client or httpx.AsyncClient(timeout=15.0)
    try:
        try:
            resp = await http.post(
                url,
                content=body,
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError as e:
            raise VerifierClientError(f"verifier request to {url} failed: {e}") from e
        if resp.status_code >= 400:
            raise VerifierClientError(
                f"verifier returned HTTP {resp.status_code} from {url}: "
                f"{resp.text[:200]}"
            )
        return resp
    finally:
        if owns:
            await http.aclose()
