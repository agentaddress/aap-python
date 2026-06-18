"""Tests for aap.verifier_client — async OTP helper functions."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from aap.envelope import Envelope
from aap.keys import generate_keypair
from aap.payloads import (
    VerificationAttestation,
    VerifyConfirmResponse,
    VerifyStartResponse,
)
from aap.verifier_client import (
    VerifierClientError,
    VerifyStartResult,
    confirm_email_verification,
    confirm_sms_verification,
    start_email_verification,
    start_sms_verification,
)
from aap.verifiers import verifier_relay_address

VERIFIER = "https://test-verifier.example"
VERIFIER_DOMAIN = "test-verifier.example"


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seed() -> bytes:
    private, _ = generate_keypair()
    return private


def _start_response_handler(
    *,
    verifier_seed: bytes,
    otp_id: str = "otp-abc123",
    expires_at: str = "2026-06-15T12:00:00Z",
    request_nonce: str | None = None,
    verifier_domain: str = VERIFIER_DOMAIN,
):
    def handler(request: httpx.Request) -> httpx.Response:
        request_env = Envelope.from_json(request.content.decode("utf-8"))
        payload = VerifyStartResponse(
            request_nonce=request_nonce or request_env.payload["nonce"],
            otp_id=otp_id,
            expires_at=expires_at,
        )
        response = Envelope(
            type="aap.envelope/v1",
            payload_type=VerifyStartResponse.PAYLOAD_TYPE,
            payload=payload.to_dict(),
            iss=verifier_relay_address(verifier_domain),
            iat=_rfc3339(datetime.now(timezone.utc)),
        ).sign(verifier_seed)
        return httpx.Response(200, text=response.to_json())

    return handler


def _attestation_json(
    *,
    verifier_seed: bytes,
    subject_address: str,
    verifier_domain: str = VERIFIER_DOMAIN,
) -> str:
    now = datetime.now(timezone.utc)
    attestation = VerificationAttestation(
        subject_address=subject_address,
        identity={"type": "phone", "value": "+15555550100"},
        challenge_method="sms-otp",
        verified_at=_rfc3339(now),
        expires_at=_rfc3339(now + timedelta(days=365)),
        verifier=verifier_domain,
        nonce="att-nonce",
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=VerificationAttestation.PAYLOAD_TYPE,
        payload=attestation.to_dict(),
        iss=verifier_domain,
        iat=_rfc3339(now),
    ).sign(verifier_seed).to_json()


def _confirm_response_handler(
    *,
    verifier_seed: bytes,
    subject_address: str,
    otp_id: str = "otp-abc123",
    request_nonce: str | None = None,
    verifier_domain: str = VERIFIER_DOMAIN,
    attestation_envelope: str | None = None,
):
    def handler(request: httpx.Request) -> httpx.Response:
        request_env = Envelope.from_json(request.content.decode("utf-8"))
        payload = VerifyConfirmResponse(
            request_nonce=request_nonce or request_env.payload["nonce"],
            otp_id=otp_id,
            attestation_envelope=attestation_envelope
            or _attestation_json(
                verifier_seed=verifier_seed,
                subject_address=subject_address,
                verifier_domain=verifier_domain,
            ),
        )
        response = Envelope(
            type="aap.envelope/v1",
            payload_type=VerifyConfirmResponse.PAYLOAD_TYPE,
            payload=payload.to_dict(),
            iss=verifier_relay_address(verifier_domain),
            iat=_rfc3339(datetime.now(timezone.utc)),
        ).sign(verifier_seed)
        return httpx.Response(200, text=response.to_json())

    return handler


@pytest.mark.asyncio
async def test_rejects_remote_http_verifier():
    verifier_seed, verifier_public = generate_keypair()
    with pytest.raises(VerifierClientError, match="must use HTTPS"):
        await start_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            phone="+15555550100",
            verification_endpoint="http://verify.example/aap/verify",
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=verifier_public,
        )


@pytest.mark.asyncio
@respx.mock
async def test_allows_loopback_http_verifier():
    verifier_seed, verifier_public = generate_keypair()
    endpoint = "http://localhost:8080/aap/verify"
    respx.post(f"{endpoint}/sms/start").mock(
        side_effect=_start_response_handler(
            verifier_seed=verifier_seed,
            otp_id="local-otp",
            verifier_domain=VERIFIER_DOMAIN,
        ),
    )
    result = await start_sms_verification(
        seed=_seed(),
        subject_address="alice^example.com",
        phone="+15555550100",
        verification_endpoint=endpoint,
        verifier_domain=VERIFIER_DOMAIN,
        verifier_public_key=verifier_public,
    )
    assert result.otp_id == "local-otp"


@pytest.mark.asyncio
@respx.mock
async def test_start_sms_returns_verify_start_result():
    seed = _seed()
    verifier_seed, verifier_public = generate_keypair()
    route = respx.post(f"{VERIFIER}/sms/start").mock(
        side_effect=_start_response_handler(verifier_seed=verifier_seed),
    )
    result = await start_sms_verification(
        seed=seed,
        subject_address="alice^example.com",
        phone="+15555550100",
        verification_endpoint=VERIFIER,
        verifier_domain=VERIFIER_DOMAIN,
        verifier_public_key=verifier_public,
    )
    request_env = Envelope.from_json(route.calls[0].request.content.decode("utf-8"))
    assert isinstance(result, VerifyStartResult)
    assert result.otp_id == "otp-abc123"
    assert result.expires_at == "2026-06-15T12:00:00Z"
    assert request_env.payload_type == "aap.verify-sms-start/v1"
    assert request_env.payload["nonce"]


@pytest.mark.asyncio
@respx.mock
async def test_start_email_returns_verify_start_result():
    seed = _seed()
    verifier_seed, verifier_public = generate_keypair()
    respx.post(f"{VERIFIER}/email/start").mock(
        side_effect=_start_response_handler(
            verifier_seed=verifier_seed,
            otp_id="otp-email-999",
        ),
    )
    result = await start_email_verification(
        seed=seed,
        subject_address="bob^example.com",
        email="bob@example.com",
        verification_endpoint=VERIFIER,
        verifier_domain=VERIFIER_DOMAIN,
        verifier_public_key=verifier_public,
    )
    assert isinstance(result, VerifyStartResult)
    assert result.otp_id == "otp-email-999"


@pytest.mark.asyncio
@respx.mock
async def test_start_rejects_unsigned_json_response():
    _verifier_seed, verifier_public = generate_keypair()
    respx.post(f"{VERIFIER}/sms/start").mock(
        return_value=httpx.Response(
            200,
            json={"otp_id": "otp-abc123", "expires_at": "2026-06-15T12:00:00Z"},
        ),
    )
    with pytest.raises(VerifierClientError, match="invalid verifier start response"):
        await start_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            phone="+15555550100",
            verification_endpoint=VERIFIER,
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=verifier_public,
        )


@pytest.mark.asyncio
@respx.mock
async def test_start_rejects_nonce_mismatch():
    verifier_seed, verifier_public = generate_keypair()
    respx.post(f"{VERIFIER}/sms/start").mock(
        side_effect=_start_response_handler(
            verifier_seed=verifier_seed,
            request_nonce="wrong-nonce",
        ),
    )
    with pytest.raises(VerifierClientError, match="nonce mismatch"):
        await start_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            phone="+15555550100",
            verification_endpoint=VERIFIER,
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=verifier_public,
        )


@pytest.mark.asyncio
@respx.mock
async def test_start_rejects_bad_signature():
    verifier_seed, _verifier_public = generate_keypair()
    _wrong_seed, wrong_public = generate_keypair()
    respx.post(f"{VERIFIER}/sms/start").mock(
        side_effect=_start_response_handler(verifier_seed=verifier_seed),
    )
    with pytest.raises(VerifierClientError, match="invalid verifier start response"):
        await start_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            phone="+15555550100",
            verification_endpoint=VERIFIER,
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=wrong_public,
        )


@pytest.mark.asyncio
@respx.mock
async def test_confirm_sms_returns_verified_attestation_envelope():
    seed = _seed()
    verifier_seed, verifier_public = generate_keypair()
    route = respx.post(f"{VERIFIER}/sms/confirm").mock(
        side_effect=_confirm_response_handler(
            verifier_seed=verifier_seed,
            subject_address="alice^example.com",
        ),
    )
    result = await confirm_sms_verification(
        seed=seed,
        subject_address="alice^example.com",
        otp_id="otp-abc123",
        otp="123456",
        verification_endpoint=VERIFIER,
        verifier_domain=VERIFIER_DOMAIN,
        verifier_public_key=verifier_public,
    )
    request_env = Envelope.from_json(route.calls[0].request.content.decode("utf-8"))
    result_env = Envelope.from_json(result)
    assert request_env.payload_type == "aap.verify-sms-confirm/v1"
    assert request_env.payload["nonce"]
    assert result_env.payload_type == VerificationAttestation.PAYLOAD_TYPE


@pytest.mark.asyncio
@respx.mock
async def test_confirm_email_returns_verified_attestation_envelope():
    seed = _seed()
    verifier_seed, verifier_public = generate_keypair()
    respx.post(f"{VERIFIER}/email/confirm").mock(
        side_effect=_confirm_response_handler(
            verifier_seed=verifier_seed,
            subject_address="bob^example.com",
        ),
    )
    result = await confirm_email_verification(
        seed=seed,
        subject_address="bob^example.com",
        otp_id="otp-abc123",
        token="email-token",
        verification_endpoint=VERIFIER,
        verifier_domain=VERIFIER_DOMAIN,
        verifier_public_key=verifier_public,
    )
    assert Envelope.from_json(result).payload_type == VerificationAttestation.PAYLOAD_TYPE


@pytest.mark.asyncio
@respx.mock
async def test_confirm_rejects_wrong_otp_id():
    verifier_seed, verifier_public = generate_keypair()
    respx.post(f"{VERIFIER}/sms/confirm").mock(
        side_effect=_confirm_response_handler(
            verifier_seed=verifier_seed,
            subject_address="alice^example.com",
            otp_id="wrong-otp",
        ),
    )
    with pytest.raises(VerifierClientError, match="otp_id mismatch"):
        await confirm_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            otp_id="otp-abc123",
            otp="123456",
            verification_endpoint=VERIFIER,
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=verifier_public,
        )


@pytest.mark.asyncio
@respx.mock
async def test_confirm_rejects_attestation_for_wrong_subject():
    verifier_seed, verifier_public = generate_keypair()
    bad_attestation = _attestation_json(
        verifier_seed=verifier_seed,
        subject_address="other^example.com",
    )
    respx.post(f"{VERIFIER}/sms/confirm").mock(
        side_effect=_confirm_response_handler(
            verifier_seed=verifier_seed,
            subject_address="alice^example.com",
            attestation_envelope=bad_attestation,
        ),
    )
    with pytest.raises(VerifierClientError, match="attestation subject mismatch"):
        await confirm_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            otp_id="otp-abc123",
            otp="123456",
            verification_endpoint=VERIFIER,
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=verifier_public,
        )


@pytest.mark.asyncio
@respx.mock
async def test_http_400_raises_verifier_client_error():
    verifier_seed, verifier_public = generate_keypair()
    respx.post(f"{VERIFIER}/sms/start").mock(
        return_value=httpx.Response(400, text="unexpected payload_type")
    )
    with pytest.raises(VerifierClientError, match="HTTP 400"):
        await start_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            phone="+15555550100",
            verification_endpoint=VERIFIER,
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=verifier_public,
        )


@pytest.mark.asyncio
@respx.mock
async def test_network_failure_raises_verifier_client_error():
    verifier_seed, verifier_public = generate_keypair()
    respx.post(f"{VERIFIER}/sms/start").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    with pytest.raises(VerifierClientError, match="failed"):
        await start_sms_verification(
            seed=_seed(),
            subject_address="alice^example.com",
            phone="+15555550100",
            verification_endpoint=VERIFIER,
            verifier_domain=VERIFIER_DOMAIN,
            verifier_public_key=verifier_public,
        )
