"""Tests for verification + discovery payload types."""

import pytest

from aap.payloads import (
    VerificationAttestation,
    DiscoveryIntroductionRequest,
    DiscoveryIntroductionResponse,
    DiscoveryQueryResponse,
    VerifyConfirmResponse,
    VerifyStartResponse,
)


# ── VerificationAttestation ──────────────────────────────────────────────


def test_verification_attestation_round_trips():
    att = VerificationAttestation(
        subject_address="james^james-bots.example",
        identity={"type": "phone", "value": "+14154442222"},
        challenge_method="sms-otp",
        verified_at="2026-05-22T12:00:00Z",
        expires_at="2027-05-22T12:00:00Z",
        verifier="verify.example",
        nonce="abc123",
    )
    d = att.to_dict()
    assert d == {
        "subject_address": "james^james-bots.example",
        "identity": {"type": "phone", "value": "+14154442222"},
        "challenge_method": "sms-otp",
        "verified_at": "2026-05-22T12:00:00Z",
        "expires_at": "2027-05-22T12:00:00Z",
        "verifier": "verify.example",
        "nonce": "abc123",
    }
    assert VerificationAttestation.from_dict(d) == att


def test_verification_attestation_payload_type():
    assert VerificationAttestation.PAYLOAD_TYPE == "aap.verification-attestation/v1"


def test_verification_attestation_requires_identity_type_and_value():
    with pytest.raises(ValueError, match="identity.*missing"):
        VerificationAttestation.from_dict({
            "subject_address": "foo^x.com",
            "identity": {"type": "phone"},  # missing value
            "challenge_method": "sms-otp",
            "verified_at": "2026-05-22T12:00:00Z",
            "expires_at": "2027-05-22T12:00:00Z",
            "verifier": "v.example.com",
            "nonce": "n",
        })


def test_verification_attestation_identity_email():
    att = VerificationAttestation(
        subject_address="foo^x.com",
        identity={"type": "email", "value": "foo@example.com"},
        challenge_method="email-link",
        verified_at="2026-05-22T12:00:00Z",
        expires_at="2027-05-22T12:00:00Z",
        verifier="v.example.com",
        nonce="n",
    )
    assert VerificationAttestation.from_dict(att.to_dict()) == att


def test_verify_start_response_round_trips():
    resp = VerifyStartResponse(
        request_nonce="req-123",
        otp_id="otp-abc",
        expires_at="2026-05-22T12:10:00Z",
    )
    assert VerifyStartResponse.from_dict(resp.to_dict()) == resp


def test_verify_start_response_payload_type():
    assert VerifyStartResponse.PAYLOAD_TYPE == "aap.verify-start-response/v1"


def test_verify_confirm_response_round_trips():
    resp = VerifyConfirmResponse(
        request_nonce="req-123",
        otp_id="otp-abc",
        attestation_envelope='{"type":"aap.envelope/v1"}',
    )
    assert VerifyConfirmResponse.from_dict(resp.to_dict()) == resp


def test_verify_confirm_response_payload_type():
    assert VerifyConfirmResponse.PAYLOAD_TYPE == "aap.verify-confirm-response/v1"


# ── DiscoveryIntroductionRequest / Response ──────────────────────────────


def test_discovery_introduction_request_round_trips():
    req = DiscoveryIntroductionRequest(
        searcher="chris^relay.example",
        searcher_label_for_recipient="James Lane",
        searcher_attestations=[
            '{"type":"aap.envelope/v1","payload_type":"aap.verification-attestation/v1",...}',
        ],
        verifier_nonce="vfr-123",
        expires_at="2026-05-22T12:10:00Z",
    )
    d = req.to_dict()
    assert d["searcher"] == "chris^relay.example"
    assert d["searcher_label_for_recipient"] == "James Lane"
    assert len(d["searcher_attestations"]) == 1
    assert DiscoveryIntroductionRequest.from_dict(d) == req


def test_discovery_introduction_request_optional_fields_omitted():
    """searcher_label_for_recipient and searcher_attestations are optional."""
    req = DiscoveryIntroductionRequest(
        searcher="chris^x.com",
        searcher_label_for_recipient=None,
        searcher_attestations=[],
        verifier_nonce="n",
        expires_at="2026-05-22T12:10:00Z",
    )
    d = req.to_dict()
    # Empty attestation list is omitted to match the existing convention
    assert "searcher_attestations" not in d or d["searcher_attestations"] == []
    assert d.get("searcher_label_for_recipient") is None or "searcher_label_for_recipient" not in d


def test_discovery_introduction_request_payload_type():
    assert DiscoveryIntroductionRequest.PAYLOAD_TYPE == "aap.discovery-introduction-request/v1"


def test_discovery_introduction_response_round_trips():
    resp = DiscoveryIntroductionResponse(
        verifier_nonce="vfr-123",
        approved=True,
    )
    d = resp.to_dict()
    assert d == {"verifier_nonce": "vfr-123", "approved": True}
    assert DiscoveryIntroductionResponse.from_dict(d) == resp


def test_discovery_introduction_response_denied():
    resp = DiscoveryIntroductionResponse(verifier_nonce="n", approved=False)
    assert DiscoveryIntroductionResponse.from_dict(resp.to_dict()) == resp


def test_discovery_introduction_response_payload_type():
    assert DiscoveryIntroductionResponse.PAYLOAD_TYPE == "aap.discovery-introduction-response/v1"


def test_discovery_query_response_round_trips():
    resp = DiscoveryQueryResponse(
        query_nonce="query-123",
        result="bob^example.com",
        expires_at="2026-05-22T12:10:00Z",
    )
    d = resp.to_dict()
    assert d == {
        "query_nonce": "query-123",
        "result": "bob^example.com",
        "expires_at": "2026-05-22T12:10:00Z",
    }
    assert DiscoveryQueryResponse.from_dict(d) == resp


def test_discovery_query_response_allows_null_result():
    resp = DiscoveryQueryResponse(query_nonce="query-123", result=None)
    assert resp.to_dict() == {"query_nonce": "query-123", "result": None}
    assert DiscoveryQueryResponse.from_dict(resp.to_dict()) == resp


def test_discovery_query_response_payload_type():
    assert DiscoveryQueryResponse.PAYLOAD_TYPE == "aap.discovery-query-response/v1"
