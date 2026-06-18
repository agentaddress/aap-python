"""Tests for service request/response correlation storage."""

from __future__ import annotations

import pytest

from aap.envelope import Envelope
from aap.keys import generate_keypair
from aap.payloads import ServiceResponseStatus
from aap.services import (
    build_service_request_envelope,
    build_service_response_envelope,
)
from aap.stores.service_requests import ServiceRequestStore


CUSTOMER = "john^example.com"
BUSINESS = "reception^frankies.example"


def _request_json(seed: bytes, *, nonce: str = "req-1", service_id: str = "book-table") -> str:
    return build_service_request_envelope(
        seed=seed,
        sender_address=CUSTOMER,
        target_address=BUSINESS,
        service_id=service_id,
        payload={"name": "John"},
        nonce=nonce,
        iat="2026-06-15T12:00:00Z",
    ).to_json()


def _response_json(
    seed: bytes,
    *,
    sender: str = BUSINESS,
    request_nonce: str = "req-1",
    service_id: str = "book-table",
    response_nonce: str = "resp-1",
) -> str:
    return build_service_response_envelope(
        seed=seed,
        sender_address=sender,
        service_id=service_id,
        request_nonce=request_nonce,
        status=ServiceResponseStatus.CONFIRMED,
        nonce=response_nonce,
        payload={"confirmation_id": "FR-9X42"},
        iat="2026-06-15T12:05:00Z",
    ).to_json()


def test_record_request_persists_pending(tmp_path):
    customer_seed, _ = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)

    row = store.record_request(
        business_address=BUSINESS,
        request_envelope_json=_request_json(customer_seed),
    )

    assert row.request_nonce == "req-1"
    assert row.business_address == BUSINESS
    reloaded = ServiceRequestStore.load(tmp_path)
    assert reloaded.find_pending("req-1") is not None


def test_record_response_verifies_and_consumes_pending_request(tmp_path):
    customer_seed, _ = generate_keypair()
    business_seed, business_public = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)
    store.record_request(
        business_address=BUSINESS,
        request_envelope_json=_request_json(customer_seed),
    )

    response = store.record_response(
        response_envelope_json=_response_json(business_seed),
        business_public_key=business_public,
    )

    assert response.response_nonce == "resp-1"
    assert response.request_nonce == "req-1"
    assert store.find_pending("req-1") is None
    assert store.find_response("resp-1") == response
    reloaded = ServiceRequestStore.load(tmp_path)
    assert reloaded.find_pending("req-1") is None
    assert reloaded.find_response("resp-1") is not None


def test_record_request_rejects_wrong_payload_type(tmp_path):
    seed, _ = generate_keypair()
    env = Envelope(
        type="aap.envelope/v1",
        payload_type="aap.message/v1",
        payload={"text": "hi"},
        iss=CUSTOMER,
        iat="2026-06-15T12:00:00Z",
    ).sign(seed)
    store = ServiceRequestStore.load(tmp_path)
    with pytest.raises(ValueError, match="expected .*service-request"):
        store.record_request(
            business_address=BUSINESS,
            request_envelope_json=env.to_json(),
        )


def test_record_request_rejects_duplicate_request_nonce(tmp_path):
    customer_seed, _ = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)
    request_json = _request_json(customer_seed)
    store.record_request(business_address=BUSINESS, request_envelope_json=request_json)
    with pytest.raises(ValueError, match="already recorded"):
        store.record_request(business_address=BUSINESS, request_envelope_json=request_json)


def test_record_response_rejects_bad_signature(tmp_path):
    customer_seed, _ = generate_keypair()
    business_seed, _ = generate_keypair()
    _, wrong_public = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)
    store.record_request(
        business_address=BUSINESS,
        request_envelope_json=_request_json(customer_seed),
    )

    with pytest.raises(ValueError, match="failed verification"):
        store.record_response(
            response_envelope_json=_response_json(business_seed),
            business_public_key=wrong_public,
        )


def test_record_response_rejects_unknown_request_nonce(tmp_path):
    business_seed, business_public = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)

    with pytest.raises(ValueError, match="pending request"):
        store.record_response(
            response_envelope_json=_response_json(business_seed),
            business_public_key=business_public,
        )


def test_record_response_rejects_wrong_business_issuer(tmp_path):
    customer_seed, _ = generate_keypair()
    attacker_seed, attacker_public = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)
    store.record_request(
        business_address=BUSINESS,
        request_envelope_json=_request_json(customer_seed),
    )

    with pytest.raises(ValueError, match="issuer"):
        store.record_response(
            response_envelope_json=_response_json(
                attacker_seed,
                sender="attacker^frankies.example",
            ),
            business_public_key=attacker_public,
        )


def test_record_response_rejects_wrong_service_id(tmp_path):
    customer_seed, _ = generate_keypair()
    business_seed, business_public = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)
    store.record_request(
        business_address=BUSINESS,
        request_envelope_json=_request_json(customer_seed, service_id="book-table"),
    )

    with pytest.raises(ValueError, match="service_id"):
        store.record_response(
            response_envelope_json=_response_json(
                business_seed,
                service_id="cancel-table",
            ),
            business_public_key=business_public,
        )


def test_record_response_rejects_duplicate_response_nonce(tmp_path):
    customer_seed, _ = generate_keypair()
    business_seed, business_public = generate_keypair()
    store = ServiceRequestStore.load(tmp_path)
    store.record_request(
        business_address=BUSINESS,
        request_envelope_json=_request_json(customer_seed, nonce="req-1"),
    )
    store.record_response(
        response_envelope_json=_response_json(
            business_seed,
            request_nonce="req-1",
            response_nonce="resp-1",
        ),
        business_public_key=business_public,
    )
    store.record_request(
        business_address=BUSINESS,
        request_envelope_json=_request_json(customer_seed, nonce="req-2"),
    )
    with pytest.raises(ValueError, match="replay"):
        store.record_response(
            response_envelope_json=_response_json(
                business_seed,
                request_nonce="req-2",
                response_nonce="resp-1",
            ),
            business_public_key=business_public,
        )
