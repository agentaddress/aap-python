"""Persistent service-request/response correlation with signed proof."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

from aap.envelope import Envelope
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.payloads import ServiceRequest, ServiceResponse
from aap.storage import write_json_private

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoredServiceRequest:
    """A signed outbound service request awaiting a business response."""

    request_nonce: str
    business_address: str
    service_id: str
    requested_at: str
    request_envelope_json: str


@dataclass(frozen=True)
class StoredServiceResponse:
    """A verified response to a previously recorded service request."""

    response_nonce: str
    request_nonce: str
    business_address: str
    service_id: str
    responded_at: str
    response_envelope_json: str


class ServiceRequestStore:
    """JSON-backed service request ledger.

    Hosts record outbound request envelopes before sending them. Inbound
    responses are accepted only when they are signed by the expected business,
    reference a pending request nonce, match that request's service id, and use
    a response nonce that has not been seen before.
    """

    def __init__(self, base_dir: Path) -> None:
        self._path = base_dir / "aap-service-requests.json"
        self.pending: list[StoredServiceRequest] = []
        self.responses: list[StoredServiceResponse] = []

    @classmethod
    def load(cls, base_dir: Path) -> "ServiceRequestStore":
        store = cls(base_dir)
        if not store._path.exists():
            return store
        try:
            data = json.loads(store._path.read_text())
        except Exception:
            logger.exception("failed to load %s; starting empty", store._path)
            return store
        for row in data.get("pending") or []:
            try:
                store.pending.append(StoredServiceRequest(**row))
            except TypeError:
                logger.warning("skipping malformed service request row: %r", row)
        for row in data.get("responses") or []:
            try:
                store.responses.append(StoredServiceResponse(**row))
            except TypeError:
                logger.warning("skipping malformed service response row: %r", row)
        return store

    def _save(self) -> None:
        write_json_private(
            self._path,
            {
                "pending": [asdict(r) for r in self.pending],
                "responses": [asdict(r) for r in self.responses],
            },
        )

    def record_request(
        self,
        *,
        business_address: str,
        request_envelope_json: str,
    ) -> StoredServiceRequest:
        env = Envelope.from_json(request_envelope_json)
        if env.payload_type != ServiceRequest.PAYLOAD_TYPE:
            raise ValueError(
                f"expected {ServiceRequest.PAYLOAD_TYPE!r} envelope, "
                f"got {env.payload_type!r}"
            )
        try:
            request = ServiceRequest.from_dict(env.payload)
        except ValueError as e:
            raise ValueError(f"invalid service request payload: {e}") from e
        if self.find_pending(request.nonce) is not None:
            raise ValueError("service request nonce already recorded")
        row = StoredServiceRequest(
            request_nonce=request.nonce,
            business_address=business_address,
            service_id=request.service_id,
            requested_at=env.iat,
            request_envelope_json=request_envelope_json,
        )
        self.pending.append(row)
        self._save()
        return row

    def record_response(
        self,
        *,
        response_envelope_json: str,
        business_public_key: bytes,
    ) -> StoredServiceResponse:
        env = Envelope.from_json(response_envelope_json)
        if env.payload_type != ServiceResponse.PAYLOAD_TYPE:
            raise ValueError(
                f"expected {ServiceResponse.PAYLOAD_TYPE!r} envelope, "
                f"got {env.payload_type!r}"
            )
        try:
            verify_envelope(env, business_public_key)
        except EnvelopePolicyError as e:
            raise ValueError(f"service response envelope failed verification: {e}") from e
        try:
            response = ServiceResponse.from_dict(env.payload)
        except ValueError as e:
            raise ValueError(f"invalid service response payload: {e}") from e

        if any(r.response_nonce == response.nonce for r in self.responses):
            raise ValueError("service response replay detected: nonce already stored")
        request = self.find_pending(response.request_nonce)
        if request is None:
            raise ValueError("service response does not match a pending request")
        if env.iss != request.business_address:
            raise ValueError(
                f"service response issuer {env.iss!r} does not match "
                f"expected business {request.business_address!r}"
            )
        if response.service_id != request.service_id:
            raise ValueError(
                f"service response service_id {response.service_id!r} does not "
                f"match request service_id {request.service_id!r}"
            )

        row = StoredServiceResponse(
            response_nonce=response.nonce,
            request_nonce=response.request_nonce,
            business_address=request.business_address,
            service_id=response.service_id,
            responded_at=env.iat,
            response_envelope_json=response_envelope_json,
        )
        self.pending = [
            r for r in self.pending if r.request_nonce != response.request_nonce
        ]
        self.responses.append(row)
        self._save()
        return row

    def find_pending(self, request_nonce: str) -> StoredServiceRequest | None:
        for row in self.pending:
            if row.request_nonce == request_nonce:
                return row
        return None

    def find_response(self, response_nonce: str) -> StoredServiceResponse | None:
        for row in self.responses:
            if row.response_nonce == response_nonce:
                return row
        return None

    def list_pending(self) -> list[StoredServiceRequest]:
        return list(self.pending)

    def list_responses(self) -> list[StoredServiceResponse]:
        return list(self.responses)
