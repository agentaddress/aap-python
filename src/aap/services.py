"""Signed service catalog cache + ServiceRequest/ServiceResponse helpers.

Replaces the capability/scope/token machinery for the customer→business
path. A business publishes ``/.well-known/aap-services`` as a signed
``aap.service-catalog/v1`` envelope; customer agents verify + cache the
catalog, validate user-supplied payloads against ``input_schema``, and
build signed ``aap.service-request/v1`` envelopes that the receiver
either fulfills or denies with an ``aap.service-response/v1``.

The catalog wire format::

    GET https://reception.frankies.example/.well-known/aap-services
    <signed aap.envelope/v1, payload_type=aap.service-catalog/v1>
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

import httpx
import jsonschema

from aap.envelope import Envelope, EnvelopeError
from aap.envelope_policy import EnvelopePolicyError, verify_envelope
from aap.payloads import (
    ServiceRequest,
    ServiceResponse,
    ServiceResponseStatus,
)
from aap.storage import write_json_private

logger = logging.getLogger(__name__)

SERVICE_CATALOG_PAYLOAD_TYPE = "aap.service-catalog/v1"
AgentPublicKeyResolver = Callable[[str], bytes | Awaitable[bytes]]


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceDefinition:
    """One entry in a business's published service catalog."""

    id: str
    display_name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] = field(default_factory=dict)
    verification_required: dict[str, dict[str, Any]] = field(default_factory=dict)
    recurrence: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ServiceDefinition":
        if not isinstance(d.get("input_schema"), dict):
            raise ValueError("service entry missing input_schema dict")
        return cls(
            id=str(d["id"]),
            display_name=str(d.get("display_name", d["id"])),
            description=str(d.get("description", "")),
            input_schema=dict(d["input_schema"]),
            output_schema=dict(d.get("output_schema") or {}),
            verification_required=dict(d.get("verification_required") or {}),
            recurrence=dict(d["recurrence"]) if isinstance(d.get("recurrence"), dict) else None,
        )


@dataclass(frozen=True)
class ServiceCatalogPayload:
    PAYLOAD_TYPE = SERVICE_CATALOG_PAYLOAD_TYPE

    agent: str
    services: list[ServiceDefinition]
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "services": [_service_definition_to_dict(sd) for sd in self.services],
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ServiceCatalogPayload":
        agent = d.get("agent")
        if not isinstance(agent, str) or not agent:
            raise ValueError("service catalog missing agent")
        nonce = d.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("service catalog missing nonce")
        services_raw = d.get("services")
        if not isinstance(services_raw, list):
            raise ValueError("service catalog services must be a list")
        services = [ServiceDefinition.from_dict(entry) for entry in services_raw]
        return cls(agent=agent, services=services, nonce=nonce)


@dataclass
class ServiceCatalog:
    """A business's full catalog, as fetched from /.well-known/aap-services.

    ``business_address`` is the address the caller used to look the catalog
    up. ``canonical_agent_address`` is the address the catalog itself
    declares in its top-level ``agent`` field — the authoritative AAP
    address to talk to. They can differ when a caller guesses (e.g.
    ``reception^frankies.example``) at a domain whose canonical
    agent localpart is something else (``bookings^...``); peers
    should use the canonical address for service-requests and chat.
    """

    business_address: str
    fetched_at: datetime
    services: dict[str, ServiceDefinition]
    canonical_agent_address: Optional[str] = None
    etag: Optional[str] = None
    catalog_envelope_json: str = ""

    def get(self, service_id: str) -> Optional[ServiceDefinition]:
        return self.services.get(service_id)

    def ids(self) -> list[str]:
        return list(self.services.keys())


# ---------------------------------------------------------------------------
# Catalog cache (in-process + on-disk)
# ---------------------------------------------------------------------------


def _safe_filename(business_address: str) -> str:
    # reception^frankies.example -> reception_frankies.example.json
    return business_address.replace("^", "_") + ".json"


DEFAULT_TTL_SECONDS = 3600  # 1 hour


class ServiceCatalogCache:
    """Async catalog fetcher with TTL + on-disk persistence.

    One instance per adapter — created at ``connect`` time, shared across
    dispatch handlers and tool calls. Fetches happen via an ``AsyncClient``
    against the agent's domain, parsed into :class:`ServiceCatalog`.
    """

    def __init__(
        self,
        *,
        cache_dir: Path,
        agent_public_key_resolver: AgentPublicKeyResolver,
        client: Optional[httpx.AsyncClient] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._cache_dir = cache_dir
        self._agent_public_key_resolver = agent_public_key_resolver
        self._mem: dict[str, ServiceCatalog] = {}
        self._lock = asyncio.Lock()
        self._client = client or httpx.AsyncClient(timeout=10.0)
        self._owns_client = client is None
        self._ttl = ttl_seconds

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def get(self, business_address: str) -> Optional[ServiceCatalog]:
        """Return a catalog, fetching if needed. ``None`` on any failure
        (network, malformed JSON, no domain in address)."""
        async with self._lock:
            cached = self._mem.get(business_address)
            if cached and self._is_fresh(cached):
                return cached
            if not cached:
                disk = await self._load_from_disk(business_address)
                if disk and self._is_fresh(disk):
                    self._mem[business_address] = disk
                    return disk
        return await self.refresh(business_address)

    async def refresh(self, business_address: str) -> Optional[ServiceCatalog]:
        """Force a re-fetch from the well-known endpoint."""
        domain = self._domain_of(business_address)
        if not domain:
            return None
        url = f"https://{domain}/.well-known/aap-services"
        try:
            resp = await self._client.get(url)
        except Exception as e:
            logger.debug("catalog fetch error for %s: %s", business_address, e)
            return None
        if resp.status_code != 200:
            logger.debug("catalog fetch HTTP %s for %s", resp.status_code, business_address)
            return None
        try:
            catalog = await self._catalog_from_envelope_json(
                business_address,
                resp.content.decode("utf-8"),
                etag=resp.headers.get("etag"),
            )
        except Exception as e:
            logger.debug("catalog fetch parse/verify error for %s: %s", business_address, e)
            return None
        async with self._lock:
            self._mem[business_address] = catalog
        self._save_to_disk(catalog)
        return catalog

    def _is_fresh(self, catalog: ServiceCatalog) -> bool:
        age = (_now_utc() - catalog.fetched_at).total_seconds()
        return age < self._ttl

    @staticmethod
    def _domain_of(address: str) -> Optional[str]:
        if "^" not in address:
            return None
        return address.split("^", 1)[1] or None

    async def _load_from_disk(self, business_address: str) -> Optional[ServiceCatalog]:
        path = self._cache_dir / _safe_filename(business_address)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except Exception:
            return None
        if "catalog_envelope_json" not in data:
            try:
                path.unlink()
            except OSError:
                pass
            return None
        try:
            fetched_at = datetime.fromisoformat(data["fetched_at"])
        except (KeyError, ValueError):
            return None
        try:
            catalog = await self._catalog_from_envelope_json(
                business_address,
                data["catalog_envelope_json"],
                fetched_at=fetched_at,
                etag=data.get("etag"),
            )
        except Exception:
            return None
        return catalog

    def _save_to_disk(self, catalog: ServiceCatalog) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_dir / _safe_filename(catalog.business_address)
        payload = {
            "business_address": catalog.business_address,
            "canonical_agent_address": catalog.canonical_agent_address,
            "fetched_at": catalog.fetched_at.isoformat(),
            "etag": catalog.etag,
            "catalog_envelope_json": catalog.catalog_envelope_json,
        }
        write_json_private(path, payload, default=str)

    async def _catalog_from_envelope_json(
        self,
        business_address: str,
        envelope_json: str,
        *,
        fetched_at: datetime | None = None,
        etag: str | None = None,
    ) -> ServiceCatalog:
        try:
            env = Envelope.from_json(envelope_json)
        except EnvelopeError as e:
            raise ValueError(f"invalid service catalog envelope: {e}") from e
        if env.payload_type != SERVICE_CATALOG_PAYLOAD_TYPE:
            raise ValueError(
                f"expected {SERVICE_CATALOG_PAYLOAD_TYPE!r}, got {env.payload_type!r}"
            )
        payload = ServiceCatalogPayload.from_dict(env.payload)
        if env.iss != payload.agent:
            raise ValueError("service catalog issuer does not match agent")
        requested_domain = self._domain_of(business_address)
        agent_domain = self._domain_of(payload.agent)
        if not requested_domain or agent_domain != requested_domain:
            raise ValueError("service catalog agent does not belong to requested domain")
        public_key = await self._resolve_agent_public_key(payload.agent)
        try:
            verify_envelope(env, public_key)
        except EnvelopePolicyError as e:
            raise ValueError(f"service catalog envelope failed verification: {e}") from e
        services = {sd.id: sd for sd in payload.services}
        return ServiceCatalog(
            business_address=business_address,
            canonical_agent_address=payload.agent,
            fetched_at=fetched_at or _now_utc(),
            services=services,
            etag=etag,
            catalog_envelope_json=env.to_json(),
        )

    async def _resolve_agent_public_key(self, address: str) -> bytes:
        value = self._agent_public_key_resolver(address)
        if inspect.isawaitable(value):
            value = await value
        if not isinstance(value, bytes):
            raise ValueError("agent_public_key_resolver must return bytes")
        return value


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def _service_definition_to_dict(sd: ServiceDefinition) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": sd.id,
        "display_name": sd.display_name,
        "description": sd.description,
        "input_schema": sd.input_schema,
        "output_schema": sd.output_schema,
        "verification_required": sd.verification_required,
    }
    if sd.recurrence is not None:
        out["recurrence"] = sd.recurrence
    return out


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationFailure:
    """A single payload validation problem."""

    message: str
    path: tuple[str | int, ...]


def validate_service_payload(
    payload: dict[str, Any], service: ServiceDefinition
) -> list[ValidationFailure]:
    """Validate ``payload`` against ``service.input_schema``.

    Returns an empty list when valid; otherwise one or more failures with
    JSON-path style location info so the LLM can correct itself.
    """
    validator = jsonschema.Draft202012Validator(service.input_schema)
    failures: list[ValidationFailure] = []
    for err in validator.iter_errors(payload):
        path = tuple(err.absolute_path)
        failures.append(ValidationFailure(message=err.message, path=path))
    return failures


# ---------------------------------------------------------------------------
# Envelope builders
# ---------------------------------------------------------------------------


def build_service_request_envelope(
    *,
    seed: bytes,
    sender_address: str,
    target_address: str,
    service_id: str,
    payload: dict[str, Any],
    verification_attestations: Optional[list[str]] = None,
    nonce: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    """Build a signed ``aap.service-request/v1`` envelope.

    ``verification_attestations`` is a list of signed
    ``aap.verification-attestation/v1`` envelope JSON strings — they ride
    on the outer envelope, not in the ServiceRequest payload itself.
    """
    req = ServiceRequest(
        service_id=service_id,
        payload=dict(payload),
        nonce=nonce or secrets.token_urlsafe(12),
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=ServiceRequest.PAYLOAD_TYPE,
        payload=req.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
        verification_attestations=list(verification_attestations) if verification_attestations else None,
    ).sign(seed)
    return env


def build_service_catalog_envelope(
    *,
    seed: bytes,
    agent_address: str,
    services: list[ServiceDefinition],
    nonce: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    """Build a signed ``aap.service-catalog/v1`` envelope for publishing."""
    payload = ServiceCatalogPayload(
        agent=agent_address,
        services=list(services),
        nonce=nonce or secrets.token_urlsafe(12),
    )
    return Envelope(
        type="aap.envelope/v1",
        payload_type=SERVICE_CATALOG_PAYLOAD_TYPE,
        payload=payload.to_dict(),
        iss=agent_address,
        iat=iat or _now_iso(),
    ).sign(seed)


def build_service_response_envelope(
    *,
    seed: bytes,
    sender_address: str,
    service_id: str,
    request_nonce: str,
    status: ServiceResponseStatus,
    nonce: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
    denial_reason: Optional[str] = None,
    iat: Optional[str] = None,
) -> Envelope:
    """Build a signed ``aap.service-response/v1`` envelope."""
    resp = ServiceResponse(
        service_id=service_id,
        request_nonce=request_nonce,
        status=status,
        nonce=nonce or secrets.token_urlsafe(12),
        payload=dict(payload or {}),
        denial_reason=denial_reason,
    )
    env = Envelope(
        type="aap.envelope/v1",
        payload_type=ServiceResponse.PAYLOAD_TYPE,
        payload=resp.to_dict(),
        iss=sender_address,
        iat=iat or _now_iso(),
    ).sign(seed)
    return env
