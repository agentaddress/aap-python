"""Tests for the services module — catalog cache + payload validation + builders."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from aap.keys import generate_keypair
from aap.payloads import ServiceRequest, ServiceResponseStatus

from aap.services import (
    SERVICE_CATALOG_PAYLOAD_TYPE,
    ServiceCatalogCache,
    ServiceDefinition,
    build_service_catalog_envelope,
    build_service_request_envelope,
    build_service_response_envelope,
    validate_service_payload,
)


# -- ServiceDefinition.from_dict --------------------------------------------


def test_service_definition_minimal_round_trip():
    sd = ServiceDefinition.from_dict({
        "id": "book-table",
        "display_name": "Reserve",
        "input_schema": {"type": "object", "required": ["name"]},
    })
    assert sd.id == "book-table"
    assert sd.display_name == "Reserve"
    assert sd.verification_required == {}
    assert sd.recurrence is None


def test_service_definition_with_verification_and_recurrence():
    sd = ServiceDefinition.from_dict({
        "id": "routine-cleaning",
        "display_name": "Routine cleaning",
        "description": "Standard 30-min cleaning",
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
        "verification_required": {
            "phone": {"verified_by_oneof": ["verify.aap.org"], "max_age_days": 365}
        },
        "recurrence": {
            "cadence_iso": "P6M",
            "outreach_window_before": "P1M",
            "rationale": "ADA standard interval",
        },
    })
    assert sd.recurrence["cadence_iso"] == "P6M"
    assert "phone" in sd.verification_required


def test_service_definition_rejects_missing_input_schema():
    with pytest.raises(ValueError, match="input_schema"):
        ServiceDefinition.from_dict({"id": "x"})


# -- validate_service_payload ----------------------------------------------


def test_validate_passes_when_schema_matches():
    sd = ServiceDefinition.from_dict({
        "id": "book-table",
        "display_name": "x",
        "input_schema": {
            "type": "object",
            "required": ["name", "party_size"],
            "properties": {
                "name": {"type": "string"},
                "party_size": {"type": "integer", "minimum": 1},
            },
        },
    })
    failures = validate_service_payload({"name": "John", "party_size": 4}, sd)
    assert failures == []


def test_validate_reports_missing_required_field():
    sd = ServiceDefinition.from_dict({
        "id": "book-table",
        "display_name": "x",
        "input_schema": {
            "type": "object",
            "required": ["name"],
            "properties": {"name": {"type": "string"}},
        },
    })
    failures = validate_service_payload({}, sd)
    assert len(failures) == 1
    assert "'name' is a required property" in failures[0].message


def test_validate_reports_type_mismatch():
    sd = ServiceDefinition.from_dict({
        "id": "x",
        "display_name": "x",
        "input_schema": {
            "type": "object",
            "properties": {"party_size": {"type": "integer"}},
        },
    })
    failures = validate_service_payload({"party_size": "four"}, sd)
    assert any("integer" in f.message for f in failures)


def test_validate_reports_minimum_violation():
    sd = ServiceDefinition.from_dict({
        "id": "x",
        "display_name": "x",
        "input_schema": {
            "type": "object",
            "properties": {"party_size": {"type": "integer", "minimum": 1}},
        },
    })
    failures = validate_service_payload({"party_size": 0}, sd)
    assert any("0" in f.message for f in failures)


# -- ServiceCatalogCache (with respx HTTP mock) -----------------------------


def _catalog_services() -> list[ServiceDefinition]:
    return [
        ServiceDefinition.from_dict({
            "id": "book-table",
            "display_name": "Reserve a table",
            "description": "...",
            "input_schema": {
                "type": "object",
                "required": ["name", "party_size", "iso_datetime"],
                "properties": {
                    "name": {"type": "string"},
                    "party_size": {"type": "integer", "minimum": 1, "maximum": 20},
                    "iso_datetime": {"type": "string", "format": "date-time"},
                },
            },
            "verification_required": {
                "phone": {"verified_by_oneof": ["verify.aap.org"], "max_age_days": 365}
            },
        }),
        ServiceDefinition.from_dict({
            "id": "ask",
            "display_name": "Ask a question",
            "input_schema": {
                "type": "object",
                "required": ["text"],
                "properties": {"text": {"type": "string"}},
            },
        }),
    ]


def _signed_catalog(agent: str = "reception^frankies.example"):
    seed, public = generate_keypair()
    env = build_service_catalog_envelope(
        seed=seed,
        agent_address=agent,
        services=_catalog_services(),
        nonce="catalog-nonce",
    )
    return env, public


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_fetches_and_parses(tmp_path):
    env, public = _signed_catalog()
    respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(200, text=env.to_json())
    )
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: public,
    )
    try:
        cat = await cache.get("reception^frankies.example")
    finally:
        await cache.aclose()
    assert cat is not None
    assert "book-table" in cat.ids()
    assert "ask" in cat.ids()
    assert cat.canonical_agent_address == "reception^frankies.example"
    assert cat.catalog_envelope_json
    book = cat.get("book-table")
    assert book.input_schema["required"] == ["name", "party_size", "iso_datetime"]


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_reuses_in_memory_within_ttl(tmp_path):
    env, public = _signed_catalog()
    route = respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(200, text=env.to_json())
    )
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: public,
    )
    try:
        await cache.get("reception^frankies.example")
        await cache.get("reception^frankies.example")
    finally:
        await cache.aclose()
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_persists_to_disk(tmp_path):
    env, public = _signed_catalog()
    respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(200, text=env.to_json())
    )
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: public,
    )
    try:
        await cache.get("reception^frankies.example")
    finally:
        await cache.aclose()
    on_disk = list(tmp_path.iterdir())
    assert len(on_disk) == 1
    data = json.loads(on_disk[0].read_text())
    assert data["business_address"] == "reception^frankies.example"
    assert data["catalog_envelope_json"] == env.to_json()


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_returns_none_on_404(tmp_path):
    respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(404)
    )
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: b"x" * 32,
    )
    try:
        cat = await cache.get("reception^frankies.example")
    finally:
        await cache.aclose()
    assert cat is None


@pytest.mark.asyncio
async def test_catalog_cache_returns_none_for_address_without_domain(tmp_path):
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: b"x" * 32,
    )
    try:
        cat = await cache.get("bogus-no-at-sign")
    finally:
        await cache.aclose()
    assert cat is None


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_loads_from_disk_after_restart(tmp_path):
    env, public = _signed_catalog()
    respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(200, text=env.to_json())
    )
    cache_a = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: public,
    )
    try:
        await cache_a.get("reception^frankies.example")
    finally:
        await cache_a.aclose()

    # Fresh cache instance — simulates a process restart. No HTTP mock
    # this time; if it tries to fetch, respx will raise.
    respx.reset()
    cache_b = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: public,
    )
    try:
        cat = await cache_b.get("reception^frankies.example")
    finally:
        await cache_b.aclose()
    assert cat is not None
    assert "book-table" in cat.ids()


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_rejects_unsigned_json(tmp_path):
    respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(200, json={
            "agent": "reception^frankies.example",
            "services": [],
            "nonce": "n",
        })
    )
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: b"x" * 32,
    )
    try:
        cat = await cache.get("reception^frankies.example")
    finally:
        await cache.aclose()
    assert cat is None


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_rejects_bad_signature(tmp_path):
    env, _ = _signed_catalog()
    _, wrong_public = generate_keypair()
    respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(200, text=env.to_json())
    )
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: wrong_public,
    )
    try:
        cat = await cache.get("reception^frankies.example")
    finally:
        await cache.aclose()
    assert cat is None


@pytest.mark.asyncio
@respx.mock
async def test_catalog_cache_rejects_agent_from_other_domain(tmp_path):
    env, public = _signed_catalog(agent="reception^evil.example")
    respx.get("https://frankies.example/.well-known/aap-services").mock(
        return_value=httpx.Response(200, text=env.to_json())
    )
    cache = ServiceCatalogCache(
        cache_dir=tmp_path,
        agent_public_key_resolver=lambda address: public,
    )
    try:
        cat = await cache.get("reception^frankies.example")
    finally:
        await cache.aclose()
    assert cat is None


def test_build_service_catalog_envelope_signs_and_verifies():
    seed, public = generate_keypair()
    env = build_service_catalog_envelope(
        seed=seed,
        agent_address="reception^frankies.example",
        services=_catalog_services(),
        nonce="catalog-nonce",
    )
    assert env.payload_type == SERVICE_CATALOG_PAYLOAD_TYPE
    assert env.payload["agent"] == "reception^frankies.example"
    assert env.payload["nonce"] == "catalog-nonce"
    assert env.payload["services"][0]["id"] == "book-table"
    assert env.verify(public)


# -- envelope builders ------------------------------------------------------


def test_build_service_request_envelope_signs_and_verifies():
    seed, pub = generate_keypair()
    env = build_service_request_envelope(
        seed=seed,
        sender_address="john^example.com",
        target_address="reception^frankies.example",
        service_id="book-table",
        payload={"name": "John", "party_size": 4},
    )
    assert env.payload_type == ServiceRequest.PAYLOAD_TYPE
    assert env.payload["service_id"] == "book-table"
    assert env.payload["nonce"]  # auto-generated
    assert env.verify(pub)


def test_build_service_request_envelope_carries_attestations():
    seed, _ = generate_keypair()
    fake_att = '{"signed-att": "..."}'
    env = build_service_request_envelope(
        seed=seed,
        sender_address="john^example.com",
        target_address="reception^frankies.example",
        service_id="book-table",
        payload={"name": "John"},
        verification_attestations=[fake_att],
    )
    assert env.verification_attestations == [fake_att]


def test_build_service_response_envelope_confirmed():
    seed, pub = generate_keypair()
    env = build_service_response_envelope(
        seed=seed,
        sender_address="reception^frankies.example",
        service_id="book-table",
        request_nonce="req-1",
        status=ServiceResponseStatus.CONFIRMED,
        nonce="resp-1",
        payload={"confirmation_id": "FR-9X42"},
    )
    assert env.payload["status"] == "confirmed"
    assert env.payload["nonce"] == "resp-1"
    assert env.payload["payload"]["confirmation_id"] == "FR-9X42"
    assert env.verify(pub)


def test_build_service_response_envelope_denied_carries_reason():
    seed, _ = generate_keypair()
    env = build_service_response_envelope(
        seed=seed,
        sender_address="reception^frankies.example",
        service_id="book-table",
        request_nonce="req-1",
        status=ServiceResponseStatus.DENIED,
        denial_reason="no_availability",
    )
    assert env.payload["status"] == "denied"
    assert env.payload["denial_reason"] == "no_availability"
