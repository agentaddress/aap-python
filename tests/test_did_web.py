"""Tests for strict did:web key resolution and TOFU pinning."""

import json
import stat

import httpx
import pytest
import respx

from aap.did_web import (
    DIDWebError,
    KeyPinChanged,
    KeyPins,
    did_web_document_url,
    resolve_did_web_key,
)
from aap.keys import encode_b64url, generate_keypair


def _did_document(did: str, public_key: bytes) -> dict:
    key_id = did + "#agent"
    return {
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": encode_b64url(public_key),
            },
        }],
        "assertionMethod": [key_id],
    }


def test_did_web_document_url_for_domain_and_path():
    assert (
        did_web_document_url("did:web:example.com#agent")
        == "https://example.com/.well-known/did.json"
    )
    assert (
        did_web_document_url("did:web:example.com:agents:alice#key-1")
        == "https://example.com/agents/alice/did.json"
    )


@respx.mock
@pytest.mark.asyncio
async def test_resolve_did_web_key_from_authorized_jwk():
    _, public_key = generate_keypair()
    did = "did:web:example.com"
    respx.get("https://example.com/.well-known/did.json").mock(
        return_value=httpx.Response(200, json=_did_document(did, public_key))
    )

    async with httpx.AsyncClient(follow_redirects=False) as client:
        resolved = await resolve_did_web_key(did + "#agent", client=client)

    assert resolved == public_key


@respx.mock
@pytest.mark.asyncio
async def test_resolve_accepts_relative_did_key_references():
    _, public_key = generate_keypair()
    did = "did:web:example.com"
    document = _did_document(did, public_key)
    document["verificationMethod"][0]["id"] = "#agent"
    document["assertionMethod"] = ["#agent"]
    respx.get("https://example.com/.well-known/did.json").mock(
        return_value=httpx.Response(200, json=document)
    )

    async with httpx.AsyncClient(follow_redirects=False) as client:
        resolved = await resolve_did_web_key(did + "#agent", client=client)

    assert resolved == public_key


@respx.mock
@pytest.mark.asyncio
async def test_resolve_rejects_key_not_authorized_for_assertion():
    _, public_key = generate_keypair()
    did = "did:web:example.com"
    document = _did_document(did, public_key)
    document["assertionMethod"] = []
    respx.get("https://example.com/.well-known/did.json").mock(
        return_value=httpx.Response(200, json=document)
    )

    async with httpx.AsyncClient(follow_redirects=False) as client:
        with pytest.raises(DIDWebError, match="assertionMethod"):
            await resolve_did_web_key(did + "#agent", client=client)


@respx.mock
@pytest.mark.asyncio
async def test_resolve_rejects_mismatched_document_id():
    _, public_key = generate_keypair()
    document = _did_document("did:web:evil.example", public_key)
    respx.get("https://example.com/.well-known/did.json").mock(
        return_value=httpx.Response(200, json=document)
    )

    async with httpx.AsyncClient(follow_redirects=False) as client:
        with pytest.raises(DIDWebError, match="id does not match"):
            await resolve_did_web_key("did:web:example.com#agent", client=client)


def test_key_pins_reject_rotation_and_persist_privately(tmp_path):
    path = tmp_path / "key-pins.json"
    _, first = generate_keypair()
    _, second = generate_keypair()
    pins = KeyPins(path)

    pins.check_or_pin("alice^example.com", first)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == {
        "alice^example.com": encode_b64url(first)
    }
    with pytest.raises(KeyPinChanged, match="changed"):
        pins.check_or_pin("alice^example.com", second)

    assert pins.forget("alice^example.com") is True
    pins.check_or_pin("alice^example.com", second)
